use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED: &str = "41d31e64b0f5d6c57a43769d7b8785556a311684";

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("checker must live at support/jar-revision-check");
    let mut manifests = Vec::new();
    let mut locks = Vec::new();
    collect_dependency_files(root, &mut manifests, &mut locks)
        .expect("walk workspace dependency files");

    let mut errors = Vec::new();
    for path in manifests {
        let source = fs::read_to_string(&path).expect("read Cargo.toml");
        validate_manifest(&path, &source, &mut errors);
    }
    for path in locks {
        let source = fs::read_to_string(&path).expect("read Cargo.lock");
        validate_lock(&path, &source, &mut errors);
    }
    let runtime_revision = root.join("vos/src/v2/mod.rs");
    let source = fs::read_to_string(&runtime_revision).expect("read VOS v2 runtime constants");
    validate_runtime_revision(&runtime_revision, &source, &mut errors);

    if !errors.is_empty() {
        eprintln!("mixed JAR execution semantics are forbidden:");
        for error in errors {
            eprintln!("  {error}");
        }
        std::process::exit(1);
    }
    println!("all JAR consumers use {EXPECTED}");
}

fn collect_dependency_files(
    dir: &Path,
    manifests: &mut Vec<PathBuf>,
    locks: &mut Vec<PathBuf>,
) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            // Ignore nested tool worktrees and generated caches. They are not
            // part of this checkout's dependency graph.
            let hidden = name.to_string_lossy().starts_with('.');
            if !hidden && name != "target" {
                collect_dependency_files(&path, manifests, locks)?;
            }
        } else if entry.file_name() == "Cargo.toml" {
            manifests.push(path);
        } else if entry.file_name() == "Cargo.lock" {
            locks.push(path);
        }
    }
    Ok(())
}

fn validate_manifest(path: &Path, source: &str, errors: &mut Vec<String>) {
    for (index, line) in source.lines().enumerate() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let direct_consumer = is_direct_jar_consumer(line);
        if direct_consumer
            && !line.contains("workspace = true")
            && (!line.contains("https://github.com/olanod/jar.git")
                || dependency_revision(line) != Some(EXPECTED))
        {
            errors.push(format!(
                "{}:{} has a JAR consumer outside the pinned workspace revision",
                path.display(),
                index + 1,
            ));
            continue;
        }
        if !line.contains("jar.git") {
            continue;
        }
        if dependency_revision(line) != Some(EXPECTED) {
            errors.push(format!(
                "{}:{} has an unpinned or different JAR revision",
                path.display(),
                index + 1,
            ));
        }
        if line.contains("ssh://") {
            errors.push(format!(
                "{}:{} uses a non-reproducible SSH source URL",
                path.display(),
                index + 1,
            ));
        }
    }
}

fn validate_lock(path: &Path, source: &str, errors: &mut Vec<String>) {
    for (index, line) in source.lines().enumerate() {
        if !line.contains("/jar.git") {
            continue;
        }
        let requested = line
            .split_once("?rev=")
            .and_then(|(_, tail)| tail.split_once('#'));
        if !matches!(requested, Some((revision, resolved)) if revision == EXPECTED && resolved.trim_end_matches('"') == EXPECTED)
        {
            errors.push(format!(
                "{}:{} does not request and resolve the exact JAR commit",
                path.display(),
                index + 1,
            ));
        }
    }
    for package in source.split("[[package]]").skip(1) {
        let name = package.lines().find_map(|line| {
            line.trim()
                .strip_prefix("name = \"")
                .and_then(|tail| tail.strip_suffix('"'))
        });
        if !matches!(name, Some("javm" | "grey-transpiler")) {
            continue;
        }
        let source_line = package
            .lines()
            .find(|line| line.trim().starts_with("source = \""))
            .map(str::trim);
        let expected =
            format!("source = \"git+https://github.com/olanod/jar.git?rev={EXPECTED}#{EXPECTED}\"");
        if source_line != Some(expected.as_str()) {
            errors.push(format!(
                "{} resolves {} outside the pinned JAR commit",
                path.display(),
                name.expect("matched JAR package name"),
            ));
        }
    }
}

fn is_direct_jar_consumer(line: &str) -> bool {
    let key = line.split_once('=').map(|(key, _)| key.trim());
    matches!(key, Some("javm" | "grey-transpiler"))
        || line.contains("package = \"javm\"")
        || line.contains("package = \"grey-transpiler\"")
}

fn dependency_revision(line: &str) -> Option<&str> {
    let (_, tail) = line.split_once("rev = \"")?;
    tail.split_once('"').map(|(revision, _)| revision)
}

fn validate_runtime_revision(path: &Path, source: &str, errors: &mut Vec<String>) {
    let revisions = source
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("pub const JAR_REVISION: &str = \"")
                .and_then(|tail| tail.strip_suffix("\";"))
        })
        .collect::<Vec<_>>();
    if revisions != [EXPECTED] {
        errors.push(format!(
            "{} must expose exactly JAR_REVISION = {EXPECTED}",
            path.display(),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_other_and_unpinned_revisions() {
        let mut errors = Vec::new();
        validate_manifest(
            Path::new("Cargo.toml"),
            "javm = { git = \"https://github.com/olanod/jar.git\", rev = \"deadbeef\" }",
            &mut errors,
        );
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn rejects_a_direct_consumer_from_crates_io_or_another_fork() {
        for dependency in [
            "javm = \"0.4\"",
            "grey-transpiler = { path = \"../jar/grey/crates/grey-transpiler\" }",
            &format!(
                "vm = {{ package = \"javm\", git = \"https://example.com/jar.git\", rev = \"{EXPECTED}\" }}"
            ),
        ] {
            let mut errors = Vec::new();
            validate_manifest(Path::new("Cargo.toml"), dependency, &mut errors);
            assert_eq!(
                errors.len(),
                1,
                "dependency unexpectedly accepted: {dependency}"
            );
        }
    }

    #[test]
    fn accepts_workspace_inherited_consumers() {
        let mut errors = Vec::new();
        validate_manifest(
            Path::new("nested/Cargo.toml"),
            "javm = { workspace = true, optional = true }\ngrey-transpiler = { workspace = true }",
            &mut errors,
        );
        assert!(errors.is_empty());
    }

    #[test]
    fn accepts_the_consensus_revision() {
        let mut errors = Vec::new();
        validate_manifest(
            Path::new("Cargo.toml"),
            &format!(
                "javm = {{ git = \"https://github.com/olanod/jar.git\", rev = \"{EXPECTED}\" }}"
            ),
            &mut errors,
        );
        assert!(errors.is_empty());
    }

    #[test]
    fn rejects_a_stale_nested_lock_revision() {
        let mut errors = Vec::new();
        validate_lock(
            Path::new("nested/Cargo.lock"),
            "source = \"git+ssh://git@github.com/olanod/jar.git?rev=6db1168#6db1168\"",
            &mut errors,
        );
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn rejects_a_lock_whose_requested_and_resolved_revisions_differ() {
        let mut errors = Vec::new();
        validate_lock(
            Path::new("Cargo.lock"),
            &format!("source = \"git+https://github.com/olanod/jar.git?rev={EXPECTED}#deadbeef\""),
            &mut errors,
        );
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn rejects_a_lock_that_resolves_javm_from_another_source() {
        let mut errors = Vec::new();
        validate_lock(
            Path::new("Cargo.lock"),
            "[[package]]\nname = \"javm\"\nversion = \"0.4.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"",
            &mut errors,
        );
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn accepts_only_the_matching_runtime_revision_constant() {
        let mut errors = Vec::new();
        validate_runtime_revision(
            Path::new("vos/src/v2/mod.rs"),
            &format!("pub const JAR_REVISION: &str = \"{EXPECTED}\";"),
            &mut errors,
        );
        assert!(errors.is_empty());

        validate_runtime_revision(
            Path::new("vos/src/v2/mod.rs"),
            "pub const JAR_REVISION: &str = \"deadbeef\";",
            &mut errors,
        );
        assert_eq!(errors.len(), 1);
    }
}
