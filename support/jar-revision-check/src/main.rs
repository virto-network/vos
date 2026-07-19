use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED: &str = "b17aeda84497cc481589ae71a5ae60819649abe8";

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
        if line.starts_with('#') || !line.contains("jar.git") {
            continue;
        }
        if !line.contains(&format!("rev = \"{EXPECTED}\"")) {
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
        if line.contains("/jar.git") && !line.contains(EXPECTED) {
            errors.push(format!(
                "{}:{} resolves a different JAR commit",
                path.display(),
                index + 1,
            ));
        }
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
}
