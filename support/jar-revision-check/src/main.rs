use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED: &str = "ba1276acffa3e84f33cb90491e389280fd070a48";

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("checker must live at support/jar-revision-check");
    let mut manifests = Vec::new();
    collect_manifests(root, &mut manifests).expect("walk workspace manifests");

    let mut errors = Vec::new();
    for path in manifests {
        let source = fs::read_to_string(&path).expect("read Cargo.toml");
        validate_manifest(&path, &source, &mut errors);
    }
    let lock_path = root.join("Cargo.lock");
    if let Ok(lock) = fs::read_to_string(&lock_path) {
        validate_lock(&lock_path, &lock, &mut errors);
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

fn collect_manifests(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = entry.file_name();
            // Ignore nested tool worktrees and generated caches. They are not
            // part of this checkout's dependency graph.
            let hidden = name.to_string_lossy().starts_with('.');
            if !hidden && name != "target" {
                collect_manifests(&path, out)?;
            }
        } else if entry.file_name() == "Cargo.toml" {
            out.push(path);
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
}
