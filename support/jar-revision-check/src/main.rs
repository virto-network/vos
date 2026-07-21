use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const EXPECTED: &str = "41d31e64b0f5d6c57a43769d7b8785556a311684";
const JAR_GIT: &str = "https://github.com/olanod/jar.git";
const JAR_PACKAGES: &[&str] = &[
    "javm",
    "grey-transpiler",
    "grey-crypto",
    "grey-types",
    "scale",
    "scale-derive",
];

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
    let mut jar_package_names = JAR_PACKAGES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    for path in &manifests {
        let source = fs::read_to_string(path).expect("read Cargo.toml");
        collect_known_alias_targets(&source, &mut jar_package_names);
    }
    for path in manifests {
        let source = fs::read_to_string(&path).expect("read Cargo.toml");
        validate_manifest(&path, &source, &mut errors);
    }
    for path in locks {
        let source = fs::read_to_string(&path).expect("read Cargo.lock");
        validate_lock(&path, &source, &jar_package_names, &mut errors);
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
    let document = match source.parse::<toml::Value>() {
        Ok(document) => document,
        Err(error) => {
            errors.push(format!("{} is not valid TOML: {error}", path.display()));
            return;
        }
    };
    let Some(root) = document.as_table() else {
        errors.push(format!("{} has no TOML root table", path.display()));
        return;
    };
    validate_dependency_sections(path, root, errors);
    if let Some(workspace) = root.get("workspace").and_then(toml::Value::as_table) {
        validate_dependency_table(path, workspace.get("dependencies"), errors);
    }
    if let Some(targets) = root.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            validate_dependency_sections(path, target, errors);
        }
    }
}

fn validate_lock(
    path: &Path,
    source: &str,
    jar_package_names: &BTreeSet<String>,
    errors: &mut Vec<String>,
) {
    let document = match source.parse::<toml::Value>() {
        Ok(document) => document,
        Err(error) => {
            errors.push(format!("{} is not valid TOML: {error}", path.display()));
            return;
        }
    };
    let expected = format!("git+{JAR_GIT}?rev={EXPECTED}#{EXPECTED}");
    let Some(packages) = document.get("package").and_then(toml::Value::as_array) else {
        return;
    };
    for package in packages.iter().filter_map(toml::Value::as_table) {
        let Some(name) = package.get("name").and_then(toml::Value::as_str) else {
            continue;
        };
        if jar_package_names.contains(name)
            && package.get("source").and_then(toml::Value::as_str) != Some(expected.as_str())
        {
            errors.push(format!(
                "{} resolves JAR package {name} from a non-canonical source",
                path.display(),
            ));
        }
    }
}

fn validate_dependency_sections(
    path: &Path,
    table: &toml::map::Map<String, toml::Value>,
    errors: &mut Vec<String>,
) {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        validate_dependency_table(path, table.get(section), errors);
    }
}

fn validate_dependency_table(
    path: &Path,
    dependencies: Option<&toml::Value>,
    errors: &mut Vec<String>,
) {
    let Some(dependencies) = dependencies.and_then(toml::Value::as_table) else {
        return;
    };
    for (alias, specification) in dependencies {
        let package = specification
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(toml::Value::as_str)
            .unwrap_or(alias);
        let known_alias = JAR_PACKAGES.contains(&alias.as_str());
        let known_package = JAR_PACKAGES.contains(&package);
        if !known_alias && !known_package {
            continue;
        }
        let valid = (!known_alias || package == alias)
            && specification.as_table().is_some_and(|table| {
                if table.get("workspace").and_then(toml::Value::as_bool) == Some(true) {
                    return table.get("git").is_none()
                        && table.get("path").is_none()
                        && table.get("registry").is_none();
                }
                table.get("git").and_then(toml::Value::as_str) == Some(JAR_GIT)
                    && table.get("rev").and_then(toml::Value::as_str) == Some(EXPECTED)
                    && table.get("path").is_none()
                    && table.get("registry").is_none()
            });
        if !valid {
            errors.push(format!(
                "{} dependency {alias} ({package}) must use the exact canonical JAR source and revision",
                path.display(),
            ));
        }
    }
}

fn collect_known_alias_targets(source: &str, names: &mut BTreeSet<String>) {
    let Ok(document) = source.parse::<toml::Value>() else {
        return;
    };
    let Some(root) = document.as_table() else {
        return;
    };
    collect_alias_targets_from_sections(root, names);
    if let Some(workspace) = root.get("workspace").and_then(toml::Value::as_table) {
        collect_alias_targets(workspace.get("dependencies"), names);
    }
    if let Some(targets) = root.get("target").and_then(toml::Value::as_table) {
        for target in targets.values().filter_map(toml::Value::as_table) {
            collect_alias_targets_from_sections(target, names);
        }
    }
}

fn collect_alias_targets_from_sections(
    table: &toml::map::Map<String, toml::Value>,
    names: &mut BTreeSet<String>,
) {
    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        collect_alias_targets(table.get(section), names);
    }
}

fn collect_alias_targets(dependencies: Option<&toml::Value>, names: &mut BTreeSet<String>) {
    let Some(dependencies) = dependencies.and_then(toml::Value::as_table) else {
        return;
    };
    for (alias, specification) in dependencies {
        if !JAR_PACKAGES.contains(&alias.as_str()) {
            continue;
        }
        if let Some(package) = specification
            .as_table()
            .and_then(|table| table.get("package"))
            .and_then(toml::Value::as_str)
        {
            names.insert(package.to_owned());
        }
    }
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

    fn known_packages() -> BTreeSet<String> {
        JAR_PACKAGES.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn rejects_other_and_unpinned_revisions() {
        let mut errors = Vec::new();
        validate_manifest(
            Path::new("Cargo.toml"),
            "[dependencies]\njavm = { git = \"https://github.com/olanod/jar.git\", rev = \"deadbeef\" }",
            &mut errors,
        );
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn rejects_path_registry_and_alternate_url_sources() {
        for source in [
            "[dependencies]\njavm = { path = \"../jar/grey/crates/javm\" }",
            "[dependencies]\njavm = { version = \"0.4\", registry = \"crates-io\" }",
            &format!(
                "[dependencies]\njavm = {{ git = \"https://github.com/olanod/jar\", rev = \"{EXPECTED}\" }}"
            ),
        ] {
            let mut errors = Vec::new();
            validate_manifest(Path::new("Cargo.toml"), source, &mut errors);
            assert_eq!(errors.len(), 1, "source unexpectedly accepted: {source}");
        }
    }

    #[test]
    fn checks_renamed_jar_packages_and_workspace_inheritance() {
        let mut errors = Vec::new();
        validate_manifest(
            Path::new("Cargo.toml"),
            "[dependencies]\nvm = { package = \"javm\", path = \"../javm\" }",
            &mut errors,
        );
        assert_eq!(errors.len(), 1);

        errors.clear();
        validate_manifest(
            Path::new("Cargo.toml"),
            "[dependencies]\njavm = { workspace = true }",
            &mut errors,
        );
        assert!(errors.is_empty());
    }

    #[test]
    fn known_alias_cannot_substitute_a_forked_package_identity() {
        let manifest = "[dependencies]\njavm = { package = \"javm-fork\", path = \"../fork\" }";
        let mut errors = Vec::new();
        validate_manifest(Path::new("Cargo.toml"), manifest, &mut errors);
        assert_eq!(errors.len(), 1);

        let mut packages = known_packages();
        collect_known_alias_targets(manifest, &mut packages);
        assert!(packages.contains("javm-fork"));
        errors.clear();
        validate_lock(
            Path::new("Cargo.lock"),
            "[[package]]\nname = \"javm-fork\"\nversion = \"0.1.0\"",
            &packages,
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
                "[dependencies]\njavm = {{ git = \"https://github.com/olanod/jar.git\", rev = \"{EXPECTED}\" }}"
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
            "[[package]]\nname = \"javm\"\nversion = \"0.4.0\"\nsource = \"git+ssh://git@github.com/olanod/jar.git?rev=6db1168#6db1168\"",
            &known_packages(),
            &mut errors,
        );
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn rejects_a_lock_whose_requested_and_resolved_revisions_differ() {
        let mut errors = Vec::new();
        validate_lock(
            Path::new("Cargo.lock"),
            &format!(
                "[[package]]\nname = \"javm\"\nversion = \"0.4.0\"\nsource = \"git+https://github.com/olanod/jar.git?rev={EXPECTED}#deadbeef\""
            ),
            &known_packages(),
            &mut errors,
        );
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn rejects_registry_and_path_jar_packages_in_locks() {
        for source in [
            "[[package]]\nname = \"javm\"\nversion = \"0.4.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"",
            "[[package]]\nname = \"javm\"\nversion = \"0.4.0\"",
        ] {
            let mut errors = Vec::new();
            validate_lock(
                Path::new("Cargo.lock"),
                source,
                &known_packages(),
                &mut errors,
            );
            assert_eq!(errors.len(), 1);
        }
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
