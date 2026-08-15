//! Canonical package construction from a binary Task project.

use std::path::{Path, PathBuf};
use std::process::Command;

use vos::v2::{V2Wire, VosPackageV2};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "vosx-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn build_accepts_the_canonical_binary_task_project() {
    let vosx = PathBuf::from(env!("CARGO_BIN_EXE_vosx"));
    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repository = crate_root.parent().expect("vosx lives in the workspace");
    let actor = crate_root.join("blobs/dev_project.elf");
    let task = repository.join("tests/fixtures/provable/clerk-apply");
    let output = TempDir::new("task-project-output");
    let config = TempDir::new("task-project-config");
    let task_target = TempDir::new("task-project-target");

    let built = Command::new(vosx)
        .arg("build")
        .arg(&actor)
        .args(["--name", "task-project-e2e", "--task"])
        .arg(&task)
        .arg("--out-dir")
        .arg(output.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("CARGO_TARGET_DIR", task_target.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run vosx build");
    assert!(
        built.status.success(),
        "vosx build failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let bytes =
        std::fs::read(output.path().join("task-project-e2e.vos")).expect("read generated package");
    let package = VosPackageV2::decode(&bytes).expect("decode generated package");
    package.validate().expect("generated package is canonical");
    assert_eq!(package.task_dependencies.len(), 1);
    assert_eq!(
        package.task_dependencies[0].binding.witness_capacity,
        16 * 1024
    );
}
