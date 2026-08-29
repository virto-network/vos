//! Canonical package construction from a binary Task project.

use std::path::{Path, PathBuf};
use std::process::Command;

use vos::agent::MethodMode;
use vos::agent::package::Package;
use vos::agent::schema::{MethodMeta as AgentMethodMeta, SchemaMeta};
use vos::metadata::{ActorMeta, MessageMeta};
use vos::service::ServiceWire;

/// The standard-agent SPI identity is deliberately distinct from the
/// service-runtime Task identity used by Clerk's production package.
const AGENT_CLERK_APPLY_TASK_HASH: [u8; 32] = [
    0xb0, 0xd0, 0xe9, 0x05, 0x4c, 0x3e, 0x1f, 0x8a, 0x59, 0x1b, 0xf8, 0xfb, 0x30, 0x57, 0x22, 0x7a,
    0x9f, 0x00, 0x6e, 0x7d, 0xe8, 0xfb, 0x8d, 0x6d, 0xd1, 0x6f, 0x9d, 0x3d, 0x34, 0xb3, 0xbb, 0x8d,
];

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
    let task = repository.join("tests/fixtures/provable/clerk-apply");
    let input = TempDir::new("task-project-actor");
    let output = TempDir::new("task-project-output");
    let config = TempDir::new("task-project-config");
    let task_target = TempDir::new("task-project-target");

    let mut actor = vos_pvm_compiler::assembler::Assembler::new();
    actor.trap();
    let actor_pvm = actor.build_standard();
    let actor_path = input.path().join("actor.pvm");
    let metadata_path = input.path().join("actor.meta");
    let agent_schema_path = input.path().join("actor.agent");
    std::fs::write(&actor_path, actor_pvm).expect("write actor PVM");

    const META: ActorMeta = ActorMeta {
        actor_name: "task-project-e2e",
        messages: &[MessageMeta {
            name: "value",
            is_query: true,
            fields: &[],
            returns: "u64",
            doc: "",
            timeout_ms: 0,
            mode: 0,
            attested: false,
            capability: None,
            space_role: None,
            actor_role: None,
        }],
        constructor: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
    };
    let (metadata, metadata_len) = vos::metadata::encode::<512>(&META);
    std::fs::write(&metadata_path, &metadata[..metadata_len]).expect("write actor metadata");
    const AGENT_SCHEMA: SchemaMeta = SchemaMeta {
        uses_storage: false,
        fields: &[],
        methods: &[AgentMethodMeta {
            name: "value",
            mode: MethodMode::Query,
            explicit: false,
        }],
    };
    let (agent_schema, agent_schema_len) = vos::agent::schema::encode::<512>(&AGENT_SCHEMA);
    std::fs::write(&agent_schema_path, &agent_schema[..agent_schema_len])
        .expect("write agent schema");

    let built = Command::new(vosx)
        .args(["agent", "build"])
        .arg(&actor_path)
        .args(["--name", "task-project-e2e", "--task"])
        .arg(&task)
        .arg("--schemas")
        .arg(&metadata_path)
        .arg("--agent-schema")
        .arg(&agent_schema_path)
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
    assert_eq!(bytes.get(..4), Some(b"VOSK".as_slice()));
    let package = Package::decode(&bytes).expect("decode generated package");
    package.validate().expect("generated package is canonical");
    assert_eq!(package.task_dependencies.len(), 1);
    assert_eq!(
        package.task_dependencies[0].binding.task.0, AGENT_CLERK_APPLY_TASK_HASH,
        "the agent package builder must preserve the immutable SPI Task identity",
    );
    assert_eq!(
        package.task_dependencies[0].binding.witness_capacity,
        16 * 1024
    );
    assert!(
        String::from_utf8_lossy(&built.stdout).contains(&hex::encode(AGENT_CLERK_APPLY_TASK_HASH)),
        "build output exposes the dependency pin for release/review tooling",
    );
}
