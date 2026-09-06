//! Canonical VOS3/ATD1 construction from a binary Task project.

use std::path::{Path, PathBuf};
use std::process::Command;

use vos::agent::sdk;

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
    let authorizations_path = input.path().join("actor.auth");
    std::fs::write(&actor_path, actor_pvm).expect("write actor PVM");

    const META: vos::metadata::ActorMeta = vos::metadata::ActorMeta {
        actor_name: "task-project-e2e",
        messages: &[vos::metadata::MessageMeta {
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
    const AGENT_SCHEMA: sdk::schema::SchemaMeta = sdk::schema::SchemaMeta {
        constructor: sdk::schema::ConstructorMeta::Forbidden,
        fields: &[],
        methods: &[sdk::schema::MethodMeta {
            source_index: 0,
            name: "value",
            mode: sdk::MethodMode::Query,
            explicit: false,
        }],
    };
    let (agent_schema, agent_schema_len) = sdk::schema::encode::<512>(&AGENT_SCHEMA);
    std::fs::write(&agent_schema_path, &agent_schema[..agent_schema_len])
        .expect("write agent schema");
    let (authorizations, authorizations_len) =
        vos::metadata::encode_agent_authorizations::<512>(&[
            vos::metadata::AgentMethodAuthorizationMeta {
                name: "value",
                selector: vos::metadata::AgentAuthorizationSelectorMeta::Public,
            },
        ]);
    std::fs::write(&authorizations_path, &authorizations[..authorizations_len])
        .expect("write Agent authorization metadata");
    let proof_system = "73".repeat(32);

    let built = Command::new(vosx)
        .args(["actor", "build"])
        .arg(&actor_path)
        .args(["--name", "task-project-e2e", "--task"])
        .arg(&task)
        .arg("--metadata")
        .arg(&metadata_path)
        .arg("--agent-schema")
        .arg(&agent_schema_path)
        .arg("--agent-authorizations")
        .arg(&authorizations_path)
        .arg("--proof-system")
        .arg(&proof_system)
        .arg("--out-dir")
        .arg(output.path())
        .env("XDG_CONFIG_HOME", config.path())
        .env("CARGO_TARGET_DIR", task_target.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run vosx actor build");
    assert!(
        built.status.success(),
        "vosx actor build failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );

    let bytes =
        std::fs::read(output.path().join("task-project-e2e.vos")).expect("read generated package");
    assert_eq!(bytes.get(..4), Some(b"VOS3".as_slice()));
    let package = sdk::package::PackageEnvelope::decode(&bytes).expect("decode generated package");
    package
        .validate_shape()
        .expect("generated package is canonical");
    let task_set = package.task_dependency_set().unwrap();
    assert_eq!(task_set.dependencies.len(), 1);
    let dependency = &task_set.dependencies[0];
    assert_eq!(dependency.witness_capacity, 16 * 1024);
    assert!(matches!(
        dependency.proof,
        sdk::task::TaskProofRequirement::Required { proof_system }
            if proof_system == sdk::Hash([0x73; 32])
    ));
    let task_pvm = package.task_program_bytes(dependency.task).unwrap();
    dependency.validate_pvm_bytes(task_pvm).unwrap();
    assert!(vos_pvm::spi::parse_standard_program(task_pvm).is_some());
    assert_eq!(package.artifacts.len(), 6);
    assert!(
        String::from_utf8_lossy(&built.stdout).contains(&hex::encode(dependency.task.0)),
        "build output exposes the full typed TaskId for release/review tooling",
    );
}
