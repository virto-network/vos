//! Producer-only portable actor package gates. These tests authenticate the exact
//! VOS3 closure emitted by `vosx actor build`; host admission is covered by its
//! own focused integration suite.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::{Signature, VerifyingKey};
use vos::agent::sdk;
use vos::agent::sdk::package::{PackageEnvelope, PackageManifest, PackageVerifier};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "vosx-agent-v3-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct DalekVerifier;

impl PackageVerifier for DalekVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        VerifyingKey::from_bytes(public_key)
            .map(|key| key.verify_strict(message, &Signature::from_bytes(signature)))
            .is_ok_and(|result| result.is_ok())
    }
}

fn actor_manifest(package: &PackageEnvelope) -> &sdk::package::ActorPackageManifest {
    let PackageManifest::Actor(manifest) = &package.manifest else {
        panic!("actor build emitted a runtime package")
    };
    manifest
}

#[test]
fn project_build_emits_verified_exact_vos3_closure_and_portable_role_id() {
    let temp = TempDir::new("project");
    let out = temp.0.join("dist");
    let output = Command::new(env!("CARGO_BIN_EXE_vosx"))
        .args([
            "actor",
            "build",
            "../examples/actors/shared-board",
            "--out-dir",
        ])
        .arg(&out)
        .env("XDG_CONFIG_HOME", temp.0.join("config"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run vosx actor build");
    assert!(
        output.status.success(),
        "actor build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read(out.join("Board.vos")).unwrap();
    assert_eq!(bytes.get(..4), Some(b"VOS3".as_slice()));
    let package = PackageEnvelope::decode(&bytes).unwrap();
    package.verify(&DalekVerifier).unwrap();
    let deployment = package.deployment_id().unwrap();
    assert_ne!(deployment, sdk::DeploymentId::ZERO);
    let mut replacement_signature = package.clone();
    replacement_signature.manifest.signing_mut().signature[0] ^= 1;
    assert_eq!(replacement_signature.deployment_id().unwrap(), deployment);
    let manifest = actor_manifest(&package);
    assert_eq!(
        manifest.signing.producer,
        sdk::ProducerId::of_public_key(&manifest.signing.public_key)
    );
    assert!(!manifest.scheduling);
    assert!(!manifest.requirements.scheduling);
    assert!(manifest.requirements.proof_systems.is_empty());
    assert_eq!(package.artifacts.len(), 5, "empty ATD1 remains in closure");
    let actor_pvm = package.actor_program_bytes().unwrap();
    assert!(vos_pvm::spi::parse_standard_program(actor_pvm).is_some());
    assert_ne!(sdk::ProgramId::of_pvm(actor_pvm), sdk::ProgramId::ZERO);
    assert!(matches!(
        package.actor_schema().unwrap().constructor,
        sdk::schema::ConstructorContract::Forbidden
    ));
    let policy = package.actor_method_policy().unwrap();
    let introspection = package.actor_introspection().unwrap();
    assert_eq!(policy.methods.len(), introspection.methods.len());
    let set_title = policy
        .methods
        .iter()
        .find(|method| method.name == "set_title")
        .expect("macro method surface contains set_title");
    assert_eq!(
        set_title.authorization_policy,
        sdk::method_policy::AuthorizationPolicySelector::ActorRole(sdk::RoleId([0x42; 32]))
    );
    assert!(
        package
            .task_dependency_set()
            .unwrap()
            .dependencies
            .is_empty()
    );
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 2);

    let mut old_vos2 = bytes;
    old_vos2[..4].copy_from_slice(b"VOS2");
    assert!(PackageEnvelope::decode(&old_vos2).is_err());
}

struct ProducerInputs {
    pvm: PathBuf,
    metadata: PathBuf,
    schema: PathBuf,
    authorizations: PathBuf,
}

fn write_inputs(
    root: &Path,
    metadata: &vos::metadata::ActorMeta,
    schema: &sdk::schema::SchemaMeta,
    authorizations: &[vos::metadata::AgentMethodAuthorizationMeta],
) -> ProducerInputs {
    let mut assembler = vos_pvm_compiler::assembler::Assembler::new();
    assembler.trap();
    let pvm = assembler.build_standard();
    let (metadata_bytes, metadata_len) = vos::metadata::encode::<4096>(metadata);
    let (schema_bytes, schema_len) = sdk::schema::encode::<4096>(schema);
    let (authorization_bytes, authorization_len) =
        vos::metadata::encode_agent_authorizations::<4096>(authorizations);
    let inputs = ProducerInputs {
        pvm: root.join("actor.pvm"),
        metadata: root.join("actor.meta"),
        schema: root.join("actor.aas"),
        authorizations: root.join("actor.auth"),
    };
    std::fs::write(&inputs.pvm, pvm).unwrap();
    std::fs::write(&inputs.metadata, &metadata_bytes[..metadata_len]).unwrap();
    std::fs::write(&inputs.schema, &schema_bytes[..schema_len]).unwrap();
    std::fs::write(
        &inputs.authorizations,
        &authorization_bytes[..authorization_len],
    )
    .unwrap();
    inputs
}

fn build_pvm(
    inputs: &ProducerInputs,
    out: &Path,
    config: &Path,
    name: &str,
    extra: &[&str],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_vosx"));
    command
        .args(["actor", "build"])
        .arg(&inputs.pvm)
        .arg("--metadata")
        .arg(&inputs.metadata)
        .arg("--agent-schema")
        .arg(&inputs.schema)
        .arg("--agent-authorizations")
        .arg(&inputs.authorizations)
        .arg("--out-dir")
        .arg(out)
        .args(["--name", name])
        .args(extra)
        .env("XDG_CONFIG_HOME", config)
        .output()
        .unwrap()
}

const QUERY_METHOD: sdk::schema::MethodMeta = sdk::schema::MethodMeta {
    source_index: 0,
    name: "value",
    mode: sdk::MethodMode::Query,
    explicit: true,
};

const ACTOR_ROLE_AUTHORIZATION: vos::metadata::AgentMethodAuthorizationMeta =
    vos::metadata::AgentMethodAuthorizationMeta {
        name: "value",
        selector: vos::metadata::AgentAuthorizationSelectorMeta::ActorRole([0x31; 32]),
    };

const VALUE_MESSAGE: vos::metadata::MessageMeta = vos::metadata::MessageMeta {
    name: "value",
    is_query: true,
    fields: &[],
    returns: "u64",
    doc: "Read the value.",
    timeout_ms: 0,
    mode: 0,
    attested: false,
    space_role: None,
    actor_role: Some(1),
    capability: None,
};

const ATTESTED_VALUE_MESSAGE: vos::metadata::MessageMeta = vos::metadata::MessageMeta {
    attested: true,
    ..VALUE_MESSAGE
};

#[test]
fn scheduling_and_proof_system_are_explicit_and_exact() {
    const META: vos::metadata::ActorMeta = vos::metadata::ActorMeta {
        actor_name: "Synthetic",
        messages: &[VALUE_MESSAGE],
        constructor: &[],
        cli_methods: &["value"],
        doc: "Synthetic actor.",
        crdt: false,
        provable: false,
    };
    const SCHEMA: sdk::schema::SchemaMeta = sdk::schema::SchemaMeta {
        constructor: sdk::schema::ConstructorMeta::Forbidden,
        fields: &[],
        methods: &[QUERY_METHOD],
    };
    let temp = TempDir::new("explicit");
    let inputs = write_inputs(&temp.0, &META, &SCHEMA, &[ACTOR_ROLE_AUTHORIZATION]);
    let proof_hex = "11".repeat(32);

    let unused = build_pvm(
        &inputs,
        &temp.0.join("unused"),
        &temp.0.join("unused-config"),
        "UnusedProof",
        &["--proof-system", &proof_hex],
    );
    assert!(!unused.status.success());
    assert!(String::from_utf8_lossy(&unused.stderr).contains("no attested method"));

    let scheduled = build_pvm(
        &inputs,
        &temp.0.join("scheduled"),
        &temp.0.join("scheduled-config"),
        "Scheduled",
        &["--scheduling"],
    );
    assert!(
        scheduled.status.success(),
        "{}",
        String::from_utf8_lossy(&scheduled.stderr)
    );
    let package =
        PackageEnvelope::decode(&std::fs::read(temp.0.join("scheduled/Scheduled.vos")).unwrap())
            .unwrap();
    assert!(actor_manifest(&package).scheduling);
    assert!(actor_manifest(&package).requirements.scheduling);

    let policy_ref = actor_manifest(&package).method_policy.clone();
    let policy_bytes = package
        .artifacts
        .iter()
        .find(|artifact| artifact.identity == policy_ref)
        .unwrap()
        .bytes
        .clone();
    let policy_path = temp.0.join("generated.amp2");
    std::fs::write(&policy_path, &policy_bytes).unwrap();
    let policy_arg = policy_path.to_str().unwrap();
    let exact_policy = build_pvm(
        &inputs,
        &temp.0.join("exact-policy"),
        &temp.0.join("exact-policy-config"),
        "ExactPolicy",
        &["--method-policy", policy_arg],
    );
    assert!(
        exact_policy.status.success(),
        "{}",
        String::from_utf8_lossy(&exact_policy.stderr)
    );
    let mut wrong_policy = policy_bytes;
    wrong_policy.push(0);
    std::fs::write(&policy_path, wrong_policy).unwrap();
    let rejected_policy = build_pvm(
        &inputs,
        &temp.0.join("wrong-policy"),
        &temp.0.join("wrong-policy-config"),
        "WrongPolicy",
        &["--method-policy", policy_arg],
    );
    assert!(!rejected_policy.status.success());
    assert!(String::from_utf8_lossy(&rejected_policy.stderr).contains("byte-equal"));

    const ATTESTED_META: vos::metadata::ActorMeta = vos::metadata::ActorMeta {
        actor_name: META.actor_name,
        messages: &[ATTESTED_VALUE_MESSAGE],
        constructor: META.constructor,
        cli_methods: META.cli_methods,
        doc: META.doc,
        crdt: META.crdt,
        provable: META.provable,
    };
    let attested_root = temp.0.join("attested-input");
    std::fs::create_dir_all(&attested_root).unwrap();
    let attested_inputs = write_inputs(
        &attested_root,
        &ATTESTED_META,
        &SCHEMA,
        &[ACTOR_ROLE_AUTHORIZATION],
    );
    let missing = build_pvm(
        &attested_inputs,
        &temp.0.join("missing-proof"),
        &temp.0.join("missing-config"),
        "MissingProof",
        &[],
    );
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("require an exact --proof-system"));

    let proved = build_pvm(
        &attested_inputs,
        &temp.0.join("proved"),
        &temp.0.join("proved-config"),
        "Proved",
        &["--proof-system", &proof_hex],
    );
    assert!(
        proved.status.success(),
        "{}",
        String::from_utf8_lossy(&proved.stderr)
    );
    let package =
        PackageEnvelope::decode(&std::fs::read(temp.0.join("proved/Proved.vos")).unwrap()).unwrap();
    assert_eq!(
        package.actor_method_policy().unwrap().methods[0].authorization_policy,
        sdk::method_policy::AuthorizationPolicySelector::ActorRole(sdk::RoleId([0x31; 32]))
    );
    package.verify(&DalekVerifier).unwrap();
    let proof = sdk::Hash([0x11; 32]);
    assert_eq!(
        actor_manifest(&package)
            .requirements
            .proof_systems
            .as_slice(),
        &[proof]
    );
    assert!(matches!(
        package.actor_method_policy().unwrap().methods[0].attestation,
        sdk::method_policy::AttestationRequirement::Required { proof_system }
            if proof_system == proof
    ));
}

#[test]
fn job_metadata_does_not_implicitly_enable_scheduling() {
    const JOB_MESSAGE: vos::metadata::MessageMeta = vos::metadata::MessageMeta {
        name: "start_job",
        is_query: false,
        fields: &[],
        returns: "u64",
        doc: "Start a job.",
        timeout_ms: 0,
        mode: 1,
        attested: false,
        space_role: None,
        actor_role: None,
        capability: None,
    };
    const META: vos::metadata::ActorMeta = vos::metadata::ActorMeta {
        actor_name: "JobActor",
        messages: &[JOB_MESSAGE],
        constructor: &[],
        cli_methods: &["start_job"],
        doc: "Job actor.",
        crdt: false,
        provable: false,
    };
    const SCHEMA: sdk::schema::SchemaMeta = sdk::schema::SchemaMeta {
        constructor: sdk::schema::ConstructorMeta::Forbidden,
        fields: &[],
        methods: &[sdk::schema::MethodMeta {
            source_index: 0,
            name: "start_job",
            mode: sdk::MethodMode::Linear,
            explicit: true,
        }],
    };
    const AUTHORIZATION: vos::metadata::AgentMethodAuthorizationMeta =
        vos::metadata::AgentMethodAuthorizationMeta {
            name: "start_job",
            selector: vos::metadata::AgentAuthorizationSelectorMeta::Public,
        };

    let temp = TempDir::new("job-no-scheduling");
    let inputs = write_inputs(&temp.0, &META, &SCHEMA, &[AUTHORIZATION]);
    let output = build_pvm(
        &inputs,
        &temp.0.join("dist"),
        &temp.0.join("config"),
        "JobActor",
        &[],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let package =
        PackageEnvelope::decode(&std::fs::read(temp.0.join("dist/JobActor.vos")).unwrap()).unwrap();
    assert!(!actor_manifest(&package).scheduling);
    assert!(!actor_manifest(&package).requirements.scheduling);
    assert_eq!(
        package.actor_introspection().unwrap().methods[0].dispatch,
        sdk::introspection::MethodDispatch::Job
    );
}

#[test]
fn required_raw_preserves_present_empty_and_old_aas1_is_rejected() {
    const RAW_FIELD: vos::metadata::FieldMeta = vos::metadata::FieldMeta {
        name: "bytes",
        ty: "&[u8]",
    };
    const META: vos::metadata::ActorMeta = vos::metadata::ActorMeta {
        actor_name: "Raw",
        messages: &[VALUE_MESSAGE],
        constructor: &[RAW_FIELD],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
    };
    const SCHEMA: sdk::schema::SchemaMeta = sdk::schema::SchemaMeta {
        constructor: sdk::schema::ConstructorMeta::RequiredRaw(
            sdk::schema::ConstructorArgumentMeta {
                name: "bytes",
                type_identity: sdk::schema::RAW_CONSTRUCTOR_TYPE_IDENTITY,
            },
        ),
        fields: &[],
        methods: &[QUERY_METHOD],
    };
    let temp = TempDir::new("raw");
    let inputs = write_inputs(&temp.0, &META, &SCHEMA, &[ACTOR_ROLE_AUTHORIZATION]);
    let output = build_pvm(
        &inputs,
        &temp.0.join("dist"),
        &temp.0.join("config"),
        "Raw",
        &[],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let package =
        PackageEnvelope::decode(&std::fs::read(temp.0.join("dist/Raw.vos")).unwrap()).unwrap();
    assert!(package.requires_installation_data().unwrap());
    assert!(matches!(
        package.actor_schema().unwrap().constructor,
        sdk::schema::ConstructorContract::RequiredRaw(_)
    ));

    let mut old_aas1 = std::fs::read(&inputs.schema).unwrap();
    old_aas1[..4].copy_from_slice(b"AAS1");
    std::fs::write(&inputs.schema, old_aas1).unwrap();
    let rejected = build_pvm(
        &inputs,
        &temp.0.join("old"),
        &temp.0.join("old-config"),
        "Old",
        &[],
    );
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("AAS2"));
}
