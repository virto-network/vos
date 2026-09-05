//! Host admission for the clean VOS3 Agent package generation.
//!
//! The portable SDK owns the canonical envelope and artifact contracts. This
//! module adds the host-only checks which deliberately do not belong in a
//! `no_std` guest: raw Ed25519 verification and full standard-PVM parsing.
//! Callers receive opaque admitted values so lifecycle code cannot accidentally
//! persist or execute a merely decoded package.

use alloc::vec::Vec;
use core::fmt;

use vos_agent_sdk::package::{
    ActorPackageManifest, AgentRuntimePackageManifest, PackageEnvelope, PackageError,
    PackageManifest, PackageVerifier,
};
use vos_agent_sdk::{
    AgentProfile, BlobRef, DeploymentId, ProducerId, ProgramId, RuntimeCapabilities,
    RuntimeRequirements, TaskId,
};

/// The package is syntactically VOS3 but is not the one canonical byte
/// representation produced by the SDK codec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageAdmissionError {
    PreviousGeneration,
    Package(PackageError),
    NonCanonical,
    WrongKind,
    InvalidActorProgram,
    InvalidTaskProgram(TaskId),
    InvalidRuntimeProgram,
    UnsupportedProfile,
    IncompatibleRuntime,
}

impl fmt::Display for PackageAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreviousGeneration => formatter.write_str(
                "unsupported Agent package generation; only canonical VOS3 packages are accepted",
            ),
            Self::Package(error) => write!(formatter, "invalid VOS3 package: {error}"),
            Self::NonCanonical => formatter.write_str("VOS3 package bytes are not canonical"),
            Self::WrongKind => formatter.write_str("VOS3 package has the wrong package kind"),
            Self::InvalidActorProgram => {
                formatter.write_str("VOS3 actor artifact is not a canonical standard PVM")
            }
            Self::InvalidTaskProgram(task) => {
                write!(
                    formatter,
                    "VOS3 Task artifact {task:?} is not a canonical standard PVM"
                )
            }
            Self::InvalidRuntimeProgram => {
                formatter.write_str("VOS3 AgentRuntime artifact is not a canonical standard PVM")
            }
            Self::UnsupportedProfile => {
                formatter.write_str("VOS3 actor requirements are unsupported by the Agent profile")
            }
            Self::IncompatibleRuntime => {
                formatter.write_str("VOS3 actor package is incompatible with the AgentRuntime")
            }
        }
    }
}

impl core::error::Error for PackageAdmissionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Package(error) => Some(error),
            _ => None,
        }
    }
}

impl From<PackageError> for PackageAdmissionError {
    fn from(value: PackageError) -> Self {
        Self::Package(value)
    }
}

struct RawEd25519Verifier;

impl PackageVerifier for RawEd25519Verifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        super::authority::verify_raw_ed25519(public_key, message, signature)
    }
}

/// One signature-checked VOS3 AgentActor package whose complete executable
/// closure has passed the host's standard-PVM parser.
#[derive(Clone, Debug)]
pub struct AdmittedActorPackage {
    envelope: PackageEnvelope,
    exact_bytes: Vec<u8>,
    package: BlobRef,
    deployment: DeploymentId,
    program: ProgramId,
}

impl AdmittedActorPackage {
    pub fn envelope(&self) -> &PackageEnvelope {
        &self.envelope
    }

    pub fn manifest(&self) -> &ActorPackageManifest {
        let PackageManifest::Actor(manifest) = &self.envelope.manifest else {
            unreachable!("admitted actor package changed kind")
        };
        manifest
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub const fn package_ref(&self) -> &BlobRef {
        &self.package
    }

    pub const fn deployment(&self) -> DeploymentId {
        self.deployment
    }

    pub const fn program(&self) -> ProgramId {
        self.program
    }

    pub fn producer(&self) -> ProducerId {
        self.manifest().signing.producer
    }

    pub fn requirements(&self) -> RuntimeRequirements {
        self.manifest().requirements
    }

    pub fn introspection_bytes(&self) -> &[u8] {
        artifact_bytes(&self.envelope, &self.manifest().introspection)
            .expect("admitted package retained its exact closure")
    }

    pub fn program_bytes(&self) -> &[u8] {
        artifact_bytes(&self.envelope, &self.manifest().program)
            .expect("admitted package retained its exact closure")
    }

    /// Check installation-time profile and runtime compatibility after both
    /// packages have independently crossed host admission.
    pub fn require_runtime(
        &self,
        profile: AgentProfile,
        runtime: &AdmittedRuntimePackage,
    ) -> Result<(), PackageAdmissionError> {
        if !self.requirements().supported_by(profile) {
            return Err(PackageAdmissionError::UnsupportedProfile);
        }
        self.envelope
            .require_compatible_with(runtime.manifest().contract, runtime.capabilities())
            .map_err(|_| PackageAdmissionError::IncompatibleRuntime)
    }
}

/// One signature-checked VOS3 AgentRuntime package whose outer executable has
/// passed the host's standard-PVM parser.
#[derive(Clone, Debug)]
pub struct AdmittedRuntimePackage {
    envelope: PackageEnvelope,
    exact_bytes: Vec<u8>,
    package: BlobRef,
    deployment: DeploymentId,
    program: ProgramId,
}

impl AdmittedRuntimePackage {
    pub fn envelope(&self) -> &PackageEnvelope {
        &self.envelope
    }

    pub fn manifest(&self) -> &AgentRuntimePackageManifest {
        let PackageManifest::AgentRuntime(manifest) = &self.envelope.manifest else {
            unreachable!("admitted runtime package changed kind")
        };
        manifest
    }

    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }

    pub const fn package_ref(&self) -> &BlobRef {
        &self.package
    }

    pub const fn deployment(&self) -> DeploymentId {
        self.deployment
    }

    pub const fn program(&self) -> ProgramId {
        self.program
    }

    pub fn producer(&self) -> ProducerId {
        self.manifest().signing.producer
    }

    pub fn capabilities(&self) -> RuntimeCapabilities {
        self.manifest().capabilities
    }

    pub fn program_bytes(&self) -> &[u8] {
        artifact_bytes(&self.envelope, &self.manifest().outer_program)
            .expect("admitted package retained its exact closure")
    }
}

/// Admit exactly one VOS3 AgentActor envelope.
pub fn admit_actor_package(bytes: &[u8]) -> Result<AdmittedActorPackage, PackageAdmissionError> {
    let envelope = decode_and_verify(bytes)?;
    let PackageManifest::Actor(manifest) = &envelope.manifest else {
        return Err(PackageAdmissionError::WrongKind);
    };
    let program_bytes = artifact_bytes(&envelope, &manifest.program)?;
    if vos_pvm::spi::parse_standard_program(program_bytes).is_none() {
        return Err(PackageAdmissionError::InvalidActorProgram);
    }
    let program = ProgramId::of_pvm(program_bytes);
    let tasks = envelope.task_dependency_set()?;
    for dependency in tasks.dependencies {
        let task_program = envelope.task_program_bytes(dependency.task)?;
        if vos_pvm::spi::parse_standard_program(task_program).is_none() {
            return Err(PackageAdmissionError::InvalidTaskProgram(dependency.task));
        }
    }
    let package = BlobRef::of_bytes(bytes);
    let deployment = envelope.deployment_id()?;
    Ok(AdmittedActorPackage {
        envelope,
        exact_bytes: bytes.to_vec(),
        package,
        deployment,
        program,
    })
}

/// Admit exactly one VOS3 AgentRuntime envelope.
pub fn admit_runtime_package(
    bytes: &[u8],
) -> Result<AdmittedRuntimePackage, PackageAdmissionError> {
    let envelope = decode_and_verify(bytes)?;
    let PackageManifest::AgentRuntime(manifest) = &envelope.manifest else {
        return Err(PackageAdmissionError::WrongKind);
    };
    let program_bytes = artifact_bytes(&envelope, &manifest.outer_program)?;
    if vos_pvm::spi::parse_standard_program(program_bytes).is_none() {
        return Err(PackageAdmissionError::InvalidRuntimeProgram);
    }
    let program = ProgramId::of_pvm(program_bytes);
    let package = BlobRef::of_bytes(bytes);
    let deployment = envelope.deployment_id()?;
    Ok(AdmittedRuntimePackage {
        envelope,
        exact_bytes: bytes.to_vec(),
        package,
        deployment,
        program,
    })
}

fn decode_and_verify(bytes: &[u8]) -> Result<PackageEnvelope, PackageAdmissionError> {
    if bytes.get(..4) != Some(b"VOS3") {
        return Err(PackageAdmissionError::PreviousGeneration);
    }
    let envelope = PackageEnvelope::decode(bytes)?;
    if envelope.encode()? != bytes {
        return Err(PackageAdmissionError::NonCanonical);
    }
    envelope.verify(&RawEd25519Verifier)?;
    Ok(envelope)
}

fn artifact_bytes<'a>(
    envelope: &'a PackageEnvelope,
    identity: &BlobRef,
) -> Result<&'a [u8], PackageAdmissionError> {
    envelope
        .artifacts
        .binary_search_by(|artifact| artifact.identity.cmp(identity))
        .ok()
        .and_then(|index| envelope.artifacts.get(index))
        .map(|artifact| artifact.bytes.as_slice())
        .ok_or(PackageAdmissionError::Package(PackageError::InvalidClosure))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use vos_agent_sdk::contract::{ActorPackageContract, RuntimePackageContract};
    use vos_agent_sdk::introspection::ActorIntrospectionArtifact;
    use vos_agent_sdk::method_policy::ActorMethodPolicyArtifact;
    use vos_agent_sdk::package::{
        ActorPackageManifest, AgentRuntimePackageManifest, PackageArtifact, PackageManifest,
        PackageSigning,
    };
    use vos_agent_sdk::schema::{
        ConstructorContract, ParsedField, ParsedInlineField, ParsedSchema,
    };
    use vos_agent_sdk::task::{TaskDependency, TaskDependencySetArtifact, TaskProofRequirement};
    use vos_agent_sdk::wire::CanonicalWire;
    use vos_agent_sdk::{Hash, LaneSet, ProofSystemSet, StateLane};
    use vos_pvm_compiler::assembler::{Assembler, Reg};

    use super::*;

    #[derive(Clone, Copy)]
    struct ActorFixture {
        lane: Option<StateLane>,
        scheduling: bool,
        task: Option<TaskProofRequirement>,
        valid_actor_pvm: bool,
        valid_task_pvm: bool,
    }

    impl Default for ActorFixture {
        fn default() -> Self {
            Self {
                lane: None,
                scheduling: false,
                task: None,
                valid_actor_pvm: true,
                valid_task_pvm: true,
            }
        }
    }

    fn standard_pvm(marker: u64) -> Vec<u8> {
        let mut assembler = Assembler::new();
        assembler.load_imm_64(Reg::A0, marker).trap();
        assembler.build_standard()
    }

    fn artifact(bytes: &[u8]) -> PackageArtifact {
        PackageArtifact {
            identity: BlobRef::of_bytes(bytes),
            bytes: bytes.to_vec(),
        }
    }

    fn signing() -> PackageSigning {
        let key = SigningKey::from_bytes(&[0x5a; 32]);
        let public_key = key.verifying_key().to_bytes();
        PackageSigning {
            producer: ProducerId::of_public_key(&public_key),
            public_key,
            signature: [0; 64],
        }
    }

    fn sign(mut package: PackageEnvelope) -> PackageEnvelope {
        let message = package.signing_bytes().unwrap();
        package.manifest.signing_mut().signature = SigningKey::from_bytes(&[0x5a; 32])
            .sign(&message)
            .to_bytes();
        package
    }

    fn actor_package(fixture: ActorFixture) -> PackageEnvelope {
        let actor_program = if fixture.valid_actor_pvm {
            standard_pvm(1)
        } else {
            b"not a standard actor PVM".to_vec()
        };
        let fields = fixture
            .lane
            .map(|lane| {
                vec![ParsedField::Inline(ParsedInlineField {
                    source_index: 0,
                    name: "value".into(),
                    type_identity: "core::primitive::u64".into(),
                    persistence: vos_agent_sdk::FieldPersistence::State(lane),
                })]
            })
            .unwrap_or_default();
        let schema = ParsedSchema {
            constructor: ConstructorContract::Forbidden,
            fields,
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let policy = ActorMethodPolicyArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();
        let introspection = ActorIntrospectionArtifact {
            actor_schema: BlobRef::of_bytes(&schema),
            method_policy: BlobRef::of_bytes(&policy),
            actor_doc: "fixture".into(),
            methods: Vec::new(),
        }
        .encode()
        .unwrap();

        let mut proof_systems = ProofSystemSet::EMPTY;
        let mut task_program = None;
        let dependencies = fixture
            .task
            .map(|proof| {
                if let Some(system) = proof.proof_system() {
                    proof_systems.insert(system).unwrap();
                }
                let bytes = if fixture.valid_task_pvm {
                    standard_pvm(2)
                } else {
                    b"not a standard Task PVM".to_vec()
                };
                let dependency = TaskDependency::new(
                    BlobRef::of_bytes(&bytes),
                    ProgramId::of_pvm(&bytes),
                    64,
                    128,
                    proof,
                )
                .unwrap();
                task_program = Some(bytes);
                vec![dependency]
            })
            .unwrap_or_default();
        let tasks = TaskDependencySetArtifact { dependencies }.encode().unwrap();
        let lanes = fixture.lane.map(LaneSet::of).unwrap_or(LaneSet::NONE);
        let mut artifacts = vec![
            artifact(&actor_program),
            artifact(&schema),
            artifact(&policy),
            artifact(&introspection),
            artifact(&tasks),
        ];
        if let Some(task_program) = task_program {
            artifacts.push(artifact(&task_program));
        }
        artifacts.sort_unstable_by(|left, right| left.identity.cmp(&right.identity));
        sign(PackageEnvelope {
            manifest: PackageManifest::Actor(ActorPackageManifest {
                name: "fixture".into(),
                program: BlobRef::of_bytes(&actor_program),
                contract: ActorPackageContract::canonical(),
                state_lane_schema: BlobRef::of_bytes(&schema),
                method_policy: BlobRef::of_bytes(&policy),
                introspection: BlobRef::of_bytes(&introspection),
                task_dependencies: BlobRef::of_bytes(&tasks),
                scheduling: fixture.scheduling,
                requirements: RuntimeRequirements {
                    lanes,
                    scheduling: fixture.scheduling,
                    proof_systems,
                },
                signing: signing(),
            }),
            artifacts,
        })
    }

    fn runtime_package(capabilities: RuntimeCapabilities, valid_program: bool) -> PackageEnvelope {
        let program = if valid_program {
            standard_pvm(3)
        } else {
            b"not a standard runtime PVM".to_vec()
        };
        sign(PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "fixture-runtime".into(),
                outer_program: BlobRef::of_bytes(&program),
                contract: RuntimePackageContract::canonical(),
                capabilities,
                signing: signing(),
            }),
            artifacts: vec![artifact(&program)],
        })
    }

    fn admit_actor(fixture: ActorFixture) -> AdmittedActorPackage {
        let bytes = actor_package(fixture).encode().unwrap();
        admit_actor_package(&bytes).unwrap()
    }

    fn admit_runtime(capabilities: RuntimeCapabilities) -> AdmittedRuntimePackage {
        let bytes = runtime_package(capabilities, true).encode().unwrap();
        admit_runtime_package(&bytes).unwrap()
    }

    #[test]
    fn admits_exact_signed_actor_and_runtime_packages() {
        let actor_envelope = actor_package(ActorFixture::default());
        let actor_bytes = actor_envelope.encode().unwrap();
        let actor = admit_actor_package(&actor_bytes).unwrap();
        assert_eq!(actor.manifest().name, "fixture");
        assert_eq!(actor.exact_bytes(), actor_bytes);
        assert_eq!(*actor.package_ref(), BlobRef::of_bytes(&actor_bytes));
        assert_eq!(actor.deployment(), actor_envelope.deployment_id().unwrap());
        assert_eq!(actor.program(), ProgramId::of_pvm(actor.program_bytes()));
        assert_eq!(actor.producer(), actor.manifest().signing.producer);

        let runtime_envelope = runtime_package(RuntimeCapabilities::standard(), true);
        let runtime_bytes = runtime_envelope.encode().unwrap();
        let runtime = admit_runtime_package(&runtime_bytes).unwrap();
        assert_eq!(runtime.manifest().name, "fixture-runtime");
        assert_eq!(runtime.exact_bytes(), runtime_bytes);
        assert_eq!(*runtime.package_ref(), BlobRef::of_bytes(&runtime_bytes));
        assert_eq!(
            runtime.deployment(),
            runtime_envelope.deployment_id().unwrap()
        );
        assert_eq!(
            runtime.program(),
            ProgramId::of_pvm(runtime.program_bytes())
        );
        actor
            .require_runtime(AgentProfile::Local, &runtime)
            .unwrap();
    }

    #[test]
    fn rejects_previous_generations_wrong_kinds_and_bad_signatures() {
        assert_eq!(
            admit_actor_package(b"VOSKprevious-generation").unwrap_err(),
            PackageAdmissionError::PreviousGeneration
        );

        let runtime = runtime_package(RuntimeCapabilities::standard(), true);
        assert_eq!(
            admit_actor_package(&runtime.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::WrongKind
        );
        let actor = actor_package(ActorFixture::default());
        assert_eq!(
            admit_runtime_package(&actor.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::WrongKind
        );

        let mut tampered = actor;
        tampered.manifest.signing_mut().signature[0] ^= 0xff;
        assert_eq!(
            admit_actor_package(&tampered.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::Package(PackageError::InvalidSignature)
        );
    }

    #[test]
    fn rejects_nonstandard_actor_task_and_runtime_programs() {
        let actor = actor_package(ActorFixture {
            valid_actor_pvm: false,
            ..ActorFixture::default()
        });
        assert_eq!(
            admit_actor_package(&actor.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::InvalidActorProgram
        );

        let actor = actor_package(ActorFixture {
            task: Some(TaskProofRequirement::None),
            valid_task_pvm: false,
            ..ActorFixture::default()
        });
        assert!(matches!(
            admit_actor_package(&actor.encode().unwrap()),
            Err(PackageAdmissionError::InvalidTaskProgram(_))
        ));

        let runtime = runtime_package(RuntimeCapabilities::standard(), false);
        assert_eq!(
            admit_runtime_package(&runtime.encode().unwrap()).unwrap_err(),
            PackageAdmissionError::InvalidRuntimeProgram
        );
    }

    #[test]
    fn enforces_profile_and_runtime_capability_compatibility() {
        let linear = admit_actor(ActorFixture {
            lane: Some(StateLane::Linear),
            ..ActorFixture::default()
        });
        let standard = admit_runtime(RuntimeCapabilities::standard());
        assert_eq!(
            linear.require_runtime(AgentProfile::Private, &standard),
            Err(PackageAdmissionError::UnsupportedProfile)
        );
        assert!(
            linear
                .require_runtime(AgentProfile::Shared, &standard)
                .is_ok()
        );

        let no_lanes = admit_runtime(RuntimeCapabilities {
            lanes: LaneSet::NONE,
            ..RuntimeCapabilities::standard()
        });
        assert_eq!(
            linear.require_runtime(AgentProfile::Local, &no_lanes),
            Err(PackageAdmissionError::IncompatibleRuntime)
        );

        let scheduled = admit_actor(ActorFixture {
            scheduling: true,
            ..ActorFixture::default()
        });
        assert_eq!(
            scheduled.require_runtime(AgentProfile::Local, &standard),
            Err(PackageAdmissionError::IncompatibleRuntime)
        );
        let scheduler = admit_runtime(RuntimeCapabilities {
            scheduling: true,
            ..RuntimeCapabilities::standard()
        });
        assert!(
            scheduled
                .require_runtime(AgentProfile::Local, &scheduler)
                .is_ok()
        );

        let proof_system = Hash::digest(b"test/proof-system", &[b"v1"]);
        let proof_actor = admit_actor(ActorFixture {
            task: Some(TaskProofRequirement::Required { proof_system }),
            ..ActorFixture::default()
        });
        assert_eq!(
            proof_actor.require_runtime(AgentProfile::Local, &standard),
            Err(PackageAdmissionError::IncompatibleRuntime)
        );
        let mut proof_systems = ProofSystemSet::EMPTY;
        proof_systems.insert(proof_system).unwrap();
        let proof_runtime = admit_runtime(RuntimeCapabilities {
            proof_systems,
            ..RuntimeCapabilities::standard()
        });
        assert!(
            proof_actor
                .require_runtime(AgentProfile::Local, &proof_runtime)
                .is_ok()
        );
    }
}
