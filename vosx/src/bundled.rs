//! Build-time-bundled PVM actor ELFs.
//!
//! The binary carries the infrastructure needed to start a space without
//! auxiliary artifact paths:
//!
//! - **space-registry**: per-space program/agent/member catalog.
//!   Required for every `vosx space new` / `space up <token>`; without it
//!   those commands have to take a `--registry` source explicitly.
//! - **space-authority**: canonical actor PVM used to construct the root-signed
//!   authority package at first service startup. Package signing remains local to
//!   the immutable space root.
//! - **agent-runtime**: standard runtime used for newly created agents unless
//!   the caller selects a compatible custom runtime package.
//!
//! `build.rs` loads the checked release blobs and verifies their pinned
//! digests. Developer target directories are never selected implicitly.

use anyhow::{anyhow, bail};
use libp2p::identity::{KeyType, Keypair};
use vos::agent::package_admission::{AdmittedRuntimePackage, admit_runtime_package};
use vos::agent::sdk::contract::RuntimePackageContract;
use vos::agent::sdk::package::{
    AgentRuntimePackageManifest, PackageArtifact, PackageEnvelope, PackageManifest, PackageSigning,
};
use vos::agent::sdk::{BlobRef, ProducerId, RuntimeCapabilities};

const BUNDLED_REGISTRY_ELF: &[u8] = include_bytes!(env!("VOSX_BUNDLED_REGISTRY_ELF"));
const BUNDLED_SPACE_AUTHORITY_PVM: &[u8] = include_bytes!(env!("VOSX_BUNDLED_SPACE_AUTHORITY_PVM"));
const BUNDLED_AGENT_RUNTIME_PVM: &[u8] = include_bytes!(env!("VOSX_BUNDLED_AGENT_RUNTIME_PVM"));
const BUNDLED_AGENT_RUNTIME_PACKAGE_NAME: &str = "standard-agent-runtime";

/// Returns the bundled space-registry ELF bytes, or `None` if
/// vosx was built without the actor pre-built.
pub fn registry_elf() -> Option<&'static [u8]> {
    // `BUNDLED_REGISTRY_ELF` is `&[u8; N]` from `include_bytes!`, so
    // clippy sees this length check as a const-false; in practice
    // build.rs writes either the actor bytes or an empty placeholder
    // and we have to discriminate at runtime.
    #[allow(clippy::const_is_empty)]
    if BUNDLED_REGISTRY_ELF.is_empty() {
        None
    } else {
        Some(BUNDLED_REGISTRY_ELF)
    }
}

/// Returns the canonical space-authority PVM bytes, or `None` when a
/// development build omitted the checked infrastructure artifact.
pub fn space_authority_pvm() -> Option<&'static [u8]> {
    #[allow(clippy::const_is_empty)]
    if BUNDLED_SPACE_AUTHORITY_PVM.is_empty() {
        None
    } else {
        Some(BUNDLED_SPACE_AUTHORITY_PVM)
    }
}

/// Returns the canonical bundled standard agent runtime.
pub fn agent_runtime_pvm() -> &'static [u8] {
    BUNDLED_AGENT_RUNTIME_PVM
}

/// Construct and admit the bundled standard AgentRuntime package signed by an
/// explicit per-space operator root.
///
/// The bundled PVM is a reproducible release artifact, but this VOS3 envelope
/// is deliberately *not* a global release signature. Its producer,
/// deployment, and package identities are bound to the caller-supplied space
/// root. No identity is loaded or generated here, and non-Ed25519 roots are
/// rejected instead of being converted or replaced.
pub(crate) fn root_signed_agent_runtime_package(
    root: &Keypair,
) -> anyhow::Result<AdmittedRuntimePackage> {
    require_ed25519_space_root(root.key_type())?;
    let public_key = root
        .public()
        .try_into_ed25519()
        .map_err(|_| anyhow!("space root did not yield a raw Ed25519 public key"))?
        .to_bytes();
    let runtime_pvm = agent_runtime_pvm();
    let outer_program = BlobRef::of_bytes(runtime_pvm);
    let mut envelope = PackageEnvelope {
        manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
            name: BUNDLED_AGENT_RUNTIME_PACKAGE_NAME.into(),
            outer_program: outer_program.clone(),
            contract: RuntimePackageContract::canonical(),
            capabilities: RuntimeCapabilities::standard(),
            signing: PackageSigning {
                producer: ProducerId::of_public_key(&public_key),
                public_key,
                signature: [0; 64],
            },
        }),
        artifacts: vec![PackageArtifact {
            identity: outer_program,
            bytes: runtime_pvm.to_vec(),
        }],
    };

    let signature = root
        .sign(&envelope.signing_bytes()?)
        .map_err(|error| anyhow!("sign bundled AgentRuntime package: {error}"))?
        .try_into()
        .map_err(|signature: Vec<u8>| {
            anyhow!(
                "Ed25519 space root returned a {}-byte signature instead of 64 bytes",
                signature.len()
            )
        })?;
    envelope.manifest.signing_mut().signature = signature;
    let bytes = envelope.encode()?;

    // Return only the host-admitted value. This proves canonical encoding,
    // signer/producer binding, exact Ed25519 verification, and that the
    // bundled outer artifact parses as a canonical standard PVM.
    admit_runtime_package(&bytes).map_err(Into::into)
}

fn require_ed25519_space_root(key_type: KeyType) -> anyhow::Result<()> {
    if key_type != KeyType::Ed25519 {
        bail!("bundled AgentRuntime packages require an Ed25519 space root");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use vos::agent::package_admission::{PackageAdmissionError, admit_runtime_package};
    use vos::agent::sdk::package::{PackageEnvelope, PackageError, PackageManifest};
    use vos::agent::sdk::{BlobRef, ProducerId, ProgramId};

    use super::*;

    const SPACE_ROOT_SEED: [u8; 32] = [0x5a; 32];

    fn space_root() -> Keypair {
        Keypair::ed25519_from_bytes(SPACE_ROOT_SEED).expect("valid Ed25519 fixture seed")
    }

    #[test]
    fn root_signed_runtime_is_exact_deterministic_and_host_admitted() {
        let root = space_root();
        let first = root_signed_agent_runtime_package(&root).expect("sign bundled runtime");
        let repeated = root_signed_agent_runtime_package(&root).expect("repeat exact signing");
        assert_eq!(first.exact_bytes(), repeated.exact_bytes());

        let raw_public_key = root
            .public()
            .try_into_ed25519()
            .expect("fixture is Ed25519")
            .to_bytes();
        let expected_producer = ProducerId::of_public_key(&raw_public_key);
        let expected_program = ProgramId::of_pvm(agent_runtime_pvm());
        let expected_package = BlobRef::of_bytes(first.exact_bytes());

        assert_eq!(first.program_bytes(), agent_runtime_pvm());
        assert_eq!(first.program(), expected_program);
        assert_eq!(first.package_ref(), &expected_package);
        assert_eq!(first.producer(), expected_producer);
        assert_eq!(first.manifest().name, BUNDLED_AGENT_RUNTIME_PACKAGE_NAME);
        assert_eq!(
            first.manifest().outer_program,
            BlobRef::of_bytes(agent_runtime_pvm())
        );
        assert_eq!(
            first.manifest().contract,
            RuntimePackageContract::canonical()
        );
        assert_eq!(
            first.manifest().capabilities,
            RuntimeCapabilities::standard()
        );
        assert_eq!(first.manifest().signing.public_key, raw_public_key);

        let decoded = PackageEnvelope::decode(first.exact_bytes()).expect("decode canonical VOS3");
        assert_eq!(
            decoded.encode().expect("re-encode canonical VOS3"),
            first.exact_bytes()
        );
        assert_eq!(decoded.deployment_id().unwrap(), first.deployment());
        assert_eq!(decoded.package_ref().unwrap(), expected_package);
        let admitted = admit_runtime_package(first.exact_bytes()).expect("re-admit exact VOS3");
        assert_eq!(admitted.deployment(), first.deployment());
        assert_eq!(admitted.program(), expected_program);
        assert_eq!(admitted.producer(), expected_producer);
    }

    #[test]
    fn host_admission_rejects_a_tampered_bundled_runtime_signature() {
        let admitted =
            root_signed_agent_runtime_package(&space_root()).expect("sign bundled runtime");
        let mut envelope =
            PackageEnvelope::decode(admitted.exact_bytes()).expect("decode signed runtime");
        let PackageManifest::AgentRuntime(manifest) = &mut envelope.manifest else {
            panic!("bundled helper returned a non-runtime package")
        };
        manifest.signing.signature[0] ^= 0x80;
        let tampered = envelope.encode().expect("encode shape-valid tamper");

        assert!(matches!(
            admit_runtime_package(&tampered),
            Err(PackageAdmissionError::Package(
                PackageError::InvalidSignature
            ))
        ));
    }

    #[test]
    fn bundled_runtime_rejects_every_non_ed25519_key_type() {
        for key_type in [KeyType::RSA, KeyType::Secp256k1, KeyType::Ecdsa] {
            let error = require_ed25519_space_root(key_type)
                .expect_err("non-Ed25519 roots must not sign VOS3 runtime packages");
            assert_eq!(
                error.to_string(),
                "bundled AgentRuntime packages require an Ed25519 space root"
            );
        }
    }
}
