//! `vosx run` one-shot execution.
//!
//! Signed `.vos` packages run through the canonical v2 root-tree service.
//! ELF is accepted only by `vosx build`, where it is transpiled once into the
//! canonical actor PVM stored in the signed package.

use std::io::Read;
use std::path::{Path, PathBuf};

use vos::v2::{
    ActorId, AuthorizationEvidenceV2, ConsistencyModeV2, DeploymentId, Hash, InvocationId,
    LocalRootTreeConfigV2, LocalRootTreeServiceV2, LocalWorkRequestV2, MemoryCommittedImageStoreV2,
    Origin, ProgramId, RootServiceId, ServiceIdentityV2, SpaceId, SystemCapabilityId, V2Wire,
    VosPackageV2,
};
use vos::value::{Msg, TAG_DYNAMIC, Value};
use vos::{Decode, Encode};

pub fn run(
    program: &Path,
    payloads: &[PathBuf],
    hex: &[String],
    methods: &[String],
    service_pvm: Option<&Path>,
    gas: u64,
) {
    let mut items = load_items(payloads, hex);
    items.extend(methods.iter().map(|method| dynamic_message(method)));

    if !is_v2_package(program) {
        die(
            "vosx run accepts only signed .vos v2 packages; use `vosx build <actor-project-or-elf> \
             --service-pvm <vos-service.pvm>` first",
        );
    }
    let service_pvm = service_pvm
        .unwrap_or_else(|| die("running a .vos package requires --service-pvm <vos-service.pvm>"));
    if items.is_empty() {
        die("running a .vos package requires --method, --payload, or --hex work input");
    }
    run_v2(program, service_pvm, items, gas);
}

fn is_v2_package(path: &Path) -> bool {
    path.extension().and_then(|extension| extension.to_str()) == Some("vos")
}

fn run_v2(package_path: &Path, service_path: &Path, items: Vec<Vec<u8>>, gas: u64) {
    let package_bytes = load_file(package_path);
    let package = VosPackageV2::decode(&package_bytes)
        .unwrap_or_else(|error| die(&format!("decoding {}: {error}", package_path.display())));
    package
        .validate()
        .unwrap_or_else(|error| die(&format!("validating {}: {error}", package_path.display())));
    if !package.manifest.external_actors.is_empty() {
        die("vosx run cannot resolve package external actors; install this package in a space");
    }
    verify_deployment_signature(&package);

    let canonical_service = load_file(service_path);
    if javm::program::parse_blob(&canonical_service).is_none() {
        die(&format!(
            "{} is not a canonical service PVM",
            service_path.display()
        ));
    }
    let service_program = ProgramId::of_pvm(&canonical_service);
    if package.manifest.service_program != service_program {
        die("package is bound to a different generic service ProgramId");
    }

    let deployment = package.deployment_id();
    let identity = local_service_identity(deployment, service_program);
    let actor = local_root_actor(deployment);
    let consistency = if package.manifest.crdt {
        ConsistencyModeV2::Crdt
    } else {
        ConsistencyModeV2::Local
    };
    let mut service = LocalRootTreeServiceV2::open(
        LocalRootTreeConfigV2 {
            service_pvm: canonical_service,
            package,
            service: identity,
            root_actor: actor,
            actor_name: package_name(package_path),
            consistency,
            initial_state: Vec::new(),
            owned_actors: vec![],
            external_actors: vec![],
            install_authorization: AuthorizationEvidenceV2::SystemCapability {
                capability: SystemCapabilityId(
                    Hash::digest(b"vosx/local-install-capability/v2", &[&deployment.0]).0,
                ),
                authenticator: deployment.0.to_vec(),
            },
            refine_gas: gas,
            accumulate_gas: gas.saturating_mul(10),
        },
        MemoryCommittedImageStoreV2::default(),
    )
    .unwrap_or_else(|error| die(&format!("opening local root-tree service: {error}")));

    for (ordinal, arguments) in items.into_iter().enumerate() {
        let method = method_from_payload(&arguments)
            .unwrap_or_else(|| die("v2 work input must be TAG_DYNAMIC followed by a valid Msg"));
        let invocation = InvocationId::derive(
            b"vosx/local-invocation/v2",
            &Hash::digest(
                b"vosx/local-invocation-nonce/v2",
                &[&deployment.0, &(ordinal as u64).to_le_bytes(), &arguments],
            )
            .0,
        );
        let committed = service
            .invoke(LocalWorkRequestV2 {
                invocation,
                workflow_step: 0,
                logical_timeslot: ordinal as u64,
                target: actor,
                method,
                arguments,
                origin: Origin::Anonymous,
                authorization: AuthorizationEvidenceV2::Public,
                causal_parent: None,
                parent_call: None,
                awaited_reply: None,
                awaited_timeout: None,
                imported_blobs: vec![],
                proof_requested: false,
            })
            .unwrap_or_else(|error| die(&format!("executing v2 work: {error:?}")));

        if let Some(reply) = &committed.published.reply {
            match Value::try_decode(&reply.result) {
                Some(value) => println!("{value:?}"),
                None => println!("0x{}", hex::encode(&reply.result)),
            }
        }
        if !committed.published.outbox.is_empty() {
            println!(
                "checkpointed {} durable outbound call(s) at sequence {}",
                committed.published.outbox.len(),
                committed.receipt.sequence
            );
        }
        if let Some(publication) = committed.publication.as_ref() {
            let duplicate = service
                .acknowledge_publication(publication)
                .unwrap_or_else(|error| {
                    die(&format!("acknowledging committed publication: {error:?}"))
                });
            if duplicate {
                die("fresh publication acknowledgement was unexpectedly deduplicated");
            }
        }
    }

    eprintln!("\nvosx: done");
}

fn package_name(path: &Path) -> String {
    path.file_stem()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("root")
        .to_string()
}

fn verify_deployment_signature(package: &VosPackageV2) {
    let public_key =
        libp2p::identity::PublicKey::try_decode_protobuf(&package.deployment_signature.public_key)
            .unwrap_or_else(|error| die(&format!("decoding deployment public key: {error}")));
    if !public_key.verify(
        &package.signing_message(),
        &package.deployment_signature.signature,
    ) {
        die("deployment signature is invalid");
    }
}

fn local_service_identity(
    deployment: DeploymentId,
    service_program: ProgramId,
) -> ServiceIdentityV2 {
    ServiceIdentityV2 {
        space: SpaceId(Hash::digest(b"vosx/local-space/v2", &[&deployment.0]).0),
        root_service: RootServiceId(
            Hash::digest(b"vosx/local-root-service/v2", &[&deployment.0]).0,
        ),
        deployment,
        service_program,
        service_abi: vos::v2::ABI_VERSION,
        execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
    }
}

fn local_root_actor(deployment: DeploymentId) -> ActorId {
    ActorId(Hash::digest(b"vosx/local-root-actor/v2", &[&deployment.0]).0)
}

fn method_from_payload(payload: &[u8]) -> Option<String> {
    if payload.first() != Some(&TAG_DYNAMIC) {
        return None;
    }
    Msg::try_decode(&payload[1..]).map(|message| message.name)
}

fn dynamic_message(method: &str) -> Vec<u8> {
    let mut payload = vec![TAG_DYNAMIC];
    payload.extend_from_slice(&Msg::new(method).encode());
    payload
}

fn load_items(payloads: &[PathBuf], hex_items: &[String]) -> Vec<Vec<u8>> {
    let mut items = Vec::new();
    for path in payloads {
        items.push(if path.as_os_str() == "-" {
            read_stdin()
        } else {
            load_file(path)
        });
    }
    for item in hex_items {
        items.push(hex_decode(item).unwrap_or_else(|| die(&format!("invalid hex '{item}'"))));
    }
    items
}

fn die(message: &str) -> ! {
    eprintln!("error: {message}");
    std::process::exit(1);
}

fn load_file(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| die(&format!("reading {}: {error}", path.display())))
}

fn read_stdin() -> Vec<u8> {
    let mut buffer = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buffer)
        .unwrap_or_else(|error| die(&format!("stdin: {error}")));
    buffer
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim_start_matches("0x");
    hex.len()
        .is_multiple_of(2)
        .then(|| {
            (0..hex.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).ok())
                .collect::<Option<Vec<_>>>()
        })
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_argument_method_payload_round_trips() {
        let payload = dynamic_message("value");
        assert_eq!(method_from_payload(&payload).as_deref(), Some("value"));
        assert_eq!(method_from_payload(b"value"), None);
    }

    #[test]
    fn local_identities_are_stable_and_deployment_scoped() {
        let first = DeploymentId([1; 32]);
        let second = DeploymentId([2; 32]);
        let program = ProgramId([3; 32]);
        assert_eq!(
            local_service_identity(first, program),
            local_service_identity(first, program)
        );
        assert_ne!(
            local_service_identity(first, program).root_service,
            local_service_identity(second, program).root_service
        );
        assert_ne!(local_root_actor(first), local_root_actor(second));
    }

    #[test]
    fn one_shot_runner_accepts_only_signed_v2_packages() {
        assert!(is_v2_package(Path::new("Counter.vos")));
        assert!(!is_v2_package(Path::new("counter.elf")));
        assert!(!is_v2_package(Path::new("counter.pvm")));
    }
}
