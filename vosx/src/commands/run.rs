//! `vosx run` one-shot execution.
//!
//! Signed `.vos` packages run through the canonical v2 root-tree service.
//! Raw ELF/PVM inputs retain the legacy executor only as an explicit
//! infrastructure/regression path during the production-node cutover.

use std::io::Read;
use std::path::{Path, PathBuf};

use vos::runtime::{GasConfig, VosRuntime};
use vos::v2::{
    AccumulateRequestV2, AccumulationEnvelopeV2, AccumulationResultV2, ActorId,
    AuthorizationEvidenceV2, BlobRefV2, ConsistencyModeV2, DeploymentId, Hash, InvocationId,
    JamServiceV2, LocalJamStoreV2, LocalWorkRequestV2, LocalWorkSchedulerV2,
    NoRefineProtocolHostV2, Origin, ProgramId, PublicationAckV2, RootServiceId, ServiceGenesisV2,
    ServiceIdentityV2, SpaceId, SystemCapabilityId, V2Wire, VosPackageV2,
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

    if program.extension().and_then(|extension| extension.to_str()) == Some("vos") {
        let service_pvm = service_pvm.unwrap_or_else(|| {
            die("running a .vos package requires --service-pvm <vos-service.pvm>")
        });
        if items.is_empty() {
            die("running a .vos package requires --method, --payload, or --hex work input");
        }
        run_v2(program, service_pvm, items, gas);
    } else {
        if !methods.is_empty() {
            die("--method is available only for signed .vos v2 packages");
        }
        run_legacy(program, items, gas);
    }
}

fn run_v2(package_path: &Path, service_path: &Path, items: Vec<Vec<u8>>, gas: u64) {
    let package_bytes = load_file(package_path);
    let package = VosPackageV2::decode(&package_bytes)
        .unwrap_or_else(|error| die(&format!("decoding {}: {error}", package_path.display())));
    package
        .validate()
        .unwrap_or_else(|error| die(&format!("validating {}: {error}", package_path.display())));
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
    let initial_bytes = Vec::new();
    let initial = BlobRefV2::of_bytes(&initial_bytes);
    let actor_genesis = package
        .actor_genesis(actor, package.manifest.name.clone(), None, initial.clone())
        .unwrap_or_else(|error| die(&format!("building actor installation: {error}")));

    let mut host = LocalJamStoreV2::default();
    if host.import_blob(initial_bytes) != initial
        || host.import_program(package.actor_pvm.clone()) != package.manifest.actor_program
    {
        die("package content identity changed while importing it");
    }
    let mut service = JamServiceV2::new(
        canonical_service,
        service_program,
        NoRefineProtocolHostV2,
        host,
        gas,
        gas.saturating_mul(10),
    )
    .unwrap_or_else(|error| die(&format!("starting generic service: {error}")));
    let genesis = ServiceGenesisV2 {
        service: identity.clone(),
        consistency,
        actors: vec![actor_genesis],
        external_actors: vec![],
        authorization: AuthorizationEvidenceV2::SystemCapability {
            capability: SystemCapabilityId(
                Hash::digest(b"vosx/local-install-capability/v2", &[&deployment.0]).0,
            ),
            authenticator: package.deployment_signature.signature.clone(),
        },
    };
    service.accumulate_host_mut().allow_install(&genesis);
    match service
        .accumulate(&AccumulateRequestV2::Install(genesis))
        .unwrap_or_else(|error| die(&format!("installing root tree: {error}")))
        .result
    {
        AccumulationResultV2::Installed(_) => {}
        AccumulationResultV2::Rejected(rejection) => die(&format!(
            "guest rejected root-tree installation: {rejection:?}"
        )),
        _ => die("generic service returned a non-install result for installation"),
    }

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
        let prepared = LocalWorkSchedulerV2::prepare(
            service.accumulate_host(),
            LocalWorkRequestV2 {
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
                imported_blobs: vec![],
                proof_requested: false,
            },
        )
        .unwrap_or_else(|error| die(&format!("scheduling v2 work: {error}")));
        let refined = service
            .refine_actor_tree(&prepared.work, &prepared.imports)
            .unwrap_or_else(|error| die(&format!("refining actor tree: {error}")));
        let input = prepared.work.input_id();
        let applied = service
            .accumulate(&AccumulateRequestV2::Apply(AccumulationEnvelopeV2 {
                work: prepared.work,
                transition: refined.transition,
                provided_blobs: refined.exported_blobs,
            }))
            .unwrap_or_else(|error| die(&format!("accumulating transition: {error}")));
        let (receipt, published) = match applied.result {
            AccumulationResultV2::Accepted {
                receipt,
                published,
                duplicate: false,
            } => (receipt, published),
            AccumulationResultV2::Accepted {
                duplicate: true, ..
            } => die("fresh local invocation was unexpectedly deduplicated"),
            AccumulationResultV2::Rejected(rejection) => {
                die(&format!("guest rejected transition: {rejection:?}"))
            }
            _ => die("generic service returned a non-apply result for actor work"),
        };

        if let Some(reply) = &published.reply {
            match Value::try_decode(&reply.result) {
                Some(value) => println!("{value:?}"),
                None => println!("0x{}", hex::encode(&reply.result)),
            }
        }
        if !published.outbox.is_empty() {
            println!(
                "checkpointed {} durable outbound call(s) at sequence {}",
                published.outbox.len(),
                receipt.sequence
            );
        }

        let publication = service
            .accumulate_host()
            .pending_publications()
            .unwrap_or_else(|error| die(&format!("reading committed publications: {error}")))
            .into_iter()
            .find(|publication| publication.input == input)
            .unwrap_or_else(|| die("accepted transition did not retain its publication row"));
        match service
            .accumulate(&AccumulateRequestV2::AcknowledgePublication(
                PublicationAckV2 {
                    service: identity.clone(),
                    input,
                    publication: publication.commitment(),
                },
            ))
            .unwrap_or_else(|error| die(&format!("acknowledging publication: {error}")))
            .result
        {
            AccumulationResultV2::PublicationAcknowledged {
                duplicate: false, ..
            } => {}
            other => die(&format!(
                "guest rejected publication acknowledgement: {other:?}"
            )),
        }
    }

    eprintln!("\nvosx: done");
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

fn run_legacy(program: &Path, mut items: Vec<Vec<u8>>, gas: u64) {
    let blob = load_blob(program);
    let mut runtime = VosRuntime::with_gas_config(GasConfig { refine_gas: gas });
    let index = runtime.register_service_blob(blob);
    let id = runtime.register_service(index);
    tracing::info!("loaded '{}' as {id:?}", program.display());

    if items.is_empty() {
        items.push(Vec::new());
    }
    for item in items {
        runtime.send_to(id, item);
    }
    tracing::info!("running");
    runtime.run_blocking();
    exit_with_status(runtime.panics);
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

fn load_blob(path: &Path) -> Vec<u8> {
    let data = load_file(path);
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("pvm") => data,
        _ => grey_transpiler::link_elf(&data)
            .unwrap_or_else(|error| die(&format!("transpiling '{}': {error:?}", path.display()))),
    }
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

fn exit_with_status(panics: u32) {
    if panics > 0 {
        eprintln!("\nvosx: {panics} panic(s)");
        std::process::exit(1);
    }
    eprintln!("\nvosx: done");
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
}
