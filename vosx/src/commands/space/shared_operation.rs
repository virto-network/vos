//! Root-operated Shared lifecycle with exact durable client retry.
//! Public application evidence is not member admission or serving readiness.

use std::io::Read as _;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use libp2p::identity::Keypair;
use vos::agent::genesis::{
    AgentGenesisArchiveRecord, AgentGenesisLocator, AgentReplicaCommittee, AgentReplicaMember,
    MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES, derive_replica_raft_slot,
};
use vos::agent::local_lifecycle::{
    SharedCreateDisposition, SharedCreateSubmission, SharedInstallDisposition,
    SharedInstallSubmission,
};
use vos::agent::package_admission::{AdmittedActorPackage, AdmittedStateRuntimePackage};
use vos::agent::private_crypto::StrictNodeEncryptionEnrollmentVerifier;
use vos::agent::sdk::authority::{
    AuthorityActorTarget, AuthorityCredentialCall, ManagedAgentTarget,
};
use vos::agent::sdk::private::NodeEncryptionEnrollment;
use vos::agent::sdk::{
    AgentDescriptor, AgentId, AgentIdentity, AgentProfile, AgentReplica, Hash, InstallActor,
    InstallationId, InvocationId, ManagementRequest, PrincipalId, ProducerId, ReplicaRole, SpaceId,
    wire::CanonicalWire as _,
};
use vos::service::ServiceWire as _;

use super::clean_identity::CleanOperatorIdentitySigner;
use super::clean_store::{
    CleanCredentialReservation, CleanSharedCreateFile, CleanSharedInstallFile,
    CredentialReservationStatus, ensure_private_directory,
};

#[derive(clap::Args, Debug)]
pub struct CreateSharedArgs {
    pub space: String,
    /// Signed external-state VOS3 runtime (XSW2); ignored after request retention.
    #[arg(long, required_unless_present = "resume")]
    pub runtime: Option<PathBuf>,
    /// Actual signed NEN1 enrollment; repeat exactly three times for fresh Create.
    #[arg(long = "enrollment", action = clap::ArgAction::Append, required_unless_present = "resume")]
    pub enrollments: Vec<PathBuf>,
    /// Public OGAR handoff under an existing private parent; never replaced.
    #[arg(long)]
    pub archive_out: PathBuf,
    #[arg(long)]
    pub http: Option<SocketAddr>,
    /// Retry retained bytes; does not rediscover or replace authorization.
    #[arg(long)]
    pub resume: bool,
}

#[derive(clap::Args, Debug)]
pub struct InstallSharedArgs {
    pub space: String,
    /// Full target Agent ID (hex), checked against live Authority for fresh work.
    pub agent: String,
    /// Signed VOS3 actor package; not reread after request retention.
    #[arg(required_unless_present = "resume")]
    pub package: Option<PathBuf>,
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub constructor_data: Option<PathBuf>,
    #[arg(long)]
    pub http: Option<SocketAddr>,
    #[arg(long)]
    pub resume: bool,
}

#[derive(clap::Args, Debug)]
pub struct AdmitSharedArgs {
    pub space: String,
    /// Exact public OGAR exported by Shared Create; retry the same archive.
    #[arg(long)]
    pub archive: PathBuf,
    #[arg(long)]
    pub http: Option<SocketAddr>,
}

pub(crate) fn run_admit(args: AdmitSharedArgs) -> anyhow::Result<()> {
    let (data, space, node_public, address) =
        super::local_create::resolve_local_space(&args.space, args.http)?;
    let operator = crate::identity::load_existing()?;
    let locator =
        admit_shared_archive(&data, address, &operator, space, node_public, &args.archive)?;
    crate::output::print_json(&local_admission_output(locator, node_public));
    Ok(())
}

// The archive is the immutable request: no credential reservation or new
// authorization is issued by this client. All finality/publication/attachment
// checks still belong to the actual node's lifecycle owner.
pub(super) fn admit_shared_archive(
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    archive: &Path,
) -> anyhow::Result<AgentGenesisLocator> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "Shared member admission requires a nonzero loopback endpoint"
    );
    // R22 verifies the deployed System before even reading a handoff input.
    let authority = authority(data, operator, space, node_public)?;
    let bytes = read_bounded(archive, MAX_AGENT_GENESIS_ARCHIVE_RECORD_BYTES)?;
    let record = AgentGenesisArchiveRecord::decode(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid Shared archive: {error:?}"))?;
    anyhow::ensure!(record.encode() == bytes, "noncanonical Shared archive");
    let public = libp2p::identity::ed25519::PublicKey::try_from_bytes(&node_public)?;
    let node = super::clean_identity::node_id_from_authenticated_peer(
        &libp2p::identity::PublicKey::from(public).to_peer_id(),
    );
    let locator = super::clean_store::CleanSharedMemberGenesisFiles::validate_client_record(
        vos::service::SpaceId(space.0),
        vos::service::NodeId(node.0),
        &record,
    )?;
    let descriptor = record
        .provision()
        .proposal()
        .clean_descriptor()
        .map_err(|error| anyhow::anyhow!("invalid Shared descriptor: {error:?}"))?;
    anyhow::ensure!(
        descriptor.authority == authority.binding
            && descriptor.identity.owner
                == PrincipalId::of_public_key(&authority.binding.public_key)
            && descriptor.identity.agent != authority.system_agent,
        "Shared archive differs from the configured Root/System target"
    );
    post_member_admission(address, &bytes, locator, node)
}

fn post_member_admission(
    address: SocketAddr,
    bytes: &[u8],
    locator: AgentGenesisLocator,
    expected_node: vos::agent::sdk::NodeId,
) -> anyhow::Result<AgentGenesisLocator> {
    let response = super::local_create::post_shared_member_admission_response(
        address,
        bytes,
        expected_node,
        locator.encode().len(),
    )?;
    let returned = AgentGenesisLocator::decode(&response)
        .map_err(|error| anyhow::anyhow!("invalid local admission response: {error:?}"))?;
    anyhow::ensure!(
        returned == locator && returned.encode() == response,
        "local admission response differs from the supplied archive"
    );
    Ok(returned)
}

fn local_admission_output(
    locator: AgentGenesisLocator,
    node_public: [u8; 32],
) -> serde_json::Value {
    serde_json::json!({
        "phase": "locally-admitted", "ready": false,
        "space": hex::encode(locator.space.0), "agent": hex::encode(locator.agent.0),
        "node_public_key": hex::encode(node_public),
        "local_admitted": true, "local_attached": true,
        "next": "verify live quorum readiness separately before relying on shared service",
    })
}

pub(crate) fn run_create(args: CreateSharedArgs) -> anyhow::Result<()> {
    let (data, space, public, address) =
        super::local_create::resolve_local_space(&args.space, args.http)?;
    let operator = crate::identity::load_existing()?;
    let disposition = create_shared(&data, address, &operator, space, public, &args)?;
    let SharedCreateDisposition::Applied(application) = disposition else {
        crate::output::print_json(&serde_json::json!({
            "phase": "completed", "decision": "denied", "ready": false,
            "space": hex::encode(space.0),
            "management_completed": true, "response_retained": true,
        }));
        anyhow::bail!(
            "Shared Create denied; verified terminal retained; no archive published; a new attempt requires fresh authorization without --resume"
        );
    };
    let archive = super::clean_startup::publish_shared_archive(
        &args.archive_out,
        &application.archive().encode(),
    ).map_err(|error| anyhow::anyhow!(
        "{error}; Shared Create is Applied, not Ready; exact request/response retained; retry --resume with a valid or fresh --archive-out instead of issuing a new Create"
    ))?;
    crate::output::print_json(&serde_json::json!({
        "phase": "applied", "ready": false,
        "space": hex::encode(application.acknowledgement().managed.space.0),
        "agent": hex::encode(application.acknowledgement().managed.agent.0),
        "management_completed": true, "response_retained": true,
        "archive": archive,
        "next": "admit the exact archive on the other members and verify live quorum readiness",
    }));
    Ok(())
}

pub(crate) fn run_install(args: InstallSharedArgs) -> anyhow::Result<()> {
    let (data, space, node_public, address) =
        super::local_create::resolve_local_space(&args.space, args.http)?;
    let agent = AgentId(
        hex::decode(&args.agent)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid full Agent ID"))?,
    );
    let operator = crate::identity::load_existing()?;
    let disposition = install_shared(&data, address, &operator, space, node_public, agent, &args)?;
    let (decision, actor, error) = match &disposition {
        SharedInstallDisposition::Applied(ack) => {
            let vos::agent::sdk::ManagementReply::Installed(entry) = &ack.application else {
                anyhow::bail!("verified Install returned an unexpected application");
            };
            ("applied", Some(hex::encode(entry.actor.0)), None)
        }
        SharedInstallDisposition::Denied(_) => ("denied", None, None),
        SharedInstallDisposition::Failed(failure) => {
            ("failed", None, Some(format!("{:?}", failure.error)))
        }
    };
    crate::output::print_json(&serde_json::json!({
        "phase": "completed", "decision": decision,
        "space": hex::encode(space.0), "agent": hex::encode(agent.0),
        "actor": actor, "error": error,
        "management_completed": true, "response_retained": true,
    }));
    if decision != "applied" {
        anyhow::bail!(
            "Shared Install {decision}; verified terminal retained; a new attempt requires fresh authorization without --resume"
        );
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> anyhow::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "input must be a bounded regular file: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= maximum && bytes.len() as u64 == metadata.len(),
        "input changed or exceeded its wire bound: {}",
        path.display()
    );
    Ok(bytes)
}

fn authority(
    data: &Path,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
) -> anyhow::Result<AuthorityActorTarget> {
    super::local_config::require_image_local_lifecycle(data)?;
    super::clean_startup::client_system_authority_target(data, space, operator, node_public)
}

fn attempt(
    data: &Path,
    identity: &CleanOperatorIdentitySigner<'_>,
    space: SpaceId,
    resume: bool,
) -> anyhow::Result<(
    CleanCredentialReservation,
    Hash,
    CredentialReservationStatus,
    PathBuf,
)> {
    let root = data.join("agent-client");
    let _root = ensure_private_directory(&root)?;
    let claims = root.join("credentials");
    let _claims = ensure_private_directory(&claims)?;
    let mut reservation =
        CleanCredentialReservation::open_or_create(&claims, space, identity.credential())?;
    let nonce = match reservation.current()? {
        Some((nonce, _)) if resume => nonce,
        Some((nonce, CredentialReservationStatus::Pending)) => anyhow::bail!(
            "credential operation {} is pending; resume its original command",
            hex::encode(nonce.0)
        ),
        _ if resume => anyhow::bail!("no retained credential operation to resume"),
        _ => {
            let mut nonce = [0; 32];
            getrandom::getrandom(&mut nonce)
                .map_err(|error| anyhow::anyhow!("operation nonce entropy: {error}"))?;
            anyhow::ensure!(nonce != [0; 32], "operation nonce entropy was zero");
            Hash(nonce)
        }
    };
    let status = reservation.reserve(nonce)?;
    let operations = root.join("operations");
    let _operations = ensure_private_directory(&operations)?;
    let operation = operations.join(format!(
        "{}-{}",
        hex::encode(identity.credential().0),
        hex::encode(nonce.0)
    ));
    let _operation = ensure_private_directory(&operation)?;
    Ok((reservation, nonce, status, operation))
}

fn window() -> anyhow::Result<(u64, u64)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    Ok((
        now.saturating_sub(60),
        now.checked_add(3600)
            .ok_or_else(|| anyhow::anyhow!("validity window overflow"))?,
    ))
}

fn sign_call(
    operator: &Keypair,
    authority: AuthorityActorTarget,
    descriptor: &AgentDescriptor,
    request: &ManagementRequest,
    sequence: NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<AuthorityCredentialCall> {
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        descriptor.identity.space == authority.space
            && descriptor.identity.profile == AgentProfile::Shared
            && descriptor.identity.owner == identity.principal()
            && descriptor.authority == authority.binding
            && descriptor.validate().is_ok(),
        "Shared descriptor differs from selected Space, Root or Authority"
    );
    let mut call = AuthorityCredentialCall {
        invocation: InvocationId::ZERO,
        authority,
        managed: ManagedAgentTarget {
            space: descriptor.identity.space,
            agent: descriptor.identity.agent,
            owner: descriptor.identity.owner,
            profile: AgentProfile::Shared,
            runtime_deployment: descriptor.identity.runtime_deployment,
            transition_producer: descriptor.identity.transition_producer,
        },
        principal: identity.principal(),
        credential: identity.credential(),
        request_sequence: sequence,
        credential_public_key: identity.raw_public_key(),
        authenticated_node: None,
        requested_valid_from: valid_from,
        requested_expires_at: expires_at,
        plan: request
            .authorization_plan()
            .ok_or_else(|| anyhow::anyhow!("invalid Shared management plan"))?,
        signature: [0; 64],
    };
    call.invocation = call.expected_invocation();
    call.signature = operator
        .sign(&call.signing_bytes())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("management signature must be Ed25519"))?;
    Ok(call)
}

pub(super) fn create_materials(
    operator: &Keypair,
    authority: AuthorityActorTarget,
    node_public: [u8; 32],
    nonce: Hash,
    runtime: &AdmittedStateRuntimePackage,
    enrollments: &[NodeEncryptionEnrollment],
) -> anyhow::Result<(AgentDescriptor, AgentReplicaCommittee)> {
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    anyhow::ensure!(
        enrollments.len() == 3 && node_public != identity.raw_public_key(),
        "Shared Create requires three distinct actual voters and a separate node identity"
    );
    let agent = AgentId::derive(authority.space, identity.principal(), nonce.as_bytes());
    let mut members = Vec::new();
    let mut nodes = std::collections::BTreeSet::new();
    let mut prefixes = std::collections::BTreeSet::new();
    for enrollment in enrollments {
        anyhow::ensure!(
            enrollment.space == authority.space
                && enrollment.principal == identity.principal()
                && enrollment.verify_with(&StrictNodeEncryptionEnrollmentVerifier),
            "enrollment differs from Space, Root or authenticated node possession"
        );
        let peer = libp2p::PeerId::from_bytes(&enrollment.transport_peer_id)?;
        anyhow::ensure!(
            nodes.insert(enrollment.node)
                && prefixes.insert(vos::network::derive_node_prefix(&peer)),
            "duplicate or colliding replica identities"
        );
        members.push(AgentReplicaMember::new(
            vos::agent::AgentReplica {
                node: vos::service::NodeId(enrollment.node.0),
                principal: vos::service::PrincipalId(enrollment.principal.0),
                role: vos::agent::ReplicaRole::Voter,
            },
            enrollment.transport_peer_id.to_vec(),
            enrollment.transport_public_key,
            Some(derive_replica_raft_slot(&enrollment.transport_peer_id)),
        )?);
    }
    anyhow::ensure!(
        enrollments
            .iter()
            .filter(|row| row.transport_public_key == node_public)
            .count()
            == 1,
        "selected daemon is not an actual voter in the roster"
    );
    members.sort_by_key(|member| member.replica().node);
    let committee = AgentReplicaCommittee::new(
        vos::service::SpaceId(authority.space.0),
        vos::service::AgentId(agent.0),
        vos::agent::AgentProfile::Shared,
        members,
    )?;
    let descriptor = AgentDescriptor {
        identity: AgentIdentity {
            space: authority.space,
            agent,
            owner: identity.principal(),
            profile: AgentProfile::Shared,
            runtime_deployment: runtime.deployment(),
            runtime_program: runtime.program(),
            runtime_producer: runtime.manifest().signing.producer,
            transition_producer: ProducerId::of_public_key(&node_public),
        },
        creation_nonce: nonce,
        authority: authority.binding,
        private_recovery: None,
        runtime_package: runtime.package_ref().clone(),
        runtime_contract: runtime.manifest().contract,
        capabilities: runtime.manifest().capabilities,
        replicas: committee
            .members()
            .iter()
            .map(|member| AgentReplica {
                node: vos::agent::sdk::NodeId(member.replica().node.0),
                principal: PrincipalId(member.replica().principal.0),
                role: ReplicaRole::Voter,
            })
            .collect(),
    };
    descriptor
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid Shared descriptor: {error:?}"))?;
    committee.validate_for_clean_descriptor(&descriptor)?;
    Ok((descriptor, committee))
}

fn create_shared(
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    args: &CreateSharedArgs,
) -> anyhow::Result<SharedCreateDisposition> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "Shared Create requires nonzero loopback HTTP"
    );
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    let authority = authority(data, operator, space, node_public)?;
    let (mut reservation, nonce, status, operation) = attempt(data, &identity, space, args.resume)?;
    let mut store = CleanSharedCreateFile::open_or_create(operation.join("request"))?;
    let request = match store.load_request()? {
        Some(bytes) => bytes,
        None => {
            anyhow::ensure!(
                status == CredentialReservationStatus::Pending,
                "completed Create is missing its retained request"
            );
            let runtime_path = args.runtime.as_deref().ok_or_else(|| {
                anyhow::anyhow!("fresh Create requires --runtime with a signed XSW2 package")
            })?;
            anyhow::ensure!(
                args.enrollments.len() == 3,
                "fresh Shared Create requires exactly three --enrollment files"
            );
            let runtime =
                vos::agent::package_admission::admit_state_runtime_package(&read_bounded(
                    runtime_path,
                    vos::agent::sdk::package::MAX_PACKAGE_ENCODED_BYTES,
                )?)
                .map_err(|error| anyhow::anyhow!("invalid signed external runtime: {error:?}"))?;
            let enrollments = args
                .enrollments
                .iter()
                .map(|path| {
                    NodeEncryptionEnrollment::decode(&read_bounded(
                        path,
                        NodeEncryptionEnrollment::MAX_ENCODED_BYTES,
                    )?)
                    .map_err(|error| anyhow::anyhow!("invalid NEN1 enrollment: {error:?}"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            // Validate roster/package before performing a credential query.
            let (descriptor, committee) = create_materials(
                operator,
                authority,
                node_public,
                nonce,
                &runtime,
                &enrollments,
            )?;
            let (_, sequence) = super::local_create::discover_credential(
                &operation.join("query"),
                address,
                operator,
                authority,
            )?;
            let (valid_from, expires_at) = window()?;
            let call = sign_call(
                operator,
                authority,
                &descriptor,
                &ManagementRequest::Create(Box::new(descriptor.clone())),
                sequence,
                valid_from,
                expires_at,
            )?;
            let bytes = SharedCreateSubmission::new(descriptor, call, runtime, committee)
                .map_err(|error| anyhow::anyhow!("invalid signed Shared Create: {error:?}"))?
                .encode();
            store.publish_request(&bytes)?;
            bytes
        }
    };
    let submission = SharedCreateSubmission::decode(&request)
        .map_err(|error| anyhow::anyhow!("invalid retained SCQ1: {error:?}"))?;
    let descriptor = submission.descriptor();
    anyhow::ensure!(
        descriptor.creation_nonce == nonce
            && descriptor.identity.space == space
            && descriptor.identity.owner == identity.principal()
            && descriptor.identity.transition_producer == ProducerId::of_public_key(&node_public)
            && submission.call().principal == identity.principal()
            && submission.call().credential == identity.credential()
            && submission.call().authority == authority,
        "retained Shared Create differs from selected Space, Root or originating node"
    );
    let response = match store.load_response()? {
        Some(bytes) => bytes,
        None => {
            let (status, bytes) = super::local_create::post_binary_response(
                address,
                "/_vos/agents/shared/create",
                202,
                &request,
                SharedCreateSubmission::MAX_RESPONSE_BYTES,
                Some(SharedCreateSubmission::MAX_RESPONSE_BYTES),
                None,
            )
            .map_err(super::local_create::retained_submission_error)?;
            let disposition = submission.decode_response(&bytes).map_err(|error| {
                anyhow::anyhow!("invalid request-bound SCR1: {error:?}; request retained")
            })?;
            anyhow::ensure!(
                status == create_response_status(&disposition),
                "HTTP status differs from verified Shared Create disposition; request retained"
            );
            store.publish_response(&bytes)?;
            bytes
        }
    };
    let disposition = submission
        .decode_response(&response)
        .map_err(|error| anyhow::anyhow!("invalid request-bound SCR1: {error:?}"))?;
    reservation.complete_shared_create(&mut store)?;
    Ok(disposition)
}

fn create_response_status(disposition: &SharedCreateDisposition) -> u16 {
    match disposition {
        SharedCreateDisposition::Applied(_) => 202,
        SharedCreateDisposition::Denied(_) => 403,
    }
}

// The integrated packaged fixture supplies the actual selected root and HTTP
// endpoint. All discovery, signing, custody and delivery remain the CLI path.
#[cfg(test)]
pub(super) fn create_shared_for_test(
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    args: &CreateSharedArgs,
) -> anyhow::Result<SharedCreateDisposition> {
    create_shared(data, address, operator, space, node_public, args)
}

fn prepare_install(
    operator: &Keypair,
    authority: AuthorityActorTarget,
    descriptor: &AgentDescriptor,
    install: InstallActor,
    package: AdmittedActorPackage,
    sequence: NonZeroU64,
    valid_from: u64,
    expires_at: u64,
) -> anyhow::Result<SharedInstallSubmission> {
    anyhow::ensure!(
        descriptor.replicas.len() == 3
            && descriptor
                .replicas
                .iter()
                .all(|replica| replica.role == ReplicaRole::Voter),
        "Shared Install requires a fixed-three voter descriptor"
    );
    package
        .envelope()
        .require_compatible_with(descriptor.runtime_contract, descriptor.capabilities)
        .map_err(|error| anyhow::anyhow!("unsupported actor requirements: {error:?}"))?;
    let call = sign_call(
        operator,
        authority,
        descriptor,
        &ManagementRequest::Install(Box::new(install.clone())),
        sequence,
        valid_from,
        expires_at,
    )?;
    SharedInstallSubmission::new(install, call, package)
        .map_err(|error| anyhow::anyhow!("invalid signed Shared Install: {error:?}"))
}

fn install_shared(
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    agent: AgentId,
    args: &InstallSharedArgs,
) -> anyhow::Result<SharedInstallDisposition> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0 && agent != AgentId::ZERO,
        "invalid Shared Install target/endpoint"
    );
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    let authority = authority(data, operator, space, node_public)?;
    let (mut reservation, nonce, status, operation) = attempt(data, &identity, space, args.resume)?;
    let mut store = CleanSharedInstallFile::open_or_create(operation.join("request"))?;
    let request = match store.load_request()? {
        Some(bytes) => bytes,
        None => {
            anyhow::ensure!(
                status == CredentialReservationStatus::Pending,
                "completed Install is missing its retained request"
            );
            let path = args
                .package
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("fresh Install requires a signed actor package"))?;
            let package = vos::agent::package_admission::admit_actor_package(&read_bounded(
                path,
                vos::agent::sdk::package::MAX_PACKAGE_ENCODED_BYTES,
            )?)
            .map_err(|error| anyhow::anyhow!("invalid actor package: {error:?}"))?;
            let data = args
                .constructor_data
                .as_deref()
                .map(|path| read_bounded(path, vos::agent::sdk::MAX_INSTALLATION_DATA_BYTES))
                .transpose()?;
            let name = args
                .name
                .clone()
                .unwrap_or_else(|| package.manifest().name.clone());
            let registry_reservation = Hash::digest(
                b"vos/shared-install/registry-reservation/v1",
                &[
                    space.as_bytes(),
                    agent.as_bytes(),
                    nonce.as_bytes(),
                    package.package_ref().hash.as_bytes(),
                ],
            );
            let install = super::local_install::build_install(
                agent,
                InstallationId(nonce.0),
                registry_reservation,
                name,
                None,
                data,
                &package,
            )?;
            let (credential, sequence) = super::local_create::discover_credential(
                &operation.join("query"),
                address,
                operator,
                authority,
            )?;
            let descriptor = super::local_install::discover_agent(
                address,
                operator,
                authority,
                credential.head,
                agent,
            )?;
            let (valid_from, expires_at) = window()?;
            let bytes = prepare_install(
                operator,
                authority,
                &descriptor,
                install,
                package,
                sequence,
                valid_from,
                expires_at,
            )?
            .encode();
            store.publish_request(&bytes)?;
            bytes
        }
    };
    let submission = SharedInstallSubmission::decode(&request)
        .map_err(|error| anyhow::anyhow!("invalid retained SIQ1: {error:?}"))?;
    let call = submission.call();
    anyhow::ensure!(
        submission.install().installation_id.0 == nonce.0
            && call.authority == authority
            && call.managed.space == space
            && call.managed.agent == agent
            && call.managed.owner == identity.principal()
            && call.principal == identity.principal()
            && call.credential == identity.credential(),
        "retained Shared Install differs from selected Space, Agent or Root"
    );
    let response = match store.load_response()? {
        Some(bytes) => bytes,
        None => {
            let (status, bytes) =
                super::local_create::post_shared_install_response(address, &request)
                    .map_err(super::local_create::retained_submission_error)?;
            let disposition = submission
                .decode_response(&bytes)
                .map_err(|error| anyhow::anyhow!("invalid request-bound SIR1: {error:?}"))?;
            anyhow::ensure!(
                status == install_status(&disposition),
                "HTTP status contradicts the verified Install terminal"
            );
            store.publish_response(&bytes)?;
            bytes
        }
    };
    let disposition = submission
        .decode_response(&response)
        .map_err(|error| anyhow::anyhow!("invalid retained SIR1: {error:?}"))?;
    reservation.complete_shared_install(&mut store)?;
    Ok(disposition)
}

fn install_status(disposition: &SharedInstallDisposition) -> u16 {
    match disposition {
        SharedInstallDisposition::Applied(_) => 201,
        SharedInstallDisposition::Denied(_) => 403,
        SharedInstallDisposition::Failed(_) => 422,
    }
}

// The integrated candidate fixture supplies actual production roots/HTTP and
// the real operator. This wrapper does not change delivery or sign test proof.
#[cfg(test)]
pub(super) fn install_shared_for_test(
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    agent: AgentId,
    args: &InstallSharedArgs,
) -> anyhow::Result<SharedInstallDisposition> {
    install_shared(data, address, operator, space, node_public, agent, args)
}

// Retain precisely the normal CLI preparation without sending it, so a real
// file-owner receipt fault can be introduced before public startup recovery.
#[cfg(test)]
pub(super) fn retain_install_for_test(
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    agent: AgentId,
    package: AdmittedActorPackage,
    discover: impl FnOnce(
        &Path,
        SocketAddr,
        AuthorityActorTarget,
    ) -> anyhow::Result<(AgentDescriptor, NonZeroU64)>,
) -> anyhow::Result<(PathBuf, SharedInstallSubmission)> {
    let identity = CleanOperatorIdentitySigner::new(operator)?;
    let authority = authority(data, operator, space, node_public)?;
    let (_reservation, nonce, status, operation) = attempt(data, &identity, space, false)?;
    anyhow::ensure!(
        status == CredentialReservationStatus::Pending,
        "fresh Install reservation"
    );
    let request_root = operation.join("request");
    let mut store = CleanSharedInstallFile::open_or_create(&request_root)?;
    anyhow::ensure!(store.load_request()?.is_none(), "fresh Install request");
    let registry_reservation = Hash::digest(
        b"vos/shared-install/registry-reservation/v1",
        &[
            space.as_bytes(),
            agent.as_bytes(),
            nonce.as_bytes(),
            package.package_ref().hash.as_bytes(),
        ],
    );
    let install = super::local_install::build_install(
        agent,
        InstallationId(nonce.0),
        registry_reservation,
        package.manifest().name.clone(),
        None,
        None,
        &package,
    )?;
    // The fixture may retry only these normal discovery reads while this
    // original credential reservation, nonce and query path remain held.
    // Signing and immutable SIQ1 publication below still run exactly once.
    let (descriptor, sequence) = discover(&operation.join("query"), address, authority)?;
    let (valid_from, expires_at) = window()?;
    let submission = prepare_install(
        operator,
        authority,
        &descriptor,
        install,
        package,
        sequence,
        valid_from,
        expires_at,
    )?;
    store.publish_request(&submission.encode())?;
    Ok((request_root, submission))
}

#[cfg(test)]
mod tests {
    use super::super::clean_store::tests::Fixture;
    use super::*;
    use clap::Parser as _;
    use std::io::Write as _;

    fn enrollments(create: &SharedCreateSubmission) -> Vec<NodeEncryptionEnrollment> {
        [0x46, 0x47, 0x48]
            .map(|seed| {
                let node = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
                super::super::clean_identity::sign_node_encryption_enrollment(
                    &node,
                    create.descriptor().identity.space,
                    create.descriptor().identity.owner,
                    [0x73; 32],
                )
                .unwrap()
            })
            .to_vec()
    }

    #[test]
    fn cli_requires_explicit_fresh_inputs_and_allows_retained_resume_without_them() {
        for argv in [
            vec![
                "vosx",
                "space",
                "create-shared-agent",
                "demo",
                "--runtime",
                "runtime.vos",
                "--enrollment",
                "a.nen",
                "--enrollment",
                "b.nen",
                "--enrollment",
                "c.nen",
                "--archive-out",
                "agent.ogar",
            ],
            vec![
                "vosx",
                "space",
                "create-shared-agent",
                "demo",
                "--resume",
                "--archive-out",
                "agent.ogar",
            ],
            vec![
                "vosx",
                "space",
                "install-shared-actor",
                "demo",
                "01",
                "actor.vos",
            ],
            vec![
                "vosx",
                "space",
                "install-shared-actor",
                "demo",
                "01",
                "--resume",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(argv).is_ok());
        }
        for argv in [
            vec![
                "vosx",
                "space",
                "create-shared-agent",
                "demo",
                "--archive-out",
                "agent.ogar",
            ],
            vec!["vosx", "space", "create-shared-agent", "demo", "--resume"],
            vec!["vosx", "space", "install-shared-actor", "demo", "01"],
        ] {
            assert!(crate::Cli::try_parse_from(argv).is_err());
        }
    }

    #[test]
    fn cli_member_admission_requires_an_explicit_archive_without_new_authorization() {
        for argv in [
            vec![
                "vosx",
                "space",
                "admit-shared",
                "demo",
                "--archive",
                "agent.ogar",
            ],
            vec![
                "vosx",
                "space",
                "admit-shared",
                "demo",
                "--archive",
                "agent.ogar",
                "--http",
                "127.0.0.1:8080",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(argv).is_ok());
        }
        for argv in [
            vec!["vosx", "space", "admit-shared", "demo"],
            vec!["vosx", "space", "admit-shared", "demo", "--resume"],
            vec![
                "vosx",
                "space",
                "admit-shared",
                "demo",
                "--archive",
                "agent.ogar",
                "--runtime",
                "other.vos",
            ],
        ] {
            assert!(crate::Cli::try_parse_from(argv).is_err());
        }
    }

    #[test]
    fn member_admission_transport_binds_exact_locator_and_never_claims_ready() {
        // Transport/response fixture only. Root's integrated physical handoff
        // separately qualifies canonical OGAR and real lifecycle attachment.
        let locator = AgentGenesisLocator {
            space: vos::service::SpaceId([0xc1; 32]),
            agent: vos::service::AgentId([0xc2; 32]),
        };
        let expected_node = vos::agent::sdk::NodeId([0xc5; 32]);
        let request = b"exact-archive-validated-before-transport";
        for _ in 0..2 {
            let (address, server) =
                response_server_with_member_target(200, locator.encode(), Some(expected_node));
            assert_eq!(
                post_member_admission(address, request, locator, expected_node).unwrap(),
                locator
            );
            assert_eq!(server.join().unwrap(), request);
        }
        for substituted in [
            AgentGenesisLocator {
                space: vos::service::SpaceId([0xc3; 32]),
                ..locator
            },
            AgentGenesisLocator {
                agent: vos::service::AgentId([0xc4; 32]),
                ..locator
            },
        ] {
            let (address, server) =
                response_server_with_member_target(200, substituted.encode(), Some(expected_node));
            assert!(post_member_admission(address, request, locator, expected_node).is_err());
            assert_eq!(server.join().unwrap(), request);
        }
        let mut trailing = locator.encode();
        trailing.push(0);
        for malformed in [b"queued".to_vec(), trailing] {
            let (address, server) =
                response_server_with_member_target(200, malformed, Some(expected_node));
            assert!(post_member_admission(address, request, locator, expected_node).is_err());
            assert_eq!(server.join().unwrap(), request);
        }
        for status in [201, 202, 403, 409, 503, 504] {
            let (address, server) =
                response_server_with_member_target(status, locator.encode(), Some(expected_node));
            assert!(post_member_admission(address, request, locator, expected_node).is_err());
            assert_eq!(server.join().unwrap(), request);
        }
        let output = local_admission_output(locator, [0xc5; 32]);
        assert_eq!(output["ready"], false);
        assert_eq!(output["local_admitted"], true);
        assert_eq!(output["local_attached"], true);
        assert!(output.get("management_completed").is_none());
        assert!(output.get("quorum").is_none());
    }

    #[test]
    fn member_admission_target_refusal_cannot_be_reported_as_local_success() {
        let locator = AgentGenesisLocator {
            space: vos::service::SpaceId([0xd1; 32]),
            agent: vos::service::AgentId([0xd2; 32]),
        };
        let selected = vos::agent::sdk::NodeId([0xd3; 32]);
        let request = b"exact-archive-validated-before-transport";
        // A target mismatch from the real owner is HTTP403, even when another
        // voter could admit the same OGAR and return the same Agent locator.
        // This transport-only fixture cannot establish native storage behavior;
        // the genuine production-owner handoff fixture covers that boundary.
        let (address, server) =
            response_server_with_member_target(403, locator.encode(), Some(selected));
        assert!(post_member_admission(address, request, locator, selected).is_err());
        assert_eq!(server.join().unwrap(), request);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(
            post_member_admission(
                listener.local_addr().unwrap(),
                request,
                locator,
                vos::agent::sdk::NodeId([0; 32]),
            )
            .is_err()
        );
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "an invalid target must refuse before sending any HTTP request"
        );
    }

    #[test]
    fn member_admission_rejects_missing_certified_system_before_reading_or_reserving() {
        let fixture = Fixture::new("shared-cli-admission-refusal");
        let (operator, create, _) = super::super::clean_store::shared_client_submissions_for_test();
        let space = create.descriptor().identity.space;
        let node_public = enrollments(&create)[0].transport_public_key;
        let config = super::super::local_config::LocalConfig {
            system_bootstrap_bundle: Some(fixture.parent.join("missing.bundle")),
            ..Default::default()
        };
        super::super::local_config::save(&fixture.parent, &config).unwrap();
        let before = std::fs::read(super::super::local_config::path(&fixture.parent)).unwrap();
        assert!(
            admit_shared_archive(
                &fixture.parent,
                "127.0.0.1:1".parse().unwrap(),
                &operator,
                space,
                node_public,
                &fixture.parent.join("missing-archive.ogar"),
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(super::super::local_config::path(&fixture.parent)).unwrap(),
            before
        );
        for name in [
            "agent-client",
            "shared-agent-members",
            "system-agent",
            "node.key",
        ] {
            assert!(!fixture.parent.join(name).exists());
        }
    }

    #[test]
    fn fresh_create_uses_only_the_signed_supplied_runtime_and_actual_fixed_three_roster() {
        let (operator, supplied, _) =
            super::super::clean_store::shared_client_submissions_for_test();
        let authority = supplied.call().authority;
        let rows = enrollments(&supplied);
        let node_public = rows[0].transport_public_key;
        let prepare = |rows: &[NodeEncryptionEnrollment], local| {
            create_materials(
                &operator,
                authority,
                local,
                supplied.descriptor().creation_nonce,
                supplied.runtime(),
                rows,
            )
        };
        let (descriptor, committee) = prepare(&rows, node_public).unwrap();
        assert_eq!(
            descriptor.runtime_package,
            *supplied.runtime().package_ref()
        );
        assert_eq!(
            descriptor.identity.transition_producer,
            ProducerId::of_public_key(&node_public)
        );
        assert_eq!(committee.members().len(), 3);
        for replica in &descriptor.replicas {
            let enrolled = rows.iter().find(|row| row.node == replica.node).unwrap();
            assert_eq!(replica.principal, enrolled.principal);
            assert_eq!(replica.principal, descriptor.identity.owner);
            assert_ne!(
                replica.principal,
                PrincipalId::of_public_key(&enrolled.transport_public_key)
            );
        }
        for member in committee.members() {
            let enrolled = rows
                .iter()
                .find(|row| row.node.0 == member.replica().node.0)
                .unwrap();
            assert_eq!(member.replica().principal.0, enrolled.principal.0);
        }
        let call = sign_call(
            &operator,
            authority,
            &descriptor,
            &ManagementRequest::Create(Box::new(descriptor.clone())),
            NonZeroU64::new(7).unwrap(),
            10,
            30,
        )
        .unwrap();
        let submission =
            SharedCreateSubmission::new(descriptor, call, supplied.runtime().clone(), committee)
                .unwrap();
        assert_eq!(
            SharedCreateSubmission::decode(&submission.encode())
                .unwrap()
                .encode(),
            submission.encode()
        );
        assert_eq!(submission.call().authenticated_node, None);
        // Authority reconstructs compact Create slots using the enrolled
        // logical owners, not the transport-key principals.
        let vos::agent::sdk::authority::ManagementAuthorizationPlan::Create {
            descriptor: compact,
            replicas: slots,
            descriptor_commitment,
        } = &submission.call().plan
        else {
            unreachable!()
        };
        let reconstructed = compact.with_replicas(
            slots
                .iter()
                .map(|slot| AgentReplica {
                    node: slot.node,
                    principal: rows
                        .iter()
                        .find(|row| row.node == slot.node)
                        .unwrap()
                        .principal,
                    role: slot.role,
                })
                .collect(),
        );
        reconstructed.validate().unwrap();
        assert_eq!(reconstructed, *submission.descriptor());
        assert_eq!(reconstructed.commitment(), *descriptor_commitment);
        assert!(prepare(&rows[..2], node_public).is_err());
        assert!(prepare(&[rows[0], rows[1], rows[0]], node_public).is_err());
        assert!(
            prepare(
                &rows,
                operator.public().try_into_ed25519().unwrap().to_bytes()
            )
            .is_err()
        );
        assert!(
            prepare(
                &rows,
                Keypair::ed25519_from_bytes([0x49; 32])
                    .unwrap()
                    .public()
                    .try_into_ed25519()
                    .unwrap()
                    .to_bytes()
            )
            .is_err()
        );
        let mut changed = rows.clone();
        changed[1].transport_signature[0] ^= 1;
        assert!(prepare(&changed, node_public).is_err());
        for (space, principal) in [
            (SpaceId([0x71; 32]), supplied.descriptor().identity.owner),
            (
                supplied.descriptor().identity.space,
                PrincipalId([0x72; 32]),
            ),
        ] {
            let mut changed = rows.clone();
            let node = Keypair::ed25519_from_bytes([0x47; 32]).unwrap();
            changed[1] = super::super::clean_identity::sign_node_encryption_enrollment(
                &node, space, principal, [0x73; 32],
            )
            .unwrap();
            assert!(prepare(&changed, node_public).is_err());
        }
        let (_, _, _, image) = super::super::local_create::tests::fixture();
        assert!(
            vos::agent::package_admission::admit_state_runtime_package(image.exact_bytes())
                .is_err()
        );
    }

    #[test]
    fn credential_attempt_lease_and_resume_never_mint_a_replacement_nonce() {
        let fixture = Fixture::new("shared-cli-attempt");
        let (operator, create, _) = super::super::clean_store::shared_client_submissions_for_test();
        let identity = CleanOperatorIdentitySigner::new(&operator).unwrap();
        let space = create.descriptor().identity.space;
        assert!(attempt(&fixture.parent, &identity, space, true).is_err());
        let (reservation, nonce, status, operation) =
            attempt(&fixture.parent, &identity, space, false).unwrap();
        assert_eq!(status, CredentialReservationStatus::Pending);
        assert!(attempt(&fixture.parent, &identity, space, true).is_err());
        drop(reservation);
        assert!(attempt(&fixture.parent, &identity, space, false).is_err());
        let (mut reservation, resumed, status, reopened) =
            attempt(&fixture.parent, &identity, space, true).unwrap();
        assert_eq!(
            (resumed, status, reopened),
            (nonce, CredentialReservationStatus::Pending, operation)
        );
        assert_eq!(
            reservation.current().unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
    }

    fn response_server(
        status: u16,
        response: Vec<u8>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
        response_server_with_member_target(status, response, None)
    }

    fn response_server_with_member_target(
        status: u16,
        response: Vec<u8>,
        expected_node: Option<vos::agent::sdk::NodeId>,
    ) -> (SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0; 1];
                stream.read_exact(&mut byte).unwrap();
                header.push(byte[0]);
                assert!(header.len() < 8192);
            }
            let header_text = String::from_utf8(header).unwrap();
            let targets: Vec<_> = header_text
                .lines()
                .filter_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case(
                        vos::agent::local_lifecycle::SharedMemberAdmissionSubmission::TARGET_NODE_HEADER,
                    )
                    .then_some(value.trim())
                })
                .collect();
            match expected_node {
                Some(node) => {
                    let encoded = hex::encode(node.0);
                    assert_eq!(targets, [encoded.as_str()]);
                }
                None => assert!(
                    targets.is_empty(),
                    "unrelated control must remain untargeted"
                ),
            }
            let length = header_text
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut request = vec![0; length];
            stream.read_exact(&mut request).unwrap();
            write!(stream, "HTTP/1.1 {status} Response\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
            stream.write_all(&response).unwrap();
            request
        });
        (address, worker)
    }

    #[test]
    fn shared_failure_transport_does_not_expand_local_accepted_statuses() {
        let request = b"exact-retained-request";
        let response = b"SIR1signed-failure-verified-separately".to_vec();
        let (address, server) = response_server(422, response.clone());
        assert_eq!(
            super::super::local_create::post_shared_install_response(address, request).unwrap(),
            (422, response)
        );
        assert_eq!(server.join().unwrap(), request);
        let (address, server) = response_server(422, b"not-a-local-success".to_vec());
        assert!(
            super::super::local_create::post_binary_response(
                address,
                "/__agents/local/install",
                201,
                request,
                1024,
                None,
                None
            )
            .is_err()
        );
        assert_eq!(server.join().unwrap(), request);
        for status in [409, 503, 504] {
            let (address, server) = response_server(status, b"unknown-not-terminal".to_vec());
            assert!(
                super::super::local_create::post_shared_install_response(address, request).is_err()
            );
            assert_eq!(server.join().unwrap(), request);
        }
    }

    #[test]
    fn retained_install_retry_ignores_new_inputs_and_durably_completes_the_same_attempt() {
        let fixture = Fixture::new("shared-cli-retained-install");
        let (operator, create, original) =
            super::super::clean_store::shared_client_submissions_for_test();
        let mut descriptor = create.descriptor().clone();
        let space = descriptor.identity.space;
        let node_public = enrollments(&create)[0].transport_public_key;
        let target = authority(&fixture.parent, &operator, space, node_public).unwrap();
        descriptor.authority = target.binding;
        let submission = prepare_install(
            &operator,
            target,
            &descriptor,
            original.install().clone(),
            original.package().clone(),
            NonZeroU64::new(2).unwrap(),
            10,
            30,
        )
        .unwrap();
        let identity = CleanOperatorIdentitySigner::new(&operator).unwrap();
        let nonce = Hash(submission.install().installation_id.0);
        let client = fixture.parent.join("agent-client");
        let _client = ensure_private_directory(&client).unwrap();
        let claims = client.join("credentials");
        let _claims = ensure_private_directory(&claims).unwrap();
        let mut reservation =
            CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                .unwrap();
        reservation.reserve(nonce).unwrap();
        drop(reservation);
        let (reservation, _, _, operation) =
            attempt(&fixture.parent, &identity, space, true).unwrap();
        let request_root = operation.join("request");
        let request = submission.encode();
        CleanSharedInstallFile::open_or_create(&request_root)
            .unwrap()
            .publish_request(&request)
            .unwrap();
        drop(reservation);
        let args = InstallSharedArgs {
            space: "unused-by-explicit-helper".into(),
            agent: hex::encode(descriptor.identity.agent.0),
            package: Some(fixture.parent.join("not-a-replacement-package")),
            name: Some("ignored-replacement-name".into()),
            constructor_data: Some(fixture.parent.join("not-a-replacement-constructor")),
            http: None,
            resume: true,
        };
        let (address, server) = response_server(409, b"ambiguous-retained-state".to_vec());
        assert!(
            install_shared(
                &fixture.parent,
                address,
                &operator,
                space,
                node_public,
                descriptor.identity.agent,
                &args
            )
            .is_err()
        );
        assert_eq!(server.join().unwrap(), request);
        assert_eq!(
            CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                .unwrap()
                .current()
                .unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
        let acknowledgement = super::super::clean_store::shared_client_acknowledgement_for_test(
            &operator,
            &submission,
        );
        let disposition = SharedInstallDisposition::Applied(acknowledgement);
        let response = submission.encode_response(&disposition).unwrap();
        let (address, server) = response_server(201, response.clone());
        assert_eq!(
            install_shared(
                &fixture.parent,
                address,
                &operator,
                space,
                node_public,
                descriptor.identity.agent,
                &args
            )
            .unwrap(),
            disposition
        );
        assert_eq!(server.join().unwrap(), request);
        assert_eq!(
            install_shared(
                &fixture.parent,
                "127.0.0.1:1".parse().unwrap(),
                &operator,
                space,
                node_public,
                descriptor.identity.agent,
                &args
            )
            .unwrap(),
            disposition
        );
        let mut store = CleanSharedInstallFile::open_or_create(&request_root).unwrap();
        assert_eq!(store.load_request().unwrap(), Some(request));
        assert_eq!(store.load_response().unwrap(), Some(response));
        assert_eq!(
            CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                .unwrap()
                .current()
                .unwrap(),
            Some((nonce, CredentialReservationStatus::Completed))
        );
    }

    #[test]
    fn retained_create_denial_requires_exact_signed_terminal_and_resumes_without_network() {
        let fixture = Fixture::new("shared-cli-retained-create-denial");
        let (operator, original, _) =
            super::super::clean_store::shared_client_submissions_for_test();
        let space = original.descriptor().identity.space;
        let rows = enrollments(&original);
        let node_public = rows[0].transport_public_key;
        let target = authority(&fixture.parent, &operator, space, node_public).unwrap();
        let nonce = original.descriptor().creation_nonce;
        let (descriptor, committee) = create_materials(
            &operator,
            target,
            node_public,
            nonce,
            original.runtime(),
            &rows,
        )
        .unwrap();
        let call = sign_call(
            &operator,
            target,
            &descriptor,
            &ManagementRequest::Create(Box::new(descriptor.clone())),
            NonZeroU64::new(2).unwrap(),
            10,
            30,
        )
        .unwrap();
        let submission =
            SharedCreateSubmission::new(descriptor, call, original.runtime().clone(), committee)
                .unwrap();
        let identity = CleanOperatorIdentitySigner::new(&operator).unwrap();
        let client = fixture.parent.join("agent-client");
        let _client = ensure_private_directory(&client).unwrap();
        let claims = client.join("credentials");
        let _claims = ensure_private_directory(&claims).unwrap();
        let mut reservation =
            CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                .unwrap();
        reservation.reserve(nonce).unwrap();
        drop(reservation);
        let (reservation, _, _, operation) =
            attempt(&fixture.parent, &identity, space, true).unwrap();
        let request_root = operation.join("request");
        let request = submission.encode();
        CleanSharedCreateFile::open_or_create(&request_root)
            .unwrap()
            .publish_request(&request)
            .unwrap();
        drop(reservation);
        let args = CreateSharedArgs {
            space: "unused-by-explicit-helper".into(),
            runtime: Some(fixture.parent.join("not-a-replacement-runtime")),
            enrollments: vec![],
            archive_out: fixture.parent.join("denial-must-not-publish.ogar"),
            http: None,
            resume: true,
        };
        for body in [b"forbidden".to_vec(), b"SCR1\x01\x04\0\0\0CND1".to_vec()] {
            let (address, server) = response_server(403, body);
            assert!(
                create_shared(
                    &fixture.parent,
                    address,
                    &operator,
                    space,
                    node_public,
                    &args
                )
                .is_err()
            );
            assert_eq!(server.join().unwrap(), request);
            assert_eq!(
                CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                    .unwrap()
                    .current()
                    .unwrap(),
                Some((nonce, CredentialReservationStatus::Pending))
            );
            assert_eq!(
                CleanSharedCreateFile::open_or_create(&request_root)
                    .unwrap()
                    .load_response()
                    .unwrap(),
                None
            );
        }
        let certificate = super::super::local_create::tests::denial_for_create(
            &operator,
            submission.descriptor().clone(),
            submission.call().clone(),
        );
        let disposition =
            SharedCreateDisposition::Denied(submission.verify_denial(&certificate).unwrap());
        let response = submission.encode_response(&disposition).unwrap();
        let (address, server) = response_server(202, response.clone());
        assert!(
            create_shared(
                &fixture.parent,
                address,
                &operator,
                space,
                node_public,
                &args
            )
            .is_err()
        );
        assert_eq!(server.join().unwrap(), request);
        assert_eq!(
            CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                .unwrap()
                .current()
                .unwrap(),
            Some((nonce, CredentialReservationStatus::Pending))
        );
        let (address, server) = response_server(403, response.clone());
        assert_eq!(
            create_shared(
                &fixture.parent,
                address,
                &operator,
                space,
                node_public,
                &args
            )
            .unwrap(),
            disposition
        );
        assert_eq!(server.join().unwrap(), request);
        assert_eq!(
            create_shared(
                &fixture.parent,
                "127.0.0.1:1".parse().unwrap(),
                &operator,
                space,
                node_public,
                &args,
            )
            .unwrap(),
            disposition
        );
        let mut store = CleanSharedCreateFile::open_or_create(&request_root).unwrap();
        assert_eq!(store.load_request().unwrap(), Some(request));
        assert_eq!(store.load_response().unwrap(), Some(response));
        assert_eq!(
            CleanCredentialReservation::open_or_create(&claims, space, identity.credential())
                .unwrap()
                .current()
                .unwrap(),
            Some((nonce, CredentialReservationStatus::Denied))
        );
        assert!(!args.archive_out.exists());
    }
}
