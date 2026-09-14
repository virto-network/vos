//! Fresh deployment-scoped role administration and exact retained resume.
use super::clean_store::{
    CleanAdminCredentialReservation, CleanOperationClientFile, CredentialReservationStatus,
    ensure_private_directory,
};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use vos::agent::clean_bootstrap::{
    NativeAuthorityAdminPreparation, NativeAuthorityAdminSubmission,
};
use vos::agent::sdk::{authority::*, wire::CanonicalWire as _, *};

#[derive(clap::Args, Debug)]
pub struct SetActorRoleArgs {
    pub space: String,
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    pub agent: Option<String>,
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    pub actor: Option<String>,
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    pub deployment: Option<String>,
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    pub role: Option<String>,
    /// Grant to this principal; defaults to the local operator.
    #[arg(long, conflicts_with = "resume")]
    pub principal: Option<String>,
    #[arg(long, conflicts_with = "resume")]
    pub revoke: bool,
    #[arg(long)]
    pub resume: bool,
    #[arg(long)]
    pub http: Option<SocketAddr>,
}

fn id(value: Option<&str>, name: &str) -> anyhow::Result<[u8; 32]> {
    let value = value.ok_or_else(|| anyhow::anyhow!("missing --{name}"))?;
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("--{name} requires a 32-byte hex identifier"))
}

pub(crate) fn run(args: SetActorRoleArgs) -> anyhow::Result<()> {
    let (data, space, node_public, address) =
        super::local_create::resolve_local_space(&args.space, args.http)?;
    let operator = crate::identity::load_existing()?;
    let identity = super::clean_identity::CleanOperatorIdentitySigner::new(&operator)?;
    let runtime = crate::bundled::root_signed_agent_runtime_package(&operator)?;
    let package = crate::bundled::root_signed_actor_package(
        crate::bundled::system_authority_package_template(),
        "system-authority",
        &operator,
    )?;
    let (authority, _) = super::clean_startup::derive_system_authority_target(
        space,
        identity.raw_public_key(),
        &runtime,
        &package,
    )?;
    let public = libp2p::identity::ed25519::PublicKey::try_from_bytes(&node_public)?;
    let node = NodeId::of_authenticated_peer(
        &libp2p::identity::PublicKey::from(public)
            .to_peer_id()
            .to_bytes(),
    );
    let operation = if args.resume {
        None
    } else {
        Some(AuthorityAdminOperation::SetActorRole {
            principal: match args.principal.as_deref() {
                Some(value) => PrincipalId(id(Some(value), "principal")?),
                None => identity.principal(),
            },
            agent: AgentId(id(args.agent.as_deref(), "agent")?),
            actor: ActorId(id(args.actor.as_deref(), "actor")?),
            deployment: DeploymentId(id(args.deployment.as_deref(), "deployment")?),
            role: RoleId(id(args.role.as_deref(), "role")?),
            granted: !args.revoke,
        })
    };
    let (root, response, status) = execute(
        &data,
        address,
        &operator,
        authority,
        node,
        operation.as_ref(),
    )?;
    crate::output::print_json(&serde_json::json!({
        "decision": if status == CredentialReservationStatus::Denied { "denied" } else { "applied" },
        "request_dir": root, "response": hex::encode(response),
        "retirement_retained": true, "reservation_pending": false,
    }));
    Ok(())
}

pub(super) fn execute(
    data: &Path,
    address: SocketAddr,
    operator: &libp2p::identity::Keypair,
    authority: AuthorityActorTarget,
    node: NodeId,
    initial: Option<&AuthorityAdminOperation>,
) -> anyhow::Result<(PathBuf, Vec<u8>, CredentialReservationStatus)> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "admin control requires nonzero loopback HTTP"
    );
    let identity = super::clean_identity::CleanOperatorIdentitySigner::new(operator)?;
    let root = data.join("admin-client");
    ensure_private_directory(&root)?;
    let claims = root.join("credentials");
    ensure_private_directory(&claims)?;
    let requests = root.join("requests");
    ensure_private_directory(&requests)?;
    let mut reservation = CleanAdminCredentialReservation::open_or_create(
        &claims,
        authority.space,
        identity.credential(),
    )?;
    let current = reservation.current()?;
    let nonce = if let Some(operation) = initial {
        anyhow::ensure!(
            !matches!(current, Some((_, CredentialReservationStatus::Pending))),
            "admin work is pending; use --resume before starting another change"
        );
        anyhow::ensure!(operation.validate_shape(), "invalid admin operation");
        let mut query_id = [0; 32];
        getrandom::getrandom(&mut query_id)?;
        let discovery = root.join(format!("discovery-{}", hex::encode(query_id)));
        let (credential, _) = super::local_create::discover_admin_credential(
            &discovery, address, operator, authority,
        )?;
        let draft =
            super::admin_signing::draft(operator, authority, node, &credential, operation.clone())?;
        let nonce = Hash(query_id);
        let operation_root = requests.join(hex::encode(nonce.0));
        ensure_private_directory(&operation_root)?;
        let mut preparation =
            CleanOperationClientFile::open_admin_preparation(operation_root.join("preparation"))?;
        preparation.publish_request(
            &draft
                .encode()
                .map_err(|e| anyhow::anyhow!("invalid draft: {e:?}"))?,
        )?;
        // The immutable draft is durable before a claim can point at it.
        reservation.reserve(nonce, &draft)?;
        nonce
    } else {
        current
            .ok_or_else(|| anyhow::anyhow!("no admin request to resume"))?
            .0
    };
    let operation_root = requests.join(hex::encode(nonce.0));
    let preparation_root = operation_root.join("preparation");
    let delivery_root = operation_root.join("submission");
    let mut preparation_store =
        CleanOperationClientFile::open_admin_preparation(&preparation_root)?;
    let bytes = preparation_store
        .load_request()?
        .ok_or_else(|| anyhow::anyhow!("admin claim is missing its retained draft"))?;
    let draft = AuthorityAdminCall::decode(&bytes)
        .map_err(|e| anyhow::anyhow!("invalid retained draft: {e:?}"))?;
    anyhow::ensure!(
        draft.authority == authority
            && draft.authenticated_node == node
            && draft.administrator == identity.principal()
            && draft.credential == identity.credential()
            && draft.credential_public_key == identity.raw_public_key(),
        "retained admin draft differs from selected space, node or operator"
    );
    let status = reservation.reserve(nonce, &draft)?;
    let mut retained_preparation = preparation_store.load_response()?;
    drop(preparation_store);
    let mut delivery = CleanOperationClientFile::open_admin_submission(&delivery_root)?;
    let request = match delivery.load_request()? {
        Some(bytes) => bytes,
        None => {
            delivery.load_response()?;
            anyhow::ensure!(
                status == CredentialReservationStatus::Pending,
                "terminal admin claim is missing its signed submission"
            );
            let prepared_bytes =
                super::admin_client::deliver(&preparation_root, None, address, true)?;
            let preparation = NativeAuthorityAdminPreparation::decode(&prepared_bytes)
                .map_err(|e| anyhow::anyhow!("invalid retained preparation: {e:?}"))?;
            let submission = super::admin_signing::prepared(operator, &draft, &preparation)?;
            let bytes = submission
                .encode()
                .map_err(|e| anyhow::anyhow!("invalid NAS1: {e:?}"))?;
            delivery.publish_request(&bytes)?;
            retained_preparation = Some(prepared_bytes);
            bytes
        }
    };
    let submission = NativeAuthorityAdminSubmission::decode(&request)
        .map_err(|e| anyhow::anyhow!("invalid retained NAS1: {e:?}"))?;
    anyhow::ensure!(
        retained_preparation.as_deref()
            == Some(
                submission
                    .preparation()
                    .encode()
                    .map_err(|e| anyhow::anyhow!("invalid NAP1: {e:?}"))?
                    .as_slice()
            ),
        "submission is missing its exact retained preparation"
    );
    let mut expected = submission
        .preparation()
        .call_to_sign(&draft)
        .map_err(|e| anyhow::anyhow!("submission differs from draft: {e:?}"))?;
    expected.signature = submission.call().signature;
    anyhow::ensure!(
        &expected == submission.call(),
        "submission differs from retained draft"
    );
    reservation.bind_submission(nonce, &draft, &submission)?;
    drop(delivery);
    let response = super::admin_client::deliver(&delivery_root, None, address, false)?;
    let mut delivery = CleanOperationClientFile::open_admin_submission(&delivery_root)?;
    let finished = reservation.complete(nonce, &mut delivery)?;
    Ok((operation_root, response, finished))
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct Args {
        #[command(subcommand)]
        command: super::super::SpaceCommand,
    }
    #[test]
    fn admin_orchestration_cli_requires_complete_intent_or_resume() {
        assert!(Args::try_parse_from(["space", "set-actor-role", "test", "--resume"]).is_ok());
        assert!(Args::try_parse_from(["space", "set-actor-role", "test"]).is_err());
        assert!(
            Args::try_parse_from(["space", "set-actor-role", "test", "--resume", "--revoke"])
                .is_err()
        );
        let id = "11".repeat(32);
        assert!(
            Args::try_parse_from([
                "space",
                "set-actor-role",
                "test",
                "--agent",
                &id,
                "--actor",
                &id,
                "--deployment",
                &id,
                "--role",
                &id
            ])
            .is_ok()
        );
        assert!(super::id(Some("11"), "role").is_err());
    }
}
