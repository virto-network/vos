//! `space up` — boot a saved space and run forever.
//!
//! Loads the registry blob from the local cache (looked up by
//! the hash recorded in spaces.toml at `space new` time),
//! registers it as the well-known `ServiceId::REGISTRY` agent
//! with `Consistency::Crdt`, and hands the node off to
//! `run_forever` (or `run` for `--once`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use vos::abi::service::ServiceId;
use vos::actors::client::ClientError;
use vos::node::{AgentConfig, Consistency, VosNode};
use vos::registry::RegistryInvoker;
use vos::registry::{RegistryRef, Status};

use crate::blob_store::{self, BlobHash};
use crate::commands::space::common::{
    consistency_from_u8, derive_hyperspace_id, instance_service_id, registry_replication_id,
    service_root_actor_id, service_root_service_id,
};
use crate::commands::space::{reconcile, subscriptions};
use crate::spaces_index;

const PENDING_INVITE_FILE: &str = ".pending-invite.token";

pub struct Args {
    pub query: String,
    pub once: bool,
    pub listen: Vec<String>,
    pub connect: Vec<String>,
    pub service_pvm: Option<PathBuf>,
    pub production_trust_socket: Option<PathBuf>,
    pub allow_conformance: bool,
}

#[derive(Clone)]
struct PinnedService {
    pvm: std::sync::Arc<Vec<u8>>,
}

fn load_pinned_service_service(path: Option<&Path>) -> anyhow::Result<Option<PinnedService>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let pvm = std::fs::read(path)
        .map_err(|error| anyhow::anyhow!("read pinned service PVM {}: {error}", path.display()))?;
    vos_pvm::program::parse_blob(&pvm)
        .ok_or_else(|| anyhow::anyhow!("{} is not a canonical PVM PVM", path.display()))?;
    let actual = vos::service::ProgramId::of_pvm(&pvm);
    if actual != vos::service::VOS_SERVICE_PROGRAM_ID {
        anyhow::bail!(
            "{} has service ProgramId {}, expected the protocol-pinned {}",
            path.display(),
            hex::encode(actual.0),
            hex::encode(vos::service::VOS_SERVICE_PROGRAM_ID.0),
        );
    }
    vos::service::ServicePvm::new(pvm.clone(), vos::service::VOS_SERVICE_PROGRAM_ID)
        .map_err(|error| anyhow::anyhow!("invalid generic service PVM: {error}"))?;
    Ok(Some(PinnedService {
        pvm: std::sync::Arc::new(pvm),
    }))
}

fn validate_service_trust_mode(
    has_service_pvm: bool,
    has_production_trust: bool,
    allow_conformance: bool,
) -> anyhow::Result<()> {
    if has_production_trust && allow_conformance {
        anyhow::bail!(
            "choose exactly one service trust profile: --production-trust-socket or \
             --allow-conformance",
        );
    }
    if !has_service_pvm && (has_production_trust || allow_conformance) {
        anyhow::bail!("a service trust profile requires --service-pvm <exact-vos-service.pvm>",);
    }
    if has_service_pvm && !has_production_trust && !allow_conformance {
        anyhow::bail!(
            "--service-pvm requires --production-trust-socket <socket>; use \
             --allow-conformance only for development and protocol tests",
        );
    }
    Ok(())
}

/// Construct the frozen authority package contents for the current service
/// platform. The signature wrapper is intentionally supplied separately: it is not
/// part of [`vos::service::DeploymentId`]. The actor PVM is stable across releases,
/// while the package, deployment, and derived replication identities are
/// scoped because the manifest binds the platform and execution semantics.
fn frozen_role_authority_package(public_key: Vec<u8>) -> anyhow::Result<vos::service::VosPackage> {
    use vos::service::{ServiceWire, artifact_hash};

    let actor_pvm = crate::bundled::space_authority_pvm()
        .ok_or_else(|| anyhow::anyhow!("vosx was built without the canonical space-authority PVM"))?
        .to_vec();
    vos_pvm::program::parse_blob(&actor_pvm)
        .ok_or_else(|| anyhow::anyhow!("bundled space-authority PVM is invalid"))?;
    let (schemas, schemas_len) =
        vos::metadata::encode::<16384>(&space_authority::SpaceAuthorityMsg::META);
    let schemas = schemas[..schemas_len].to_vec();
    let metadata = vos::metadata::decode(&schemas)
        .ok_or_else(|| anyhow::anyhow!("canonical space-authority metadata is invalid"))?;
    let role_policies = vos::service::PackageRolePolicies::from_metadata(&metadata)?.encode();
    let actor_program = vos::service::ProgramId::of_pvm(&actor_pvm);
    Ok(vos::service::VosPackage {
        manifest: vos::service::PackageManifest {
            name: vos::service::ROLE_AUTHORITY_INSTANCE_.into(),
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            actor_program,
            crdt: false,
            interfaces_hash: artifact_hash(b"interfaces", &[]),
            role_policies_hash: artifact_hash(b"role-policies", &role_policies),
            schemas_hash: artifact_hash(b"schemas", &schemas),
            task_dependencies_hash: vos::service::task_dependencies_hash(&[]),
        },
        actor_pvm,
        generated_interfaces: vec![],
        role_policies,
        schemas,
        task_dependencies: vec![],
        diagnostics: None,
        deployment_signature: vos::service::DeploymentSignature {
            producer: vos::service::ProducerId::of_public_key(&public_key),
            public_key,
            signature: vec![0],
        },
    })
}

fn frozen_role_authority_deployment() -> anyhow::Result<vos::service::DeploymentId> {
    Ok(frozen_role_authority_package(Vec::new())?.deployment_id())
}

/// Construct the canonical authority package for the current service ABI.
/// The immutable space root signs these exact actor bytes once; peers consume
/// the signed package from the registry and never author substitutes.
fn root_signed_role_authority_package(
    root: &libp2p::identity::Keypair,
) -> anyhow::Result<vos::service::VosPackage> {
    let mut package = frozen_role_authority_package(root.public().encode_protobuf())?;
    package.deployment_signature.signature = root
        .sign(&package.signing_message())
        .map_err(|error| anyhow::anyhow!("sign canonical space-authority package: {error}"))?;
    package.validate()?;
    Ok(package)
}

/// On the immutable-root node, publish and install the canonical authority
/// before application roots are resolved. Joiners wait for those signed
/// registry rows rather than constructing another deployment.
fn ensure_service_role_authority(node: &VosNode, space_id: [u8; 32]) -> anyhow::Result<()> {
    use crate::commands::space::common::auto_replication_id;
    use vos::service::ServiceWire;

    let reg = RegistryRef::at(ServiceId::REGISTRY);
    let root_peer = vos::block_on(reg.root(&mut &*node))
        .map_err(|error| anyhow::anyhow!("query space root for service authority: {error}"))?;
    let operator_peer = node.operator_peer().map(<[u8]>::to_vec);
    if root_peer.is_empty() || operator_peer.as_deref() != Some(root_peer.as_slice()) {
        tracing::info!(
            "service role authority is not installed locally; waiting for the space root's signed catalog rows"
        );
        return Ok(());
    }
    let root = crate::identity::load_or_create()?;
    if libp2p::PeerId::from(root.public()).to_bytes() != root_peer {
        anyhow::bail!("loaded operator key no longer matches the registry's immutable space root");
    }
    let package = root_signed_role_authority_package(&root)?;
    let exact_package = package.encode();
    let package_hash = blob_store::cache_put(&exact_package)
        .map_err(|error| anyhow::anyhow!("cache canonical space-authority package: {error}"))?;
    let replication_id = auto_replication_id(
        &space_id,
        vos::service::ROLE_AUTHORITY_INSTANCE_,
        &package_hash.0,
    );
    let authority = vos::block_on(reg.role_authority(&mut &*node))
        .map_err(|error| anyhow::anyhow!("query role authority: {error}"))?;
    if authority.is_empty() {
        let auth = crate::commands::space::op_sign::op_auth(
            &root,
            "set_role_authority",
            &[&replication_id],
        )?;
        let status =
            vos::block_on(reg.set_role_authority(&mut &*node, replication_id.to_vec(), auth))
                .map_err(|error| anyhow::anyhow!("bind role authority: {error}"))?;
        match status {
            Status::Ok => {}
            other => anyhow::bail!("binding canonical role authority returned {other}"),
        }
    } else if authority.as_slice() != replication_id {
        anyhow::bail!("registry is bound to a different canonical role authority");
    }

    if vos::block_on(reg.agent(&mut &*node, vos::service::ROLE_AUTHORITY_INSTANCE_.into()))
        .map_err(|error| anyhow::anyhow!("query service role authority: {error}"))?
        .is_some()
    {
        return Ok(());
    }
    let program_name = package.manifest.name.clone();
    let existing = vos::block_on(reg.program(&mut &*node, program_name.clone()))
        .map_err(|error| anyhow::anyhow!("query canonical space-authority package: {error}"))?;
    match existing {
        Some(row) if row.hash == package_hash.0 => {}
        Some(_) | None => {
            let status = vos::block_on(reg.publish(
                &mut &*node,
                program_name.clone(),
                package_hash.0.to_vec(),
                false,
                Vec::new(),
            ))
            .map_err(|error| anyhow::anyhow!("publish canonical space-authority: {error}"))?;
            if status != Status::Ok {
                anyhow::bail!("publishing canonical space-authority returned status {status}");
            }
        }
    }
    let status = vos::block_on(reg.install(
        &mut &*node,
        vos::service::ROLE_AUTHORITY_INSTANCE_.into(),
        program_name,
        package_hash.0.to_vec(),
        replication_id.to_vec(),
        Consistency::Raft as u8,
        false,
        vos::registry::SyncFloor::Member,
        Vec::new(),
    ))
    .map_err(|error| anyhow::anyhow!("install canonical space-authority: {error}"))?;
    if !matches!(status, Status::Ok | Status::InstanceExists) {
        anyhow::bail!("installing canonical space-authority returned status {status}");
    }
    tracing::info!(
        deployment = %hex::encode(package.deployment_id().0),
        "installed root-signed canonical service role authority"
    );
    Ok(())
}

pub fn run(args: Args) -> anyhow::Result<()> {
    // Validate and open the requested service execution profile before resolving
    // the trivalent target. Target resolution may scaffold a recipe space,
    // create its node identity, or persist an invite bearer, so an invalid
    // trust selection must fail before any of those durable mutations.
    validate_service_trust_mode(
        args.service_pvm.is_some(),
        args.production_trust_socket.is_some(),
        args.allow_conformance,
    )?;
    let pinned_service_service = load_pinned_service_service(args.service_pvm.as_deref())?;
    let production_trust = args
        .production_trust_socket
        .as_deref()
        .map(super::production_trust::SocketProductionTrust::open)
        .transpose()
        .map_err(|error| anyhow::anyhow!("open production trust authority: {error}"))?
        .map(|trust| {
            std::sync::Arc::new(trust) as std::sync::Arc<dyn vos::service::ProductionTrust>
        });
    if let Some(trust) = production_trust.as_ref() {
        tracing::info!(
            policy = %hex::encode(trust.policy_id().0),
            "service roots use the fail-closed production trust profile",
        );
    } else if pinned_service_service.is_some() {
        tracing::warn!(
            "signed service roots use the conformance-only trust seam; this mode is not production-safe",
        );
    }

    // Trivalent positional (decision 1): an existing `.toml` recipe
    // (create-if-missing + genesis apply), a `vos-…` invite token
    // (join-if-needed + auto-redeem), or a known space name / id. Any of
    // these may scaffold/join the space and persist a pending token or
    // recipe; all that flows forward is the lookup key.
    let lookup = resolve_up_target(&args)?;
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, &lookup)?;

    if entry.registry_hash.is_empty() {
        anyhow::bail!(
            "space '{}' has no registry_hash recorded — re-create it with \
             `vosx space new`",
            entry.name,
        );
    }
    let hash = BlobHash::from_hex(&entry.registry_hash)
        .map_err(|_| anyhow::anyhow!("space registry_hash is not 64 hex chars"))?;
    let elf = match blob_store::cache_get(&hash)? {
        Some(b) => b,
        None => anyhow::bail!(
            "registry blob {hash} not in local cache. Re-fetch with \
             `vosx space pull-blob {hash}` once that command lands.",
        ),
    };
    // Cache stores raw ELF bytes (hash addresses the source); the
    // PVM kernel needs the transpiled PVM blob.
    let blob = vos_pvm_compiler::link_elf(&elf)
        .map_err(|e| anyhow::anyhow!("transpile registry elf: {e:?}"))?;

    let space_id = entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;
    let replication_id = registry_replication_id(&space_id);

    let data_dir = PathBuf::from(&entry.data_dir);
    if !data_dir.exists() {
        anyhow::bail!(
            "data dir does not exist: {} (was the space forgotten?)",
            data_dir.display(),
        );
    }
    // Hold the immutable space-id lock for the complete daemon lifetime.
    // Offline backup takes a shared lock and restore takes the same exclusive
    // lock, so neither can copy/replace redb images or private side stores
    // while this process is opening, replaying, or committing them. The lock
    // lives outside `data_dir`, allowing restore to rename that directory
    // without changing the protected inode.
    let _space_data_lock = super::space_lock::SpaceDataLock::exclusive(&space_id)?;
    let mut pending_token = load_pending_token(&data_dir)?;

    // Verify the genesis CrdtEvent against the advertised
    // space_id BEFORE registering the agent (which opens the
    // redb exclusively). Creators pass immediately; joiners
    // who haven't seen the genesis yet get a "trust on first
    // use" warning and proceed — on the next `space up` after
    // sync, verification activates.
    let registry_db = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", ServiceId::REGISTRY.0));
    if registry_db.exists() {
        match crate::commands::space::verify::verify_with_timeout(
            &registry_db,
            &space_id,
            std::time::Duration::from_millis(0),
        )? {
            crate::commands::space::verify::VerifyOutcome::Verified { genesis_cid } => {
                tracing::info!("genesis verified (root={})", hex::encode(genesis_cid));
            }
            crate::commands::space::verify::VerifyOutcome::Mismatch {
                genesis_cid,
                derived,
                advertised,
            } => {
                anyhow::bail!(
                    "genesis mismatch — local registry's seq=1 root {} \
                     derives to space_id {} but the saved entry advertises {}. \
                     The bootnode pointed us at a different space, or the \
                     local data dir was tampered with.",
                    hex::encode(genesis_cid),
                    hex::encode(derived),
                    hex::encode(advertised),
                );
            }
            crate::commands::space::verify::VerifyOutcome::NoGenesisYet => {
                tracing::warn!(
                    "registry redb has no seq=1 event yet — trust-on-first-use \
                     until sync delivers genesis; verification activates on the \
                     next `space up`",
                );
            }
        }
    }

    // Hyperspace membership comes from the persisted index entry. A
    // recipe's `hyperspace = …` is folded into `entry.hyperspace` when
    // the recipe is resolved (see `resolve_recipe`), so a bare `space
    // up` re-attaches to the federation without needing the recipe again.
    let hyperspace = (!entry.hyperspace.is_empty()).then(|| entry.hyperspace.clone());

    // Always attach a libp2p network — even local-only spaces
    // bind a loopback port so client commands (`space publish`,
    // `space install`, etc.) have an endpoint to dial.
    let network = build_network_for_daemon(entry, &data_dir, &args.listen, &args.connect)?;
    let local_prefix = network.local_prefix();

    // Serve program blobs (actor ELFs) to space members from the same
    // content-addressed cache `blob_store` writes, so a joiner that installs
    // an agent it never received in the recipe can fetch the ELF from us.
    let mut node =
        VosNode::with_prefix(local_prefix).with_program_blobs_dir(blob_store::cache_dir());

    // Record this daemon's operator — the CLI identity that ran `vosx space
    // up` (the same `vosx/identity.key` the operator later presents when
    // driving agents with `vosx <agent> …`). Two roles: (1) the locality
    // gate admits this caller, and only this caller, to a device-local
    // (`consistency = local`) agent such as the messenger, so the operator
    // can drive their own E2EE messenger while every remote peer is refused;
    // (2) the registry agent author-signs catalog mutators on relay with
    // this key — a keyless PVM agent (the messenger cloning a channel's
    // actor pair) or the in-process reconcile can't carry a CLI signature,
    // so the daemon signs `install`/`publish`/… before recording. Set BEFORE
    // registering the registry so its thread captures the signer. A
    // best-effort load: if the operator identity can't be resolved the
    // daemon still boots, but no caller reaches a confined agent and no
    // catalog op is signed (fail closed).
    match crate::identity::load_or_create() {
        Ok(kp) => {
            let operator = libp2p::PeerId::from(kp.public());
            let operator_bytes = operator.to_bytes();
            node.set_operator_peer(operator_bytes.clone());
            node.set_operator_signer(move |canonical: &[u8]| {
                // libp2p ed25519 sign interops with the registry's
                // ed25519-dalek verify_strict; pack as signer_peer_id || sig(64).
                let sig = kp.sign(canonical).ok()?;
                let sig: [u8; 64] = sig.as_slice().try_into().ok()?;
                Some(vos::registry::pack_auth(&operator_bytes, &sig))
            });
            tracing::info!(%operator, "auth: recorded operator for device-local agents");
        }
        Err(e) => {
            tracing::warn!(
                "auth: could not load operator identity ({e}); device-local agents will be \
                 unreachable AND this node cannot author registry catalog ops \
                 (install/publish/upgrade/…) — if this is the space-admin node its recipe \
                 agents will not install. Restart with a readable identity matching the space root.",
            );
        }
    }

    // Bind the registry's genesis to this space so a member can't grind a
    // low-CID forged `set_root` and hijack the registry root on replay
    // (the hyperspace registry is the separate-trust federation surface
    // and is left ungated). See `genesis_node_validator`.
    let cfg = AgentConfig::new(blob.clone())
        .with_name(vos::node::REGISTRY_AGENT_NAME)
        .with_consistency(Consistency::Crdt)
        .with_replication_id(replication_id)
        .with_node_validator(crate::commands::space::common::genesis_node_validator(
            space_id,
        ))
        .persist(&data_dir);
    let id = node.register_at_id(cfg, ServiceId::REGISTRY);

    // Anchor this space's space_id into the registry (first-write-wins;
    // idempotent on later boots). `redeem_invite` binds it so an invite
    // minted here can't be replayed at a sibling space the same operator
    // runs — the genesis root is the shared operator identity and can't
    // tell them apart. Without this the invite canonical would bind an
    // empty id and every redemption would fail. Best-effort: a warn, not
    // a boot-wedging error, on the unusual failure paths.
    {
        let reg = vos::registry::RegistryRef::at(ServiceId::REGISTRY);
        match vos::block_on(reg.set_space_id(&mut &node, space_id.to_vec())) {
            Ok(vos::registry::Status::Ok) => tracing::info!("anchored space_id into the registry"),
            Ok(_) => {} // already anchored — idempotent
            Err(e) => tracing::warn!("could not anchor space_id into the registry: {e}"),
        }
    }

    // Spawn the hyperspace registry replica if this space declares
    // membership in one. Same blob as the local registry; distinct
    // ServiceId slot (HYPERSPACE_REGISTRY = svc_id 1) and a
    // replication_id derived from the hyperspace name so all member
    // spaces' nodes converge on a single shared registry. The slot
    // id is well-known so callers don't need the return value.
    if let Some(name) = &hyperspace {
        let hs_rep = derive_hyperspace_id(name);
        let hs_cfg = AgentConfig::new(blob)
            .with_name(vos::node::HYPERSPACE_REGISTRY_AGENT_NAME)
            .with_consistency(Consistency::Crdt)
            .with_replication_id(hs_rep)
            .persist(&data_dir);
        let hs_id = node.register_at_id(hs_cfg, ServiceId::HYPERSPACE_REGISTRY);
        tracing::info!(
            "hyperspace '{name}' registry as {hs_id} (rep={}…)",
            &hex::encode(hs_rep)[..12],
        );
    }

    node.attach_network(network);

    tracing::info!(
        "space '{}' (id={}…) registry as {id}{}",
        entry.name,
        &entry.id[..12],
        hyperspace
            .as_ref()
            .map(|n| format!(" — hyperspace '{n}'"))
            .unwrap_or_default(),
    );

    // Genesis apply: consume a pending recipe exactly once. Installs the
    // recipe's agents into the just-anchored registry (the replicated
    // half) and projects its node-local half into `local.toml`, then
    // clears the marker so a later bare `space up` doesn't re-apply.
    if !entry.pending_recipe.is_empty() {
        genesis_apply(
            &mut node,
            &entry.pending_recipe,
            local_prefix,
            &space_id,
            &data_dir,
        )?;
        clear_pending_recipe(&entry.id)?;
    }

    // `local.toml` retains host-private service signing configuration and
    // native extension registrations across restarts.
    let local_cfg = subscriptions::load(&data_dir).unwrap_or_default();
    let agent_policies = agent_policies_from_local(&local_cfg)?;
    // Shared across bootstrap and runtime reconciliation. Bootstrap opens at
    // most one service root synchronously; remaining rows inherit the same global
    // window/backoff and are opened only after the endpoint is published.
    let mut service_registration_backoff = RegistrationBackoff::default();

    // Register node-local `.so` extensions from `local.toml`, returning
    // each one's effective relay caps for the endpoint descriptor
    // (`space describe` / `space caps`).
    let extension_caps =
        register_extensions_from_local(&mut node, &local_cfg, &data_dir, local_prefix)?;

    if pinned_service_service.is_some() {
        ensure_service_role_authority(&node, space_id)?;
    }

    // Spawn every installed agent recorded in the registry.
    // Each gets a deterministic per-node ServiceId so its redb
    // path is stable across restarts.
    spawn_installed_agents(
        &mut node,
        &data_dir,
        space_id,
        local_prefix,
        hyperspace.is_some(),
        &agent_policies,
        pinned_service_service.as_ref(),
        production_trust.clone(),
        &mut service_registration_backoff,
    )?;

    // The space creator's operator key is granted ADMIN at genesis
    // (a signed `grant_role` baked into the DAG by `space new`),
    // so there's no first-boot bootstrap file to consume here.

    // Wait for the swarm to bind, then publish endpoint info
    // so client commands (`space publish`, `space install`, …)
    // can dial us. Removed in the cleanup block at the end.
    publish_endpoint(&node, &data_dir, local_prefix, extension_caps)?;

    if args.once {
        // The redeem loop and spawn-reconcile live only in the
        // run-forever tick, so `--once` (a smoke-test idle-exit) does not
        // redeem a pending token. Warn rather than silently no-op.
        if pending_token.is_some() {
            tracing::warn!(
                "--once will NOT redeem the pending invite (redemption runs in the long-lived \
                 tick). Re-run `space up {}` without --once to join.",
                entry.name,
            );
        }
        tracing::warn!(
            "--once opens at most one service root during bootstrap; any additional service roots require \
             a long-running `space up {}` reconciliation pass",
            entry.name,
        );
        tracing::info!("--once: exiting when registry goes idle");
        node.run();
    } else {
        // Install SIGINT/SIGTERM handlers so the daemon exits
        // cleanly on `docker stop` / `kill -TERM` / Ctrl-C
        // without losing in-flight commits or leaking the
        // endpoint file. The handler flips the same
        // AtomicBool that `run_forever`'s poll loop watches.
        crate::shutdown::install(node.shutdown_handle());
        tracing::info!("running until shutdown (Ctrl-C / SIGTERM)");

        // Spawn-reconcile from the router tick hook: agents
        // installed after boot — `space install`, `dev new`, an
        // extension calling `registry.install`, or rows CRDT-synced
        // from a peer — come up within a few seconds instead of
        // waiting for the next daemon restart. `local_cfg` (loaded
        // above) is captured once; editing local.toml still needs a
        // restart to take effect.
        // A pending invite is redeemed from the same tick: each pass,
        // until the bootnode grants this node's key, re-parse the token
        // and invoke the bootnode's `redeem_invite`; clear the marker on
        // success. The joiner reaches redeem by remote invoke (ungated)
        // before it can sync anything — the cert IS the auth.
        let mut redeem_warned = false;
        let mut damped = std::collections::HashSet::new();
        let mut boot_grace = BootGrace::new();
        // Program-blob fetches in flight, shared with the background fetch
        // tasks the reconcile pass spawns for uncached rows.
        let in_flight: InFlightBlobs =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
        let mut query_warned = false;
        let mut last_pass = std::time::Instant::now();
        node.run_forever_with(|n| {
            if last_pass.elapsed() < SPAWN_RECONCILE_EVERY {
                return;
            }
            last_pass = std::time::Instant::now();
            if let Some(tok) = pending_token.clone() {
                // Expiry is checked here for a clean local failure and at
                // the serving node's admission boundary for enforcement.
                if token_expired(&tok) {
                    pending_token = None;
                    let _ = clear_pending_token(&data_dir);
                    tracing::warn!(
                        "invite token expired — not redeeming; ask the admin for a fresh \
                         `space invite`",
                    );
                } else {
                    match try_redeem(n, &data_dir, &tok) {
                        Ok(true) => {
                            pending_token = None;
                            if let Err(e) = clear_pending_token(&data_dir) {
                                tracing::warn!("clearing pending invite secret: {e}");
                            }
                            tracing::info!(
                                "invite redeemed — node key granted; the grant syncs back on the \
                                 next FetchHeads",
                            );
                        }
                        Ok(false) => {} // bootnode not reachable/ready yet — retry next pass
                        Err(e) if !redeem_warned => {
                            redeem_warned = true;
                            tracing::warn!("redeem: {e}");
                        }
                        Err(e) => tracing::debug!("redeem: {e}"),
                    }
                }
            }
            match reconcile_installed_agents(
                n,
                &data_dir,
                space_id,
                local_prefix,
                &local_cfg,
                &mut damped,
                &mut service_registration_backoff,
                &mut boot_grace,
                &in_flight,
                &agent_policies,
                pinned_service_service.as_ref(),
                production_trust.clone(),
            ) {
                Ok(()) => query_warned = false,
                // Usually a stopped/wedged registry; the condition
                // persists across passes, so warn once and demote
                // the 2s-cadence repeats.
                Err(e) if !query_warned => {
                    query_warned = true;
                    tracing::warn!("spawn-reconcile: {e}");
                }
                Err(e) => tracing::debug!("spawn-reconcile: {e}"),
            }
        });
    }

    let results = node.collect();
    let mut panics = 0u32;
    for r in &results {
        panics += r.panics;
        if let Some(err) = &r.error {
            tracing::error!("agent {} error: {err}", r.id);
        }
    }

    // Best-effort cleanup; if a crash short-circuits this,
    // the next client invocation sees the stale endpoint and
    // surfaces it via `endpoint::is_alive`.
    crate::commands::space::endpoint::delete(&data_dir);

    if panics > 0 {
        anyhow::bail!("{panics} pvm panics");
    }
    Ok(())
}

/// Invite admission now includes the canonical Raft-authority commit before
/// the registry reply is emitted. Its bounded invoke may legitimately spend
/// one voter-auth probe, a read barrier, genesis admission, and the two
/// proposals used by one root invocation, so this must cover the full root
/// budget plus transport/dispatch margin. The pending bearer remains durable
/// across a timeout and is retried on the next reconciliation tick.
const REDEEM_REGISTRY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(35);

// ── Trivalent `up` positional (decision 1) ───────────────────────────

/// Resolve `args.query` to the space lookup key, handling the recipe /
/// token / name trivalent and stamping any pending token or recipe
/// onto the index. `-` reads a token from stdin.
fn resolve_up_target(args: &Args) -> anyhow::Result<String> {
    let raw = if args.query == "-" {
        read_token_stdin()?
    } else {
        args.query.clone()
    };
    // (a) recipe: an existing `.toml` path. File existence + extension is
    //     unambiguous — a space name may not start with `vos-` and a
    //     token is never a path.
    if is_recipe_path(&raw) {
        return resolve_recipe(&raw);
    }
    // (b) token: a `vos-…` string.
    if raw.starts_with(crate::token::TOKEN_HRP) {
        return resolve_token(&raw);
    }
    // (c) known name / id — the caller resolves it via `spaces_index::find`.
    Ok(raw)
}

fn is_recipe_path(arg: &str) -> bool {
    arg.ends_with(".toml") && Path::new(arg).is_file()
}

/// Read a `vos-…` token from stdin (`space up -`), keeping a bearer
/// string out of argv / shell history.
fn read_token_stdin() -> anyhow::Result<String> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| anyhow::anyhow!("read token from stdin: {e}"))?;
    let tok = buf.trim().to_string();
    if tok.is_empty() {
        anyhow::bail!("no token on stdin (`space up -` expects a vos-… token piped in)");
    }
    Ok(tok)
}

/// Recipe path: parse the recipe, scaffold genesis if its `space = …`
/// name is unknown, stamp `pending_recipe` (+ any `hyperspace`) on the
/// entry, and return the space name to boot.
fn resolve_recipe(path: &str) -> anyhow::Result<String> {
    let (recipe, _dir) = reconcile::parse_recipe_file(Path::new(path))?;
    let name = recipe.space.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "recipe {path} has no top-level `space = \"…\"` — add one so `space up` knows which \
             space to create or boot",
        )
    })?;
    // Absolute so the genesis apply on the next tick re-reads it
    // regardless of the daemon's cwd.
    let abs = std::fs::canonicalize(path)
        .unwrap_or_else(|_| Path::new(path).to_path_buf())
        .to_string_lossy()
        .to_string();

    if !spaces_index::load()?.spaces.iter().any(|e| e.name == name) {
        crate::commands::space::new::scaffold(&name, None, None)?;
        tracing::info!("created space '{name}' from recipe {path}");
    }

    let mut index = spaces_index::LockedSpacesIndex::acquire()?;
    let entry = index
        .spaces
        .iter_mut()
        .find(|e| e.name == name)
        .ok_or_else(|| anyhow::anyhow!("space '{name}' missing after scaffold"))?;
    entry.pending_recipe = abs;
    if let Some(hs) = &recipe.hyperspace
        && !hs.is_empty()
    {
        entry.hyperspace = hs.clone();
    }
    index.save()?;
    Ok(name)
}

/// Token path: parse the invite, join-if-needed (scaffold the local data
/// dir + node key + registry blob + index entry, taking `space_id` on
/// trust — `space up` verifies genesis once synced), persist the bearer
/// token in an owner-only per-space file, and return the space id.
fn resolve_token(token_str: &str) -> anyhow::Result<String> {
    let payload = crate::token::parse(token_str)?;
    let space_id_hex = hex::encode(payload.space_id);

    if !spaces_index::load()?
        .spaces
        .iter()
        .any(|e| e.id == space_id_hex)
    {
        join_scaffold(&payload)?;
        tracing::info!("joined space '{}' from invite token", payload.name);
    }

    let mut index = spaces_index::LockedSpacesIndex::acquire()?;
    let entry = index
        .spaces
        .iter_mut()
        .find(|e| e.id == space_id_hex)
        .ok_or_else(|| anyhow::anyhow!("space missing after join"))?;
    for b in &payload.bootnodes {
        if !entry.bootnodes.contains(b) {
            entry.bootnodes.push(b.clone());
        }
    }
    let data_dir = PathBuf::from(&entry.data_dir);
    index.save()?;
    save_pending_token(&data_dir, token_str)?;
    // Return the space_id, not the name: the token's space is unambiguous
    // by id, and a name can collide with another already-known space.
    Ok(space_id_hex)
}

/// Lay out a joined space's local state from a parsed invite — mirrors
/// the retired `space join`: a fresh per-space node key, the bundled
/// registry blob cached under its hash, the data dir, and the index
/// entry carrying the token's bootnodes.
fn join_scaffold(payload: &crate::token::InvitePayload) -> anyhow::Result<()> {
    let (registry_hash, _bytes, _label) =
        crate::commands::space::new::resolve_registry_source(None)?;
    let mut index = spaces_index::LockedSpacesIndex::acquire()?;
    let mut entry = spaces_index::entry_for(&payload.space_id, &payload.name)?;
    let space_dir = PathBuf::from(&entry.data_dir);
    entry.registry_hash = registry_hash.to_hex();
    entry.bootnodes = payload.bootnodes.clone();
    index.validate_upsert(&entry)?;
    if !space_dir.exists() {
        std::fs::create_dir_all(&space_dir)?;
        std::fs::create_dir_all(space_dir.join("agents"))?;
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let key_bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| anyhow::anyhow!("encode keypair: {e}"))?;
        std::fs::write(space_dir.join("node.key"), key_bytes)?;
    }
    spaces_index::upsert(&mut index, entry);
    index.save()?;
    Ok(())
}

// ── Genesis apply + node-local extension registration ────────────────

/// Consume a pending recipe: install its agents into the in-process
/// registry (replicated half) and project its node-local half into
/// `local.toml`. `install_agents` tolerates already-present rows, so a
/// re-run is a no-op; the caller clears `pending_recipe` after.
fn genesis_apply(
    node: &mut VosNode,
    recipe_path: &str,
    prefix: u16,
    space_id: &[u8; 32],
    data_dir: &Path,
) -> anyhow::Result<()> {
    let path = Path::new(recipe_path);
    let (recipe, dir) = reconcile::parse_recipe_file(path)?;
    reconcile::install_agents(node, &recipe, &dir, prefix, space_id)?;
    let base = subscriptions::load(data_dir).unwrap_or_default();
    let next = crate::commands::space::apply::project_node_local(&base, &recipe, &dir);
    if next != base {
        subscriptions::save(data_dir, &next)?;
    }
    tracing::info!("genesis apply of recipe {recipe_path} complete");
    Ok(())
}

/// Register every `[[extension]]` recorded in `local.toml`, returning
/// each one's effective relay caps for the endpoint descriptor. `.so`
/// paths are stored absolute (by `apply` / genesis), so the base dir
/// passed to `register_extension` is inert.
fn register_extensions_from_local(
    node: &mut VosNode,
    cfg: &subscriptions::LocalConfig,
    data_dir: &Path,
    prefix: u16,
) -> anyhow::Result<Vec<crate::commands::space::endpoint::ExtensionCaps>> {
    use crate::commands::space::endpoint::ExtensionCaps;
    if cfg.extensions.is_empty() {
        return Ok(Vec::new());
    }
    let reg = RegistryRef::at(ServiceId::new(prefix, ServiceId::REGISTRY.local_id()));
    let space_cap_policy = match cfg.cap_policy.as_deref() {
        Some(s) => vos::extension::CapPolicy::parse(s),
        None => vos::extension::CapPolicy::default(),
    };
    // Roster for named-intra_cap validation: every installed agent +
    // every extension + the built-in registry.
    let mut known_names: HashSet<String> = cfg
        .extensions
        .iter()
        .map(|e| e.name.clone())
        .chain(std::iter::once("space-registry".to_string()))
        .collect();
    if let Ok(agents) = vos::block_on(reg.agents_all(&mut &*node)) {
        for a in agents {
            known_names.insert(a.instance_name);
        }
    }
    let mut caps = Vec::with_capacity(cfg.extensions.len());
    for e in &cfg.extensions {
        let ext_def = reconcile::ExtensionDef {
            name: e.name.clone(),
            path: e.path.clone(),
            init: e.init.clone(),
            cap_policy: e.cap_policy.clone(),
            intra_caps: e.intra_caps.clone(),
            tick_ms: e.tick_ms,
        };
        let effective = reconcile::register_extension(
            node,
            &reg,
            &ext_def,
            data_dir,
            prefix,
            space_cap_policy,
            &known_names,
        )?;
        caps.push(ExtensionCaps {
            name: e.name.clone(),
            caps: effective,
        });
    }
    Ok(caps)
}

// ── Invite redemption (boot tick) ────────────────────────────────────

/// A bounded registry invocation over the running node, so a redeem
/// attempt to a slow or vanished bootnode can't stall the router tick
/// for the node's 10 s default.
struct TimedNode<'a> {
    node: &'a VosNode,
    timeout: std::time::Duration,
}

fn decode_timed_node_reply(outcome: Option<Vec<u8>>) -> Result<vos::value::Value, ClientError> {
    match outcome {
        Some(b) if b.len() == 5 && b[0] == vos::STATUS_FORBIDDEN && b[1..] == [0, 0, 0, 0] => {
            Err(ClientError::Forbidden)
        }
        Some(b) if b.is_empty() => Ok(vos::value::Value::Unit),
        Some(b) => <vos::value::Value as vos::Decode>::try_decode(&b).ok_or(ClientError::Decode),
        None => Err(ClientError::Unreachable),
    }
}

impl RegistryInvoker for TimedNode<'_> {
    fn invoke_registry(
        &mut self,
        target: ServiceId,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<vos::value::Value, ClientError>> + '_ {
        let outcome = self.node.invoke_with_timeout(target, payload, self.timeout);
        async move { decode_timed_node_reply(outcome) }
    }
}

fn authority_invite_redemption(
    payload: &crate::token::InvitePayload,
    holder_peer_id: Vec<u8>,
    redeem_signature: [u8; vos::registry::OP_SIG_LEN],
    holder_signature: Vec<u8>,
) -> anyhow::Result<vos::service::RoleAuthorityInviteRedemption> {
    let authority_replication_id = payload.authority_replication_id;
    if authority_replication_id == [0; 32] {
        anyhow::bail!("invite is not bound to a canonical service role authority");
    }
    let role = match vos::SpaceRole::from_u8(payload.role) {
        Some(role @ (vos::SpaceRole::Member | vos::SpaceRole::Developer)) => role,
        _ => anyhow::bail!("invite role {} is not canonical service", payload.role),
    };
    let holder_signature = holder_signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("node invite signature is not Ed25519"))?;
    Ok(vos::service::RoleAuthorityInviteRedemption {
        space: vos::service::SpaceId(payload.space_id),
        authority_replication_id,
        token_pub: payload.token_pub,
        role,
        expires_at: payload.expires_at,
        admin_peer_id: payload.admin_peer_id.clone(),
        admin_signature: payload.admin_sig,
        holder_peer_id,
        redeem_signature,
        holder_signature,
    })
}

#[cfg(test)]
fn authority_invite_invocation(
    redemption: &vos::service::RoleAuthorityInviteRedemption,
    peer_prefix: u16,
) -> (ServiceId, vos::service::RootTreeInvocation) {
    use vos::Encode;
    use vos::service::ServiceWire;

    let root_service = service_root_service_id(
        redemption.space,
        vos::service::ROLE_AUTHORITY_INSTANCE_,
        redemption.authority_replication_id,
    );
    let target = service_root_actor_id(root_service, vos::service::ROLE_AUTHORITY_INSTANCE_);
    let redemption = redemption.encode();
    let mut arguments = vec![vos::value::TAG_DYNAMIC];
    arguments.extend_from_slice(
        &vos::value::Msg::new(vos::service::ROLE_AUTHORITY_INVITE_METHOD_)
            .with("redemption", redemption.clone())
            .encode(),
    );
    (
        instance_service_id(vos::service::ROLE_AUTHORITY_INSTANCE_, peer_prefix),
        vos::service::RootTreeInvocation {
            invocation: vos::service::InvocationId::derive(
                b"vos/invite-authority-redemption/service",
                &redemption,
            ),
            target,
            method: vos::service::ROLE_AUTHORITY_INVITE_METHOD_.into(),
            arguments,
            proof_requested: false,
        },
    )
}

/// One redeem attempt: build the joiner's two signatures and invoke each
/// connected peer's registry. The serving root host first drives the exact
/// redemption through its canonical authority and injects a root-signed
/// acceptance attestation into the recorded registry operation. `Ok(true)`
/// therefore means both commits completed; a rejected or unavailable
/// authority leaves no effective registry grant and remains retryable.
fn try_redeem(node: &VosNode, data_dir: &Path, token_str: &str) -> anyhow::Result<bool> {
    let payload = crate::token::parse(token_str)?;

    // Redemption grants the DAEMON's node key (not the operator CLI
    // key) — the identity peers see on sync — so sign with node.key.
    let key_bytes = std::fs::read(data_dir.join("node.key"))
        .map_err(|e| anyhow::anyhow!("read node.key for redeem: {e}"))?;
    let node_kp = libp2p::identity::Keypair::from_protobuf_encoding(&key_bytes)
        .map_err(|e| anyhow::anyhow!("decode node.key: {e}"))?;
    let node_peer_id = libp2p::PeerId::from(node_kp.public()).to_bytes();

    // Both signatures cover the same canonical: the token secret proves
    // possession, the node key proves control of the granted peer-id.
    let redeem_sig = crate::token::redeem_sig(&payload, &node_peer_id)?;
    let redeem_canon =
        vos::registry::canonical_op_bytes("redeem_invite", &[&payload.token_pub, &node_peer_id]);
    let node_sig = node_kp
        .sign(&redeem_canon)
        .map_err(|e| anyhow::anyhow!("node_sig sign: {e}"))?;
    // Validate the exact authority wire locally before handing the same fields
    // to a serving peer. The peer reconstructs and commits this value before
    // author-signing registry admission.
    let _authority_redemption =
        authority_invite_redemption(&payload, node_peer_id.clone(), redeem_sig, node_sig.clone())?;

    let Some(net) = node.network() else {
        return Ok(false);
    };
    let peers = net.connected_peers();
    if peers.is_empty() {
        return Ok(false);
    }
    for peer in peers {
        let peer_prefix = vos::network::derive_node_prefix(&peer);
        let reg = RegistryRef::at(ServiceId::new(peer_prefix, ServiceId::REGISTRY.local_id()));
        let mut inv = TimedNode {
            node,
            timeout: REDEEM_REGISTRY_TIMEOUT,
        };
        let status = vos::block_on(reg.redeem_invite(
            &mut inv,
            payload.token_pub.to_vec(),
            payload.role,
            payload.expires_at,
            payload.authority_replication_id.to_vec(),
            payload.admin_peer_id.clone(),
            payload.admin_sig.to_vec(),
            node_peer_id.clone(),
            redeem_sig.to_vec(),
            node_sig.clone(),
            Vec::new(),
        ));
        match status {
            Ok(Status::Ok) => return Ok(true),
            Ok(other) => tracing::debug!("redeem via {peer}: {other}"),
            Err(e) => tracing::debug!("redeem via {peer}: {e}"),
        }
    }
    Ok(false)
}

/// True if the invite token's `expires_at` has been reached (host wall
/// clock). A parse failure is treated as NOT expired — `try_redeem`
/// reports the corrupt token with a clearer error. The serving node
/// independently enforces the same deadline before actor dispatch.
fn token_expired(token_str: &str) -> bool {
    let Ok(payload) = crate::token::parse(token_str) else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(u64::MAX);
    now >= payload.expires_at
}

fn pending_token_path(data_dir: &Path) -> PathBuf {
    data_dir.join(PENDING_INVITE_FILE)
}

fn load_pending_token(data_dir: &Path) -> anyhow::Result<Option<String>> {
    let Some(bytes) = crate::secure_file::read_optional(&pending_token_path(data_dir))? else {
        return Ok(None);
    };
    let token = String::from_utf8(bytes)
        .map_err(|e| anyhow::anyhow!("pending invite token is not UTF-8: {e}"))?;
    let token = token.trim().to_string();
    if token.is_empty() {
        Ok(None)
    } else {
        Ok(Some(token))
    }
}

fn save_pending_token(data_dir: &Path, token: &str) -> anyhow::Result<()> {
    crate::secure_file::write_owner_only_atomic(&pending_token_path(data_dir), token.as_bytes())
}

/// Remove the node-local bearer credential after redemption or expiry.
fn clear_pending_token(data_dir: &Path) -> anyhow::Result<()> {
    crate::secure_file::remove_if_exists(&pending_token_path(data_dir))
}

/// Clear the `pending_recipe` marker after a one-shot genesis apply.
fn clear_pending_recipe(space_id_hex: &str) -> anyhow::Result<()> {
    clear_pending(space_id_hex, |e| e.pending_recipe.clear())
}

fn clear_pending(
    space_id_hex: &str,
    clear: impl FnOnce(&mut spaces_index::SpaceEntry),
) -> anyhow::Result<()> {
    let mut index = spaces_index::LockedSpacesIndex::acquire()?;
    if let Some(entry) = index.spaces.iter_mut().find(|e| e.id == space_id_hex) {
        clear(entry);
        index.save()?;
    }
    Ok(())
}

/// Build a Network for the daemon. Always attaches — local-only
/// spaces get an auto-port loopback bind so clients have an
/// endpoint to dial.
///
/// Listen-addr resolution order (first non-empty wins):
///   1. `--listen` flag(s) on this `space up` invocation
///   2. `local.toml`'s `listen = [...]` (per-space user pref)
///   3. default `/ip4/127.0.0.1/tcp/0` (loopback auto-port)
///
/// `--connect` extends the entry's saved bootnodes additively
/// — the user can dial extra peers without losing the
/// original join target.
fn build_network_for_daemon(
    entry: &spaces_index::SpaceEntry,
    data_dir: &std::path::Path,
    listen_override: &[String],
    connect_extra: &[String],
) -> anyhow::Result<vos::network::Network> {
    let parse = |s: &str, kind: &str| -> anyhow::Result<libp2p::Multiaddr> {
        libp2p::Multiaddr::from_str(s)
            .map_err(|e| anyhow::anyhow!("bad {kind} multiaddr '{s}': {e}"))
    };
    let local_cfg = crate::commands::space::subscriptions::load(data_dir).unwrap_or_default();
    let listen_src: &[String] = if !listen_override.is_empty() {
        listen_override
    } else if !local_cfg.listen.is_empty() {
        &local_cfg.listen
    } else {
        &[]
    };
    let mut listen: Vec<libp2p::Multiaddr> = listen_src
        .iter()
        .map(|s| parse(s, "listen"))
        .collect::<anyhow::Result<_>>()?;
    if listen.is_empty() {
        // Default: bind to a loopback auto-port. The actual port
        // is captured into `.endpoint` once the swarm reports it.
        listen.push("/ip4/127.0.0.1/tcp/0".parse().unwrap());
    }
    let mut bootstrap: Vec<libp2p::Multiaddr> = entry
        .bootnodes
        .iter()
        .map(|s| parse(s, "bootnode"))
        .collect::<anyhow::Result<_>>()?;
    for s in connect_extra {
        bootstrap.push(parse(s, "connect")?);
    }

    let key_path = data_dir.join("node.key");
    let key_bytes = std::fs::read(&key_path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", key_path.display()))?;
    let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&key_bytes)
        .map_err(|e| anyhow::anyhow!("decode keypair: {e}"))?;
    let peer_id = libp2p::PeerId::from(keypair.public());
    let local_prefix = vos::network::derive_node_prefix(&peer_id);
    tracing::info!("node identity {peer_id} (prefix {local_prefix:#06x})");

    // mDNS auto-dial is on by default — a long-running daemon
    // benefits from same-LAN peer discovery. Set
    // `VOSX_DISABLE_MDNS=1` to opt out; the integration suite uses
    // it so test daemons don't latch onto unrelated libp2p apps
    // (IPFS / Substrate / etc.) on the dev machine.
    let auto_dial_mdns = std::env::var("VOSX_DISABLE_MDNS").is_err();
    Ok(vos::network::Network::start(vos::network::NetworkConfig {
        keypair,
        local_prefix,
        listen,
        bootstrap,
        auto_dial_mdns,
    }))
}

/// Node-local service policy from the recipe (never replicated).
#[derive(Default, Clone)]
struct AgentLocalPolicy {
    device_secret: bool,
}

type AgentPolicies = std::collections::BTreeMap<String, AgentLocalPolicy>;

/// Collect host-private service policy from `local.toml`.
fn agent_policies_from_local(cfg: &subscriptions::LocalConfig) -> anyhow::Result<AgentPolicies> {
    let mut map = AgentPolicies::new();
    for (name, a) in &cfg.agents {
        if a.device_secret {
            map.insert(
                name.clone(),
                AgentLocalPolicy {
                    device_secret: a.device_secret,
                },
            );
        }
    }
    Ok(map)
}

fn publish_endpoint(
    node: &VosNode,
    data_dir: &std::path::Path,
    prefix: u16,
    extensions: Vec<crate::commands::space::endpoint::ExtensionCaps>,
) -> anyhow::Result<()> {
    use std::time::{Duration, Instant};

    let net = node
        .network()
        .ok_or_else(|| anyhow::anyhow!("network not attached when publishing endpoint"))?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let multiaddrs = loop {
        let addrs = net.listen_addrs();
        if !addrs.is_empty() {
            break addrs;
        }
        if Instant::now() >= deadline {
            anyhow::bail!("swarm didn't bind a listen address within 3s");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let peer_id = net.peer_id().to_string();
    let multiaddrs: Vec<String> = multiaddrs.iter().map(|m| m.to_string()).collect();
    let ep = crate::commands::space::endpoint::Endpoint {
        peer_id,
        multiaddrs: multiaddrs.clone(),
        prefix,
        pid: std::process::id(),
        extensions,
    };
    crate::commands::space::endpoint::write(data_dir, &ep)?;
    tracing::info!("endpoint published on {} address(es)", multiaddrs.len());
    for a in &multiaddrs {
        tracing::info!("  {a}");
    }
    Ok(())
}

/// Query the registry for installed agents and register each
/// on the local node. If `<data_dir>/local.toml` declares a
/// `subscriptions` filter, only listed instances spawn — the
/// rest are skipped (their state still arrives via gossipsub
/// for full replicas, but isn't materialized into a running
/// agent here).
fn spawn_installed_agents(
    node: &mut VosNode,
    data_dir: &std::path::Path,
    space_id: [u8; 32],
    local_prefix: u16,
    has_hyperspace: bool,
    policies: &AgentPolicies,
    pinned_service_service: Option<&PinnedService>,
    production_trust: Option<std::sync::Arc<dyn vos::service::ProductionTrust>>,
    service_registration_backoff: &mut RegistrationBackoff,
) -> anyhow::Result<()> {
    use std::collections::HashSet;
    use vos::registry::{RegistryRef, Status};

    let local_cfg = crate::commands::space::subscriptions::load(data_dir).unwrap_or_default();
    if local_cfg.is_filtering() {
        tracing::info!(
            "subscriptions filter active — {} agent(s)",
            local_cfg.subscriptions.len(),
        );
    }

    let reg = RegistryRef::at(ServiceId::REGISTRY);
    let agents = vos::block_on(reg.agents_all(&mut &*node))
        .map_err(|e| anyhow::anyhow!("query agents: {e}"))?;
    let root_peer_id = vos::block_on(reg.root(&mut &*node))
        .map_err(|e| anyhow::anyhow!("query immutable space root: {e}"))?;

    // Set of svc_ids the catalog knows about — used at the
    // end to sweep orphaned redbs into trash. We add to this
    // even for skipped agents (subscriptions filter, missing
    // blob, …) so we don't accidentally trash their state.
    let mut live_svc_ids: HashSet<u32> = HashSet::new();
    let mut live_service_services: HashSet<[u8; 32]> = HashSet::new();
    live_svc_ids.insert(ServiceId::REGISTRY.0);
    if has_hyperspace {
        // The hyperspace registry replica owns its own redb at
        // svc_id 1; protect it from the orphan sweep.
        live_svc_ids.insert(ServiceId::HYPERSPACE_REGISTRY.0);
    }

    let agent_names: Vec<String> = agents.iter().map(|a| a.instance_name.clone()).collect();
    for a in agents.iter() {
        let svc_id = instance_service_id(&a.instance_name, local_prefix);
        live_svc_ids.insert(svc_id.0);
        live_service_services.insert(
            service_root_service_id(
                vos::service::SpaceId(space_id),
                &a.instance_name,
                a.replication_id,
            )
            .0,
        );
    }

    // Contested raft bootstraps always defer at boot (their grace
    // spans reconcile passes); the throwaway map just satisfies the
    // protocol — the runtime reconciler owns the durable counters.
    let mut boot_grace = BootGrace::new();
    // Whether this node is a space member, probed once; rows whose sync floor
    // requires membership are narrowed out on a non-member. The runtime
    // reconciler re-evaluates each pass, so a row spawns if a grant lands later.
    let is_member = node_is_member(node, &reg, local_prefix);
    let mut service_registration_attempts = 0usize;
    let mut spawn_rows = agents.iter().collect::<Vec<_>>();
    spawn_rows.sort_by_key(|row| {
        (row.instance_name != vos::service::ROLE_AUTHORITY_INSTANCE_)
            .then_some(row.instance_name.as_str())
    });
    for a in spawn_rows {
        let is_role_authority = a.instance_name == vos::service::ROLE_AUTHORITY_INSTANCE_;
        if !is_role_authority && !local_cfg.should_spawn(&a.instance_name) {
            tracing::debug!("skipping '{}' (not subscribed)", a.instance_name);
            continue;
        }
        if !node_meets_floor(is_member, a.sync_role) {
            tracing::info!(
                "agent '{}' not spawned — its '{}' sync floor is above this \
                 node's space role",
                a.instance_name,
                a.sync_role.as_str(),
            );
            continue;
        }
        // Resolve the complete executable/configuration before any Raft
        // membership action. In particular, an unsupported signed package
        // must never seed or join a group whose worker will not be spawned.
        let prepared = match agent_config_from_row(
            data_dir,
            space_id,
            a,
            &agents,
            policies,
            pinned_service_service,
            &root_peer_id,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                tracing::warn!(
                    "skipping agent '{}' — failed to prepare: {error}",
                    a.instance_name,
                );
                continue;
            }
        };
        let supports_raft = matches!(&prepared, RowConfig::Service { .. });
        let raft_seed =
            if supports_raft && consistency_from_u8(a.consistency) == Some(Consistency::Raft) {
                if !blob_store::cache_path_for(&BlobHash(a.program_hash)).exists() {
                    tracing::warn!(
                        "skipping agent '{}' — program blob {} not in local cache",
                        a.instance_name,
                        BlobHash(a.program_hash),
                    );
                    continue;
                }
                let Some(db_path) = raft_db_path_for_row(data_dir, &prepared) else {
                    continue;
                };
                match raft_members_for_row(node, &db_path, a, local_prefix, &mut boot_grace) {
                    Ok(seed @ (RaftSeed::Members { .. } | RaftSeed::Join { .. })) => Some(seed),
                    Ok(RaftSeed::Defer(reason)) => {
                        tracing::info!(
                            "agent '{}' (raft) deferred to the runtime reconciler: {reason}",
                            a.instance_name,
                        );
                        continue;
                    }
                    Err(e) => {
                        tracing::warn!("agent '{}' (raft) deferred: {e}", a.instance_name);
                        continue;
                    }
                }
            } else {
                None
            };
        match prepared {
            RowConfig::Service {
                config,
                state_path,
                network_reachable,
            } => {
                let registration_key = (a.instance_name.clone(), a.program_hash);
                if !take_service_registration_attempt(
                    &mut service_registration_attempts,
                    service_registration_backoff,
                    &registration_key,
                    std::time::Instant::now(),
                ) {
                    tracing::debug!(
                        "service root tree '{}' deferred until post-publication reconciliation",
                        a.instance_name,
                    );
                    continue;
                }
                let svc_id = instance_service_id(&a.instance_name, local_prefix);
                match register_service_root_from_row(
                    node,
                    data_dir,
                    a.instance_name.clone(),
                    a.replication_id,
                    *config,
                    state_path,
                    raft_seed,
                    local_prefix,
                    svc_id,
                    network_reachable,
                    production_trust.clone(),
                ) {
                    Ok(id) => {
                        service_registration_backoff
                            .success(&registration_key, std::time::Instant::now());
                        tracing::info!(
                            "service root tree '{}' as {id} ({})",
                            a.instance_name,
                            crate::commands::space::common::consistency_name(a.consistency),
                        );
                    }
                    Err(error) => {
                        let retryable = is_retryable_service_registration_error(&error);
                        service_registration_backoff.finish(
                            registration_key,
                            retryable,
                            std::time::Instant::now(),
                        );
                        tracing::warn!(
                            "skipping agent '{}' — service route failed to register: {error}",
                            a.instance_name,
                        );
                    }
                }
            }
            RowConfig::MissingBlob => {
                tracing::warn!(
                    "skipping agent '{}' — program blob {} not in local cache",
                    a.instance_name,
                    BlobHash(a.program_hash),
                );
            }
            RowConfig::Deferred(reason) => {
                tracing::info!("agent '{}' deferred: {reason}", a.instance_name);
            }
            RowConfig::BadConsistency => {
                tracing::warn!(
                    "skipping agent '{}' — unknown consistency {}",
                    a.instance_name,
                    a.consistency,
                );
            }
            RowConfig::UnsupportedPackage(reason) => {
                tracing::warn!(
                    "skipping agent '{}' — unsupported service package: {reason}",
                    a.instance_name,
                );
            }
        }
    }

    // Hyperspace mode: advertise every local agent into the
    // hyperspace registry so cross-space `resolve` calls land on the
    // right host. Best-effort — failures log a warning but don't
    // abort boot, since the local space still works without
    // cross-space addressing.
    if has_hyperspace {
        let hs_reg = RegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
        for name in agent_names {
            match vos::block_on(hs_reg.register_remote(
                &mut &*node,
                name.clone(),
                local_prefix as u32,
            )) {
                Ok(Status::Ok) => {
                    tracing::info!("hyperspace: registered '{name}' @ prefix {local_prefix:#06x}",)
                }
                Ok(other) => {
                    tracing::warn!("hyperspace: register_remote('{name}') returned status {other}",)
                }
                Err(e) => tracing::warn!("hyperspace: register_remote('{name}') failed: {e}",),
            }
        }
    }

    // Sweep `agents/` for redbs whose svc_id no longer maps to
    // a catalog entry — the trace left by past `space uninstall`
    // calls. Move them to `<data_dir>/trash/<svc_id>.redb` so
    // a future `--undo` (or just an `ls`) can recover the bytes
    // instead of finding orphans.
    sweep_orphan_redbs(data_dir, &live_svc_ids);
    sweep_orphan_service_services(data_dir, &live_service_services);

    Ok(())
}

/// How often the idle hook re-runs the spawn-reconcile pass. The
/// pass is a single local registry invoke plus a hash-set probe
/// per row, so a low couple-of-seconds cadence keeps freshly
/// installed agents snappy without measurable idle cost.
const SPAWN_RECONCILE_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

/// Cap on program-blob fetches running concurrently across the daemon. A
/// joiner that syncs a large registry can face many missing blobs at once;
/// this bounds the fan-out (and the peer load) while the reconcile pass keeps
/// retrying uncached rows every [`SPAWN_RECONCILE_EVERY`].
const MAX_INFLIGHT_BLOB_FETCHES: usize = 4;

/// Per-peer wait for a [`FetchProgramBlob`](vos::network) reply before rotating
/// to the next connected peer. Generous — an ELF can be a few hundred KiB — but
/// bounded so one unresponsive peer doesn't wedge a fetch task.
const PROGRAM_BLOB_FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

/// Hashes of program blobs currently being fetched from peers, shared between
/// the reconcile pass (which starts fetches) and the background fetch tasks
/// (which clear their entry when done). Dedups concurrent fetches of the same
/// blob and caps total in-flight at [`MAX_INFLIGHT_BLOB_FETCHES`].
type InFlightBlobs = std::sync::Arc<std::sync::Mutex<std::collections::HashSet<[u8; 32]>>>;

/// Clears a hash from the in-flight set when the fetch task ends — including on
/// an unwinding panic — so a slot can never leak permanently and wedge future
/// fetches (four leaks would exhaust [`MAX_INFLIGHT_BLOB_FETCHES`]).
struct InFlightGuard {
    hash: [u8; 32],
    in_flight: InFlightBlobs,
}
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Ok(mut set) = self.in_flight.lock() {
            set.remove(&self.hash);
        }
    }
}

/// Kick off a best-effort background fetch of program blob `hash` from the
/// node's connected peers, unless it's already in flight or the in-flight cap
/// is reached. Returns immediately — the reconcile pass never blocks on the
/// network. A spawned thread rotates through peers, verifies each reply's bytes
/// against `hash` before caching (a peer can't poison the content-addressed
/// cache), and clears the in-flight entry when done so a later pass can retry
/// if no peer had the blob yet. The now-cached blob is picked up next pass.
fn spawn_program_blob_fetch(node: &VosNode, hash: [u8; 32], in_flight: &InFlightBlobs) {
    let Some(network) = node.network() else {
        return; // no swarm attached (e.g. `--once`) — nothing to fetch from
    };
    {
        let mut set = match in_flight.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        if set.contains(&hash) || set.len() >= MAX_INFLIGHT_BLOB_FETCHES {
            return;
        }
        set.insert(hash);
    }
    let peers = network.connected_peers();
    if peers.is_empty() {
        // Nobody to ask yet; free the slot so the next pass retries once a
        // peer connects.
        if let Ok(mut set) = in_flight.lock() {
            set.remove(&hash);
        }
        return;
    }
    let in_flight = in_flight.clone();
    std::thread::spawn(move || {
        // Frees the in-flight slot on return OR panic — the loop below only
        // touches `network`, so a leak here would be permanent.
        let _guard = InFlightGuard { hash, in_flight };
        for peer in peers {
            let rx = network.send_fetch_program_blob(peer, hash);
            if let Ok(Some(bytes)) = rx.recv_timeout(PROGRAM_BLOB_FETCH_TIMEOUT) {
                // A peer serves arbitrary bytes; trust them only if they hash to
                // the requested content address.
                if BlobHash::of(&bytes).0 != hash {
                    tracing::warn!(
                        "peer {peer} served the wrong bytes for program blob {} — ignoring",
                        BlobHash(hash),
                    );
                    continue;
                }
                match blob_store::cache_put(&bytes) {
                    Ok(_) => {
                        tracing::info!(
                            "fetched program blob {} from peer {peer} ({} bytes)",
                            BlobHash(hash),
                            bytes.len(),
                        );
                        break;
                    }
                    Err(e) => tracing::warn!(
                        "caching fetched program blob {} failed: {e}",
                        BlobHash(hash),
                    ),
                }
            }
        }
    });
}

/// Outcome of resolving one registry row into a canonical service.
enum RowConfig {
    Service {
        config: Box<vos::service::LocalRootTreeConfig>,
        state_path: PathBuf,
        network_reachable: bool,
    },
    /// Program blob not in the local cache. On a joiner the row
    /// can arrive via registry sync before the operator has the
    /// blob, so this is retryable, not fatal.
    MissingBlob,
    /// A required platform dependency is not installed or cached yet. Runtime
    /// reconciliation retries the row after later registry/CAS progress.
    Deferred(String),
    /// Unrecognized consistency discriminant.
    BadConsistency,
    /// The artifact is a signed service package, but this daemon cannot safely host
    /// that particular row. Keep it installed and skip it without preventing
    /// the rest of the space from booting.
    UnsupportedPackage(String),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RowCatalogSupport {
    Unsupported,
    ServicePackage,
}

/// Inspect the content-addressed artifact before any membership action.
fn catalog_artifact_support(artifact: &[u8]) -> RowCatalogSupport {
    if artifact.get(..4) == Some(b"VOSP") {
        RowCatalogSupport::ServicePackage
    } else {
        RowCatalogSupport::Unsupported
    }
}

#[allow(clippy::large_enum_variant)]
enum RoleAuthorityResolution {
    Ready(vos::service::RoleAuthorityBinding),
    MissingBlob,
    MissingAgent,
}

fn validate_exact_service_package(
    exact_package: &[u8],
    instance_name: &str,
) -> anyhow::Result<vos::service::VosPackage> {
    use vos::service::ServiceWire;

    let package = vos::service::VosPackage::decode(exact_package)
        .map_err(|error| anyhow::anyhow!("decode {instance_name} package: {error}"))?;
    package
        .validate()
        .map_err(|error| anyhow::anyhow!("validate {instance_name} package: {error}"))?;
    if package.encode() != exact_package {
        anyhow::bail!("{instance_name} package wire is not canonical");
    }
    vos::service::validate_actor_program_layout(&package.actor_pvm).map_err(|error| {
        anyhow::anyhow!("{instance_name} actor PVM capability layout is invalid: {error}")
    })?;
    let public_key =
        libp2p::identity::PublicKey::try_decode_protobuf(&package.deployment_signature.public_key)
            .map_err(|error| anyhow::anyhow!("decode {instance_name} deployment key: {error}"))?;
    if !public_key.verify(
        &package.signing_message(),
        &package.deployment_signature.signature,
    ) {
        anyhow::bail!("{instance_name} deployment signature is invalid");
    }
    Ok(package)
}

fn package_requires_role_authority(package: &vos::service::VosPackage) -> anyhow::Result<bool> {
    use vos::service::ServiceWire;

    let policies = vos::service::PackageRolePolicies::decode(&package.role_policies)
        .map_err(|error| anyhow::anyhow!("decode generated role policies: {error}"))?;
    Ok(policies.methods.iter().any(|method| !method.public))
}

pub(super) fn validate_role_authority_deployment(
    package: &vos::service::VosPackage,
    root_peer_id: &[u8],
    consistency: Consistency,
) -> anyhow::Result<()> {
    use vos::service::ServiceWire;

    package
        .validate()
        .map_err(|error| anyhow::anyhow!("validate space-authority package: {error}"))?;
    vos::service::validate_actor_program_layout(&package.actor_pvm).map_err(|error| {
        anyhow::anyhow!("space-authority actor PVM capability layout is invalid: {error}")
    })?;
    if consistency != Consistency::Raft {
        anyhow::bail!(
            "{} must use Raft consistency",
            vos::service::ROLE_AUTHORITY_INSTANCE_
        );
    }
    let frozen = frozen_role_authority_package(Vec::new())?;
    if package.manifest.name != vos::service::ROLE_AUTHORITY_INSTANCE_ {
        anyhow::bail!("installed space-authority has the wrong package name");
    }
    // Authority upgrades may replace code and the resulting actor
    // deployment. They may not silently change the wire/API surface trusted
    // by the registry, daemon, or already-installed dependent roots.
    if package.generated_interfaces != frozen.generated_interfaces
        || package.role_policies != frozen.role_policies
        || package.schemas != frozen.schemas
        || package.task_dependencies != frozen.task_dependencies
        || package.manifest.crdt != frozen.manifest.crdt
    {
        anyhow::bail!("space-authority package changes the canonical platform contract");
    }
    let deployment_key =
        libp2p::identity::PublicKey::try_decode_protobuf(&package.deployment_signature.public_key)
            .map_err(|error| anyhow::anyhow!("decode space-authority deployment key: {error}"))?;
    if root_peer_id.is_empty()
        || libp2p::PeerId::from(deployment_key.clone()).to_bytes() != root_peer_id
    {
        anyhow::bail!("space-authority package was not signed by the immutable space root");
    }
    if !deployment_key.verify(
        &package.signing_message(),
        &package.deployment_signature.signature,
    ) {
        anyhow::bail!("space-authority deployment signature is invalid");
    }
    let policies = vos::service::PackageRolePolicies::decode(&package.role_policies)
        .map_err(|error| anyhow::anyhow!("decode space-authority policies: {error}"))?;
    let mut methods = policies
        .methods
        .iter()
        .map(|method| (method.method.as_str(), method.public, method.attested))
        .collect::<Vec<_>>();
    methods.sort_unstable();
    if methods
        != vec![
            (vos::service::ROLE_AUTHORITY_DECISION_METHOD_, true, false),
            (vos::service::ROLE_AUTHORITY_MUTATION_METHOD_, true, false),
            (vos::service::ROLE_AUTHORITY_INVITE_METHOD_, true, false),
            (
                vos::service::ROLE_AUTHORITY_INVITE_REVOKE_METHOD_,
                true,
                false,
            ),
        ]
    {
        anyhow::bail!("space-authority package exposes a non-canonical method policy surface");
    }
    Ok(())
}

fn resolve_service_role_authority(
    space_id: [u8; 32],
    installed_agents: &[vos::registry::AgentRow],
    root_peer_id: &[u8],
) -> anyhow::Result<RoleAuthorityResolution> {
    resolve_service_role_authority_with(space_id, installed_agents, root_peer_id, |program_hash| {
        blob_store::cache_get(&BlobHash(program_hash)).map_err(Into::into)
    })
}

fn resolve_service_role_authority_with(
    space_id: [u8; 32],
    installed_agents: &[vos::registry::AgentRow],
    root_peer_id: &[u8],
    mut load_package: impl FnMut([u8; 32]) -> anyhow::Result<Option<Vec<u8>>>,
) -> anyhow::Result<RoleAuthorityResolution> {
    let Some(row) = installed_agents
        .iter()
        .find(|row| row.instance_name == vos::service::ROLE_AUTHORITY_INSTANCE_)
    else {
        return Ok(RoleAuthorityResolution::MissingAgent);
    };
    let Some(consistency) = consistency_from_u8(row.consistency) else {
        anyhow::bail!(
            "space-authority has unknown consistency {}",
            row.consistency
        );
    };
    let Some(exact_package) = load_package(row.program_hash)? else {
        return Ok(RoleAuthorityResolution::MissingBlob);
    };
    if catalog_artifact_support(&exact_package) != RowCatalogSupport::ServicePackage {
        anyhow::bail!("space-authority does not reference a signed service package");
    }
    let package =
        validate_exact_service_package(&exact_package, vos::service::ROLE_AUTHORITY_INSTANCE_)?;
    if package.manifest.name != row.program_name {
        anyhow::bail!("space-authority catalog row does not name its exact signed package");
    }
    validate_role_authority_deployment(&package, root_peer_id, consistency)?;
    let space = vos::service::SpaceId(space_id);
    let root_service = service_root_service_id(
        space,
        vos::service::ROLE_AUTHORITY_INSTANCE_,
        row.replication_id,
    );
    Ok(RoleAuthorityResolution::Ready(
        vos::service::RoleAuthorityBinding {
            service: vos::service::ServiceIdentity {
                space,
                root_service,
                // Actor upgrades preserve the authority service account's
                // genesis identity. Dependent roots bind that stable service
                // identity, not the catalog's current actor deployment.
                deployment: frozen_role_authority_deployment()?,
                service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
                platform: vos::service::PLATFORM_ID,
                execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
                gas_schedule: vos::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
            },
            actor: service_root_actor_id(root_service, vos::service::ROLE_AUTHORITY_INSTANCE_),
        },
    ))
}

/// Build the `AgentConfig` for one registry row — blob lookup,
/// transpile, persistence/replication wiring, init args, and
/// on_start payloads. Shared by the boot-time
/// `spawn_installed_agents` scan and the runtime
/// `reconcile_installed_agents` pass so both spawn identically.
fn agent_config_from_row(
    data_dir: &std::path::Path,
    space_id: [u8; 32],
    a: &vos::registry::AgentRow,
    installed_agents: &[vos::registry::AgentRow],
    policies: &AgentPolicies,
    pinned_service_service: Option<&PinnedService>,
    root_peer_id: &[u8],
) -> anyhow::Result<RowConfig> {
    let Some(consistency) = consistency_from_u8(a.consistency) else {
        return Ok(RowConfig::BadConsistency);
    };
    let program_hash = BlobHash(a.program_hash);
    let artifact = match blob_store::cache_get(&program_hash)? {
        Some(b) => b,
        None => match recover_service_catalog_artifact(data_dir, space_id, a, consistency)? {
            Some(bytes) => bytes,
            None => return Ok(RowConfig::MissingBlob),
        },
    };
    if catalog_artifact_support(&artifact) != RowCatalogSupport::ServicePackage {
        return Ok(RowConfig::UnsupportedPackage(
            "catalog applications must be signed service packages".into(),
        ));
    }
    Ok(
        match service_config_from_row(
            data_dir,
            space_id,
            a,
            installed_agents,
            policies,
            consistency,
            artifact,
            pinned_service_service,
            root_peer_id,
        ) {
            Ok(config) => config,
            Err(error) => RowConfig::UnsupportedPackage(error.to_string()),
        },
    )
}

/// Recover an upgraded root's exact signed package when the node-local catalog
/// cache was lost. Applied roots retain it in the committed service image; a
/// Raft voter which crashed after commitment but before application recovers
/// it from the committed log or installed snapshot before its worker starts.
/// Upgrade availability is ordered before the registry CAS, so recovery never
/// depends on the initiating operator remaining online.
fn recover_service_catalog_artifact(
    data_dir: &Path,
    space_id: [u8; 32],
    row: &vos::registry::AgentRow,
    consistency: Consistency,
) -> anyhow::Result<Option<Vec<u8>>> {
    use vos::service::ServiceWire;

    let root_service = service_root_service_id(
        vos::service::SpaceId(space_id),
        &row.instance_name,
        row.replication_id,
    );
    let image_path = data_dir
        .join("services")
        .join(format!("{}.image", hex::encode(root_service.0)));
    let image = match std::fs::read(&image_path) {
        Ok(image) => Some(image),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(anyhow::anyhow!(
                "read service service image {} while recovering catalog artifact: {error}",
                image_path.display(),
            ));
        }
    };
    let mut artifact = if let Some(image) = image {
        let snapshot = vos::service::MemoryServiceSnapshot::decode(&image).map_err(|error| {
            anyhow::anyhow!(
                "decode service service image {} while recovering catalog artifact: {error}",
                image_path.display(),
            )
        })?;
        snapshot
            .content_blobs()
            .find(|bytes| {
                bytes.get(..4) == Some(b"VOSP") && BlobHash::of(bytes).0 == row.program_hash
            })
            .map(ToOwned::to_owned)
    } else {
        None
    };
    if artifact.is_none() && consistency == Consistency::Raft {
        let raft_path = service_raft_db_path(data_dir, root_service);
        artifact =
            vos::raft::service::recover_catalog_package_artifact(&raft_path, row.program_hash)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "recover service package from durable Raft storage {}: {error}",
                        raft_path.display(),
                    )
                })?;
    }
    let Some(artifact) = artifact else {
        return Ok(None);
    };
    validate_exact_service_package(&artifact, &row.instance_name)?;
    let cached = blob_store::cache_put(&artifact)
        .map_err(|error| anyhow::anyhow!("cache recovered service package: {error}"))?;
    if cached.0 != row.program_hash {
        anyhow::bail!("recovered service package changed content address while caching");
    }
    Ok(Some(artifact))
}

fn service_config_from_row(
    data_dir: &Path,
    space_id: [u8; 32],
    row: &vos::registry::AgentRow,
    installed_agents: &[vos::registry::AgentRow],
    policies: &AgentPolicies,
    consistency: Consistency,
    exact_package: Vec<u8>,
    pinned: Option<&PinnedService>,
    root_peer_id: &[u8],
) -> anyhow::Result<RowConfig> {
    let pinned = pinned.ok_or_else(|| {
        anyhow::anyhow!(
            "signed service package requires `space up --service-pvm <exact-vos-service.pvm>`"
        )
    })?;
    let package = validate_exact_service_package(&exact_package, &row.instance_name)?;
    match (package.manifest.crdt, consistency) {
        (false, Consistency::Local | Consistency::Raft) => {}
        (false, Consistency::Crdt) => anyhow::bail!(
            "ordinary #[actor] package cannot select CRDT consistency; install it as local"
        ),
        (true, Consistency::Crdt) => {}
        (true, Consistency::Raft) => {
            anyhow::bail!("#[actor(crdt)] package must use CRDT consistency")
        }
        (_, Consistency::Ephemeral) => anyhow::bail!(
            "service ephemeral hosting is not enabled; install the package with local consistency"
        ),
        (true, Consistency::Local) => anyhow::bail!(
            "#[actor(crdt)] package must use CRDT consistency, whose daemon driver is not attached yet"
        ),
    }
    let space = vos::service::SpaceId(space_id);
    let root_service = service_root_service_id(space, &row.instance_name, row.replication_id);
    let root_actor = service_root_actor_id(root_service, &row.instance_name);
    let deployment = package.deployment_id();
    let is_role_authority = row.instance_name == vos::service::ROLE_AUTHORITY_INSTANCE_;
    let role_authority = if is_role_authority {
        validate_role_authority_deployment(&package, root_peer_id, consistency)?;
        None
    } else if package_requires_role_authority(&package)? {
        match resolve_service_role_authority(space_id, installed_agents, root_peer_id)? {
            RoleAuthorityResolution::Ready(binding) => Some(binding),
            RoleAuthorityResolution::MissingBlob => return Ok(RowConfig::MissingBlob),
            RoleAuthorityResolution::MissingAgent => {
                return Ok(RowConfig::Deferred(
                    "canonical space-authority is not installed yet".into(),
                ));
            }
        }
    } else {
        None
    };
    let initial_state = if is_role_authority {
        space_authority::initial_state(space, root_peer_id.to_vec(), row.replication_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "registry root or replication ID is not a valid space-authority identity"
                )
            })?
    } else {
        Vec::new()
    };
    let state_path = data_dir
        .join("services")
        .join(format!("{}.image", hex::encode(root_service.0)));
    let device_secret_requested = policies
        .get(&row.instance_name)
        .is_some_and(|policy| policy.device_secret);
    if consistency == Consistency::Crdt && device_secret_requested {
        anyhow::bail!("service CRDT roots do not support host-private device signing");
    }
    let device_secret = device_secret_requested
        .then(|| load_or_mint_service_device_seed(data_dir, root_service))
        .transpose()?
        .map(vos::service::DeviceSecret::new);
    if let Some(secret) = device_secret.as_ref() {
        tracing::info!(
            actor = %row.instance_name,
            public_key = %hex::encode(secret.public_key()),
            "configured host-private service device signer",
        );
    }
    let install_authenticator = package.deployment_signature.signature.clone();
    let config = vos::service::LocalRootTreeConfig {
        role_authority,
        service_pvm: pinned.pvm.as_ref().clone(),
        package,
        service: vos::service::ServiceIdentity {
            space,
            root_service,
            deployment,
            service_program: vos::service::VOS_SERVICE_PROGRAM_ID,
            platform: vos::service::PLATFORM_ID,
            execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
            gas_schedule: vos::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
        },
        root_actor,
        actor_name: row.instance_name.clone(),
        consistency: match consistency {
            Consistency::Local => vos::service::ConsistencyMode::Local,
            Consistency::Raft => vos::service::ConsistencyMode::Raft,
            Consistency::Crdt => vos::service::ConsistencyMode::Crdt,
            _ => unreachable!("service consistency was validated above"),
        },
        initial_state,
        external_actors: Vec::new(),
        install_authorization: vos::service::AuthorizationEvidence::SystemCapability {
            capability: vos::service::SystemCapabilityId(
                vos::service::Hash::digest(
                    b"vos/space-install-capability/service",
                    &[&space_id, &deployment.0],
                )
                .0,
            ),
            authenticator: install_authenticator,
        },
        device_secret,
        refine_gas: 1_000_000_000,
        accumulate_gas: 5_000_000_000,
    };
    config
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid root-service configuration: {error:?}"))?;

    Ok(RowConfig::Service {
        config: Box::new(config),
        state_path,
        network_reachable: row.network_reachable,
    })
}

/// Load the host-private signer seed for one service root. Unlike a generic
/// messenger seed this is never sent as an actor message: Refine exposes only
/// signatures through `DEVICE_SIGN`. Raft operators must provision the same
/// 32-byte file on every voter before allowing leadership transfer.
fn load_or_mint_service_device_seed(
    data_dir: &Path,
    root_service: vos::service::RootServiceId,
) -> anyhow::Result<[u8; 32]> {
    let dir = data_dir.join("services");
    let dir_existed = dir.is_dir();
    std::fs::create_dir_all(&dir)?;
    if !dir_existed {
        sync_directory(data_dir)?;
    }
    let path = dir.join(format!("{}.device-seed", hex::encode(root_service.0)));
    remove_stale_secret_temp(&path)?;
    if let Some(seed) = read_service_device_seed(&path)? {
        return Ok(seed);
    }

    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| anyhow::anyhow!("OS entropy for service device seed: {e}"))?;
    create_secret_file_atomically(&path, &seed)?;
    let persisted = read_service_device_seed(&path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "atomically created service device seed {} is not readable",
            path.display()
        )
    })?;
    if persisted != seed {
        anyhow::bail!(
            "atomically created service device seed {} changed before activation",
            path.display()
        );
    }
    tracing::warn!(
        ?path,
        "minted a service device seed; copy this exact 0600 file to every Raft voter before failover"
    );
    Ok(seed)
}

fn secret_temp_path(path: &Path) -> anyhow::Result<std::path::PathBuf> {
    let mut name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("secret path {} has no file name", path.display()))?
        .to_os_string();
    name.push(".next");
    Ok(path.with_file_name(name))
}

/// Delete only an incomplete, not-yet-activated seed left by a crash. A
/// directory at the reserved path is never recursively removed.
fn remove_stale_secret_temp(path: &Path) -> anyhow::Result<()> {
    let temp = secret_temp_path(path)?;
    match std::fs::symlink_metadata(&temp) {
        Ok(metadata) if metadata.file_type().is_dir() => anyhow::bail!(
            "service device seed temporary path {} is a directory",
            temp.display()
        ),
        Ok(_) => {
            std::fs::remove_file(&temp)?;
            if let Some(parent) = temp.parent() {
                sync_directory(parent)?;
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Open one existing signer seed without following links or blocking on a
/// special file, then validate the metadata of the opened object itself.
fn read_service_device_seed(path: &Path) -> anyhow::Result<Option<[u8; 32]>> {
    use std::io::Read;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow::anyhow!(
                "cannot securely open service device seed {}: {error}",
                path.display()
            ));
        }
    };
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "service device seed {} must be a regular file",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            anyhow::bail!(
                "service device seed {} must have mode 0600, found {mode:04o}",
                path.display()
            );
        }
    }
    if metadata.len() != 32 {
        anyhow::bail!(
            "service device seed {} must contain exactly 32 bytes",
            path.display()
        );
    }
    let mut seed = [0u8; 32];
    file.read_exact(&mut seed)?;
    Ok(Some(seed))
}

/// Persist a new seed before making its final name visible. On Unix the
/// hard-link activation is atomic and refuses to replace an existing seed;
/// syncing the directory makes that name durable before the root is exposed.
fn create_secret_file_atomically(path: &Path, bytes: &[u8; 32]) -> anyhow::Result<()> {
    use std::io::Write;

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("secret path {} has no parent", path.display()))?;
    let temp = secret_temp_path(path)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    #[cfg(unix)]
    let activated = std::fs::hard_link(&temp, path);
    #[cfg(not(unix))]
    let activated = if path.exists() {
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "device seed already exists",
        ))
    } else {
        std::fs::rename(&temp, path)
    };
    if let Err(error) = activated {
        let _ = std::fs::remove_file(&temp);
        return Err(anyhow::anyhow!(
            "cannot atomically activate service device seed {}: {error}",
            path.display()
        ));
    }
    #[cfg(unix)]
    std::fs::remove_file(&temp)?;
    sync_directory(parent)?;
    Ok(())
}

fn sync_directory(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[derive(Debug)]
struct RetryableRootRegistration(String);

impl core::fmt::Display for RetryableRootRegistration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RetryableRootRegistration {}

fn is_retryable_service_registration_error(error: &anyhow::Error) -> bool {
    error.downcast_ref::<RetryableRootRegistration>().is_some()
}

fn service_registration_error(message: String, retryable: bool) -> anyhow::Error {
    if retryable {
        anyhow::Error::new(RetryableRootRegistration(message))
    } else {
        anyhow::anyhow!(message)
    }
}

fn retryable_production_dispatch(error: &vos::service::ServiceDispatchError) -> bool {
    matches!(
        error,
        vos::service::ServiceDispatchError::Pvm(
            vos::service::ServicePvmError::AccumulateHostRejected(_)
                | vos::service::ServicePvmError::KernelResourceUnavailable
                | vos::service::ServicePvmError::AccumulateCommitRejected
        )
    )
}

fn retryable_replicated_open_error<E>(error: &vos::service::ReplicatedServiceError<E>) -> bool {
    matches!(
        error,
        vos::service::ReplicatedServiceError::Dispatch(error)
            if retryable_production_dispatch(error)
    ) || matches!(
        error,
        vos::service::ReplicatedServiceError::ProofUnavailable
            | vos::service::ReplicatedServiceError::ReceiptUnavailable
    )
}

fn retryable_production_open_error<E>(error: &vos::service::LocalRootTreeOpenError<E>) -> bool {
    match error {
        vos::service::LocalRootTreeOpenError::Service(error) => {
            retryable_production_dispatch(error)
        }
        vos::service::LocalRootTreeOpenError::Replication(error) => {
            retryable_replicated_open_error(error)
        }
        // Production history validation deliberately folds verifier denial
        // and unavailability into this fail-closed error. Retrying is safe and
        // lets a recovered authority complete the validation; a truly absent
        // artifact remains damped without being mistaken for bad config.
        vos::service::LocalRootTreeOpenError::ProofHistoryUnavailable => true,
        _ => false,
    }
}

fn retryable_production_invoke_error(error: &vos::service::LocalRootTreeInvokeError) -> bool {
    match error {
        vos::service::LocalRootTreeInvokeError::Service(error) => {
            retryable_production_dispatch(error)
        }
        vos::service::LocalRootTreeInvokeError::Replication(error) => {
            retryable_replicated_open_error(error)
        }
        vos::service::LocalRootTreeInvokeError::ProofUnavailable => true,
        _ => false,
    }
}

fn retryable_service_node_registration_error(error: &vos::node::NodeRegistrationError) -> bool {
    matches!(
        error,
        vos::node::NodeRegistrationError::LogicalTimeslotUnavailable
            | vos::node::NodeRegistrationError::LogicalTimeslotRegressed
    )
}

fn retryable_production_raft_registration_error(
    error: &vos::node::RaftNodeRegistrationError<std::io::Error>,
) -> bool {
    match error {
        vos::node::RaftNodeRegistrationError::Open(error) => retryable_production_open_error(error),
        vos::node::RaftNodeRegistrationError::CatchUp(error) => {
            retryable_production_invoke_error(error)
        }
        vos::node::RaftNodeRegistrationError::Registration(error) => {
            retryable_service_node_registration_error(error)
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn register_service_root_from_row(
    node: &mut VosNode,
    data_dir: &Path,
    instance_name: String,
    replication_id: [u8; 32],
    config: vos::service::LocalRootTreeConfig,
    state_path: PathBuf,
    raft_seed: Option<RaftSeed>,
    local_prefix: u16,
    svc_id: ServiceId,
    network_reachable: bool,
    production_trust: Option<std::sync::Arc<dyn vos::service::ProductionTrust>>,
) -> anyhow::Result<ServiceId> {
    let production = production_trust.is_some();
    let backend = vos::service::FileCommittedImageStore::new(state_path);
    if config.consistency == vos::service::ConsistencyMode::Raft {
        let seed = raft_seed.ok_or_else(|| {
            anyhow::anyhow!("service Raft root tree '{instance_name}' has no resolved voter set")
        })?;
        let raft_path = service_raft_db_path(data_dir, config.service.root_service);
        if let Some(parent) = raft_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = std::sync::Arc::new(
            redb::Database::create(&raft_path)
                .map_err(|error| anyhow::anyhow!("open {}: {error}", raft_path.display()))?,
        );
        let make_config = |members, voter_peer_ids| vos::raft::RaftConfig {
            me: local_prefix,
            members,
            voter_peer_ids,
            replication_id,
            ..vos::raft::RaftConfig::default()
        };
        return match seed {
            RaftSeed::Members {
                members,
                voter_peer_ids,
            } => match production_trust {
                Some(trust) => node
                    .register_service_raft_root_at_id_production(
                        instance_name,
                        config,
                        backend,
                        db,
                        make_config(members, voter_peer_ids),
                        svc_id,
                        network_reachable,
                        trust,
                    )
                    .map_err(|error| {
                        let retryable = retryable_production_raft_registration_error(&error);
                        service_registration_error(
                            format!("register production service Raft root tree: {error}"),
                            retryable,
                        )
                    }),
                None => node
                    .register_service_raft_root_at_id(
                        instance_name,
                        config,
                        backend,
                        db,
                        make_config(members, voter_peer_ids),
                        svc_id,
                        network_reachable,
                    )
                    .map_err(|error| anyhow::anyhow!("register service Raft root tree: {error}")),
            },
            RaftSeed::Join {
                leader,
                known,
                voter_peer_ids,
            } => {
                let network = node.network().ok_or_else(|| {
                    anyhow::anyhow!("service Raft join requires an attached network")
                })?;
                let promotion_name = instance_name.clone();
                let promotion_voter_peer_ids = voter_peer_ids.clone();
                let raft_config = make_config(known.clone(), voter_peer_ids);
                match production_trust {
                    Some(trust) => node
                        .register_service_raft_root_at_id_after_local_attach_production(
                            instance_name,
                            config,
                            backend,
                            db,
                            raft_config,
                            svc_id,
                            network_reachable,
                            trust,
                            move |worker, shutdown, policy| {
                                promote_prepared_service_raft_root(
                                    &network,
                                    &promotion_name,
                                    replication_id,
                                    local_prefix,
                                    leader,
                                    known,
                                    promotion_voter_peer_ids,
                                    worker,
                                    shutdown,
                                    Some(policy),
                                )
                            },
                        )
                        .map_err(|error| {
                            let retryable = retryable_production_raft_registration_error(&error);
                            service_registration_error(
                                format!("register production service Raft root tree: {error}"),
                                retryable,
                            )
                        }),
                    None => node
                        .register_service_raft_root_at_id_after_local_attach(
                            instance_name,
                            config,
                            backend,
                            db,
                            raft_config,
                            svc_id,
                            network_reachable,
                            move |worker, shutdown| {
                                promote_prepared_service_raft_root(
                                    &network,
                                    &promotion_name,
                                    replication_id,
                                    local_prefix,
                                    leader,
                                    known,
                                    promotion_voter_peer_ids,
                                    worker,
                                    shutdown,
                                    None,
                                )
                            },
                        )
                        .map_err(|error| {
                            anyhow::anyhow!("register service Raft root tree: {error}")
                        }),
                }
            }
            RaftSeed::Defer(reason) => Err(anyhow::anyhow!(
                "service Raft root tree '{instance_name}' remains deferred: {reason}"
            )),
        };
    }

    let service = match production_trust {
        Some(trust) => {
            match vos::service::LocalRootTreeService::open_production(config, backend, trust) {
                Ok(service) => service,
                Err(error) => {
                    let retryable = retryable_production_open_error(&error);
                    return Err(service_registration_error(
                        format!("open production service root tree '{instance_name}': {error:?}"),
                        retryable,
                    ));
                }
            }
        }
        None => vos::service::LocalRootTreeService::open(config, backend).map_err(|error| {
            anyhow::anyhow!("open service root tree '{instance_name}': {error:?}")
        })?,
    };
    node.register_service_root_at_id(instance_name, service, svc_id, network_reachable)
        .map_err(|error| {
            service_registration_error(
                format!("register service root tree: {error}"),
                production && retryable_service_node_registration_error(&error),
            )
        })
}

fn service_raft_db_path(data_dir: &Path, root_service: vos::service::RootServiceId) -> PathBuf {
    data_dir
        .join("services")
        .join(format!("{}.raft.redb", hex::encode(root_service.0)))
}

fn raft_db_path_for_row(data_dir: &Path, prepared: &RowConfig) -> Option<PathBuf> {
    match prepared {
        RowConfig::Service { config, .. } => {
            Some(service_raft_db_path(data_dir, config.service.root_service))
        }
        _ => None,
    }
}

/// Per-voter wait for a `RaftStatusReq` answer. Probes run on the router
/// thread (routing paused) against exact registry-authenticated PeerIds, so
/// the worst case per pass is a handful of sub-second waits.
const RAFT_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

/// Wait for a `RaftJoinReq` answer — the leader appends a joint
/// ConfigChange before replying, so give it a little longer than a
/// status probe.
const RAFT_JOIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Consecutive passes a contested bootstrap decision must hold
/// before acting on it. "Every other voter is connected and
/// confirmed absent" can be transiently true while a peer is still
/// spawning its own replica (boot ordering, spawn-batch cap); the
/// grace keeps a momentary view from re-genesis-ing a group that is
/// about to answer.
const RAFT_BOOTSTRAP_GRACE_PASSES: u32 = 2;

/// Cap on status probes per row per pass, bounding router-thread
/// stall when a space has many voters.
const MAX_RAFT_PROBES: usize = 5;

/// Decision for spawning one raft-consistency row, produced by
/// [`decide_raft_spawn`] from the registry voter set + the peers'
/// answers. The IO around it (probes, the join handshake, config
/// seeding, grace counting) lives in [`raft_members_for_row`].
#[derive(Debug, PartialEq, Eq)]
enum RaftPlan {
    /// Spawn now with this member seed (anchored restart, or a
    /// rejoin the group still counts us in).
    Spawn(Vec<u16>),
    /// A live group exists and `leader` can admit us; join first,
    /// then spawn. `known` is the freshest member view we probed —
    /// the post-join fallback seed if the leader can't be
    /// re-probed (never spawn a joiner with just `[local]`: a
    /// one-element seed self-elects and forks the group).
    Join { leader: u16, known: Vec<u16> },
    /// Brand-new group this node should create. `contested` means
    /// other voters exist (all confirmed absent) — apply the
    /// bootstrap grace before acting; uncontested (sole voter) is
    /// immediate.
    Bootstrap { contested: bool },
    /// Not spawnable this pass; retried cheaply on later passes.
    Defer(String),
}

/// Pure decision table for one raft row. `voters` is the sorted,
/// deduped `NODE_ROLE_VOTER` prefix set from the registry;
/// `anchored` means the agent's local db already records a member
/// configuration (so the persisted config — not our seed — governs
/// on spawn); `probes` holds the status answers from every OTHER
/// connected voter, present or absent; `other_voters` is how many
/// other voters exist in total (probes < other_voters means some
/// voter was unreachable, which blocks the contested bootstrap).
fn decide_raft_spawn(
    local: u16,
    voters: &[u16],
    anchored: bool,
    probes: &[(u16, vos::network::RaftStatusReply)],
    other_voters: usize,
) -> RaftPlan {
    use vos::network::RaftRole;

    if anchored {
        // The persisted active config supersedes the seed; the
        // registry voter set is only a bootstrap hint. In particular, a
        // retiring observer must reopen its private endpoint until the group
        // durably confirms that it learned finality.
        return RaftPlan::Spawn(voters.to_vec());
    }
    if !voters.contains(&local) {
        return RaftPlan::Defer(
            "this node is not a voter (enroll it with `vosx space members add-node`)".into(),
        );
    }
    if voters == [local] {
        return RaftPlan::Bootstrap { contested: false };
    }

    // A live group somewhere wins over any bootstrap theory.
    let live: Vec<&(u16, vos::network::RaftStatusReply)> =
        probes.iter().filter(|(_, r)| r.present).collect();
    for (_, reply) in &live {
        if reply.is_active_voter(local) {
            // The group already counts us as a member (a wiped db
            // rejoining): spawn and let the leader catch us up.
            return RaftPlan::Spawn(reply.active_voters());
        }
    }
    if let Some((v, reply)) = live.iter().find(|(_, r)| r.role == RaftRole::Leader) {
        return RaftPlan::Join {
            leader: *v,
            known: reply.active_voters(),
        };
    }
    if let Some((_, reply)) = live.iter().find(|(_, r)| r.leader_hint.is_some()) {
        return RaftPlan::Join {
            leader: reply.leader_hint.expect("filtered on is_some"),
            known: reply.active_voters(),
        };
    }
    if !live.is_empty() {
        return RaftPlan::Defer("group has no leader yet (election in progress)".into());
    }

    // No live group anywhere we could see. Only the smallest voter
    // may create one, and only with positive confirmation from
    // every other voter — an "absent" from a status probe also
    // covers "host up but replica not spawned yet", hence the
    // caller-side grace. A wiped smallest-voter racing that window
    // can still re-genesis a group it can't see; the durable fix is
    // a bootstrap anchor in the registry row (with signed registry
    // ops), not reachable from this layer.
    let smallest = *voters.iter().min().expect("voters contains local");
    if smallest != local {
        return RaftPlan::Defer(format!(
            "waiting for voter {smallest:#06x} to bootstrap the group",
        ));
    }
    if probes.len() < other_voters {
        return RaftPlan::Defer(format!(
            "cannot locate the group — {} of {other_voters} other voter(s) unreachable",
            other_voters - probes.len(),
        ));
    }
    RaftPlan::Bootstrap { contested: true }
}

/// Outcome of [`raft_members_for_row`]: either the member seed to
/// spawn with, or the reason the row stays deferred this pass.
enum RaftSeed {
    Members {
        members: Vec<u16>,
        voter_peer_ids: Vec<(u16, Vec<u8>)>,
    },
    /// A live group exists, but this replica is not a voter yet. The service path
    /// starts its worker and validates its route before sending the join;
    /// conformance roots complete the eager handshake immediately before spawn.
    Join {
        leader: u16,
        known: Vec<u16>,
        voter_peer_ids: Vec<(u16, Vec<u8>)>,
    },
    Defer(String),
}

/// Grace counters for contested bootstraps, keyed like the damping
/// set. Entries are removed when the row spawns or the decision
/// changes away from bootstrap.
type BootGrace = std::collections::HashMap<(String, [u8; 32]), u32>;

/// Resolve one compact voter slot through the canonical registry roster.
/// Onboarding must never consult the global Hello prefix map: collisions are
/// expected in 16 bits and its first owner is not an identity assertion.
fn canonical_raft_voter_peer(
    voter_peer_ids: &[(u16, Vec<u8>)],
    prefix: u16,
) -> Option<libp2p::PeerId> {
    let bytes = voter_peer_ids
        .iter()
        .find_map(|(candidate, bytes)| (*candidate == prefix).then_some(bytes))?;
    let peer = libp2p::PeerId::from_bytes(bytes).ok()?;
    (vos::network::derive_node_prefix(&peer) == prefix).then_some(peer)
}

fn committed_final_membership_contains(
    snapshot: &vos::raft::worker::WorkerSnapshot,
    local_prefix: u16,
) -> bool {
    snapshot.joint_old.is_none()
        && snapshot.members.contains(&local_prefix)
        && snapshot
            .active_config_index
            .is_some_and(|index| index <= snapshot.commit_index)
}

fn select_authenticated_raft_leader(
    observations: Vec<(u16, vos::network::RaftStatusReply)>,
    voter_peer_ids: &[(u16, Vec<u8>)],
) -> Option<u16> {
    observations
        .into_iter()
        .filter_map(|(reporter, status)| {
            if !status.present || !status.is_active_voter(reporter) {
                return None;
            }
            let leader = if status.role == vos::network::RaftRole::Leader
                && status.leader_hint == Some(reporter)
            {
                reporter
            } else {
                status.leader_hint?
            };
            if !status.is_active_voter(leader)
                || canonical_raft_voter_peer(voter_peer_ids, leader).is_none()
            {
                return None;
            }
            let direct = leader == reporter && status.role == vos::network::RaftRole::Leader;
            Some((
                (
                    status.current_term,
                    direct,
                    status.commit_index,
                    status.last_log_index,
                ),
                leader,
            ))
        })
        .max_by_key(|(rank, _)| *rank)
        .map(|(_, leader)| leader)
}

/// Probe a rotating bounded window of canonical voters after an ambiguous
/// join. A dead original leader cannot pin the prepared replica forever, and
/// ambient prefix owners are never candidates.
fn rediscover_raft_leader(
    net: &std::sync::Arc<vos::network::Network>,
    replication_id: [u8; 32],
    local_prefix: u16,
    voter_peer_ids: &[(u16, Vec<u8>)],
    cursor: &mut usize,
) -> Option<u16> {
    let candidates = voter_peer_ids
        .iter()
        .filter_map(|(prefix, _)| {
            if *prefix == local_prefix {
                return None;
            }
            canonical_raft_voter_peer(voter_peer_ids, *prefix).map(|peer| (*prefix, peer))
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return None;
    }
    let start = *cursor % candidates.len();
    let count = candidates.len().min(MAX_RAFT_PROBES);
    let mut observations = Vec::with_capacity(count);
    for offset in 0..count {
        let (prefix, peer) = candidates[(start + offset) % candidates.len()];
        if let Ok(status) = net
            .send_raft_status_req(peer, replication_id)
            .recv_timeout(RAFT_PROBE_TIMEOUT)
        {
            observations.push((prefix, status));
        }
    }
    *cursor = (start + count) % candidates.len();
    select_authenticated_raft_leader(observations, voter_peer_ids)
}

/// Run the membership protocol for one raft row: read the voter
/// set, probe connected voters for the group, join a live group
/// through its leader, or anchor + bootstrap a brand-new one.
/// Called before the row's (expensive) transpile so a defer costs
/// little, and so the join handshake only ever fires when the
/// spawn follows it.
fn raft_members_for_row(
    node: &VosNode,
    db_path: &std::path::Path,
    a: &vos::registry::AgentRow,
    local_prefix: u16,
    boot_grace: &mut BootGrace,
) -> anyhow::Result<RaftSeed> {
    use vos::registry::{MEMBER_KIND_NODE, NODE_ROLE_OBSERVER, NODE_ROLE_VOTER, RegistryRef};

    let reg = RegistryRef::at(ServiceId::REGISTRY);
    let rows = vos::block_on(reg.members_all(&mut &*node))
        .map_err(|e| anyhow::anyhow!("query members: {e}"))?;
    let mut voters: Vec<u16> = rows
        .iter()
        .filter(|m| m.kind == MEMBER_KIND_NODE && m.role == NODE_ROLE_VOTER)
        .map(|m| m.prefix)
        .collect();
    voters.sort_unstable();
    voters.dedup();
    let mut voter_peer_ids = rows
        .iter()
        .filter(|member| {
            member.kind == MEMBER_KIND_NODE
                && matches!(member.role, NODE_ROLE_VOTER | NODE_ROLE_OBSERVER)
        })
        .map(|member| (member.prefix, member.key.clone()))
        .collect::<Vec<_>>();
    voter_peer_ids.sort_by_key(|(prefix, _)| *prefix);
    if voter_peer_ids
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1)
    {
        anyhow::bail!("registry contains conflicting full PeerIds for one Raft voter prefix");
    }
    voter_peer_ids.dedup();
    for (prefix, bytes) in &voter_peer_ids {
        let peer = libp2p::PeerId::from_bytes(bytes)
            .map_err(|_| anyhow::anyhow!("voter {prefix:#06x} has an invalid PeerId"))?;
        if vos::network::derive_node_prefix(&peer) != *prefix {
            anyhow::bail!("voter {prefix:#06x} does not match its full authenticated PeerId");
        }
    }

    let anchored = db_path.exists()
        && vos::raft::persisted_membership(db_path)
            .unwrap_or_default()
            .is_some();

    let net = node.network();
    let other_voters = voters.iter().filter(|&&v| v != local_prefix).count();
    let mut probes: Vec<(u16, vos::network::RaftStatusReply)> = Vec::new();
    if let Some(net) = net.as_ref() {
        for &v in voters
            .iter()
            .filter(|&&v| v != local_prefix)
            .take(MAX_RAFT_PROBES)
        {
            let Some(peer) = canonical_raft_voter_peer(&voter_peer_ids, v) else {
                continue;
            };
            if let Ok(reply) = net
                .send_raft_status_req(peer, a.replication_id)
                .recv_timeout(RAFT_PROBE_TIMEOUT)
            {
                probes.push((v, reply));
            }
        }
    }

    let grace_key = (a.instance_name.clone(), a.program_hash);
    let plan = decide_raft_spawn(local_prefix, &voters, anchored, &probes, other_voters);
    if !matches!(plan, RaftPlan::Bootstrap { contested: true }) {
        boot_grace.remove(&grace_key);
    }
    match plan {
        RaftPlan::Spawn(members) => Ok(RaftSeed::Members {
            members,
            voter_peer_ids,
        }),
        RaftPlan::Defer(reason) => Ok(RaftSeed::Defer(reason)),
        RaftPlan::Bootstrap { contested } => {
            if contested {
                let passes = boot_grace.entry(grace_key.clone()).or_insert(0);
                *passes += 1;
                if *passes < RAFT_BOOTSTRAP_GRACE_PASSES {
                    return Ok(RaftSeed::Defer(format!(
                        "group absent on every other voter — confirming for {} more pass(es) \
                         before bootstrapping",
                        RAFT_BOOTSTRAP_GRACE_PASSES - *passes,
                    )));
                }
                boot_grace.remove(&grace_key);
            }
            // Anchor the configuration BEFORE the first spawn: a
            // solo group that never changes membership writes no
            // ConfigChange entry, and without the seeded row a
            // restart would re-derive its member set from whatever
            // the registry says by then — which may have grown,
            // leaving the group unable to elect (and the pending
            // joiner with no leader to join).
            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            vos::raft::seed_initial_config(db_path, &[local_prefix])
                .map_err(|e| anyhow::anyhow!("seed raft config for '{}': {e}", a.instance_name))?;
            Ok(RaftSeed::Members {
                members: vec![local_prefix],
                voter_peer_ids,
            })
        }
        RaftPlan::Join { leader, known } => Ok(RaftSeed::Join {
            leader,
            known,
            voter_peer_ids,
        }),
    }
}

/// Ask the group's leader to admit this node as a voter, following
/// at most one leadership redirect. On `Accepted`, re-probe the
/// leader for the freshest member set (a joiner admitted between
/// our probe and our join must be in our seed, or we'd reject its
/// votes until the log catches up) and fall back to the probed
/// `known` view when the re-probe fails.
struct AcceptedRaftJoin;

struct RejectedRaftJoin {
    reason: String,
    /// The request was sent but no response arrived. The remote leader may
    /// already have appended the joint entry, so no later refusal from another
    /// peer makes local teardown safe.
    membership_may_have_changed: bool,
}

fn request_raft_join(
    net: &std::sync::Arc<vos::network::Network>,
    instance_name: &str,
    replication_id: [u8; 32],
    local_prefix: u16,
    mut leader: u16,
    known: Vec<u16>,
    voter_peer_ids: &[(u16, Vec<u8>)],
    production_trust_policy: Option<vos::service::Hash>,
) -> anyhow::Result<Result<AcceptedRaftJoin, RejectedRaftJoin>> {
    use vos::network::RaftJoinResult;

    for _redirect in 0..2 {
        let Some(peer) = canonical_raft_voter_peer(voter_peer_ids, leader) else {
            return Ok(Err(RejectedRaftJoin {
                reason: format!("raft leader {leader:#06x} has no canonical enrolled PeerId"),
                membership_may_have_changed: false,
            }));
        };
        let rx = net.send_raft_join_req_with_policy(
            peer,
            replication_id,
            local_prefix,
            production_trust_policy.map(|policy| policy.0),
        );
        match rx.recv_timeout(RAFT_JOIN_TIMEOUT) {
            Ok(RaftJoinResult::Accepted { joint_index: _ }) => {
                let mut members = match net
                    .send_raft_status_req(peer, replication_id)
                    .recv_timeout(RAFT_PROBE_TIMEOUT)
                {
                    Ok(st) if st.present && !st.active_voters().is_empty() => st.active_voters(),
                    _ => known,
                };
                members.push(local_prefix);
                members.sort_unstable();
                members.dedup();
                tracing::info!(
                    "agent '{}': joined raft group as voter (leader {leader:#06x}, {} member(s))",
                    instance_name,
                    members.len(),
                );
                return Ok(Ok(AcceptedRaftJoin));
            }
            Ok(RaftJoinResult::NotLeader {
                leader_hint: Some(h),
            }) if h != leader => {
                leader = h; // follow one redirect
            }
            Ok(RaftJoinResult::NotLeader { .. }) => {
                return Ok(Err(RejectedRaftJoin {
                    reason: "leadership moved during the join handshake".into(),
                    membership_may_have_changed: false,
                }));
            }
            Ok(RaftJoinResult::Busy) => {
                return Ok(Err(RejectedRaftJoin {
                    reason: "another membership change is in flight".into(),
                    membership_may_have_changed: false,
                }));
            }
            Ok(RaftJoinResult::UnknownGroup) => {
                return Ok(Err(RejectedRaftJoin {
                    reason: format!("peer {leader:#06x} no longer runs the group"),
                    membership_may_have_changed: false,
                }));
            }
            Ok(RaftJoinResult::NotAuthorized) => {
                // Permanent refusal — this node isn't an enrolled voter.
                // Don't retry; an admin must enrol it first.
                return Ok(Err(RejectedRaftJoin {
                    reason: format!(
                        "this node ({local_prefix:#06x}) is not enrolled as a voter for \
                         agent '{instance_name}'; an admin must run `vosx space members add <peer> \
                         --role voter`",
                    ),
                    membership_may_have_changed: false,
                }));
            }
            Ok(RaftJoinResult::PolicyMismatch) => {
                return Ok(Err(RejectedRaftJoin {
                    reason: format!(
                        "agent '{instance_name}' uses a different production trust policy than its Raft group",
                    ),
                    membership_may_have_changed: false,
                }));
            }
            Err(_) => {
                return Ok(Err(RejectedRaftJoin {
                    reason: "join request timed out".into(),
                    membership_may_have_changed: true,
                }));
            }
        }
    }
    Ok(Err(RejectedRaftJoin {
        reason: "leader redirects did not converge".into(),
        membership_may_have_changed: false,
    }))
}

fn promote_prepared_service_raft_root(
    net: &std::sync::Arc<vos::network::Network>,
    instance_name: &str,
    replication_id: [u8; 32],
    local_prefix: u16,
    mut leader: u16,
    known: Vec<u16>,
    voter_peer_ids: Vec<(u16, Vec<u8>)>,
    worker: &vos::raft::WorkerHandle,
    shutdown: &std::sync::atomic::AtomicBool,
    production_trust_policy: Option<vos::service::Hash>,
) -> Result<(), String> {
    let mut membership_may_have_changed = false;
    let mut discovery_cursor = 0;
    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("node shut down while Raft voter promotion was pending".into());
        }
        if membership_may_have_changed {
            if let Some(snapshot) = worker.snapshot() {
                if committed_final_membership_contains(&snapshot, local_prefix) {
                    return Ok(());
                }
                if let Some(hint) = snapshot.leader_hint
                    && canonical_raft_voter_peer(&voter_peer_ids, hint).is_some()
                {
                    leader = hint;
                }
            }
            if let Some(discovered) = rediscover_raft_leader(
                net,
                replication_id,
                local_prefix,
                &voter_peer_ids,
                &mut discovery_cursor,
            ) {
                leader = discovered;
            }
        }
        match request_raft_join(
            net,
            instance_name,
            replication_id,
            local_prefix,
            leader,
            known.clone(),
            &voter_peer_ids,
            production_trust_policy,
        )
        .map_err(|error| error.to_string())?
        {
            Ok(_accepted) => {
                // Accepted means the leader appended the joint entry; it does
                // not mean that entry reached either quorum. Treat the result
                // as ambiguous until this worker observes a committed final
                // configuration. If the accepting leader dies first, the
                // next iteration rediscovers a surviving canonical voter and
                // repeats the idempotent join against its replacement.
                membership_may_have_changed = true;
                wait_for_raft_promotion_retry(shutdown, RAFT_PROBE_TIMEOUT)?;
            }
            Err(rejection)
                if !membership_may_have_changed && !rejection.membership_may_have_changed =>
            {
                // No join request reached an authoritative peer, so no
                // membership change can depend on this prepared replica.
                // Return it to reconciliation instead of blocking the router.
                return Err(rejection.reason);
            }
            Err(rejection) => {
                membership_may_have_changed |= rejection.membership_may_have_changed;
                tracing::warn!(
                    "agent '{instance_name}': prepared Raft join is still pending: {}",
                    rejection.reason,
                );
                // Once a join request has left this process, a timeout is
                // ambiguous: the leader may already require this voter in its
                // joint quorum. Keep the unexposed worker alive and retry
                // instead of tearing it down and potentially wedging the old
                // group. Repeating the request is idempotent because an
                // already-member join returns Accepted { joint_index: 0 }.
                wait_for_raft_promotion_retry(shutdown, RAFT_PROBE_TIMEOUT)?;
            }
        }
    }
}

fn wait_for_raft_promotion_retry(
    shutdown: &std::sync::atomic::AtomicBool,
    duration: std::time::Duration,
) -> Result<(), String> {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("node shut down while Raft voter promotion was pending".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Ok(())
}

/// Cap on agents brought up in a single reconcile pass. The pass
/// runs on the router thread (routing paused), and each spawn
/// costs an ELF transpile + redb open + thread spawn — bounding
/// the batch keeps a burst of synced rows from freezing routing,
/// and rate-limits how fast a (possibly hostile) flood of
/// registry rows can amplify into local threads. Remaining rows
/// spawn on subsequent passes.
const MAX_SPAWNS_PER_PASS: usize = 4;
/// Registration opens durable stores and may synchronously consult the
/// production authority. Keep that blocking boundary to one root per router
/// pass; ordinary service starts retain their separate cap above.
const MAX_REGISTRATION_ATTEMPTS_PER_PASS: usize = 1;
const SERVICE_REGISTRATION_GLOBAL_RETRY_GAP: std::time::Duration =
    std::time::Duration::from_secs(2);
const SERVICE_REGISTRATION_RETRY_BASE: std::time::Duration = std::time::Duration::from_secs(10);
const SERVICE_REGISTRATION_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(300);

/// A row condition already reported (and, for hard failures,
/// permanently skipped): the damping key is `(instance_name,
/// program_hash, kind)`, so reinstalling the same name with a new
/// blob re-attempts and re-reports.
type RowDamping = std::collections::HashSet<(String, [u8; 32], RowNote)>;
type RegistrationKey = (String, [u8; 32]);

#[derive(Debug, Clone, Copy)]
struct RegistrationRetry {
    failures: u8,
    not_before: std::time::Instant,
}

#[derive(Debug, Default)]
struct RegistrationBackoff {
    rows: std::collections::HashMap<RegistrationKey, RegistrationRetry>,
    global_not_before: Option<std::time::Instant>,
}

impl RegistrationBackoff {
    fn ready(&self, key: &RegistrationKey, now: std::time::Instant) -> bool {
        self.global_not_before
            .is_none_or(|deadline| now >= deadline)
            && self
                .rows
                .get(key)
                .is_none_or(|retry| now >= retry.not_before)
    }

    fn finish(&mut self, key: RegistrationKey, retryable: bool, now: std::time::Instant) {
        self.global_not_before = now.checked_add(SERVICE_REGISTRATION_GLOBAL_RETRY_GAP);
        if !retryable {
            self.rows.remove(&key);
            return;
        }
        let failures = self
            .rows
            .get(&key)
            .map_or(1, |retry| retry.failures.saturating_add(1));
        let multiplier = 1_u64 << u32::from(failures.saturating_sub(1).min(5));
        let delay = SERVICE_REGISTRATION_RETRY_BASE
            .checked_mul(u32::try_from(multiplier).expect("bounded retry multiplier"))
            .unwrap_or(SERVICE_REGISTRATION_RETRY_MAX)
            .min(SERVICE_REGISTRATION_RETRY_MAX);
        self.rows.insert(
            key,
            RegistrationRetry {
                failures,
                not_before: now.checked_add(delay).unwrap_or(now),
            },
        );
    }

    fn success(&mut self, key: &RegistrationKey, now: std::time::Instant) {
        self.global_not_before = now.checked_add(SERVICE_REGISTRATION_GLOBAL_RETRY_GAP);
        self.rows.remove(key);
    }
}

fn take_service_registration_attempt(
    attempts: &mut usize,
    backoff: &RegistrationBackoff,
    key: &RegistrationKey,
    now: std::time::Instant,
) -> bool {
    if *attempts >= MAX_REGISTRATION_ATTEMPTS_PER_PASS || !backoff.ready(key, now) {
        return false;
    }
    *attempts += 1;
    true
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
enum RowNote {
    /// Hard per-row failure (transpile error, cache IO, bad
    /// consistency, ServiceId collision). Warned once, then the
    /// row is skipped outright — no point re-running the failing
    /// work every pass.
    Failed,
    /// A fail-closed production authority or another retryable host boundary
    /// was unavailable while opening the root. Warned once, but unlike a
    /// malformed package/configuration the row is retried on every pass.
    RegistrationWaiting,
    /// Program blob not cached yet. Warned once; the (cheap)
    /// cache probe keeps retrying, so the row spawns if the blob
    /// appears later.
    AwaitingBlob,
    /// Raft row whose membership protocol deferred the spawn
    /// (not a voter yet, group not located, join in progress…).
    /// Warned once with the current reason; later passes log the
    /// (possibly different) reason at debug. Cleared on spawn so
    /// a later wedge re-warns.
    RaftWaiting,
    /// Row whose `sync_role` floor is above this node's space role,
    /// so the node can't sync it and doesn't spawn it. Logged once;
    /// re-evaluated each pass, so it spawns if a grant later lands.
    BelowFloor,
}

fn service_registration_note(error: &anyhow::Error) -> RowNote {
    if is_retryable_service_registration_error(error) {
        RowNote::RegistrationWaiting
    } else {
        RowNote::Failed
    }
}

/// Does this node clear a row's sync floor? `is_member` is [`node_is_member`]'s
/// verdict for the whole pass. A `Public` row always spawns; a `Member`/
/// `Private` row spawns only for a member. Narrowing only — the sync gate is
/// the real access boundary; this just keeps a node from spawning replicas it
/// can't sync.
fn node_meets_floor(is_member: bool, floor: vos::registry::SyncFloor) -> bool {
    floor == vos::registry::SyncFloor::Public || is_member
}

/// Is this node a member of the space — may it sync `Member`/`Private` floors?
/// Mirrors `sync_serve_allowed`'s disjunction across every identity that can
/// carry membership, in order: the DAEMON node key (where `space up <token>`
/// redemption lands the grant — the primary post-redeem path); then the
/// operator that ran `space up` (where a role lives pre-redeem, or on an
/// operator-driven space that never redeemed); then node enrollment (a
/// voter/observer is a member even before a grant lands).
///
/// Probed once per pass. Errs toward membership: a missing identity, an
/// unreachable registry, or any probe error returns `true`, so a transient
/// condition never narrows a legitimate member out of its replicas — only a
/// node confidently non-member by EVERY signal is narrowed.
fn node_is_member(node: &VosNode, reg: &vos::registry::RegistryRef, local_prefix: u16) -> bool {
    use vos::registry::AUTH_ROLE_READONLY;
    // (1) The node key `redeem_invite` grants. This is what a token joiner
    // gets — the operator (2) is never granted on the redeem path.
    if let Some(net) = node.network() {
        let node_peer = net.peer_id().to_bytes();
        match vos::block_on(reg.peer_role(&mut &*node, node_peer)) {
            Ok(r) if r >= AUTH_ROLE_READONLY => return true, // node granted → member
            Ok(_) => {}                                      // reachable, not granted
            Err(_) => return true,                           // registry down → fail open
        }
    }
    // (2) The operator that ran `space up`.
    if let Some(operator) = node.operator_peer().map(<[u8]>::to_vec) {
        match vos::block_on(reg.peer_role(&mut &*node, operator)) {
            Ok(r) if r >= AUTH_ROLE_READONLY => return true, // granted → member
            Ok(_) => {}                                      // reachable, not granted
            Err(_) => return true,                           // registry down → fail open
        }
    }
    // (3) An enrolled node (voter/observer) is a member too. `node_role` reads
    // 0 when not enrolled, `role + 1` otherwise.
    match vos::block_on(reg.node_role(&mut &*node, local_prefix as u64)) {
        Ok(role) => role > 0,
        Err(_) => true, // probe failed → fail open
    }
}

/// One runtime spawn-reconcile pass: query the registry for
/// installed agents and bring up any that aren't running yet —
/// the runtime twin of [`spawn_installed_agents`], called from
/// `run_forever_with`'s tick hook so agents installed (or
/// CRDT-synced from a peer) after boot become usable without a
/// restart.
///
/// Idempotent by construction: rows whose deterministic ServiceId
/// is already registered on the node are skipped, including
/// agents an operator stopped with `vosx <agent> stop` (their
/// slot stays taken — a restart revives them, not this pass).
/// At most [`MAX_SPAWNS_PER_PASS`] rows spawn per pass.
///
/// Trust model: registry rows replicate via CRDT sync with no
/// per-row author check — the Admin gate on `install` fires only
/// on the originating node. What bounds this pass is the local
/// blob cache (it never fetches code; only already-cached
/// programs can spawn), the subscriptions filter, and the
/// per-pass cap. Until registry ops are author-signed, any space
/// member can make peers spawn extra instances of programs those
/// peers already hold.
///
/// Uninstall is still restart-bound: this pass only spawns, it
/// never stops agents whose rows disappeared.
fn reconcile_installed_agents(
    node: &mut VosNode,
    data_dir: &std::path::Path,
    space_id: [u8; 32],
    local_prefix: u16,
    local_cfg: &crate::commands::space::subscriptions::LocalConfig,
    damped: &mut RowDamping,
    service_registration_backoff: &mut RegistrationBackoff,
    boot_grace: &mut BootGrace,
    in_flight: &InFlightBlobs,
    policies: &AgentPolicies,
    pinned_service_service: Option<&PinnedService>,
    production_trust: Option<std::sync::Arc<dyn vos::service::ProductionTrust>>,
) -> anyhow::Result<()> {
    use vos::registry::RegistryRef;

    let reg = RegistryRef::at(ServiceId::REGISTRY);
    let agents = vos::block_on(reg.agents_all(&mut &*node))
        .map_err(|e| anyhow::anyhow!("query agents: {e}"))?;
    let root_peer_id = vos::block_on(reg.root(&mut &*node))
        .map_err(|e| anyhow::anyhow!("query immutable space root: {e}"))?;

    // Whether this node is a space member, probed once for the whole pass; rows
    // whose sync floor requires membership are narrowed out below.
    let is_member = node_is_member(node, &reg, local_prefix);
    let mut spawned_this_pass = 0usize;
    let mut service_registration_attempts = 0usize;
    let mut spawn_rows = agents.iter().collect::<Vec<_>>();
    spawn_rows.sort_by_key(|row| {
        (row.instance_name != vos::service::ROLE_AUTHORITY_INSTANCE_)
            .then_some(row.instance_name.as_str())
    });
    for a in spawn_rows {
        if spawned_this_pass >= MAX_SPAWNS_PER_PASS {
            break;
        }
        let is_role_authority = a.instance_name == vos::service::ROLE_AUTHORITY_INSTANCE_;
        if !is_role_authority && !local_cfg.should_spawn(&a.instance_name) {
            continue;
        }
        let key = |note: RowNote| (a.instance_name.clone(), a.program_hash, note);
        if damped.contains(&key(RowNote::Failed)) {
            continue;
        }
        if !node_meets_floor(is_member, a.sync_role) {
            if damped.insert(key(RowNote::BelowFloor)) {
                tracing::info!(
                    "agent '{}' not spawned here — its '{}' sync floor is above \
                     this node's space role; it spawns if a grant lands",
                    a.instance_name,
                    a.sync_role.as_str(),
                );
            }
            continue;
        }
        let svc_id = instance_service_id(&a.instance_name, local_prefix);
        if node.has_agent(svc_id) {
            // Usually this row's own agent. A *different* occupying
            // name means a ~15-bit instance-name hash collision:
            // name-deterministic, so the row can never spawn on any
            // node — surface it instead of skipping silently.
            let occupant = node.agent_name_for(svc_id.0);
            if occupant
                .as_deref()
                .is_some_and(|o| !o.eq_ignore_ascii_case(&a.instance_name))
                && damped.insert(key(RowNote::Failed))
            {
                tracing::warn!(
                    "agent '{}' can never spawn — its ServiceId collides with installed \
                     agent '{}' (rename one of them)",
                    a.instance_name,
                    occupant.unwrap_or_default(),
                );
            }
            continue;
        }
        // Resolve the complete executable/configuration before any Raft
        // membership action. Unsupported signed packages cannot join a group
        // which this node will not actually host.
        let prepared = match agent_config_from_row(
            data_dir,
            space_id,
            a,
            &agents,
            policies,
            pinned_service_service,
            &root_peer_id,
        ) {
            Ok(prepared) => prepared,
            Err(e) => {
                if damped.insert(key(RowNote::Failed)) {
                    tracing::warn!(
                        "agent '{}' failed to prepare before Raft membership: {e}",
                        a.instance_name,
                    );
                }
                continue;
            }
        };
        let supports_raft = matches!(&prepared, RowConfig::Service { .. });
        let raft_seed = if supports_raft
            && consistency_from_u8(a.consistency) == Some(Consistency::Raft)
        {
            if !blob_store::cache_path_for(&BlobHash(a.program_hash)).exists() {
                spawn_program_blob_fetch(node, a.program_hash, in_flight);
                if damped.insert(key(RowNote::AwaitingBlob)) {
                    tracing::warn!(
                        "agent '{}' pending — program blob {} not in the local cache; \
                         fetching from peers, it spawns when the blob appears",
                        a.instance_name,
                        BlobHash(a.program_hash),
                    );
                }
                continue;
            }
            let Some(db_path) = raft_db_path_for_row(data_dir, &prepared) else {
                continue;
            };
            match raft_members_for_row(node, &db_path, a, local_prefix, boot_grace) {
                Ok(seed @ (RaftSeed::Members { .. } | RaftSeed::Join { .. })) => {
                    damped.remove(&key(RowNote::RaftWaiting));
                    Some(seed)
                }
                Ok(RaftSeed::Defer(reason)) => {
                    if damped.insert(key(RowNote::RaftWaiting)) {
                        tracing::warn!("agent '{}' (raft) deferred: {reason}", a.instance_name);
                    } else {
                        tracing::debug!("agent '{}' (raft) deferred: {reason}", a.instance_name);
                    }
                    continue;
                }
                Err(e) => {
                    if damped.insert(key(RowNote::RaftWaiting)) {
                        tracing::warn!("agent '{}' (raft) deferred: {e}", a.instance_name);
                    }
                    continue;
                }
            }
        } else {
            None
        };
        match prepared {
            RowConfig::Service {
                config,
                state_path,
                network_reachable,
            } => {
                let registration_key = (a.instance_name.clone(), a.program_hash);
                if !take_service_registration_attempt(
                    &mut service_registration_attempts,
                    service_registration_backoff,
                    &registration_key,
                    std::time::Instant::now(),
                ) {
                    continue;
                }
                match register_service_root_from_row(
                    node,
                    data_dir,
                    a.instance_name.clone(),
                    a.replication_id,
                    *config,
                    state_path,
                    raft_seed,
                    local_prefix,
                    svc_id,
                    network_reachable,
                    production_trust.clone(),
                ) {
                    Ok(id) => {
                        service_registration_backoff
                            .success(&registration_key, std::time::Instant::now());
                        damped.remove(&key(RowNote::RegistrationWaiting));
                        spawned_this_pass += 1;
                        tracing::info!("service root tree '{}' spawned as {id}", a.instance_name);
                    }
                    Err(error) => {
                        let retryable = is_retryable_service_registration_error(&error);
                        service_registration_backoff.finish(
                            registration_key,
                            retryable,
                            std::time::Instant::now(),
                        );
                        let note = service_registration_note(&error);
                        if damped.insert(key(note)) {
                            tracing::warn!(
                                "agent '{}' service route failed to register: {error}",
                                a.instance_name,
                            );
                        } else if retryable {
                            tracing::debug!(
                                "agent '{}' service route remains deferred: {error}",
                                a.instance_name,
                            );
                        }
                    }
                }
            }
            RowConfig::MissingBlob => {
                spawn_program_blob_fetch(node, a.program_hash, in_flight);
                if damped.insert(key(RowNote::AwaitingBlob)) {
                    tracing::warn!(
                        "agent '{}' pending — program blob {} not in the local cache; \
                         fetching from peers, it spawns when the blob appears",
                        a.instance_name,
                        BlobHash(a.program_hash),
                    );
                }
            }
            RowConfig::Deferred(reason) => {
                if damped.insert(key(RowNote::RaftWaiting)) {
                    tracing::info!("agent '{}' deferred: {reason}", a.instance_name);
                }
            }
            RowConfig::BadConsistency => {
                if damped.insert(key(RowNote::Failed)) {
                    tracing::warn!(
                        "skipping agent '{}' — unknown consistency {}",
                        a.instance_name,
                        a.consistency,
                    );
                }
            }
            RowConfig::UnsupportedPackage(reason) => {
                if damped.insert(key(RowNote::Failed)) {
                    tracing::warn!(
                        "skipping agent '{}' — unsupported service package: {reason}",
                        a.instance_name,
                    );
                }
            }
        }
    }
    Ok(())
}

/// Walk `<data_dir>/agents/`, trash any `<svc_id>.redb` whose
/// id isn't in `live`. Best-effort — failures log a warning
/// but don't abort the daemon boot. The registry's own redb
/// (svc_id 0) is always live, by virtue of being added to
/// `live` before this runs.
fn sweep_orphan_redbs(data_dir: &std::path::Path, live: &std::collections::HashSet<u32>) {
    let agents_dir = data_dir.join("agents");
    let entries = match std::fs::read_dir(&agents_dir) {
        Ok(rd) => rd,
        Err(_) => return,
    };
    let trash = data_dir.join("trash");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(stem) = name_str.strip_suffix(".redb") else {
            continue;
        };
        let Ok(svc_id) = u32::from_str_radix(stem, 16) else {
            continue;
        };
        if live.contains(&svc_id) {
            continue;
        }
        if std::fs::create_dir_all(&trash).is_err() {
            continue;
        }
        let dest = trash.join(name_str);
        match std::fs::rename(entry.path(), &dest) {
            Ok(()) => tracing::info!(
                "moved orphan redb to trash: svc_id={svc_id:#010x}, path={}",
                dest.display(),
            ),
            Err(e) => tracing::warn!(
                "failed to trash orphan redb {}: {e}",
                entry.path().display(),
            ),
        }
    }
}

/// Move service images and private side-store directories whose installation
/// incarnation no longer exists in the registry into recoverable trash.
///
/// A service installation is keyed by `(space, name, replication_id)`. The
/// registry forbids reusing a tombstoned replication id, so keeping an orphan
/// in the active directory can only resurrect deleted state or collide with a
/// later install. The image, Raft state, signer seed, incomplete seed staging,
/// and the `.image.proofs` / `.image.records` side directories use the
/// root-service hash prefix and are swept together on the next daemon boot.
fn sweep_orphan_service_services(
    data_dir: &std::path::Path,
    live: &std::collections::HashSet<[u8; 32]>,
) {
    let services_dir = data_dir.join("services");
    let entries = match std::fs::read_dir(&services_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };
    let trash = data_dir.join("trash").join("services");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        let Some(root_hex) = name_str.get(..64) else {
            continue;
        };
        let suffix = &name_str[64..];
        if !matches!(
            suffix,
            ".image"
                | ".image.proofs"
                | ".image.records"
                | ".image.next"
                | ".raft.redb"
                | ".device-seed"
                | ".device-seed.next"
        ) {
            continue;
        }
        let Ok(root_bytes) = hex::decode(root_hex) else {
            continue;
        };
        let Ok(root_service) = <[u8; 32]>::try_from(root_bytes.as_slice()) else {
            continue;
        };
        if live.contains(&root_service) {
            continue;
        }
        if std::fs::create_dir_all(&trash).is_err() {
            continue;
        }
        let destination = trash.join(name_str);
        match std::fs::rename(entry.path(), &destination) {
            Ok(()) => tracing::info!(
                "moved orphan service service artifact to trash: {}",
                destination.display(),
            ),
            Err(error) => tracing::warn!(
                "failed to trash orphan service service artifact {}: {error}",
                entry.path().display(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_device_seed_sidecar_is_stable_private_and_strictly_sized() {
        let directory = std::env::temp_dir().join(format!(
            "vosx-device-seed-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let root = vos::service::RootServiceId([0x91; 32]);
        let first = load_or_mint_service_device_seed(&directory, root).unwrap();
        let path = directory
            .join("services")
            .join(format!("{}.device-seed", hex::encode(root.0)));
        let stale_temp = secret_temp_path(&path).unwrap();
        std::fs::write(&stale_temp, [0x92; 7]).unwrap();
        assert_eq!(
            load_or_mint_service_device_seed(&directory, root).unwrap(),
            first
        );
        assert_eq!(std::fs::read(&path).unwrap(), first);
        assert!(
            !stale_temp.exists(),
            "durable reopen removes an incomplete staging artifact"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                load_or_mint_service_device_seed(&directory, root)
                    .unwrap_err()
                    .to_string()
                    .contains("mode 0600"),
                "an existing world-readable key must fail closed"
            );
            std::fs::remove_file(&path).unwrap();
            let target = directory.join("copied-device-seed");
            std::fs::write(&target, first).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::os::unix::fs::symlink(&target, &path).unwrap();
            assert!(
                load_or_mint_service_device_seed(&directory, root).is_err(),
                "a symlink must never be followed as signer configuration"
            );
            std::fs::remove_file(&path).unwrap();
            std::fs::create_dir(&path).unwrap();
            assert!(
                load_or_mint_service_device_seed(&directory, root).is_err(),
                "a non-regular seed path must fail without blocking"
            );
            std::fs::remove_dir(&path).unwrap();
        }
        std::fs::write(&path, [0u8; 31]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(load_or_mint_service_device_seed(&directory, root).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn service_service_requires_an_explicit_trust_profile() {
        assert!(validate_service_trust_mode(false, false, false).is_ok());
        assert!(validate_service_trust_mode(true, true, false).is_ok());
        assert!(validate_service_trust_mode(true, false, true).is_ok());

        let missing = validate_service_trust_mode(true, false, false).unwrap_err();
        assert!(missing.to_string().contains("--production-trust-socket"));
        assert!(validate_service_trust_mode(false, true, false).is_err());
        assert!(validate_service_trust_mode(false, false, true).is_err());
        assert!(validate_service_trust_mode(true, true, true).is_err());
    }
    use libp2p::identity::Keypair;
    use vos::metadata::{ActorMeta, MessageMeta};
    use vos::network::{RaftRole, RaftStatusReply};
    use vos::service::{
        ActorUpgrade, DeploymentSignature, Hash, PackageManifest, PackageRolePolicies, ProducerId,
        ProductionTrust, ProductionTrustDecision, ProductionTrustError, ProgramId,
        ProofVerificationRequest, ReceiptVerificationRequest, RoleCredentialVerificationRequest,
        ServiceGenesis, ServiceWire, VosPackage, artifact_hash,
    };

    #[derive(Clone)]
    struct AllowProductionTrust(Hash);

    impl ProductionTrust for AllowProductionTrust {
        fn policy_id(&self) -> Hash {
            self.0
        }

        fn logical_timeslot(&self) -> Option<u64> {
            Some(100)
        }

        fn verify_logical_timeslot(&self, slot: u64) -> ProductionTrustDecision {
            if slot <= 100 {
                ProductionTrustDecision::Authorized
            } else {
                ProductionTrustDecision::Denied
            }
        }

        fn verify_proof(
            &self,
            _request: &ProofVerificationRequest,
            _proof: &[u8],
        ) -> ProductionTrustDecision {
            ProductionTrustDecision::Authorized
        }

        fn verify_install(&self, _genesis: &ServiceGenesis) -> ProductionTrustDecision {
            ProductionTrustDecision::Authorized
        }

        fn verify_upgrade(&self, _upgrade: &ActorUpgrade) -> ProductionTrustDecision {
            ProductionTrustDecision::Authorized
        }

        fn verify_role_credential(
            &self,
            _request: &RoleCredentialVerificationRequest,
        ) -> ProductionTrustDecision {
            ProductionTrustDecision::Authorized
        }

        fn verify_receipt(&self, _request: &ReceiptVerificationRequest) -> ProductionTrustDecision {
            ProductionTrustDecision::Authorized
        }
    }

    #[derive(Clone)]
    struct SwitchProductionTrust {
        policy: Hash,
        available: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl SwitchProductionTrust {
        fn decision(&self) -> ProductionTrustDecision {
            if self.available.load(std::sync::atomic::Ordering::Relaxed) {
                ProductionTrustDecision::Authorized
            } else {
                ProductionTrustDecision::Unavailable
            }
        }
    }

    impl ProductionTrust for SwitchProductionTrust {
        fn policy_id(&self) -> Hash {
            self.policy
        }

        fn logical_timeslot(&self) -> Option<u64> {
            self.available
                .load(std::sync::atomic::Ordering::Relaxed)
                .then_some(100)
        }

        fn verify_logical_timeslot(&self, _slot: u64) -> ProductionTrustDecision {
            self.decision()
        }

        fn verify_proof(
            &self,
            _request: &ProofVerificationRequest,
            _proof: &[u8],
        ) -> ProductionTrustDecision {
            self.decision()
        }

        fn verify_install(&self, _genesis: &ServiceGenesis) -> ProductionTrustDecision {
            self.decision()
        }

        fn verify_upgrade(&self, _upgrade: &ActorUpgrade) -> ProductionTrustDecision {
            self.decision()
        }

        fn verify_role_credential(
            &self,
            _request: &RoleCredentialVerificationRequest,
        ) -> ProductionTrustDecision {
            self.decision()
        }

        fn verify_receipt(&self, _request: &ReceiptVerificationRequest) -> ProductionTrustDecision {
            self.decision()
        }
    }

    const SERVICE_META: ActorMeta = ActorMeta {
        actor_name: "counter",
        messages: &[MessageMeta {
            name: "value",
            is_query: true,
            fields: &[],
            returns: "u64",
            doc: "",
            timeout_ms: 0,
            mode: 0,
            attested: false,
            space_role: None,
            actor_role: None,
        }],
        constructor: &[],
        kind: 0,
        caps: &[],
        cli_methods: &[],
        doc: "",
        crdt: false,
        provable: false,
    };

    #[test]
    fn timed_inviter_fails_loudly_on_remote_denial_or_malformed_reply() {
        let forbidden = vec![vos::STATUS_FORBIDDEN, 0, 0, 0, 0];
        assert!(matches!(
            decode_timed_node_reply(Some(forbidden)),
            Err(ClientError::Forbidden)
        ));
        assert!(matches!(
            decode_timed_node_reply(Some(vec![vos::STATUS_PANICKED, 0, 0, 0, 0])),
            Err(ClientError::Decode)
        ));
    }

    fn signed_service_package(service_program: ProgramId) -> VosPackage {
        signed_service_package_with_consistency(service_program, false)
    }

    fn signed_service_package_with_consistency(
        service_program: ProgramId,
        crdt: bool,
    ) -> VosPackage {
        let mut assembler = vos_pvm_compiler::assembler::Assembler::new();
        assembler
            .load_imm_64(vos_pvm_compiler::assembler::Reg::A0, 0)
            .ecalli(0);
        let actor_pvm = assembler.build();
        let metadata_source = ActorMeta {
            crdt,
            ..SERVICE_META
        };
        let (buffer, length) = vos::metadata::encode::<512>(&metadata_source);
        let schemas = buffer[..length].to_vec();
        let metadata = vos::metadata::decode(&schemas).unwrap();
        let role_policies = PackageRolePolicies::from_metadata(&metadata)
            .unwrap()
            .encode();
        let keypair = Keypair::generate_ed25519();
        let public_key = keypair.public().encode_protobuf();
        let mut package = VosPackage {
            manifest: PackageManifest {
                name: "counter".into(),
                platform: vos::service::PLATFORM_ID,
                execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
                service_program,
                actor_program: ProgramId::of_pvm(&actor_pvm),
                crdt,
                interfaces_hash: artifact_hash(b"interfaces", &[]),
                role_policies_hash: artifact_hash(b"role-policies", &role_policies),
                schemas_hash: artifact_hash(b"schemas", &schemas),
                task_dependencies_hash: vos::service::task_dependencies_hash(&[]),
            },
            actor_pvm,
            generated_interfaces: vec![],
            role_policies,
            schemas,
            task_dependencies: vec![],
            diagnostics: None,
            deployment_signature: DeploymentSignature {
                producer: ProducerId::of_public_key(&public_key),
                public_key,
                signature: vec![0],
            },
        };
        package.deployment_signature.signature = keypair.sign(&package.signing_message()).unwrap();
        package
    }

    #[test]
    fn canonical_role_authority_is_root_signed_and_resolves_exactly() {
        let root = Keypair::generate_ed25519();
        let root_peer = libp2p::PeerId::from(root.public()).to_bytes();
        let package = root_signed_role_authority_package(&root).unwrap();
        let repeated = root_signed_role_authority_package(&root).unwrap();
        assert_eq!(package.encode(), repeated.encode());
        validate_role_authority_deployment(&package, &root_peer, Consistency::Raft).unwrap();
        assert!(
            validate_role_authority_deployment(
                &package,
                &libp2p::PeerId::from(Keypair::generate_ed25519().public()).to_bytes(),
                Consistency::Raft,
            )
            .is_err()
        );
        assert!(
            validate_role_authority_deployment(&package, &root_peer, Consistency::Local).is_err()
        );

        let exact_package = package.encode();
        let program_hash = BlobHash::of(&exact_package).0;
        let row = vos::registry::AgentRow {
            instance_name: vos::service::ROLE_AUTHORITY_INSTANCE_.into(),
            program_hash,
            program_name: package.manifest.name.clone(),
            replication_id: [91; 32],
            consistency: Consistency::Raft as u8,
            network_reachable: false,
            sync_role: vos::registry::SyncFloor::Member,
        };
        let space_id = [92; 32];
        let resolved = resolve_service_role_authority_with(
            space_id,
            std::slice::from_ref(&row),
            &root_peer,
            |hash| Ok((hash == program_hash).then(|| exact_package.clone())),
        )
        .unwrap();
        let RoleAuthorityResolution::Ready(binding) = resolved else {
            panic!("root-signed authority did not resolve")
        };
        let space = vos::service::SpaceId(space_id);
        let root_service = service_root_service_id(
            space,
            vos::service::ROLE_AUTHORITY_INSTANCE_,
            row.replication_id,
        );
        assert_eq!(binding.service.space, space);
        assert_eq!(binding.service.root_service, root_service);
        assert_eq!(binding.service.deployment, package.deployment_id());
        assert_eq!(
            binding.actor,
            service_root_actor_id(root_service, vos::service::ROLE_AUTHORITY_INSTANCE_)
        );

        let mut incompatible = package.clone();
        incompatible.generated_interfaces = vec![1];
        incompatible.manifest.interfaces_hash =
            artifact_hash(b"interfaces", &incompatible.generated_interfaces);
        incompatible.deployment_signature.signature = root
            .sign(&incompatible.signing_message())
            .expect("sign incompatible authority candidate");
        incompatible.validate().unwrap();
        assert!(
            validate_role_authority_deployment(&incompatible, &root_peer, Consistency::Raft)
                .is_err()
        );
    }

    #[test]
    fn canonical_role_authority_identity_is_pinned() {
        let root = Keypair::ed25519_from_bytes([7; 32]).unwrap();
        let package = root_signed_role_authority_package(&root).unwrap();
        let package_hash = BlobHash::of(&package.encode()).0;
        let replication_id = crate::commands::space::common::auto_replication_id(
            &[92; 32],
            vos::service::ROLE_AUTHORITY_INSTANCE_,
            &package_hash,
        );

        assert_eq!(package.manifest.platform, vos::service::PLATFORM_ID);
        assert_eq!(
            hex::encode(package.manifest.actor_program.0),
            "63828f5cbe1b3796e05201c4b803984640506b1faa45e9bdcddb84630c9f2787",
        );
        assert_eq!(
            hex::encode(package.deployment_id().0),
            "4254c8707910b2f6c3fd3a1556a3d2f354c1ea6b9c7e9cac707f9688c08d150d",
        );
        assert_eq!(
            hex::encode(package_hash),
            "1ac0f3983e892fcbf761158f92eff008ecebeb4c96aac98ef5272f3bc1c48958",
        );
        assert_eq!(
            hex::encode(replication_id),
            "c53fbca271b8df712e8b1b85ec6a407dde685412d5460374f7e66d80bc1cb930",
        );
    }

    #[test]
    fn invite_redemption_maps_exact_evidence_to_stable_authority_ingress() {
        use vos::Decode;

        let payload = crate::token::InvitePayload {
            space_id: [7; 32],
            name: "invited-space".into(),
            bootnodes: vec!["/memory/1".into()],
            role: vos::registry::AUTH_ROLE_DEVELOPER,
            expires_at: 123_456,
            authority_replication_id: [15; 32],
            admin_peer_id: vec![8; 38],
            token_pub: [9; 32],
            admin_sig: [10; vos::registry::OP_SIG_LEN],
            token_secret: [11; 32],
        };
        let redemption = authority_invite_redemption(
            &payload,
            vec![12; 38],
            [13; vos::registry::OP_SIG_LEN],
            vec![14; vos::registry::OP_SIG_LEN],
        )
        .unwrap();
        assert_eq!(redemption.space, vos::service::SpaceId(payload.space_id));
        assert_eq!(redemption.authority_replication_id, [15; 32]);
        assert_eq!(redemption.role, vos::SpaceRole::Developer);
        assert_eq!(redemption.admin_peer_id, payload.admin_peer_id);
        assert_eq!(redemption.admin_signature, payload.admin_sig);
        assert_eq!(redemption.holder_peer_id, vec![12; 38]);
        assert_eq!(redemption.redeem_signature, [13; 64]);
        assert_eq!(redemption.holder_signature, [14; 64]);

        let replication_id = [15; 32];
        let (route, invocation) = authority_invite_invocation(&redemption, 0x1234);
        let repeated = authority_invite_invocation(&redemption, 0x1234);
        let root_service = service_root_service_id(
            vos::service::SpaceId(payload.space_id),
            vos::service::ROLE_AUTHORITY_INSTANCE_,
            replication_id,
        );
        assert_eq!(
            route,
            instance_service_id(vos::service::ROLE_AUTHORITY_INSTANCE_, 0x1234)
        );
        assert_eq!(repeated, (route, invocation.clone()));
        assert_eq!(
            invocation.target,
            service_root_actor_id(root_service, vos::service::ROLE_AUTHORITY_INSTANCE_)
        );
        assert_eq!(
            invocation.method,
            vos::service::ROLE_AUTHORITY_INVITE_METHOD_
        );
        assert!(!invocation.proof_requested);
        assert_eq!(invocation.arguments[0], vos::value::TAG_DYNAMIC);
        let message = vos::value::Msg::decode(&invocation.arguments[1..]);
        assert_eq!(message.name, vos::service::ROLE_AUTHORITY_INVITE_METHOD_);
        let encoded_redemption = message.args.get("redemption").unwrap().as_bytes().unwrap();
        assert_eq!(
            vos::service::RoleAuthorityInviteRedemption::decode(encoded_redemption).unwrap(),
            redemption
        );
    }

    #[test]
    fn invite_redemption_rejects_non_delegable_roles_and_wrong_signature_width() {
        let mut payload = crate::token::InvitePayload {
            space_id: [21; 32],
            name: "invited-space".into(),
            bootnodes: vec![],
            role: vos::registry::AUTH_ROLE_ADMIN,
            expires_at: 123_456,
            authority_replication_id: [29; 32],
            admin_peer_id: vec![22; 38],
            token_pub: [23; 32],
            admin_sig: [24; vos::registry::OP_SIG_LEN],
            token_secret: [25; 32],
        };
        assert!(
            authority_invite_redemption(&payload, vec![26; 38], [27; 64], vec![28; 64]).is_err()
        );
        payload.role = vos::registry::AUTH_ROLE_READONLY;
        assert!(
            authority_invite_redemption(&payload, vec![26; 38], [27; 64], vec![28; 63]).is_err()
        );
        payload.authority_replication_id = [0; 32];
        assert!(
            authority_invite_redemption(&payload, vec![26; 38], [27; 64], vec![28; 64]).is_err(),
            "a markerless token never enters the service authority path"
        );
    }

    #[test]
    fn only_generated_non_public_methods_require_the_role_authority() {
        let mut package = signed_service_package(vos::service::VOS_SERVICE_PROGRAM_ID);
        assert!(!package_requires_role_authority(&package).unwrap());
        let mut policies = PackageRolePolicies::decode(&package.role_policies).unwrap();
        policies.methods[0].public = false;
        policies.methods[0].actor_role = Some(7);
        policies.methods[0].policy = vos::service::method_role_policy_hash(None, Some(7)).unwrap();
        package.role_policies = policies.encode();
        assert!(package_requires_role_authority(&package).unwrap());
    }

    #[test]
    fn catalog_accepts_only_signed_service_packages() {
        assert_eq!(
            catalog_artifact_support(b"VOSP\x02\0package"),
            RowCatalogSupport::ServicePackage,
        );
        assert_eq!(
            catalog_artifact_support(b"PVM\0canonical"),
            RowCatalogSupport::Unsupported,
        );
    }

    #[test]
    fn signed_ordinary_service_packages_select_the_raft_root_driver() {
        let service_pvm = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm"),
        )
        .expect("the protocol-pinned service artifact must be available to tests");
        let package = signed_service_package(vos::service::VOS_SERVICE_PROGRAM_ID);
        let row = vos::registry::AgentRow {
            instance_name: "counter".into(),
            program_hash: [1; 32],
            program_name: "counter".into(),
            replication_id: [2; 32],
            consistency: Consistency::Raft as u8,
            network_reachable: true,
            sync_role: vos::registry::SyncFloor::Public,
        };
        let pinned = PinnedService {
            pvm: std::sync::Arc::new(service_pvm),
        };
        let resolved = service_config_from_row(
            Path::new("/tmp/vos-config-test"),
            [3; 32],
            &row,
            std::slice::from_ref(&row),
            &AgentPolicies::new(),
            Consistency::Raft,
            package.encode(),
            Some(&pinned),
            &[],
        )
        .expect("a signed ordinary service package may select Raft");
        let RowConfig::Service { config, .. } = resolved else {
            panic!("service package did not select the service runtime")
        };
        assert_eq!(config.consistency, vos::service::ConsistencyMode::Raft);
    }

    #[test]
    fn three_voter_appended_upgrade_recovers_package_before_registration() {
        use vos::service::CommittedAccumulateLog as _;

        let directory = std::env::temp_dir().join(format!(
            "vosx-unapplied-upgrade-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(directory.join("services")).unwrap();
        let service_pvm = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm"),
        )
        .unwrap();
        let pinned = PinnedService {
            pvm: std::sync::Arc::new(service_pvm),
        };
        let original = signed_service_package(vos::service::VOS_SERVICE_PROGRAM_ID);
        let mut row = vos::registry::AgentRow {
            instance_name: "counter".into(),
            program_hash: BlobHash::of(&original.encode()).0,
            program_name: original.manifest.name.clone(),
            replication_id: [0xD1; 32],
            consistency: Consistency::Raft as u8,
            network_reachable: false,
            sync_role: vos::registry::SyncFloor::Public,
        };
        let space_id = [0xD2; 32];
        let RowConfig::Service {
            config, state_path, ..
        } = service_config_from_row(
            &directory,
            space_id,
            &row,
            std::slice::from_ref(&row),
            &AgentPolicies::new(),
            Consistency::Raft,
            original.encode(),
            Some(&pinned),
            &[],
        )
        .unwrap()
        else {
            panic!("signed package did not resolve to a service Raft root")
        };
        let config = *config;
        let service_identity = config.service.clone();
        let root_actor = config.root_actor;
        let raft_path = service_raft_db_path(&directory, service_identity.root_service);
        let voters = [0xD101, 0xD102, 0xD103];
        assert!(vos::raft::seed_initial_config(&raft_path, &voters).unwrap());
        let policy = Hash([0xD3; 32]);
        let trust = std::sync::Arc::new(AllowProductionTrust(policy));
        let log = vos::raft::service::RaftAccumulateLog::open(
            &raft_path,
            vos::raft::RaftConfig::default(),
        )
        .unwrap();
        let service = vos::service::LocalRootTreeService::open_raft_production(
            config.clone(),
            vos::service::FileCommittedImageStore::new(state_path.clone()),
            log,
            trust.clone(),
        )
        .expect("physical guest applies genesis before the simulated crash window");
        let header = service.store().header().unwrap().unwrap();
        assert_eq!(header.revision, 0);
        drop(service);
        let original_service_image = std::fs::read(&state_path).unwrap();

        let mut replacement = original.clone();
        let mut replacement_assembler = vos_pvm_compiler::assembler::Assembler::new();
        replacement_assembler
            .load_imm_64(vos_pvm_compiler::assembler::Reg::A0, 1)
            .ecalli(0);
        replacement.actor_pvm = replacement_assembler.build();
        replacement.manifest.actor_program = ProgramId::of_pvm(&replacement.actor_pvm);
        let replacement_signer = Keypair::generate_ed25519();
        replacement.deployment_signature.public_key = replacement_signer.public().encode_protobuf();
        replacement.deployment_signature.producer =
            ProducerId::of_public_key(&replacement.deployment_signature.public_key);
        replacement.deployment_signature.signature = vec![0];
        replacement.deployment_signature.signature = replacement_signer
            .sign(&replacement.signing_message())
            .unwrap();
        let package_wire = replacement.encode();
        let upgrade_wire = vos::service::RootTreeUpgradeRequest {
            expected_deployment: original.deployment_id(),
            expected_program: original.manifest.actor_program,
            replacement: replacement.clone(),
        }
        .encode();
        let upgrade = vos::service::ActorUpgrade {
            service: service_identity.clone(),
            actor: root_actor,
            expected_deployment: original.deployment_id(),
            expected_program: original.manifest.actor_program,
            replacement_deployment: replacement.deployment_id(),
            replacement_program: replacement.manifest.actor_program,
            producer: replacement.deployment_signature.producer,
            role_policies: replacement.role_policies.clone(),
            base: vos::service::ConsistencyBase::Linear {
                revision: header.revision,
                state_root: header.state_root.unwrap(),
            },
            authorization: vos::service::AuthorizationEvidence::SystemCapability {
                capability: vos::service::SystemCapabilityId(
                    Hash::digest(
                        b"vos/root-upgrade-capability/service",
                        &[&service_identity.root_service.0, &root_actor.0],
                    )
                    .0,
                ),
                authenticator: Hash::digest(
                    b"vos/root-upgrade-authenticator/service",
                    &[&upgrade_wire],
                )
                .0
                .to_vec(),
            },
        };
        assert_ne!(upgrade.expected_deployment, upgrade.replacement_deployment);
        assert_eq!(
            vos::service::ActorUpgrade::decode(&upgrade.encode()),
            Ok(upgrade.clone()),
            "the recovery fixture itself must be a canonical actor upgrade",
        );
        let mut log = vos::raft::service::RaftAccumulateLog::open(
            &raft_path,
            vos::raft::RaftConfig::default(),
        )
        .unwrap();
        let committed = log
            .propose_at_with_availability(
                &vos::service::AccumulateRequest::UpgradeActor(upgrade).encode(),
                None,
                Some(policy),
                &[vos::service::ImportedProgram {
                    program: replacement.manifest.actor_program,
                    pvm: replacement.actor_pvm.clone(),
                }],
                &[vos::service::ImportedBlob {
                    reference: vos::service::BlobRef::of_bytes(&package_wire),
                    bytes: package_wire.clone(),
                }],
                &[],
            )
            .expect("the replacement package reaches the committed Raft log");
        assert_eq!(committed.index, 2);
        assert_eq!(log.applied_index().unwrap(), 1);
        drop(log);

        let log = vos::raft::service::RaftAccumulateLog::open(
            &raft_path,
            vos::raft::RaftConfig::default(),
        )
        .unwrap();
        let upgraded_leader = vos::service::LocalRootTreeService::open_raft_production(
            config,
            vos::service::FileCommittedImageStore::new(state_path.clone()),
            log,
            trust.clone(),
        )
        .expect("the quorum-committed leader applies before moving the catalog");
        assert_eq!(
            upgraded_leader.store().header().unwrap().unwrap().revision,
            1
        );
        drop(upgraded_leader);

        // Reproduce the three-voter persistence window rather than relying on
        // the single-node adapter's immediate local commit. The lost leader
        // has committed N+1. Both surviving voters durably appended and
        // acknowledged N+1, but crashed before the leader's next heartbeat
        // advanced their local commit_index from N.
        let lost_leader_path = directory.join("lost-leader.raft.redb");
        let second_survivor_path = directory.join("second-survivor.raft.redb");
        std::fs::copy(&raft_path, &lost_leader_path).unwrap();
        std::fs::copy(&raft_path, &second_survivor_path).unwrap();
        for survivor_path in [&raft_path, &second_survivor_path] {
            let db = redb::Database::open(survivor_path).unwrap();
            let mut meta = vos::raft::RaftMeta::load(&db).unwrap();
            assert_eq!(meta.commit_index, 2);
            assert_eq!(meta.last_applied, 2);
            meta.commit_index = 1;
            meta.last_applied = 1;
            let txn = db.begin_write().unwrap();
            meta.write_in_txn(&txn).unwrap();
            txn.commit().unwrap();
        }
        for voter_path in [&lost_leader_path, &raft_path, &second_survivor_path] {
            assert_eq!(
                vos::raft::persisted_membership(voter_path).unwrap(),
                Some(voters.to_vec()),
            );
        }
        std::fs::remove_file(&lost_leader_path).unwrap();
        std::fs::write(&state_path, original_service_image).unwrap();

        row.program_hash = BlobHash::of(&package_wire).0;
        row.program_name = replacement.manifest.name.clone();
        let cache_path = blob_store::cache_path_for(&BlobHash(row.program_hash));
        let _ = std::fs::remove_file(&cache_path);
        let RowConfig::Service { config, .. } = agent_config_from_row(
            &directory,
            space_id,
            &row,
            std::slice::from_ref(&row),
            &AgentPolicies::new(),
            Some(&pinned),
            &[],
        )
        .unwrap() else {
            panic!("the recovered catalog package did not reconstruct root configuration")
        };
        assert!(
            cache_path.is_file(),
            "configuration resolution must recover the catalog-authenticated package from the appended tail before registration",
        );
        {
            let db = redb::Database::open(&raft_path).unwrap();
            let meta = vos::raft::RaftMeta::load(&db).unwrap();
            let log = vos::raft::RaftLog::open(std::sync::Arc::new(db)).unwrap();
            assert_eq!(meta.commit_index, 1);
            assert_eq!(meta.last_applied, 1);
            assert_eq!(log.last_index(), 2);
        }

        // Artifact bootstrap cannot itself commit or apply the upgrade. Model
        // the restarted survivor winning an election and learning that N+1 is
        // committed, after which ordinary physical-guest catch-up owns the
        // state transition.
        {
            let db = redb::Database::open(&raft_path).unwrap();
            let mut meta = vos::raft::RaftMeta::load(&db).unwrap();
            meta.commit_index = 2;
            let txn = db.begin_write().unwrap();
            meta.write_in_txn(&txn).unwrap();
            txn.commit().unwrap();
        }
        let log = vos::raft::service::RaftAccumulateLog::open(
            &raft_path,
            vos::raft::RaftConfig::default(),
        )
        .unwrap();
        let recovered = vos::service::LocalRootTreeService::open_raft_production(
            *config,
            vos::service::FileCommittedImageStore::new(state_path),
            log,
            trust,
        )
        .expect("registration catches the physical guest up through the committed upgrade");
        assert_eq!(
            recovered.store().header().unwrap().unwrap().revision,
            1,
            "the previously unapplied entry is now materialized",
        );
        drop(recovered);

        let _ = std::fs::remove_file(cache_path);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn daemon_local_registration_uses_the_supplied_production_policy() {
        let directory = std::env::temp_dir().join(format!(
            "vosx-production-local-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let service_pvm = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm"),
        )
        .unwrap();
        let package = signed_service_package(vos::service::VOS_SERVICE_PROGRAM_ID);
        let row = vos::registry::AgentRow {
            instance_name: "production-counter".into(),
            program_hash: [31; 32],
            program_name: "counter".into(),
            replication_id: [32; 32],
            consistency: Consistency::Local as u8,
            network_reachable: false,
            sync_role: vos::registry::SyncFloor::Public,
        };
        let pinned = PinnedService {
            pvm: std::sync::Arc::new(service_pvm),
        };
        let RowConfig::Service {
            config,
            state_path,
            network_reachable,
        } = service_config_from_row(
            &directory,
            [33; 32],
            &row,
            std::slice::from_ref(&row),
            &AgentPolicies::new(),
            Consistency::Local,
            package.encode(),
            Some(&pinned),
            &[],
        )
        .unwrap()
        else {
            panic!("signed package did not resolve to a service root")
        };
        let config = *config;
        let reopen_config = config.clone();
        let policy = Hash([34; 32]);
        let available = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let trust = std::sync::Arc::new(SwitchProductionTrust {
            policy,
            available: available.clone(),
        });
        let route = ServiceId::new(35, 36);
        let mut node = VosNode::with_prefix(35);
        let unavailable = register_service_root_from_row(
            &mut node,
            &directory,
            row.instance_name.clone(),
            row.replication_id,
            config.clone(),
            state_path.clone(),
            None,
            35,
            route,
            network_reachable,
            Some(trust.clone()),
        )
        .unwrap_err();
        assert!(is_retryable_service_registration_error(&unavailable));
        assert!(matches!(
            service_registration_note(&unavailable),
            RowNote::RegistrationWaiting
        ));
        assert!(!node.has_agent(route));

        available.store(true, std::sync::atomic::Ordering::Relaxed);
        register_service_root_from_row(
            &mut node,
            &directory,
            row.instance_name,
            row.replication_id,
            config,
            state_path.clone(),
            None,
            35,
            route,
            network_reachable,
            Some(trust.clone()),
        )
        .unwrap();
        assert!(node.has_agent(route));
        assert!(node.collect().iter().all(vos::node::AgentResult::is_ok));

        let backend = vos::service::FileCommittedImageStore::new(state_path.clone());
        assert!(matches!(
            vos::service::LocalRootTreeService::open(reopen_config.clone(), backend),
            Err(vos::service::LocalRootTreeOpenError::ProductionTrust(
                ProductionTrustError::TrustRequired,
            )),
        ));
        let reopened = vos::service::LocalRootTreeService::open_production(
            reopen_config,
            vos::service::FileCommittedImageStore::new(state_path),
            trust,
        )
        .unwrap();
        assert_eq!(reopened.production_trust_policy_id(), Some(policy));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn retryable_service_registration_leaves_a_router_window_and_advances_to_other_rows() {
        let first = ("first".to_owned(), [1; 32]);
        let second = ("second".to_owned(), [2; 32]);
        let now = std::time::Instant::now();
        let mut backoff = RegistrationBackoff::default();
        assert!(backoff.ready(&first, now));
        let mut attempts = 0;
        assert!(take_service_registration_attempt(
            &mut attempts,
            &backoff,
            &first,
            now,
        ));
        assert!(
            !take_service_registration_attempt(&mut attempts, &backoff, &second, now),
            "bootstrap and reconciliation both admit only one open per pass"
        );

        backoff.finish(first.clone(), true, now);
        assert!(!backoff.ready(&first, now));
        assert!(!backoff.ready(&second, now));

        let next_pass = now + SERVICE_REGISTRATION_GLOBAL_RETRY_GAP;
        attempts = 0;
        assert!(
            backoff.ready(&second, next_pass),
            "another row becomes eligible after the global router window"
        );
        assert!(take_service_registration_attempt(
            &mut attempts,
            &backoff,
            &second,
            next_pass,
        ));
        assert!(
            !backoff.ready(&first, next_pass),
            "the failed row remains under its longer per-row backoff"
        );
        assert!(backoff.ready(&first, now + SERVICE_REGISTRATION_RETRY_BASE));
    }

    #[test]
    fn daemon_raft_registration_orders_the_supplied_production_policy() {
        let directory = std::env::temp_dir().join(format!(
            "vosx-production-raft-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let service_pvm = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm"),
        )
        .unwrap();
        let package = signed_service_package(vos::service::VOS_SERVICE_PROGRAM_ID);
        let replication_id = [42; 32];
        let row = vos::registry::AgentRow {
            instance_name: "production-raft-counter".into(),
            program_hash: [41; 32],
            program_name: "counter".into(),
            replication_id,
            consistency: Consistency::Raft as u8,
            network_reachable: false,
            sync_role: vos::registry::SyncFloor::Public,
        };
        let pinned = PinnedService {
            pvm: std::sync::Arc::new(service_pvm),
        };
        let RowConfig::Service {
            config,
            state_path,
            network_reachable,
        } = service_config_from_row(
            &directory,
            [43; 32],
            &row,
            std::slice::from_ref(&row),
            &AgentPolicies::new(),
            Consistency::Raft,
            package.encode(),
            Some(&pinned),
            &[],
        )
        .unwrap()
        else {
            panic!("signed package did not resolve to a service Raft root")
        };
        let root_service = config.service.root_service;
        let reopen_config = (*config).clone();
        let reopen_state_path = state_path.clone();
        let policy = Hash([44; 32]);
        let member = 45;
        let route = ServiceId::new(member, 46);
        let mut node = VosNode::with_prefix(member);
        register_service_root_from_row(
            &mut node,
            &directory,
            row.instance_name,
            replication_id,
            *config,
            state_path,
            Some(RaftSeed::Members {
                members: vec![member],
                voter_peer_ids: Vec::new(),
            }),
            member,
            route,
            network_reachable,
            Some(std::sync::Arc::new(AllowProductionTrust(policy))),
        )
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(350));
        assert!(node.has_agent(route));
        assert!(node.collect().iter().all(vos::node::AgentResult::is_ok));

        let raft_config = vos::raft::RaftConfig {
            me: member,
            members: vec![member],
            replication_id,
            ..vos::raft::RaftConfig::default()
        };
        let raft_path = service_raft_db_path(&directory, root_service);
        let log = vos::raft::RaftAccumulateLog::open(&raft_path, raft_config.clone()).unwrap();
        assert!(matches!(
            vos::service::LocalRootTreeService::open_raft(
                reopen_config.clone(),
                vos::service::FileCommittedImageStore::new(reopen_state_path.clone()),
                log,
            ),
            Err(vos::service::LocalRootTreeOpenError::ProductionTrust(
                ProductionTrustError::TrustRequired,
            )),
        ));
        let reopened = vos::service::LocalRootTreeService::open_raft_production(
            reopen_config,
            vos::service::FileCommittedImageStore::new(reopen_state_path),
            vos::raft::RaftAccumulateLog::open(&raft_path, raft_config).unwrap(),
            std::sync::Arc::new(AllowProductionTrust(policy)),
        )
        .unwrap();
        assert_eq!(reopened.production_trust_policy_id(), Some(policy));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn signed_crdt_service_packages_select_the_anti_entropy_root_driver() {
        let service_pvm = std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../services/vos-service/vos-service.pvm"),
        )
        .expect("the protocol-pinned service artifact must be available to tests");
        let package =
            signed_service_package_with_consistency(vos::service::VOS_SERVICE_PROGRAM_ID, true);
        let row = vos::registry::AgentRow {
            instance_name: "shared-counter".into(),
            program_hash: [11; 32],
            program_name: "shared-counter".into(),
            replication_id: [12; 32],
            consistency: Consistency::Crdt as u8,
            network_reachable: true,
            sync_role: vos::registry::SyncFloor::Member,
        };
        let pinned = PinnedService {
            pvm: std::sync::Arc::new(service_pvm),
        };
        let resolved = service_config_from_row(
            Path::new("/tmp/vos-crdt-config-test"),
            [13; 32],
            &row,
            std::slice::from_ref(&row),
            &AgentPolicies::new(),
            Consistency::Crdt,
            package.encode(),
            Some(&pinned),
            &[],
        )
        .expect("a signed #[actor(crdt)] package selects CRDT");
        let RowConfig::Service { config, .. } = resolved else {
            panic!("service CRDT package did not select the service runtime")
        };
        assert_eq!(config.consistency, vos::service::ConsistencyMode::Crdt);
    }

    #[test]
    fn service_raft_storage_is_scoped_to_the_installation_incarnation() {
        let data = Path::new("/tmp/vos-raft-path-test");
        let first = service_raft_db_path(data, vos::service::RootServiceId([1; 32]));
        let reinstalled = service_raft_db_path(data, vos::service::RootServiceId([2; 32]));
        assert_ne!(first, reinstalled);
        let expected = format!("{}.raft.redb", hex::encode([1; 32]));
        assert_eq!(
            first.file_name().and_then(|name| name.to_str()),
            Some(expected.as_str()),
        );
        assert!(first.starts_with(data.join("services")));
    }

    #[test]
    fn agent_policies_come_from_local_toml() {
        // Host-private signing configuration is sourced from local.toml.
        let mut cfg = subscriptions::LocalConfig::default();
        cfg.agents.insert(
            "authority".into(),
            subscriptions::AgentLocal {
                device_secret: true,
            },
        );
        cfg.agents.insert(
            "plain".into(),
            subscriptions::AgentLocal {
                device_secret: false,
            },
        );
        let policies = agent_policies_from_local(&cfg).unwrap();
        assert!(policies["authority"].device_secret);
        assert!(!policies.contains_key("plain"));
    }

    #[test]
    fn recipe_path_detection_requires_an_existing_toml() {
        // Trivalent disambiguation (decision 1): a `.toml` path is a
        // recipe only if it exists; a nonexistent path or a bare name
        // is not.
        assert!(!is_recipe_path("some-space-name"));
        assert!(!is_recipe_path("/does/not/exist.toml"));
        let dir = std::env::temp_dir().join(format!(
            "vosx-recipe-detect-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let recipe = dir.join("r.toml");
        std::fs::write(&recipe, "space = \"x\"\n").unwrap();
        assert!(is_recipe_path(recipe.to_str().unwrap()));
        // A `vos-…` token is never mistaken for a recipe.
        assert!(!is_recipe_path("vos-abc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn orphan_service_images_and_private_sidecars_move_to_recoverable_trash() {
        let dir = std::env::temp_dir().join(format!(
            "vosx-orphan-sweep-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let services = dir.join("services");
        std::fs::create_dir_all(&services).unwrap();
        let active = [0x31; 32];
        let orphan = [0x42; 32];
        let active_image = services.join(format!("{}.image", hex::encode(active)));
        let orphan_image = services.join(format!("{}.image", hex::encode(orphan)));
        let orphan_proofs = services.join(format!("{}.image.proofs", hex::encode(orphan)));
        let orphan_records = services.join(format!("{}.image.records", hex::encode(orphan)));
        let active_raft = services.join(format!("{}.raft.redb", hex::encode(active)));
        let orphan_raft = services.join(format!("{}.raft.redb", hex::encode(orphan)));
        let active_seed = services.join(format!("{}.device-seed", hex::encode(active)));
        let orphan_seed = services.join(format!("{}.device-seed", hex::encode(orphan)));
        let orphan_seed_temp = services.join(format!("{}.device-seed.next", hex::encode(orphan)));
        std::fs::write(&active_image, b"active").unwrap();
        std::fs::write(&orphan_image, b"orphan").unwrap();
        std::fs::write(&active_raft, b"active raft").unwrap();
        std::fs::write(&orphan_raft, b"orphan raft").unwrap();
        std::fs::write(&active_seed, [0x51; 32]).unwrap();
        std::fs::write(&orphan_seed, [0x52; 32]).unwrap();
        std::fs::write(&orphan_seed_temp, [0x53; 32]).unwrap();
        std::fs::create_dir_all(&orphan_proofs).unwrap();
        std::fs::write(orphan_proofs.join("proof"), b"proof").unwrap();
        std::fs::create_dir_all(&orphan_records).unwrap();
        std::fs::write(orphan_records.join("record"), b"private record").unwrap();

        sweep_orphan_service_services(&dir, &[active].into_iter().collect());

        assert!(active_image.is_file());
        assert!(active_raft.is_file());
        assert!(active_seed.is_file());
        assert!(!orphan_image.exists());
        assert!(!orphan_proofs.exists());
        assert!(!orphan_records.exists());
        assert!(!orphan_raft.exists());
        assert!(!orphan_seed.exists());
        assert!(!orphan_seed_temp.exists());
        assert!(
            dir.join("trash")
                .join("services")
                .join(orphan_image.file_name().unwrap())
                .is_file(),
        );
        assert!(
            dir.join("trash")
                .join("services")
                .join(orphan_proofs.file_name().unwrap())
                .is_dir(),
        );
        assert!(
            dir.join("trash")
                .join("services")
                .join(orphan_records.file_name().unwrap())
                .is_dir(),
        );
        assert!(
            dir.join("trash")
                .join("services")
                .join(orphan_raft.file_name().unwrap())
                .is_file(),
        );
        assert!(
            dir.join("trash")
                .join("services")
                .join(orphan_seed.file_name().unwrap())
                .is_file(),
        );
        assert!(
            dir.join("trash")
                .join("services")
                .join(orphan_seed_temp.file_name().unwrap())
                .is_file(),
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn status(role: RaftRole, members: Vec<u16>, leader_hint: Option<u16>) -> RaftStatusReply {
        RaftStatusReply {
            present: true,
            role,
            current_term: 1,
            commit_index: 1,
            last_applied: 1,
            last_log_index: 1,
            members,
            joint_old: None,
            active_config_index: Some(1),
            leader_hint,
        }
    }

    fn absent() -> RaftStatusReply {
        RaftStatusReply {
            present: false,
            role: RaftRole::Follower,
            current_term: 0,
            commit_index: 0,
            last_applied: 0,
            last_log_index: 0,
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
            leader_hint: None,
        }
    }

    #[test]
    fn raft_onboarding_resolves_the_canonical_full_peer_identity() {
        let voter = libp2p::PeerId::random();
        let prefix = vos::network::derive_node_prefix(&voter);
        let different_peer = loop {
            let candidate = libp2p::PeerId::random();
            if vos::network::derive_node_prefix(&candidate) != prefix {
                break candidate;
            }
        };
        let roster = vec![(prefix, voter.to_bytes())];

        assert_eq!(canonical_raft_voter_peer(&roster, prefix), Some(voter));
        assert_ne!(
            canonical_raft_voter_peer(&roster, prefix),
            Some(different_peer),
            "ambient prefix ownership cannot replace the enrolled voter"
        );
        assert!(canonical_raft_voter_peer(&roster, prefix ^ 1).is_none());

        let mismatched = vec![(prefix, different_peer.to_bytes())];
        assert!(
            canonical_raft_voter_peer(&mismatched, prefix).is_none(),
            "the roster entry must itself derive the claimed compact slot"
        );
    }

    #[test]
    fn ambiguous_promotion_selects_the_new_authenticated_leader() {
        let first = libp2p::PeerId::random();
        let first_prefix = vos::network::derive_node_prefix(&first);
        let second = loop {
            let candidate = libp2p::PeerId::random();
            if vos::network::derive_node_prefix(&candidate) != first_prefix {
                break candidate;
            }
        };
        let second_prefix = vos::network::derive_node_prefix(&second);
        let roster = vec![
            (first_prefix, first.to_bytes()),
            (second_prefix, second.to_bytes()),
        ];
        let observations = vec![
            (
                first_prefix,
                RaftStatusReply {
                    present: true,
                    role: RaftRole::Follower,
                    current_term: 7,
                    commit_index: 11,
                    last_applied: 11,
                    last_log_index: 11,
                    members: vec![first_prefix, second_prefix],
                    joint_old: None,
                    active_config_index: Some(10),
                    leader_hint: Some(first_prefix),
                },
            ),
            (
                second_prefix,
                RaftStatusReply {
                    present: true,
                    role: RaftRole::Leader,
                    current_term: 8,
                    commit_index: 12,
                    last_applied: 12,
                    last_log_index: 12,
                    members: vec![first_prefix, second_prefix],
                    joint_old: None,
                    active_config_index: Some(12),
                    leader_hint: Some(second_prefix),
                },
            ),
        ];

        assert_eq!(
            select_authenticated_raft_leader(observations, &roster),
            Some(second_prefix),
            "a failed original leader cannot pin an ambiguous prepared join"
        );
    }

    #[test]
    fn non_voter_defers() {
        let plan = decide_raft_spawn(0x0003, &[0x0001, 0x0002], false, &[], 2);
        assert!(matches!(plan, RaftPlan::Defer(_)));
    }

    #[test]
    fn anchored_db_spawns_with_voter_seed() {
        // The persisted config governs; the seed just has to be the
        // current voter set so the worker spawns in multi-mode.
        let plan = decide_raft_spawn(0x0001, &[0x0001, 0x0002], true, &[], 1);
        assert_eq!(plan, RaftPlan::Spawn(vec![0x0001, 0x0002]));
    }

    #[test]
    fn anchored_retiring_observer_reopens_private_replica() {
        // The persisted log, not the already-demoted registry row, decides
        // whether this endpoint is still needed to acknowledge finality.
        let plan = decide_raft_spawn(0x0001, &[0x0002], true, &[], 1);
        assert_eq!(plan, RaftPlan::Spawn(vec![0x0002]));
    }

    #[test]
    fn sole_voter_bootstraps_immediately() {
        let plan = decide_raft_spawn(0x0001, &[0x0001], false, &[], 0);
        assert_eq!(plan, RaftPlan::Bootstrap { contested: false });
    }

    #[test]
    fn floor_filter_narrows_spawning_by_membership() {
        use vos::registry::SyncFloor;
        // Public rows always spawn, member or not.
        assert!(node_meets_floor(false, SyncFloor::Public));
        assert!(node_meets_floor(true, SyncFloor::Public));
        // A non-member is narrowed out of Member/Private rows.
        assert!(!node_meets_floor(false, SyncFloor::Member));
        assert!(!node_meets_floor(false, SyncFloor::Private));
        // A member spawns everything. (`node_is_member` errs toward `true` — a
        // granted operator, an enrolled voter, or any probe failure — so a
        // legitimate member is never narrowed out.)
        assert!(node_meets_floor(true, SyncFloor::Member));
        assert!(node_meets_floor(true, SyncFloor::Private));
    }

    #[test]
    fn live_group_counting_us_respawns_with_its_members() {
        // A wiped node the group still counts as a voter rejoins by
        // spawning with the group's view; the leader catches it up.
        let probes = vec![(
            0x0001,
            status(RaftRole::Leader, vec![0x0001, 0x0002], Some(0x0001)),
        )];
        let plan = decide_raft_spawn(0x0002, &[0x0001, 0x0002], false, &probes, 1);
        assert_eq!(plan, RaftPlan::Spawn(vec![0x0001, 0x0002]));
    }

    #[test]
    fn live_group_led_by_probed_voter_joins_there() {
        let probes = vec![(0x0001, status(RaftRole::Leader, vec![0x0001], Some(0x0001)))];
        let plan = decide_raft_spawn(0x0002, &[0x0001, 0x0002], false, &probes, 1);
        assert_eq!(
            plan,
            RaftPlan::Join {
                leader: 0x0001,
                known: vec![0x0001],
            },
        );
    }

    #[test]
    fn live_group_follower_redirects_join_to_hint() {
        // Probed a follower of a three-voter group; its hint names
        // the leader we didn't probe.
        let probes = vec![(
            0x0002,
            status(RaftRole::Follower, vec![0x0001, 0x0002], Some(0x0001)),
        )];
        let plan = decide_raft_spawn(0x0003, &[0x0001, 0x0002, 0x0003], false, &probes, 2);
        assert_eq!(
            plan,
            RaftPlan::Join {
                leader: 0x0001,
                known: vec![0x0001, 0x0002],
            },
        );
    }

    #[test]
    fn live_group_without_leader_defers() {
        let probes = vec![(0x0001, status(RaftRole::Candidate, vec![0x0001], None))];
        let plan = decide_raft_spawn(0x0002, &[0x0001, 0x0002], false, &probes, 1);
        assert!(matches!(plan, RaftPlan::Defer(_)));
    }

    #[test]
    fn absent_everywhere_only_smallest_voter_bootstraps_contested() {
        let probes = vec![(0x0002, absent())];
        let plan = decide_raft_spawn(0x0001, &[0x0001, 0x0002], false, &probes, 1);
        assert_eq!(plan, RaftPlan::Bootstrap { contested: true });

        let probes = vec![(0x0001, absent())];
        let plan = decide_raft_spawn(0x0002, &[0x0001, 0x0002], false, &probes, 1);
        assert!(matches!(plan, RaftPlan::Defer(_)));
    }

    #[test]
    fn unreachable_voter_blocks_contested_bootstrap() {
        // Two other voters, only one answered: no positive
        // confirmation, no bootstrap — the group may live on the
        // silent one.
        let probes = vec![(0x0002, absent())];
        let plan = decide_raft_spawn(0x0001, &[0x0001, 0x0002, 0x0003], false, &probes, 2);
        assert!(matches!(plan, RaftPlan::Defer(_)));
    }
}
