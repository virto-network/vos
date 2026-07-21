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
use vos::actors::client::{ClientError, Invoker};
use vos::node::{AgentConfig, Consistency, VosNode};
use vos::registry::{RegistryRef, Status};

use crate::blob_store::{self, BlobHash};
use crate::commands::space::common::{
    consistency_from_u8, derive_hyperspace_id, instance_service_id, registry_replication_id,
    v2_root_actor_id, v2_root_service_id,
};
use crate::commands::space::{payload_codec, reconcile, subscriptions};
use crate::spaces_index;

const PENDING_INVITE_FILE: &str = ".pending-invite.token";

pub struct Args {
    pub query: String,
    pub once: bool,
    pub listen: Vec<String>,
    pub connect: Vec<String>,
    pub service_pvm: Option<PathBuf>,
}

#[derive(Clone)]
struct PinnedV2Service {
    pvm: std::sync::Arc<Vec<u8>>,
    program: vos::v2::ProgramId,
}

fn load_pinned_v2_service(path: Option<&Path>) -> anyhow::Result<Option<PinnedV2Service>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let pvm = std::fs::read(path)
        .map_err(|error| anyhow::anyhow!("read pinned service PVM {}: {error}", path.display()))?;
    javm::program::parse_blob(&pvm)
        .ok_or_else(|| anyhow::anyhow!("{} is not a canonical JAR PVM", path.display()))?;
    vos::v2::ServicePvmV2::new(pvm.clone(), vos::v2::ProgramId::of_pvm(&pvm))
        .map_err(|error| anyhow::anyhow!("invalid generic service PVM: {error}"))?;
    Ok(Some(PinnedV2Service {
        program: vos::v2::ProgramId::of_pvm(&pvm),
        pvm: std::sync::Arc::new(pvm),
    }))
}

pub fn run(args: Args) -> anyhow::Result<()> {
    // Trivalent positional (decision 1): an existing `.toml` recipe
    // (create-if-missing + genesis apply), a `vos1…` invite token
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
    // PVM kernel needs the transpiled JAR blob.
    let blob = grey_transpiler::link_elf(&elf)
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
    let mut pending_token = load_pending_token(&data_dir)?;
    let pinned_v2_service = load_pinned_v2_service(args.service_pvm.as_deref())?;

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

    // Node-local policy is now the single source of truth alongside the
    // registry: `local.toml`. A bare `space up` restart re-applies every
    // agent's `tick_ms` / `intra_caps` / device-seed provisioning and the
    // `[[extension]]` registrations from here — the standing bug where a
    // restart silently dropped them is gone.
    let local_cfg = subscriptions::load(&data_dir).unwrap_or_default();
    let agent_policies = agent_policies_from_local(&local_cfg)?;
    let device_secret_agents = device_secret_agents_from_local(&local_cfg);

    // Register node-local `.so` extensions from `local.toml`, returning
    // each one's effective relay caps for the endpoint descriptor
    // (`space describe` / `space caps`).
    let extension_caps =
        register_extensions_from_local(&mut node, &local_cfg, &data_dir, local_prefix)?;

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
        pinned_v2_service.as_ref(),
    )?;

    // Provision device-local secret seeds for agents that declared
    // `device_secret = true` (the messenger's MLS CSPRNG root). Runs after
    // spawn so the targets are live; the seed never touches the replicated
    // registry — it lives only in a node-local sidecar. Idempotent.
    provision_device_seeds(&node, &device_secret_agents, &data_dir, local_prefix);

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
        let has_hyperspace = hyperspace.is_some();
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
        // chronos clock/randomness feed (`vos::chronos_feed::ChronosFeeder`): a
        // separate, faster keepalive gate than the spawn-reconcile pass. The
        // per-space domain is the space id; the feeder holds its own cross-pass
        // state and the node's static VRF keypair. A node.key read failure
        // disables the feed rather than the whole daemon.
        let mut chronos_feeder =
            match vos::chronos_feed::ChronosFeeder::new(&data_dir, entry.id.as_bytes().to_vec()) {
                Ok(f) => Some(f),
                Err(e) => {
                    tracing::warn!("chronos feed disabled: {e}");
                    None
                }
            };
        let mut last_feed = std::time::Instant::now();
        node.run_forever_with(|n| {
            if last_feed.elapsed() >= CHRONOS_FEED_EVERY {
                last_feed = std::time::Instant::now();
                if let Some(feeder) = chronos_feeder.as_mut() {
                    feeder.feed(n, local_prefix);
                }
            }
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
                has_hyperspace,
                &local_cfg,
                &mut damped,
                &mut boot_grace,
                &in_flight,
                &agent_policies,
                pinned_v2_service.as_ref(),
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

/// Bounded per-attempt timeout for the redeem invoke — short so the
/// router tick isn't stalled by a slow bootnode.
const REDEEM_INVOKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

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
    //     unambiguous — a space name may not start with `vos1` and a
    //     token is never a path.
    if is_recipe_path(&raw) {
        return resolve_recipe(&raw);
    }
    // (b) token: a `vos1…` string.
    if raw.starts_with(crate::token::TOKEN_HRP) {
        return resolve_token(&raw);
    }
    // (c) known name / id — the caller resolves it via `spaces_index::find`.
    Ok(raw)
}

fn is_recipe_path(arg: &str) -> bool {
    arg.ends_with(".toml") && Path::new(arg).is_file()
}

/// Read a `vos1…` token from stdin (`space up -`), keeping a bearer
/// string out of argv / shell history.
fn read_token_stdin() -> anyhow::Result<String> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| anyhow::anyhow!("read token from stdin: {e}"))?;
    let tok = buf.trim().to_string();
    if tok.is_empty() {
        anyhow::bail!("no token on stdin (`space up -` expects a vos1… token piped in)");
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

    let mut index = spaces_index::load()?;
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
    spaces_index::save(&index)?;
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

    let mut index = spaces_index::load()?;
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
    spaces_index::save(&index)?;
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
    let space_dir = crate::paths::space_dir(&payload.space_id);
    if !space_dir.exists() {
        std::fs::create_dir_all(&space_dir)?;
        std::fs::create_dir_all(space_dir.join("agents"))?;
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        let key_bytes = keypair
            .to_protobuf_encoding()
            .map_err(|e| anyhow::anyhow!("encode keypair: {e}"))?;
        std::fs::write(space_dir.join("node.key"), key_bytes)?;
    }
    let mut index = spaces_index::load().unwrap_or_default();
    let mut entry = spaces_index::entry_for(&payload.space_id, &payload.name);
    entry.data_dir = space_dir.to_string_lossy().to_string();
    entry.registry_hash = registry_hash.to_hex();
    entry.bootnodes = payload.bootnodes.clone();
    spaces_index::upsert(&mut index, entry);
    spaces_index::save(&index)?;
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
    if let Ok(agents) = vos::block_on(reg.agents(&mut &*node)) {
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
            relay_unauthenticated: e.relay_unauthenticated,
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

/// A bounded-timeout [`Invoker`] over the running node — so a redeem
/// attempt to a slow or vanished bootnode can't stall the router tick
/// for the node's 10 s default.
struct TimedNode<'a> {
    node: &'a VosNode,
    timeout: std::time::Duration,
}

impl Invoker for TimedNode<'_> {
    fn invoke(
        &mut self,
        target: ServiceId,
        payload: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<vos::value::Value, ClientError>> + '_ {
        let outcome = self.node.invoke_with_timeout(target, payload, self.timeout);
        async move {
            match outcome {
                Some(b) if b.is_empty() => Ok(vos::value::Value::Unit),
                Some(b) => Ok(<vos::value::Value as vos::Decode>::decode(&b)),
                None => Err(ClientError::Unreachable),
            }
        }
    }
}

/// One redeem attempt: build the joiner's two signatures and invoke each
/// connected peer's `redeem_invite` until one grants this node's key.
/// `Ok(true)` = accepted (clear the pending token); `Ok(false)` = no
/// peer answered `Ok` this pass (retry); `Err` = malformed token /
/// unreadable key (warned once, then retried).
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
    let redeem_sig = crate::token::redeem_sig(&payload, &node_peer_id)?.to_vec();
    let redeem_canon =
        vos::registry::canonical_op_bytes("redeem_invite", &[&payload.token_pub, &node_peer_id]);
    let node_sig = node_kp
        .sign(&redeem_canon)
        .map_err(|e| anyhow::anyhow!("node_sig sign: {e}"))?;

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
            timeout: REDEEM_INVOKE_TIMEOUT,
        };
        let status = vos::block_on(reg.redeem_invite(
            &mut inv,
            payload.token_pub.to_vec(),
            payload.role,
            payload.expires_at,
            payload.admin_peer_id.clone(),
            payload.admin_sig.to_vec(),
            node_peer_id.clone(),
            redeem_sig.clone(),
            node_sig.clone(),
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
    let mut index = spaces_index::load()?;
    if let Some(entry) = index.spaces.iter_mut().find(|e| e.id == space_id_hex) {
        clear(entry);
        spaces_index::save(&index)?;
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

/// Node-local per-agent policy from the recipe (never replicated): the
/// periodic `tick_ms` and the parsed `intra_caps` relay bound.
#[derive(Default, Clone)]
struct AgentLocalPolicy {
    tick_ms: Option<u64>,
    intra_caps: Vec<vos::IntraCap>,
    device_secret: bool,
}

type AgentPolicies = std::collections::BTreeMap<String, AgentLocalPolicy>;

/// Collect the `tick_ms` / `intra_caps` policy for each agent from
/// `local.toml`. Parses the `intra_caps` strings eagerly so a malformed
/// cap fails the boot (like the extension path).
fn agent_policies_from_local(cfg: &subscriptions::LocalConfig) -> anyhow::Result<AgentPolicies> {
    let mut map = AgentPolicies::new();
    for (name, a) in &cfg.agents {
        let mut intra_caps = Vec::with_capacity(a.intra_caps.len());
        for tok in &a.intra_caps {
            intra_caps.push(
                vos::IntraCap::parse(tok)
                    .map_err(|e| anyhow::anyhow!("agent '{name}': intra_cap '{tok}': {e}"))?,
            );
        }
        let tick_ms = a.tick_ms.filter(|ms| *ms > 0);
        if tick_ms.is_some() || !intra_caps.is_empty() || a.device_secret {
            map.insert(
                name.clone(),
                AgentLocalPolicy {
                    tick_ms,
                    intra_caps,
                    device_secret: a.device_secret,
                },
            );
        }
    }
    Ok(map)
}

/// The instance names flagged `device_secret = true` in `local.toml` —
/// each gets a node-local CSPRNG seed provisioned post-spawn.
fn device_secret_agents_from_local(cfg: &subscriptions::LocalConfig) -> Vec<String> {
    cfg.agents
        .iter()
        .filter(|(_, a)| a.device_secret)
        .map(|(n, _)| n.clone())
        .collect()
}

/// Provision each `device_secret = true` agent with a node-local CSPRNG seed
/// (the messenger's MLS confidentiality root). The seed is 32 bytes of OS
/// entropy held in a `{data_dir}/agents/{svc_id:08x}.seed` sidecar — node-local
/// like the P0 `.seal`, never replicated — and delivered by a `seed` message
/// over a local `Caller::System` invoke (a node-local, host-initiated path
/// that bypasses the auth gate). Idempotent: the agent persists the seed in
/// its Local redb, so a re-send on a later boot is a no-op. Best-effort — a
/// failure to seed is logged, not fatal.
fn provision_device_seeds(
    node: &VosNode,
    agents: &[String],
    data_dir: &std::path::Path,
    daemon_prefix: u16,
) {
    for name in agents {
        let svc_id = crate::commands::space::common::instance_service_id(name, daemon_prefix);
        let seed = match load_or_mint_device_seed(data_dir, svc_id) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(agent = %name, "device seed: {e}");
                continue;
            }
        };
        let msg = vos::value::Msg::new("seed").with("seed_bytes", seed);
        let encoded = vos::Encode::encode(&msg);
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(vos::value::TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        match node.invoke_with_timeout(svc_id, payload, std::time::Duration::from_secs(5)) {
            Some(_) => tracing::info!(agent = %name, "device seed provisioned"),
            None => tracing::warn!(
                agent = %name,
                "device seed: provisioning invoke returned no reply (agent not spawned?)"
            ),
        }
    }
}

/// Load an agent's 32-byte device seed from its node-local sidecar, minting
/// fresh OS entropy (persisted `0600`) on first boot.
fn load_or_mint_device_seed(
    data_dir: &std::path::Path,
    svc_id: ServiceId,
) -> anyhow::Result<Vec<u8>> {
    let dir = data_dir.join("agents");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{:08x}.seed", svc_id.0));
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes);
        }
        tracing::warn!(?path, "device seed sidecar has wrong length; re-minting");
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| anyhow::anyhow!("OS entropy for device seed: {e}"))?;
    write_secret_file(&path, &seed)?;
    Ok(seed.to_vec())
}

/// Write a secret file, `0600` on Unix.
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, bytes)?;
    Ok(())
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
    pinned_v2_service: Option<&PinnedV2Service>,
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
    let agents =
        vos::block_on(reg.agents(&mut &*node)).map_err(|e| anyhow::anyhow!("query agents: {e}"))?;

    // Set of svc_ids the catalog knows about — used at the
    // end to sweep orphaned redbs into trash. We add to this
    // even for skipped agents (subscriptions filter, missing
    // blob, …) so we don't accidentally trash their state.
    let mut live_svc_ids: HashSet<u32> = HashSet::new();
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
    }

    // Contested raft bootstraps always defer at boot (their grace
    // spans reconcile passes); the throwaway map just satisfies the
    // protocol — the runtime reconciler owns the durable counters.
    let mut boot_grace = BootGrace::new();
    // Whether this node is a space member, probed once; rows whose sync floor
    // requires membership are narrowed out on a non-member. The runtime
    // reconciler re-evaluates each pass, so a row spawns if a grant lands later.
    let is_member = node_is_member(node, &reg, local_prefix);
    for a in agents {
        if !local_cfg.should_spawn(&a.instance_name) {
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
        // Raft rows resolve their member seed first — see the
        // runtime reconciler for the full rationale.
        let is_v2_package = blob_store::cache_get(&BlobHash(a.program_hash))?
            .is_some_and(|artifact| artifact.get(..4) == Some(b"VOSP"));
        let raft_members =
            if consistency_from_u8(a.consistency) == Some(Consistency::Raft) && !is_v2_package {
                if !blob_store::cache_path_for(&BlobHash(a.program_hash)).exists() {
                    tracing::warn!(
                        "skipping agent '{}' — program blob {} not in local cache",
                        a.instance_name,
                        BlobHash(a.program_hash),
                    );
                    continue;
                }
                match raft_members_for_row(node, data_dir, &a, local_prefix, &mut boot_grace) {
                    Ok(RaftSeed::Members(m)) => Some(m),
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
        match agent_config_from_row(data_dir, space_id, &a, policies, pinned_v2_service)? {
            RowConfig::Ready(cfg) => {
                let mut cfg = *cfg;
                if let Some(members) = raft_members {
                    cfg.members = members;
                }
                let svc_id = instance_service_id(&a.instance_name, local_prefix);
                let id = node.register_at_id(cfg, svc_id);
                tracing::info!(
                    "agent '{}' as {id} ({})",
                    a.instance_name,
                    crate::commands::space::common::consistency_name(a.consistency),
                );
            }
            RowConfig::V2 {
                config,
                state_path,
                network_reachable,
            } => {
                let service = vos::v2::LocalRootTreeServiceV2::open(
                    *config,
                    vos::v2::FileCommittedImageStoreV2::new(state_path),
                )
                .map_err(|error| {
                    anyhow::anyhow!("open v2 root tree '{}': {error:?}", a.instance_name)
                })?;
                let svc_id = instance_service_id(&a.instance_name, local_prefix);
                let id = node
                    .register_v2_root_at_id(
                        a.instance_name.clone(),
                        service,
                        svc_id,
                        network_reachable,
                    )
                    .map_err(|error| anyhow::anyhow!("register v2 root tree: {error}"))?;
                tracing::info!("v2 root tree '{}' as {id} (local)", a.instance_name);
            }
            RowConfig::MissingBlob => {
                tracing::warn!(
                    "skipping agent '{}' — program blob {} not in local cache",
                    a.instance_name,
                    BlobHash(a.program_hash),
                );
            }
            RowConfig::BadConsistency => {
                tracing::warn!(
                    "skipping agent '{}' — unknown consistency {}",
                    a.instance_name,
                    a.consistency,
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

/// How often the leader commits a chronos `advance`. This is a keepalive
/// cadence, deliberately NOT the 250 ms slot rate: every state-changing advance
/// is a raft commit, so feeding the clock at 4 Hz would be 4 commits/s/space —
/// too heavy for a chat workload. One commit/second bounds clock freshness to
/// ~1 s while folding roughly one entropy epoch per commit. Piggybacking the
/// slot stamp on the msg-ctl commits a space already makes (sub-second freshness
/// with no extra commits) is the future optimisation; this is the idle-keepalive
/// half of that design.
const CHRONOS_FEED_EVERY: std::time::Duration = std::time::Duration::from_secs(1);

/// Outcome of resolving one registry `AgentRow` into a spawnable
/// [`AgentConfig`].
enum RowConfig {
    Ready(Box<AgentConfig>),
    V2 {
        config: Box<vos::v2::LocalRootTreeConfigV2>,
        state_path: PathBuf,
        network_reachable: bool,
    },
    /// Program blob not in the local cache. On a joiner the row
    /// can arrive via registry sync before the operator has the
    /// blob, so this is retryable, not fatal.
    MissingBlob,
    /// Unrecognized consistency discriminant.
    BadConsistency,
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
    policies: &AgentPolicies,
    pinned_v2_service: Option<&PinnedV2Service>,
) -> anyhow::Result<RowConfig> {
    let program_hash = BlobHash(a.program_hash);
    let artifact = match blob_store::cache_get(&program_hash)? {
        Some(b) => b,
        None => return Ok(RowConfig::MissingBlob),
    };
    let Some(consistency) = consistency_from_u8(a.consistency) else {
        return Ok(RowConfig::BadConsistency);
    };
    if artifact.get(..4) == Some(b"VOSP") {
        return v2_config_from_row(
            data_dir,
            space_id,
            a,
            policies,
            consistency,
            artifact,
            pinned_v2_service,
        );
    }
    let blob = actor_blob_from_catalog(artifact, &a.instance_name)?;

    let needs_persistence = matches!(
        consistency,
        Consistency::Local | Consistency::Crdt | Consistency::Raft
    );
    let needs_replication = matches!(consistency, Consistency::Crdt | Consistency::Raft);
    let mut cfg = AgentConfig::new(blob)
        .with_name(a.instance_name.clone())
        .with_consistency(consistency);
    if needs_persistence {
        cfg = cfg.persist(data_dir);
    }
    if needs_replication {
        cfg = cfg.with_replication_id(a.replication_id);
    }
    // A node-confined (Local/Ephemeral) agent opts out of the device gate so
    // remote peers can reach it — the network-served bridges. No-op for
    // Crdt/Raft (never confined).
    if a.network_reachable {
        cfg = cfg.network_reachable();
    }
    if !a.install_args.is_empty() {
        cfg = cfg.with_storage(vec![(
            vos::lifecycle::INIT_KEY.to_vec(),
            a.install_args.clone(),
        )]);
    }

    // on_start payloads (from recipe reconciliation) get
    // dispatched on cold start. Stored as rkyv-encoded
    // `Vec<Vec<u8>>` on the agent row.
    match payload_codec::decode(&a.install_payloads) {
        Ok(payloads) if !payloads.is_empty() => {
            cfg = cfg.with_init_payloads(payloads);
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                "agent '{}' has unparseable install_payloads, ignoring: {e}",
                a.instance_name,
            );
        }
    }

    // Node-local recipe policy (never replicated): periodic `tick` cadence
    // and the bounded outbound-relay caps.
    if let Some(policy) = policies.get(&a.instance_name) {
        if let Some(ms) = policy.tick_ms {
            cfg = cfg.with_tick_ms(ms);
        }
        if !policy.intra_caps.is_empty() {
            cfg = cfg.with_intra_caps(policy.intra_caps.clone());
        }
    }
    Ok(RowConfig::Ready(Box::new(cfg)))
}

fn v2_config_from_row(
    data_dir: &Path,
    space_id: [u8; 32],
    row: &vos::registry::AgentRow,
    policies: &AgentPolicies,
    consistency: Consistency,
    exact_package: Vec<u8>,
    pinned: Option<&PinnedV2Service>,
) -> anyhow::Result<RowConfig> {
    use vos::v2::V2Wire;

    let pinned = pinned.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is a VOS v2 package; restart `space up` with \
             --service-pvm <exact-vos-service.pvm>",
            row.instance_name
        )
    })?;
    let package = vos::v2::VosPackageV2::decode(&exact_package)
        .map_err(|error| anyhow::anyhow!("decode {} package: {error}", row.instance_name))?;
    package
        .validate()
        .map_err(|error| anyhow::anyhow!("validate {} package: {error}", row.instance_name))?;
    if package.encode() != exact_package {
        anyhow::bail!("{} package wire is not canonical", row.instance_name);
    }
    verify_v2_package_signature(&package, &row.instance_name)?;
    if package.manifest.service_program != pinned.program {
        anyhow::bail!(
            "{} is pinned to service ProgramId {}, but the daemon loaded {}",
            row.instance_name,
            hex::encode(package.manifest.service_program.0),
            hex::encode(pinned.program.0),
        );
    }
    match (package.manifest.crdt, consistency) {
        (false, Consistency::Crdt) => anyhow::bail!(
            "{} is an ordinary #[actor] package and cannot select CRDT consistency; \
             install it as local or raft",
            row.instance_name
        ),
        (true, Consistency::Crdt) => anyhow::bail!(
            "{} requires the v2 CRDT anti-entropy driver, which is not attached to space up yet",
            row.instance_name
        ),
        (_, Consistency::Raft) => anyhow::bail!(
            "{} requires the v2 Raft request-log driver, which is not attached to space up yet",
            row.instance_name
        ),
        (_, Consistency::Ephemeral) => anyhow::bail!(
            "{} v2 ephemeral hosting is not enabled; install it with local consistency",
            row.instance_name
        ),
        (true, Consistency::Local) => anyhow::bail!(
            "{} is #[actor(crdt)] and must be installed with CRDT consistency",
            row.instance_name
        ),
        (false, Consistency::Local) => {}
    }
    if !row.install_args.is_empty() || !row.install_payloads.is_empty() {
        anyhow::bail!(
            "{} uses legacy install args/on_start payloads; v2 initialization must be an explicit actor invocation",
            row.instance_name
        );
    }
    if policies
        .get(&row.instance_name)
        .is_some_and(|policy| {
            policy.tick_ms.is_some() || !policy.intra_caps.is_empty() || policy.device_secret
        })
    {
        anyhow::bail!(
            "{} uses legacy tick/intra_caps/device_secret policy; v2 timers, calls, and secrets use explicit durable inputs",
            row.instance_name
        );
    }

    let space = vos::v2::SpaceId(space_id);
    let root_service = v2_root_service_id(space, &row.instance_name);
    let root_actor = v2_root_actor_id(root_service, &row.instance_name);
    let deployment = package.deployment_id();
    let state_path = data_dir
        .join("v2-services")
        .join(format!("{}.image", hex::encode(root_service.0)));
    let install_authenticator = package.deployment_signature.signature.clone();
    Ok(RowConfig::V2 {
        config: Box::new(vos::v2::LocalRootTreeConfigV2 {
            service_pvm: pinned.pvm.as_ref().clone(),
            package,
            service: vos::v2::ServiceIdentityV2 {
                space,
                root_service,
                deployment,
                service_program: pinned.program,
                service_abi: vos::v2::ABI_VERSION,
                execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            },
            root_actor,
            actor_name: row.instance_name.clone(),
            consistency: vos::v2::ConsistencyModeV2::Local,
            initial_state: vec![],
            external_actors: vec![],
            install_authorization: vos::v2::AuthorizationEvidenceV2::SystemCapability {
                capability: vos::v2::SystemCapabilityId(
                    vos::v2::Hash::digest(
                        b"vos/space-install-capability/v2",
                        &[&space_id, &deployment.0],
                    )
                    .0,
                ),
                authenticator: install_authenticator,
            },
            refine_gas: 1_000_000_000,
            accumulate_gas: 5_000_000_000,
        }),
        state_path,
        network_reachable: row.network_reachable,
    })
}

fn verify_v2_package_signature(
    package: &vos::v2::VosPackageV2,
    instance_name: &str,
) -> anyhow::Result<()> {
    let public_key =
        libp2p::identity::PublicKey::try_decode_protobuf(&package.deployment_signature.public_key)
            .map_err(|error| anyhow::anyhow!("decode {instance_name} deployment key: {error}"))?;
    if !public_key.verify(
        &package.signing_message(),
        &package.deployment_signature.signature,
    ) {
        anyhow::bail!("{instance_name} deployment signature is invalid");
    }
    Ok(())
}

/// Recover executable bytes from one content-addressed catalog artifact.
///
/// Resolve only artifacts that the legacy one-service-per-actor host may run.
///
/// A signed v2 package is a root-tree deployment input, not an actor blob for
/// [`VosNode`]. Extracting its canonical actor PVM here would execute it in the
/// native `RefinePayload`/`EffectLog` runtime and silently discard its pinned
/// generic-service, deployment, and guest-Accumulate semantics. Fail closed
/// until this daemon path installs the complete package through
/// `vos-service.pvm`.
fn actor_blob_from_catalog(artifact: Vec<u8>, instance_name: &str) -> anyhow::Result<Vec<u8>> {
    if artifact.get(..4) == Some(b"VOSP") {
        anyhow::bail!(
            "{instance_name} is a VOS v2 package and cannot run in the legacy actor runtime; \
             install it through the root-tree vos-service.pvm host"
        );
    }
    if artifact.get(..3) == Some(b"JAR") {
        javm::program::parse_blob(&artifact)
            .ok_or_else(|| anyhow::anyhow!("{instance_name} canonical PVM is invalid"))?;
        return Ok(artifact);
    }
    grey_transpiler::link_elf(&artifact)
        .map_err(|error| anyhow::anyhow!("transpile legacy {instance_name}: {error:?}"))
}

/// Per-voter wait for a `RaftStatusReq` answer. Probes run on the
/// router thread (routing paused) against already-connected peers
/// only, so the worst case per pass is a handful of sub-second
/// waits on connected-but-slow voters.
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

    if !voters.contains(&local) {
        return RaftPlan::Defer(
            "this node is not a voter (enroll it with `vosx space members add-node`)".into(),
        );
    }
    if anchored {
        // The persisted active config supersedes the seed; the
        // voter set just has to be non-empty to spawn the worker.
        return RaftPlan::Spawn(voters.to_vec());
    }
    if voters == [local] {
        return RaftPlan::Bootstrap { contested: false };
    }

    // A live group somewhere wins over any bootstrap theory.
    let live: Vec<&(u16, vos::network::RaftStatusReply)> =
        probes.iter().filter(|(_, r)| r.present).collect();
    for (_, reply) in &live {
        if reply.members.contains(&local) {
            // The group already counts us as a member (a wiped db
            // rejoining): spawn and let the leader catch us up.
            return RaftPlan::Spawn(reply.members.clone());
        }
    }
    if let Some((v, reply)) = live.iter().find(|(_, r)| r.role == RaftRole::Leader) {
        return RaftPlan::Join {
            leader: *v,
            known: reply.members.clone(),
        };
    }
    if let Some((_, reply)) = live.iter().find(|(_, r)| r.leader_hint.is_some()) {
        return RaftPlan::Join {
            leader: reply.leader_hint.expect("filtered on is_some"),
            known: reply.members.clone(),
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
    Members(Vec<u16>),
    Defer(String),
}

/// Grace counters for contested bootstraps, keyed like the damping
/// set. Entries are removed when the row spawns or the decision
/// changes away from bootstrap.
type BootGrace = std::collections::HashMap<(String, [u8; 32]), u32>;

/// Run the membership protocol for one raft row: read the voter
/// set, probe connected voters for the group, join a live group
/// through its leader, or anchor + bootstrap a brand-new one.
/// Called before the row's (expensive) transpile so a defer costs
/// little, and so the join handshake only ever fires when the
/// spawn follows it.
fn raft_members_for_row(
    node: &VosNode,
    data_dir: &std::path::Path,
    a: &vos::registry::AgentRow,
    local_prefix: u16,
    boot_grace: &mut BootGrace,
) -> anyhow::Result<RaftSeed> {
    use vos::registry::{MEMBER_KIND_NODE, NODE_ROLE_VOTER, RegistryRef};

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

    let svc_id = instance_service_id(&a.instance_name, local_prefix);
    let db_path = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", svc_id.0));
    let anchored = db_path.exists()
        && vos::raft::persisted_membership(&db_path)
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
            let Some(peer) = net.peer_for_prefix(v) else {
                continue; // not connected — can't confirm anything about it
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
        RaftPlan::Spawn(members) => Ok(RaftSeed::Members(members)),
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
            vos::raft::seed_initial_config(&db_path, &[local_prefix])
                .map_err(|e| anyhow::anyhow!("seed raft config for '{}': {e}", a.instance_name))?;
            Ok(RaftSeed::Members(vec![local_prefix]))
        }
        RaftPlan::Join { leader, known } => {
            let Some(net) = net else {
                return Ok(RaftSeed::Defer("no network attached".into()));
            };
            join_raft_group(&net, a, local_prefix, leader, known)
        }
    }
}

/// Ask the group's leader to admit this node as a voter, following
/// at most one leadership redirect. On `Accepted`, re-probe the
/// leader for the freshest member set (a joiner admitted between
/// our probe and our join must be in our seed, or we'd reject its
/// votes until the log catches up) and fall back to the probed
/// `known` view when the re-probe fails.
fn join_raft_group(
    net: &std::sync::Arc<vos::network::Network>,
    a: &vos::registry::AgentRow,
    local_prefix: u16,
    mut leader: u16,
    known: Vec<u16>,
) -> anyhow::Result<RaftSeed> {
    use vos::network::RaftJoinResult;

    for _redirect in 0..2 {
        let Some(peer) = net.peer_for_prefix(leader) else {
            return Ok(RaftSeed::Defer(format!(
                "raft leader {leader:#06x} is not connected",
            )));
        };
        let rx = net.send_raft_join_req(peer, a.replication_id, local_prefix);
        match rx.recv_timeout(RAFT_JOIN_TIMEOUT) {
            Ok(RaftJoinResult::Accepted { .. }) => {
                let mut members = match net
                    .send_raft_status_req(peer, a.replication_id)
                    .recv_timeout(RAFT_PROBE_TIMEOUT)
                {
                    Ok(st) if st.present && !st.members.is_empty() => st.members,
                    _ => known,
                };
                members.push(local_prefix);
                members.sort_unstable();
                members.dedup();
                tracing::info!(
                    "agent '{}': joined raft group as voter (leader {leader:#06x}, {} member(s))",
                    a.instance_name,
                    members.len(),
                );
                return Ok(RaftSeed::Members(members));
            }
            Ok(RaftJoinResult::NotLeader {
                leader_hint: Some(h),
            }) if h != leader => {
                leader = h; // follow one redirect
            }
            Ok(RaftJoinResult::NotLeader { .. }) => {
                return Ok(RaftSeed::Defer(
                    "leadership moved during the join handshake".into(),
                ));
            }
            Ok(RaftJoinResult::Busy) => {
                return Ok(RaftSeed::Defer(
                    "another membership change is in flight".into(),
                ));
            }
            Ok(RaftJoinResult::UnknownGroup) => {
                return Ok(RaftSeed::Defer(format!(
                    "peer {leader:#06x} no longer runs the group",
                )));
            }
            Ok(RaftJoinResult::NotAuthorized) => {
                // Permanent refusal — this node isn't an enrolled voter.
                // Don't retry; an admin must enrol it first.
                return Ok(RaftSeed::Defer(format!(
                    "this node ({local_prefix:#06x}) is not enrolled as a voter for \
                     agent '{}'; an admin must run `vosx space members add <peer> \
                     --role voter`",
                    a.instance_name,
                )));
            }
            Err(_) => {
                return Ok(RaftSeed::Defer("join request timed out".into()));
            }
        }
    }
    Ok(RaftSeed::Defer("leader redirects did not converge".into()))
}

/// Cap on agents brought up in a single reconcile pass. The pass
/// runs on the router thread (routing paused), and each spawn
/// costs an ELF transpile + redb open + thread spawn — bounding
/// the batch keeps a burst of synced rows from freezing routing,
/// and rate-limits how fast a (possibly hostile) flood of
/// registry rows can amplify into local threads. Remaining rows
/// spawn on subsequent passes.
const MAX_SPAWNS_PER_PASS: usize = 4;

/// A row condition already reported (and, for hard failures,
/// permanently skipped): the damping key is `(instance_name,
/// program_hash, kind)`, so reinstalling the same name with a new
/// blob re-attempts and re-reports.
type RowDamping = std::collections::HashSet<(String, [u8; 32], RowNote)>;

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
enum RowNote {
    /// Hard per-row failure (transpile error, cache IO, bad
    /// consistency, ServiceId collision). Warned once, then the
    /// row is skipped outright — no point re-running the failing
    /// work every pass.
    Failed,
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
    has_hyperspace: bool,
    local_cfg: &crate::commands::space::subscriptions::LocalConfig,
    damped: &mut RowDamping,
    boot_grace: &mut BootGrace,
    in_flight: &InFlightBlobs,
    policies: &AgentPolicies,
    pinned_v2_service: Option<&PinnedV2Service>,
) -> anyhow::Result<()> {
    use vos::registry::{RegistryRef, Status};

    let reg = RegistryRef::at(ServiceId::REGISTRY);
    let agents =
        vos::block_on(reg.agents(&mut &*node)).map_err(|e| anyhow::anyhow!("query agents: {e}"))?;

    // Whether this node is a space member, probed once for the whole pass; rows
    // whose sync floor requires membership are narrowed out below.
    let is_member = node_is_member(node, &reg, local_prefix);
    let mut spawned_this_pass = 0usize;
    for a in agents {
        if spawned_this_pass >= MAX_SPAWNS_PER_PASS {
            break;
        }
        if !local_cfg.should_spawn(&a.instance_name) {
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
        // Raft rows run the membership protocol BEFORE the
        // (expensive) transpile: a deferred row must not
        // re-transpile every 2 s, and the join handshake must only
        // fire when the spawn follows it. The blob probe comes
        // first for the same reason — joining a group we can't
        // spawn into would stall its quorum.
        let is_v2_package = blob_store::cache_get(&BlobHash(a.program_hash))?
            .is_some_and(|artifact| artifact.get(..4) == Some(b"VOSP"));
        let raft_members = if consistency_from_u8(a.consistency) == Some(Consistency::Raft)
            && !is_v2_package
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
            match raft_members_for_row(node, data_dir, &a, local_prefix, boot_grace) {
                Ok(RaftSeed::Members(m)) => {
                    damped.remove(&key(RowNote::RaftWaiting));
                    Some(m)
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
        match agent_config_from_row(data_dir, space_id, &a, policies, pinned_v2_service) {
            Ok(RowConfig::Ready(cfg)) => {
                let mut cfg = *cfg;
                if let Some(members) = raft_members {
                    cfg.members = members;
                }
                let id = node.register_at_id(cfg, svc_id);
                spawned_this_pass += 1;
                tracing::info!(
                    "agent '{}' spawned at runtime as {id} ({})",
                    a.instance_name,
                    crate::commands::space::common::consistency_name(a.consistency),
                );
                if has_hyperspace {
                    let hs_reg = RegistryRef::at(ServiceId::HYPERSPACE_REGISTRY);
                    match vos::block_on(hs_reg.register_remote(
                        &mut &*node,
                        a.instance_name.clone(),
                        local_prefix as u32,
                    )) {
                        Ok(Status::Ok) => {}
                        Ok(other) => tracing::warn!(
                            "hyperspace: register_remote('{}') returned status {other}",
                            a.instance_name,
                        ),
                        Err(e) => tracing::warn!(
                            "hyperspace: register_remote('{}') failed: {e}",
                            a.instance_name,
                        ),
                    }
                }
            }
            Ok(RowConfig::V2 {
                config,
                state_path,
                network_reachable,
            }) => {
                let service = match vos::v2::LocalRootTreeServiceV2::open(
                    *config,
                    vos::v2::FileCommittedImageStoreV2::new(state_path),
                ) {
                    Ok(service) => service,
                    Err(error) => {
                        if damped.insert(key(RowNote::Failed)) {
                            tracing::warn!(
                                "agent '{}' v2 service failed to open: {error:?}",
                                a.instance_name
                            );
                        }
                        continue;
                    }
                };
                match node.register_v2_root_at_id(
                    a.instance_name.clone(),
                    service,
                    svc_id,
                    network_reachable,
                ) {
                    Ok(id) => {
                        spawned_this_pass += 1;
                        tracing::info!("v2 root tree '{}' spawned as {id}", a.instance_name);
                    }
                    Err(error) => {
                        if damped.insert(key(RowNote::Failed)) {
                            tracing::warn!(
                                "agent '{}' v2 route failed to register: {error}",
                                a.instance_name
                            );
                        }
                    }
                }
            }
            Ok(RowConfig::MissingBlob) => {
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
            Ok(RowConfig::BadConsistency) => {
                if damped.insert(key(RowNote::Failed)) {
                    tracing::warn!(
                        "skipping agent '{}' — unknown consistency {}",
                        a.instance_name,
                        a.consistency,
                    );
                }
            }
            Err(e) => {
                if damped.insert(key(RowNote::Failed)) {
                    tracing::warn!("agent '{}' failed to spawn: {e}", a.instance_name);
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

#[cfg(test)]
mod tests {
    use super::*;
    use vos::network::{RaftRole, RaftStatusReply};

    #[test]
    fn signed_v2_packages_never_fall_through_to_the_legacy_actor_runtime() {
        let error = actor_blob_from_catalog(b"VOSP\x02\0package".to_vec(), "counter")
            .expect_err("v2 package must retain guest-owned service semantics");
        assert!(
            error
                .to_string()
                .contains("cannot run in the legacy actor runtime")
        );
    }

    #[test]
    fn agent_policies_come_from_local_toml() {
        // Node-local policy is now sourced from local.toml, not the
        // recipe — the fix for the bare-restart drop. A bare agent
        // (no tick_ms / caps) gets no policy entry; the malformed-cap
        // case fails the boot.
        let mut cfg = subscriptions::LocalConfig::default();
        cfg.agents.insert(
            "ticker".into(),
            subscriptions::AgentLocal {
                tick_ms: Some(250),
                intra_caps: vec!["space-registry:member".into()],
                device_secret: true,
            },
        );
        cfg.agents.insert(
            "plain".into(),
            subscriptions::AgentLocal {
                tick_ms: Some(0), // 0 = off → no policy
                intra_caps: vec![],
                device_secret: false,
            },
        );
        let policies = agent_policies_from_local(&cfg).unwrap();
        assert!(policies.contains_key("ticker"));
        assert_eq!(policies["ticker"].tick_ms, Some(250));
        assert_eq!(policies["ticker"].intra_caps.len(), 1);
        assert!(!policies.contains_key("plain"), "tick_ms=0 → no policy");

        let seeds = device_secret_agents_from_local(&cfg);
        assert_eq!(seeds, vec!["ticker".to_string()]);

        // A malformed intra_cap fails the boot rather than silently
        // dropping an authority bound.
        cfg.agents.insert(
            "bad".into(),
            subscriptions::AgentLocal {
                tick_ms: None,
                intra_caps: vec!["not a valid cap token !!".into()],
                device_secret: false,
            },
        );
        assert!(agent_policies_from_local(&cfg).is_err());
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
        // A `vos1…` token is never mistaken for a recipe.
        assert!(!is_recipe_path("vos1abc"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn status(role: RaftRole, members: Vec<u16>, leader_hint: Option<u16>) -> RaftStatusReply {
        RaftStatusReply {
            present: true,
            role,
            current_term: 1,
            commit_index: 1,
            last_log_index: 1,
            members,
            leader_hint,
        }
    }

    fn absent() -> RaftStatusReply {
        RaftStatusReply {
            present: false,
            role: RaftRole::Follower,
            current_term: 0,
            commit_index: 0,
            last_log_index: 0,
            members: Vec::new(),
            leader_hint: None,
        }
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
