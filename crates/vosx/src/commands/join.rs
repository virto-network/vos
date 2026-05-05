//! `vosx join <bootnode>` — attach a fresh node to a running
//! cluster.
//!
//! Dials the bootnode, fetches its `space.toml` + actor blobs
//! (or uses `--manifest` when supplied), then sends a
//! [`Frame::RaftJoinReq`] for every Raft agent the manifest
//! declares. The local node attaches as a voter for each group
//! and runs forever.
//!
//! Trust model: the manifest fetched from the bootnode is just
//! a coordination document. The replication_id of each agent is
//! derived from `blake2b(name || 0 || blob)`, so an attacker
//! who substitutes a different blob produces a different group
//! and consensus refuses to mix the two. The operator needing
//! stronger trust can supply `--manifest` to use a local copy.
//!
//! [`Frame::RaftJoinReq`]: vos::network::Frame::RaftJoinReq

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};

use vos::node::{AgentConfig, VosNode};
use vos::network::{
    derive_node_prefix, load_or_generate_identity, ManifestBlob, Network, NetworkConfig,
    RaftJoinResult,
};

use crate::manifest::{
    apply_init, encode_on_start, manifest_from, resolve_replication_id, ConsistencyDef, Manifest,
};
use crate::util::{die, exit_with_status, format_provides, load_blob};

/// Hard cap on how long we retry a single join request across
/// `NotLeader` redirects. If the cluster is mid-election the
/// joiner backs off and retries; if no leader emerges in this
/// window the join fails loudly.
const JOIN_RETRY_WINDOW: Duration = Duration::from_secs(15);

/// Backoff between retries inside [`JOIN_RETRY_WINDOW`]. Picked
/// small enough that a typical leader election (50–300 ms) is
/// caught quickly, large enough that the bootnode isn't spammed.
const JOIN_RETRY_DELAY: Duration = Duration::from_millis(150);

pub fn run(
    bootnode: &str,
    manifest_arg: Option<&Path>,
    data_dir_cli: Option<&Path>,
    no_persist: bool,
    listen_cli: &[String],
) {
    let bootnode_addr: Multiaddr = bootnode
        .parse()
        .unwrap_or_else(|e| die(&format!("invalid bootnode multiaddr {bootnode:?}: {e}")));
    let bootnode_peer = extract_peer_id(&bootnode_addr).unwrap_or_else(|| {
        die(&format!(
            "bootnode multiaddr must contain a /p2p/<peer-id> suffix; got {bootnode}",
        ))
    });

    // Local identity — written under data_dir/identity so a
    // restart re-uses the same prefix and the cluster's
    // membership view stays stable. We MUST NOT silently share
    // a directory with the bootnode (or any other node): two
    // nodes loading the same identity file would generate the
    // same `peer_id` and self-dial. Require the operator to
    // pass --data-dir explicitly so the failure mode is loud.
    let data_dir = data_dir_cli.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        die(
            "vosx join: --data-dir is required (each replica needs its own \
             keypair file under data_dir/identity). Pass --data-dir /tmp/raft-b \
             — different from any other replica's dir."
        )
    });
    let state_dir = if no_persist { None } else { Some(data_dir.clone()) };

    let listen: Vec<Multiaddr> = listen_cli
        .iter()
        .filter_map(|s| match s.parse() {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("vosx: ignoring invalid --listen {s:?}: {e}");
                None
            }
        })
        .collect();

    let keypair = load_or_generate_identity(None, Some(&data_dir))
        .unwrap_or_else(|e| die(&format!("identity: {e}")));
    let local_peer = PeerId::from(keypair.public());
    let local_prefix = derive_node_prefix(&local_peer);
    if local_peer == bootnode_peer {
        die(&format!(
            "vosx join: local identity collides with bootnode ({local_peer}). \
             Did two replicas accidentally share a --data-dir? Each replica \
             needs its own dir so it generates a fresh libp2p keypair.",
        ));
    }
    eprintln!("vosx: joining as {local_peer} (prefix {local_prefix:#06x})");

    let network = Network::start(NetworkConfig {
        keypair,
        local_prefix,
        listen,
        bootstrap: vec![bootnode_addr.clone()],
    });

    eprintln!("vosx: dialing bootnode {bootnode_addr}...");
    wait_for_handshake(&network, bootnode_peer).unwrap_or_else(|| {
        die("vosx: bootnode did not complete the Hello handshake within 10s");
    });
    let bootnode_prefix = network
        .peers_with_prefixes()
        .into_iter()
        .find(|(_, pid)| *pid == bootnode_peer)
        .map(|(p, _)| p)
        .unwrap_or_else(|| die("vosx: bootnode prefix not in prefix_map after handshake"));
    eprintln!("vosx: bootnode prefix {bootnode_prefix:#06x}");

    // ── Resolve the manifest. ─────────────────────────────────
    //
    // Trust model:
    // - With `--manifest <path>`, the operator vouches for the
    //   manifest AND every blob it references on disk. The
    //   bootnode never gets to ship binaries to us.
    // - Without `--manifest`, we fetch the bootnode's manifest
    //   AND its actor blobs. The replication_id derivation
    //   (`blake2b(name || 0 || blob)`) protects against the
    //   bootnode subbing in a different blob — a different blob
    //   produces a different rep_id and consensus refuses to
    //   mix the two — but a malicious bootnode CAN convince a
    //   joiner to run its choice of binary as a brand-new
    //   group. Use `--manifest` to defend against that.
    let (manifest, dir) = match manifest_arg {
        Some(p) => {
            let (m, d, _toml) = manifest_from(Some(p.to_path_buf()));
            // Validate every referenced blob exists locally
            // BEFORE we propose any change_membership at the
            // bootnode. A typo'd path otherwise surfaces only
            // mid-join, after we've grown the cluster.
            for a in &m.agent {
                let path = crate::manifest::resolve_entry_path(&a.name, &a.path, &a.service, &d);
                if !path.exists() {
                    die(&format!(
                        "vosx join: agent '{}' references {} which doesn't exist; \
                         build the actor first or fix the manifest's `path`",
                        a.name, path.display(),
                    ));
                }
            }
            (m, d)
        }
        None => {
            let (m, d, _blobs) = fetch_manifest_from_bootnode(&network, bootnode_peer)
                .unwrap_or_else(|e| die(&format!("vosx join: {e}")));
            (m, d)
        }
    };

    // ── Build the local VosNode + register every agent. ───────
    let mut node = VosNode::with_prefix(local_prefix);
    let mut name_ids: BTreeMap<String, u32> = BTreeMap::new();
    let mut provides_map: BTreeMap<String, Vec<u32>> = BTreeMap::new();

    for a in &manifest.agent {
        let path = crate::manifest::resolve_entry_path(&a.name, &a.path, &a.service, &dir);
        let elf_data = std::fs::read(&path)
            .unwrap_or_else(|e| die(&format!("read {}: {e}", path.display())));
        let blob = load_blob(&path);

        let mut cfg = AgentConfig::new(blob.clone()).with_consistency(a.consistency.into());
        if let Some(d) = state_dir.as_deref() {
            cfg = cfg.persist(d);
        }
        let rep_id = if matches!(a.consistency, ConsistencyDef::Crdt | ConsistencyDef::Raft) {
            let rid = resolve_replication_id(&a.name, a.replication_id.as_deref(), &blob);
            if let Some(id) = rid {
                cfg = cfg.with_replication_id(id);
            }
            rid
        } else {
            None
        };
        if a.consistency == ConsistencyDef::Raft {
            let rep_id = rep_id.unwrap_or_else(|| {
                die(&format!(
                    "agent '{}' uses raft consistency but replication_id resolves to None",
                    a.name,
                ))
            });
            // Send the join RPC and wait for the cluster to
            // commit the joint *and* retire entries before we
            // spawn our local RaftWorker. Spawning earlier is
            // racy: the worker would issue AppendEntries / vote
            // requests against a leader that doesn't yet count
            // us as a voter, and on its first restart it'd come
            // up with `effective_cfg = [self, bootnode]` instead
            // of the real cluster set.
            //
            // Once the leader replicates the ConfigChange
            // back to us, we know our actual member view —
            // pulled live from the leader's RaftStatus snapshot.
            let joint_index = request_join(&network, bootnode_peer, rep_id, local_prefix, &a.name);
            let cluster_members = wait_for_join_committed(
                &network,
                bootnode_peer,
                rep_id,
                joint_index,
                local_prefix,
                &a.name,
            );
            cfg = cfg.with_members(cluster_members);
        }
        cfg = apply_init(cfg, &a.init, &elf_data, &name_ids, &provides_map);
        if !a.on_start.is_empty() {
            let payloads = encode_on_start(
                &a.name, &a.on_start, &elf_data, &name_ids, &provides_map,
            );
            cfg = cfg.with_init_payloads(payloads);
        }
        let id = node.register(cfg);
        let role_tag = format_provides(&a.provides);
        eprintln!("vosx: actor '{}' as {id} ({:?}){role_tag}", a.name, a.consistency);
        name_ids.insert(a.name.clone(), id.0);
        for role in &a.provides {
            provides_map.entry(role.clone()).or_default().push(id.0);
        }
    }

    node.attach_network(network);
    eprintln!("vosx: joined cluster — running until shutdown (Ctrl-C)");
    node.run_forever();

    let results = node.collect();
    let panics: u32 = results.iter().map(|r| r.panics).sum();
    exit_with_status(panics);
}

/// Pull the bootnode's manifest + actor blobs over the wire and
/// stage the blobs to a local cache so they're loadable by name.
fn fetch_manifest_from_bootnode(
    network: &Network,
    bootnode_peer: PeerId,
) -> Result<(Manifest, std::path::PathBuf, BTreeMap<String, ManifestBlob>), String> {
    eprintln!("vosx: fetching manifest from bootnode...");
    let rx = network.send_manifest_req(bootnode_peer);
    let (toml_bytes, blobs) = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|e| format!("manifest fetch: {e}"))?;
    if toml_bytes.is_empty() {
        return Err(
            "bootnode did not expose a manifest (no `set_manifest_handler` registered) — \
             pass --manifest <path> to use a local copy"
                .into(),
        );
    }

    // Stage the blobs under a per-process scratch dir so the
    // manifest's `path = "actors/.../foo.elf"` references resolve.
    let scratch = std::env::temp_dir().join(format!(
        "vosx_join_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
    ));
    let actors_dir = scratch.join("actors");
    std::fs::create_dir_all(&actors_dir)
        .map_err(|e| format!("create scratch dir {}: {e}", actors_dir.display()))?;
    let mut blob_index = BTreeMap::new();
    for blob in &blobs {
        let target = actors_dir.join(format!("{}.elf", blob.name));
        std::fs::write(&target, &blob.blob)
            .map_err(|e| format!("write {}: {e}", target.display()))?;
        blob_index.insert(blob.name.clone(), blob.clone());
    }

    let toml_text = String::from_utf8(toml_bytes)
        .map_err(|e| format!("manifest is not valid UTF-8: {e}"))?;
    // Parse without the legacy-warning side-channel that
    // `manifest_from` runs — that path is for on-disk file
    // access, not in-memory bytes.
    let manifest: Manifest = toml::from_str(&toml_text)
        .map_err(|e| format!("parse fetched manifest: {e}"))?;
    Ok((manifest, scratch, blob_index))
}

/// Send a [`Frame::RaftJoinReq`] for one replication group,
/// retrying redirects through `leader_hint`. Returns the
/// joint-config entry index on success — caller polls for
/// `commit_index >= joint_index + 1` to know the join has
/// settled. Errors out loudly if the cluster has no leader
/// within [`JOIN_RETRY_WINDOW`].
fn request_join(
    network: &Network,
    bootnode_peer: PeerId,
    replication_id: [u8; 32],
    local_prefix: u16,
    agent_name: &str,
) -> u64 {
    let deadline = Instant::now() + JOIN_RETRY_WINDOW;
    let mut target = bootnode_peer;
    loop {
        let rx = network.send_raft_join_req(target, replication_id, local_prefix);
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(RaftJoinResult::Accepted { joint_index }) => {
                eprintln!(
                    "vosx: '{agent_name}' joined at joint_index={joint_index} \
                     (rep_id={:02x}{:02x}..)",
                    replication_id[0], replication_id[1],
                );
                return joint_index;
            }
            Ok(RaftJoinResult::NotLeader { leader_hint }) => match leader_hint {
                Some(hint) => {
                    let Some(peer) = network.peer_for_prefix(hint) else {
                        eprintln!(
                            "vosx: leader hint {hint:#06x} not in prefix_map — backing off"
                        );
                        std::thread::sleep(JOIN_RETRY_DELAY);
                        continue;
                    };
                    eprintln!("vosx: redirecting join request to leader {hint:#06x}");
                    target = peer;
                }
                None => {
                    eprintln!("vosx: bootnode has no leader hint; backing off");
                    std::thread::sleep(JOIN_RETRY_DELAY);
                }
            },
            Ok(RaftJoinResult::Busy) => {
                eprintln!("vosx: cluster busy with another change; backing off");
                std::thread::sleep(JOIN_RETRY_DELAY);
            }
            Ok(RaftJoinResult::UnknownGroup) => {
                die(&format!(
                    "vosx join: bootnode does not host replication group for '{agent_name}' \
                     (rep_id={:02x}{:02x}..) — manifest mismatch?",
                    replication_id[0], replication_id[1],
                ));
            }
            Err(e) => {
                eprintln!("vosx: join RPC failed ({e}); retrying");
                std::thread::sleep(JOIN_RETRY_DELAY);
            }
        }
        if Instant::now() >= deadline {
            die(&format!(
                "vosx join: '{agent_name}' did not complete within {}s",
                JOIN_RETRY_WINDOW.as_secs(),
            ));
        }
    }
}

/// After [`request_join`] returns, poll the leader's status
/// until the joint AND retire entries are committed
/// (`commit_index >= joint_index + 1`). Returns the cluster's
/// post-join member set so the joiner can spawn its worker
/// with the correct `effective_cfg` straight away.
///
/// Errors loudly on timeout — `JOIN_RETRY_WINDOW` is the same
/// budget the join request itself uses.
fn wait_for_join_committed(
    network: &Network,
    bootnode_peer: PeerId,
    replication_id: [u8; 32],
    joint_index: u64,
    local_prefix: u16,
    agent_name: &str,
) -> Vec<u16> {
    eprintln!(
        "vosx: waiting for '{agent_name}' joint+retire to commit \
         (joint_index={joint_index})..."
    );
    // joint_index = 0 means "already a voter" — see
    // raft/worker.rs::handle_join. Skip the wait.
    if joint_index == 0 {
        // Best-effort: ask for current members so the worker
        // boots with the right view. On failure, fall back to
        // the bootnode-pair which still works (vos-raft will
        // overwrite from the on-log ConfigChange on first
        // AppendEntries).
        let rx = network.send_raft_status_req(bootnode_peer, replication_id);
        if let Ok(reply) = rx.recv_timeout(Duration::from_secs(2)) {
            if reply.present && !reply.members.is_empty() {
                return reply.members;
            }
        }
        // Should-include-self defensive default.
        return vec![local_prefix];
    }
    let deadline = Instant::now() + JOIN_RETRY_WINDOW;
    let target_index = joint_index + 1;
    loop {
        let rx = network.send_raft_status_req(bootnode_peer, replication_id);
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(reply) if reply.present && reply.commit_index >= target_index => {
                if !reply.members.contains(&local_prefix) {
                    eprintln!(
                        "vosx: warning — joint+retire committed but local prefix \
                         {local_prefix:#06x} not in member set {:?}; the leader \
                         removed us mid-join. Will retry on its next status query.",
                        reply.members,
                    );
                }
                return reply.members;
            }
            Ok(_) => std::thread::sleep(JOIN_RETRY_DELAY),
            Err(e) => {
                eprintln!("vosx: status RPC failed ({e}); retrying");
                std::thread::sleep(JOIN_RETRY_DELAY);
            }
        }
        if Instant::now() >= deadline {
            die(&format!(
                "vosx join: '{agent_name}' joint+retire didn't commit within {}s; \
                 the cluster may have lost leadership mid-join",
                JOIN_RETRY_WINDOW.as_secs(),
            ));
        }
    }
}

/// Wait up to 10s for the bootnode to complete the Hello
/// handshake. Returns `None` on timeout.
fn wait_for_handshake(network: &Network, bootnode_peer: PeerId) -> Option<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if network
            .peers_with_prefixes()
            .into_iter()
            .any(|(_, pid)| pid == bootnode_peer)
        {
            return Some(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

/// Pull the `/p2p/<peer-id>` component out of a multiaddr.
fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| match p {
        Protocol::P2p(id) => Some(id),
        _ => None,
    })
}
