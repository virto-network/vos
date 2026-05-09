//! Transient ephemeral node — used by `vosx invoke` (and any
//! future read-only commands) to dial into a hyperspace,
//! sync the registry, run a single closure against the node,
//! then tear down.
//!
//! No data dir, no long-lived state: the redb backing the
//! local registry replica lives in `$TMPDIR/vosx-cli-…` and
//! is wiped on exit.

use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};

use vos::abi::service::ServiceId;
use vos::node::{AgentConfig, Consistency, VosNode};

use crate::manifest::Manifest;
use crate::util::{die, load_blob};

/// Spin up a transient ephemeral node that joins the manifest's
/// hyperspace, wait briefly for CRDT sync to populate the
/// local registry replica, run `f` against it, then shut down.
///
/// `sync_timeout_secs` is the upper bound; we exit early after
/// `post_peer_window` once the first peer appears.
pub fn with_query_node(
    manifest: &Manifest,
    dir: &Path,
    connect: &[String],
    sync_timeout_secs: u64,
    f: impl FnOnce(&VosNode),
) {
    let hyperspace = manifest
        .hyperspace
        .as_deref()
        .unwrap_or_else(|| die("manifest does not declare a `hyperspace`; nothing to query"));
    let blob_path = manifest
        .registry_blob
        .as_ref()
        .map(|p| dir.join(p))
        .unwrap_or_else(|| die("manifest must set `registry_blob` for query commands"));
    let blob = load_blob(&blob_path);
    let rep_id = registry::replication_id(hyperspace);

    // Always listen on a random loopback port — the CLI is a
    // transient peer; a fixed port would clash with running
    // instances. Bootstrap from --connect and from manifest.
    let listen: libp2p::Multiaddr = "/ip4/0.0.0.0/tcp/0".parse().unwrap();
    let parse = |s: &str| match libp2p::Multiaddr::from_str(s) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("vosx: ignoring bad multiaddr '{s}': {e}");
            None
        }
    };
    let mut bootstrap: Vec<libp2p::Multiaddr> = connect.iter().filter_map(|s| parse(s)).collect();
    bootstrap.extend(manifest.node.listen.iter().filter_map(|s| parse(s)));

    let keypair = libp2p::identity::Keypair::generate_ed25519();
    let local_prefix = vos::network::derive_node_prefix(&libp2p::PeerId::from(keypair.public()));

    let net = vos::network::Network::start(vos::network::NetworkConfig {
        keypair,
        local_prefix,
        listen: vec![listen],
        bootstrap,
    });

    // CRDT replicas require a `data_dir` on disk for their
    // redb. For the transient CLI we hand them a one-shot
    // tempdir wiped on the way out. The sync-from-peers path
    // doesn't care that the dir is fresh — it pulls the DAG
    // nodes over libp2p and commits them locally.
    let temp_root = std::env::temp_dir().join(format!(
        "vosx-cli-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    if let Err(e) = std::fs::create_dir_all(&temp_root) {
        die(&format!("creating tempdir {}: {e}", temp_root.display()));
    }

    let mut node = VosNode::with_prefix(local_prefix);
    node.register_at_id(
        AgentConfig::new(blob)
            .with_consistency(Consistency::Crdt)
            .persist(&temp_root)
            .with_replication_id(rep_id),
        ServiceId::REGISTRY,
    );
    node.attach_network(net);
    let net_arc = node.network().expect("network was just attached");

    // Sync warmup: wait for at least one peer to appear, then
    // give the CRDT layer a fixed window to pull the registry
    // DAG. Hello-handshake is fast (tens of ms); fetching and
    // applying logs takes a couple of sync intervals
    // (~250ms each). Whole budget is `sync_timeout_secs`.
    let deadline = Instant::now() + Duration::from_secs(sync_timeout_secs);
    while Instant::now() < deadline && net_arc.connected_peers().is_empty() {
        std::thread::sleep(Duration::from_millis(50));
    }
    let post_peer_window = Duration::from_millis(750);
    let drain_until = (Instant::now() + post_peer_window).min(deadline);
    while Instant::now() < drain_until {
        std::thread::sleep(Duration::from_millis(50));
    }

    f(&node);

    node.shutdown();
    let _ = node.collect();
    let _ = std::fs::remove_dir_all(&temp_root);
}
