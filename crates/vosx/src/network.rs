//! libp2p network startup. Combines the manifest's
//! `[node].listen` with the CLI's `--listen` / `--connect`
//! flags into a single [`vos::network::NetworkConfig`] and
//! kicks off the swarm thread.

use std::path::Path;
use std::str::FromStr;

use crate::manifest::Manifest;
use crate::util::die;

/// Start a libp2p network if any listen / connect address is
/// configured. Returns `None` when neither side asked for the
/// network (a single-process run with no peering).
pub fn start_network_if_needed(
    manifest: &Manifest,
    data_dir: Option<&Path>,
    listen_cli: &[String],
    connect_cli: &[String],
) -> Option<vos::network::Network> {
    let parse = |s: &str, kind: &str| -> Option<libp2p::Multiaddr> {
        match libp2p::Multiaddr::from_str(s) {
            Ok(a) => Some(a),
            Err(e) => {
                eprintln!("vosx: ignoring invalid {kind} multiaddr '{s}': {e}");
                None
            }
        }
    };

    let mut listen: Vec<libp2p::Multiaddr> = listen_cli
        .iter()
        .filter_map(|s| parse(s, "listen"))
        .collect();
    listen.extend(manifest.node.listen.iter().filter_map(|s| parse(s, "listen")));

    let connect: Vec<libp2p::Multiaddr> = connect_cli
        .iter()
        .filter_map(|s| parse(s, "connect"))
        .collect();

    if listen.is_empty() && connect.is_empty() {
        return None;
    }

    let keypair = vos::network::load_or_generate_identity(
        manifest.node.identity.as_deref(),
        data_dir,
    )
    .unwrap_or_else(|e| die(&format!("identity: {e}")));

    let peer_id = libp2p::PeerId::from(keypair.public());
    let local_prefix = vos::network::derive_node_prefix(&peer_id);
    eprintln!("vosx: node identity {peer_id} (prefix {local_prefix:#06x})");

    Some(vos::network::Network::start(vos::network::NetworkConfig {
        keypair,
        local_prefix,
        listen,
        bootstrap: connect,
    }))
}
