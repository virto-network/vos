//! Cross-node proof-blob fetch — exercises the libp2p
//! `Frame::FetchProofBlob` / `Frame::ProofBlobReply` round-trip
//! that landed in cycle A1 + the extension-side fan-out
//! (`handle_blob_get`) that landed in cycle A2.
//!
//! Two complementary checks:
//!
//! 1. **Wire-level** — node A puts a blob, node B asks for it
//!    via `Network::send_fetch_proof_blob` directly, gets bytes
//!    back. Pins the encode/decode + the `NetworkService::
//!    get_proof_blob` delegation.
//! 2. **Effect-level** — node B's clerk-prover extension calls
//!    `ctx.blob_get(hash)`; the local store misses; fan-out
//!    over libp2p fetches from node A; the bytes are cached
//!    locally. We assert `node_b.get_proof_blob(hash)` becomes
//!    `Some(bytes)` after the call, which is the only thing
//!    that can be true *only* if the fan-out actually happened.
//!
//! The federation test in `elf_integration.rs` pre-seeds both
//! stores and runs without libp2p attached — fast but doesn't
//! exercise the network path. This test is the network-attached
//! companion; ~3 s of mDNS / Hello handshake overhead is the
//! tax for testing the real cross-node behaviour.

use std::time::Duration;

use vos::network::{Network, NetworkConfig, derive_node_prefix};
use vos::node::{ExtensionConfig, VosNode};

fn wait_for<T>(mut probe: impl FnMut() -> Option<T>, deadline: Duration) -> Option<T> {
    let until = std::time::Instant::now() + deadline;
    loop {
        if let Some(v) = probe() {
            return Some(v);
        }
        if std::time::Instant::now() >= until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn proof_blob_fan_out_fetches_from_peer() {
    // Initialize tracing so any error! / warn! from the agent
    // threads surfaces during debugging. No-op if already set
    // (other tests in this binary may have installed first).
    let _ = tracing_subscriber::fmt()
        .with_env_filter("vos=info")
        .with_test_writer()
        .try_init();

    // ── Networks ────────────────────────────────────────────────
    let kp_a = libp2p::identity::Keypair::generate_ed25519();
    let kp_b = libp2p::identity::Keypair::generate_ed25519();
    let prefix_a = derive_node_prefix(&libp2p::PeerId::from(kp_a.public()));
    let prefix_b = derive_node_prefix(&libp2p::PeerId::from(kp_b.public()));
    let listen: libp2p::Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

    let net_a = Network::start(NetworkConfig {
        keypair: kp_a,
        local_prefix: prefix_a,
        listen: vec![listen.clone()],
        bootstrap: vec![],
        auto_dial_mdns: true,
    });
    let a_listen = wait_for(
        || net_a.listen_addrs().into_iter().next(),
        Duration::from_secs(5),
    )
    .expect("net_a binds");
    let a_dial: libp2p::Multiaddr =
        a_listen.with(libp2p::multiaddr::Protocol::P2p(net_a.peer_id()));

    let net_b = Network::start(NetworkConfig {
        keypair: kp_b,
        local_prefix: prefix_b,
        listen: vec![listen],
        bootstrap: vec![a_dial],
        auto_dial_mdns: true,
    });

    // ── Nodes ───────────────────────────────────────────────────
    let mut node_a = VosNode::with_prefix(prefix_a);
    let mut node_b = VosNode::with_prefix(prefix_b);
    node_a.attach_network(net_a);
    node_b.attach_network(net_b);

    let net_a_arc = node_a.network().expect("net_a attached");
    let net_b_arc = node_b.network().expect("net_b attached");
    wait_for(
        || {
            if net_a_arc.peer_for_prefix(prefix_b).is_some()
                && net_b_arc.peer_for_prefix(prefix_a).is_some()
            {
                Some(())
            } else {
                None
            }
        },
        Duration::from_secs(15),
    )
    .expect("Hello completes between A and B");

    // ── Put a blob on A, fetch from B over the wire ─────────────
    // Arbitrary bytes — we're testing the transport, not the
    // STARK pipeline. The hash is the canonical content address
    // returned by VosNode::put_proof_blob; passing the same
    // bytes through `proof_blob_hash` on either side derives the
    // same key.
    let blob = b"cross-node-proof-blob-test-payload".to_vec();
    let hash = node_a.put_proof_blob(blob.clone());

    // Sanity: blob lives on A, not yet on B.
    assert_eq!(
        node_a.get_proof_blob(&hash).as_deref(),
        Some(blob.as_slice())
    );
    assert!(node_b.get_proof_blob(&hash).is_none());

    // Direct wire-level fetch: B asks A for the blob via the
    // `request_response` channel; A's NetworkService::get_proof_blob
    // serves from its proof-blob store.
    let peer_a = net_b_arc
        .peer_for_prefix(prefix_a)
        .expect("peer A discovered");
    let rx = net_b_arc.send_fetch_proof_blob(peer_a, hash);
    let fetched = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("network reply");
    assert_eq!(
        fetched.as_deref(),
        Some(blob.as_slice()),
        "Frame::ProofBlobReply must round-trip A's bytes back to B"
    );

    // ── Effect-level: extension's blob_get fans out + caches ────
    // Use the general prover-extension as the convenient probe — its
    // `verify` handler calls `ctx.blob_get(hash, hint).await` before
    // trying to decode/verify. With our arbitrary `blob`, the
    // bincode-decode fails and the handler returns 0, but the
    // blob_get call itself runs to completion. The observable
    // side effect we assert on is: node_b's local proof_blobs
    // *now* has the bytes cached, which is only true if the
    // fan-out fetched them from node A.
    let prover_so = {
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        std::path::PathBuf::from(format!(
            "{}/../target/{profile}/libprover_extension.so",
            env!("CARGO_MANIFEST_DIR"),
        ))
    };
    if !prover_so.exists() {
        eprintln!(
            "SKIP: prover-extension not built. \
             Run: cargo build -p prover-extension"
        );
        let _ = node_a.collect();
        let _ = node_b.collect();
        return;
    }

    // Fresh hash so the local cache-from-step-1 doesn't short
    // circuit the fan-out path we're trying to test.
    let blob2 = b"second-blob-not-yet-on-node-b".to_vec();
    let hash2 = node_a.put_proof_blob(blob2.clone());
    assert!(node_b.get_proof_blob(&hash2).is_none(), "B starts cold");

    let prover_id = node_b.register_extension(ExtensionConfig::new(prover_so));

    // Build the general prover's `verify` message by hand so the
    // test doesn't depend on the typed Ref crate. `verify` does
    // `blob_get` BEFORE any decode/verify, so even with a 32-byte
    // dummy commitment and garbage proof bytes the fetch runs to
    // completion (then the handler returns 0).
    use vos::Encode;
    use vos::value::{Msg, TAG_DYNAMIC};
    let msg = Msg::new("verify")
        .with("program_commitment", vec![0u8; 32])
        .with("proof_hash", hash2.to_vec())
        .with("public_bytes", b"probe".to_vec())
        .with("return_bytes", b"probe".to_vec())
        // peer_prefix=0 → no hint, exercises pure fan-out path.
        .with("peer_prefix", 0u64);
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);

    let _reply = node_b
        .invoke(prover_id, payload)
        .expect("verify_voucher_proof reply");
    // We don't assert on the reply value — the bytes aren't a
    // valid bincode-encoded Proof so verify returns 0. The
    // load-bearing assertion is the cache side effect below.

    let cached = node_b.get_proof_blob(&hash2);
    assert_eq!(
        cached.as_deref(),
        Some(blob2.as_slice()),
        "fan-out fetch must populate node B's proof_blobs cache"
    );

    let _ = node_a.collect();
    let _ = node_b.collect();
}
