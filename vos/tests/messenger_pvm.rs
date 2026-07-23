//! In-PVM messenger EXECUTION gate.
//!
//! Where the `link_elf` gate (`messenger_transpile.rs`) proves the messenger
//! ELF *transpiles*, this proves it *executes*: load the ELF into `VosRuntime`
//! and drive `seed` -> `register` -> `bind_identity` -> `key_package` through
//! real PVM dispatch, which
//! exercises the whole no_std MLS path at runtime — the seed-derived Ed25519
//! signer (HKDF + ed25519-dalek), the deterministic X25519 KEM (the custom
//! `DhType::generate` drawing from the host-seeded `HostRand`), mls-rs
//! KeyPackage framing, the `spin::Mutex` + `portable_atomic_util::Arc` storage,
//! rkyv actor-state persistence across dispatches, and the `BOOT_CONTEXT`
//! hostcall (the boot token for the CSPRNG) — none of which the transpile gate
//! touches. A clean, hex-shaped KeyPackage out the other side proves the real
//! messenger runs as one portable PVM bytecode.
//!
//! `register` only returns the freshly derived `mls_pubkey`; the identity is
//! live once the operator signs a binding cert over it and `bind_identity`
//! verifies it (the in-process equivalent of `vosx messenger register`, which
//! signs with the daemon's identity key). The cert is self-contained — it
//! verifies against the Ed25519 key embedded in the operator's own libp2p
//! PeerId — so a bare runtime with no registry can mint one (see `provision`).
//! There is no directory here, so `bind_identity`'s KeyPackage publish reports
//! "directory unavailable"; the binding is stored regardless, which is all
//! `key_package` / `create` need.
//!
//! Build the ELF with `cd actors/messenger && cargo +nightly actor`. If the
//! ELF is absent the test SKIPs loudly rather than failing the suite.

use ed25519_dalek::{Signer, SigningKey};
use msg_ctl::{CommitOutcome, Status};
use space_registry::binding_signed_bytes;
use vos::abi::service::ServiceId;
use vos::runtime::VosRuntime;
use vos::value::{Msg, TAG_DYNAMIC, Value};
use vos::{Decode, Encode};

/// Fixed operator identity key for the in-process binding (any 32 bytes — the
/// PeerId is derived from it, and the cert is verified against that PeerId).
const OPERATOR_KEY: [u8; 32] = [0x33u8; 32];
/// The space the in-process member binds to. The binding cert is scoped to it
/// and the MLS leaf validator (`VosIdentityProvider`) checks every leaf against
/// it, so it must be the same value throughout a test.
const TEST_SPACE_ID: [u8; 32] = [0x42u8; 32];

/// The 38-byte libp2p ed25519 PeerId for an operator key (identity-multihash
/// `00 24 08 01 12 20 ‖ key[32]`) — what `verify_binding` recovers the
/// operator's verifying key from.
fn operator_peer_id(op: &SigningKey) -> Vec<u8> {
    let mut id = vec![0x00u8, 0x24, 0x08, 0x01, 0x12, 0x20];
    id.extend_from_slice(&op.verifying_key().to_bytes());
    id
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("register reply is hex"))
        .collect()
}

/// Bring `id` to a fully bound space member: `seed` (the PVM has no OS
/// entropy), `register` (returns `mls_pubkey=<hex>`), then operator-sign a
/// binding cert over that key and `bind_identity` it — the in-process stand-in
/// for `vosx messenger register`. Panics if any step doesn't land.
fn provision(rt: &mut VosRuntime, id: ServiceId, nickname: &str) {
    let _ = call(rt, id, Msg::new("seed").with("seed_bytes", vec![7u8; 32]));
    let reg = as_text(call(
        rt,
        id,
        Msg::new("register").with("nickname", nickname.to_string()),
    ));
    let mls_pubkey = hex_decode(
        reg.strip_prefix("mls_pubkey=")
            .unwrap_or_else(|| panic!("register did not return an mls_pubkey: {reg}")),
    );
    let op = SigningKey::from_bytes(&OPERATOR_KEY);
    let peer_id = operator_peer_id(&op);
    let cert = op
        .sign(&binding_signed_bytes(&mls_pubkey, &peer_id, &TEST_SPACE_ID))
        .to_bytes()
        .to_vec();
    let bound = as_text(call(
        rt,
        id,
        Msg::new("bind_identity")
            .with("peer_id", peer_id)
            .with("space_id", TEST_SPACE_ID.to_vec())
            .with("cert", cert),
    ));
    assert!(
        bound.contains("bound to peer"),
        "bind_identity did not bind: {bound}"
    );
    assert_eq!(rt.panics, 0, "guest panicked during provisioning");
}

/// Read the pre-built messenger actor ELF, or `None` (with a loud SKIP). The
/// messenger is its own workspace under `actors/`, so its ELF lands in the
/// crate-local target dir.
fn messenger_elf() -> Option<Vec<u8>> {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path =
        format!("{workspace}/../actors/messenger/target/riscv64em-javm/release/messenger.elf");
    match std::fs::read(&path) {
        Ok(d) => Some(d),
        Err(_) => {
            eprintln!(
                "SKIP: messenger ELF not built at {path}\n      \
                 run: cd actors/messenger && cargo +nightly actor"
            );
            None
        }
    }
}

/// Transpile + register the messenger in a fresh runtime.
fn boot() -> (VosRuntime, ServiceId) {
    let elf = messenger_elf().expect("messenger ELF present (checked by caller)");
    let blob = grey_transpiler::link_elf(&elf).expect("transpile messenger");
    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_service_blob(blob);
    let id = rt.register_service(blob_idx);
    (rt, id)
}

/// Dispatch a named message to the live service and return the decoded reply.
fn call(rt: &mut VosRuntime, id: ServiceId, msg: Msg) -> Value {
    let mut payload = vec![TAG_DYNAMIC];
    payload.extend_from_slice(&msg.encode());
    rt.send_to(id, payload);
    rt.run_blocking();
    let reply = rt
        .take_last_reply(id)
        .expect("handler produced no reply (panicked?)");
    if reply.is_empty() {
        return Value::Unit;
    }
    <Value as Decode>::decode(&reply)
}

/// The messenger's CLI handlers all return `String`.
fn as_text(v: Value) -> String {
    match v {
        Value::Str(s) => s,
        Value::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
        other => panic!("expected a text reply, got {other:?}"),
    }
}

#[test]
fn messenger_pvm_mints_a_key_package() {
    let Some(_) = messenger_elf() else { return };
    let (mut rt, id) = boot();

    // seed (mandatory — no OS entropy in the PVM), register (the seed-derived
    // Ed25519 signer), and bind the operator-signed identity. The KeyPackage
    // carries the bound credential, so it can't be minted before this.
    provision(&mut rt, id, "alice");

    // key_package runs the full deterministic MLS path inside the PVM:
    // build_client (BOOT_CONTEXT token -> HostRand -> VosCryptoProvider),
    // generate_key_package_message (mls-rs framing + the deterministic X25519
    // KEM), and the store snapshot back into rkyv state. The reply is the
    // KeyPackage hex-encoded for out-of-band transport.
    let hex = as_text(call(&mut rt, id, Msg::new("key_package")));
    assert_eq!(
        rt.panics, 0,
        "guest panicked minting a KeyPackage in the PVM"
    );
    assert!(
        hex.len() > 200 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "expected a hex-encoded KeyPackage, got {} chars: {:.48}…",
        hex.len(),
        hex
    );
}

/// Fire-and-forget dispatch (don't require a reply — a unit handler that traps
/// records none), returning the panic count after running to completion.
fn send_tick(rt: &mut VosRuntime, id: ServiceId) {
    let mut payload = vec![TAG_DYNAMIC];
    payload.extend_from_slice(&Msg::new("tick").encode());
    rt.send_to(id, payload);
    rt.run_blocking();
}

/// The periodic `tick` (the host dispatches it every `tick_ms` once the
/// messenger is a PVM agent) must not trap on a fresh, channel-less messenger,
/// neither on a cold first dispatch nor after another committed dispatch.
#[test]
fn messenger_pvm_tick_does_not_panic() {
    let Some(_) = messenger_elf() else { return };
    let (mut rt, id) = boot();
    // Cold first dispatch.
    send_tick(&mut rt, id);
    assert_eq!(rt.panics, 0, "tick trapped on the cold first dispatch");
    // After a prior mutating dispatch.
    let _ = call(
        &mut rt,
        id,
        Msg::new("seed").with("seed_bytes", vec![7u8; 32]),
    );
    send_tick(&mut rt, id);
    assert_eq!(rt.panics, 0, "tick trapped after a committed dispatch");
}

/// A channel in the messenger's node-local state must survive a `tick`.
/// Isolates the e2e symptom where alice's channel vanished between `send` and
/// `invite` while only ticks ran.
///
/// The original failure was NOT a stack overflow (the guest SP stays healthy):
/// it was a grey-transpiler codegen bug — a `pending_load_imm` fusion left by a
/// PCREL load leaked across an emitted `CALL_PLT`, and the next fusable
/// instruction "undid" it, truncating the call and desyncing every address_map
/// entry past it, so a branch target landed mid-instruction → a PVM trap. Fixed
/// in `grey-transpiler` (`link_elf`: clear `pending_load_imm` before
/// `emit_call`). This test passes with that fix.
#[test]
fn messenger_pvm_channel_survives_a_tick() {
    let Some(_) = messenger_elf() else { return };
    let (mut rt, id) = boot();
    provision(&mut rt, id, "alice");
    let _ = call(&mut rt, id, Msg::new("key_package")); // published_kp_count -> 1
    let joined = as_text(call(
        &mut rt,
        id,
        Msg::new("join").with("channel", "general".to_string()),
    ));
    assert!(joined.contains("watching"), "join reply: {joined}");

    let before = as_text(call(&mut rt, id, Msg::new("status")));
    assert!(
        before.contains("general"),
        "status before tick must list the channel: {before}"
    );

    send_tick(&mut rt, id);
    assert_eq!(rt.panics, 0, "tick panicked");

    let after = as_text(call(&mut rt, id, Msg::new("status")));
    assert!(
        after.contains("general"),
        "channel LOST after a tick: {after}"
    );
}

/// `create` then `send` reach the full group path with no live registry by
/// answering the messenger's outbound asks: `resolve(name)` to a fake service
/// id (so `ensure_channel_agents` succeeds) and `post` to `STATUS_OK`. The
/// round-trip proves a sent message is encrypted, logged, and read back through
/// `history` at the channel's current epoch.
#[test]
fn messenger_pvm_create_via_external_resolve() {
    use vos::runtime::ExternalInvokeReply;
    let Some(_) = messenger_elf() else { return };
    let (mut rt, id) = boot();
    rt.set_external_invoke(Box::new(|_target: ServiceId, msg: &[u8]| {
        if msg.windows(7).any(|w| w == b"resolve") {
            Some(ExternalInvokeReply::Done(Value::U32(0x1234).encode()))
        } else if msg.windows(4).any(|w| w == b"post") {
            Some(ExternalInvokeReply::Done(Value::U32(0).encode()))
        } else {
            None
        }
    }));
    provision(&mut rt, id, "alice");
    let r = as_text(call(
        &mut rt,
        id,
        Msg::new("create").with("channel", "general".to_string()),
    ));
    assert_eq!(rt.panics, 0, "guest trapped during create");
    assert!(r.contains("created"), "create did not succeed: {r}");

    for text in ["hello one", "hello two"] {
        let sent = as_text(call(
            &mut rt,
            id,
            Msg::new("send")
                .with("channel", "general".to_string())
                .with("text", text.to_string()),
        ));
        assert!(sent.contains("sent"), "send did not succeed: {sent}");
    }

    let history = as_text(call(
        &mut rt,
        id,
        Msg::new("history")
            .with("channel", "general".to_string())
            .with("limit", 20u32),
    ));
    assert_eq!(rt.panics, 0, "guest trapped reading history");
    assert!(
        history.contains("hello one") && history.contains("hello two"),
        "history missing sent messages: {history:?}"
    );
}

/// Drive `commit_chain_op`'s sequencer-retry loop in the real PVM with a
/// *scripted* channel sequencer. `create` a channel, then `update` it (a
/// self-update commit — the simplest op that goes through `commit_chain_op`:
/// no second member, no Welcome), answering each commit submission with the
/// next verdict from `verdicts` (the last one sticks once the script is spent).
///
/// This gates the messenger's *orchestration*, not MLS convergence: on
/// `EpochTaken` it drops the rejected pending commit, drains the chain (a clean
/// no-op here — the fake chain always pages back empty), and re-issues once at
/// the next attempt. The convergence after a *real* catch-up (applying another
/// member's winning commit) is the separate concern covered by
/// `mls::tests::losing_commit_is_rejected_and_reissues_to_convergence`; here the
/// sequencer's verdict is faked precisely to exercise the loop control the e2e
/// (which only ever races on replication, never on a commit epoch) never hits.
fn update_with_ctl_verdicts(verdicts: &[Status]) -> (String, u32) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use vos::runtime::ExternalInvokeReply;

    let (mut rt, id) = boot();
    let verdicts: Vec<Status> = verdicts.to_vec();
    let submissions = AtomicUsize::new(0);
    rt.set_external_invoke(Box::new(move |_target: ServiceId, msg: &[u8]| {
        let has = |needle: &[u8]| msg.windows(needle.len()).any(|w| w == needle);
        if has(b"commit_body") {
            // A commit submission: hand back the next scripted verdict.
            let n = submissions.fetch_add(1, Ordering::Relaxed);
            let status = verdicts.get(n).copied().unwrap_or(Status::Ok);
            let outcome = CommitOutcome {
                status,
                next_epoch: n as u64 + 1,
            };
            Some(ExternalInvokeReply::Done(
                Value::Bytes(outcome.encode()).encode(),
            ))
        } else if has(b"from_epoch") {
            // The catch-up drain pages the chain — report it empty so the drain
            // is a no-op and the loop falls through to the re-issue.
            Some(ExternalInvokeReply::Done(Value::Bytes(Vec::new()).encode()))
        } else if has(b"resolve") {
            // Any agent lookup (the channel ctl/log, chronos) resolves to one
            // fake id; the chronos `latest_final` ask then goes unanswered.
            Some(ExternalInvokeReply::Done(Value::U32(0x1234).encode()))
        } else if has(b"post") {
            // create's genesis log append.
            Some(ExternalInvokeReply::Done(Value::U32(0).encode()))
        } else {
            None
        }
    }));

    provision(&mut rt, id, "alice");
    let created = as_text(call(
        &mut rt,
        id,
        Msg::new("create").with("channel", "general".to_string()),
    ));
    assert!(
        created.contains("created"),
        "create did not succeed: {created}"
    );

    let reply = as_text(call(
        &mut rt,
        id,
        Msg::new("update").with("channel", "general".to_string()),
    ));
    (reply, rt.panics)
}

/// A transient `EpochTaken` on the first submission must not surface as an
/// error: the messenger drains the chain and re-issues, and the self-update
/// lands at the next epoch.
#[test]
fn messenger_pvm_commit_retries_after_epoch_taken() {
    let Some(_) = messenger_elf() else { return };
    let (reply, panics) = update_with_ctl_verdicts(&[Status::EpochTaken, Status::Ok]);
    assert_eq!(panics, 0, "guest trapped during the commit retry");
    assert!(
        reply.contains("rotated keys") && reply.contains("epoch 1"),
        "the retry did not converge: {reply}"
    );
}

/// Two contended epochs in a row exhaust the single re-issue: the op is refused
/// — not retried forever, not silently dropped.
#[test]
fn messenger_pvm_commit_refuses_on_repeated_contention() {
    let Some(_) = messenger_elf() else { return };
    let (reply, panics) = update_with_ctl_verdicts(&[Status::EpochTaken, Status::EpochTaken]);
    assert_eq!(panics, 0, "guest trapped during the contended commit");
    assert!(
        reply.contains("contended"),
        "expected a contention refusal, got: {reply}"
    );
}
