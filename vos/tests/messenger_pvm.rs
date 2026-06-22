//! In-PVM messenger EXECUTION gate.
//!
//! Where the `link_elf` gate (`messenger_transpile.rs`) proves the messenger
//! ELF *transpiles*, this proves it *executes*: load the ELF into `VosRuntime`
//! and drive `seed` -> `register` -> `key_package` through real PVM dispatch,
//! which
//! exercises the whole no_std MLS path at runtime — the seed-derived Ed25519
//! signer (HKDF + ed25519-dalek), the deterministic X25519 KEM (the custom
//! `DhType::generate` drawing from the host-seeded `HostRand`), mls-rs
//! KeyPackage framing, the `spin::Mutex` + `portable_atomic_util::Arc` storage,
//! rkyv actor-state persistence across dispatches, and the `BOOT_CONTEXT`
//! hostcall (the boot token for the CSPRNG) — none of which the transpile gate
//! touches. A clean, hex-shaped KeyPackage out the other side proves the real
//! messenger runs as one portable PVM bytecode.
//!
//! There is no registry in this bare runtime, so `register`'s directory ask
//! cleanly returns NOT_FOUND and it reports "directory unavailable" — the
//! identity (nickname + seed-derived signer) is still established, which is all
//! `key_package` needs.
//!
//! Build the ELF with `cd extensions/messenger && cargo +nightly actor`. If the
//! ELF is absent the test SKIPs loudly rather than failing the suite.

use vos::abi::service::ServiceId;
use vos::runtime::VosRuntime;
use vos::value::{Msg, TAG_DYNAMIC, Value};
use vos::{Decode, Encode};

/// Read the pre-built messenger actor ELF, or `None` (with a loud SKIP). The
/// messenger stays a host-workspace member, so its ELF lands in the shared
/// workspace target dir (not a crate-local one).
fn messenger_elf() -> Option<Vec<u8>> {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path =
        format!("{workspace}/../target/riscv64em-javm/release/messenger_extension.elf");
    match std::fs::read(&path) {
        Ok(d) => Some(d),
        Err(_) => {
            eprintln!(
                "SKIP: messenger ELF not built at {path}\n      \
                 run: cd extensions/messenger && cargo +nightly actor"
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

    // The PVM actor has no OS entropy, so the CSPRNG seed is mandatory.
    let reply = as_text(call(
        &mut rt,
        id,
        Msg::new("seed").with("seed_bytes", vec![7u8; 32]),
    ));
    assert!(reply.contains("provisioned"), "seed reply: {reply}");
    assert_eq!(rt.panics, 0, "guest panicked during seed");

    // register establishes the identity: the nickname + the seed-derived Ed25519
    // signer (mls::signer_public). The directory ask finds no registry here and
    // returns cleanly, so the reply notes the directory is unavailable while the
    // identity is set — which is all key_package needs.
    let reply = as_text(call(
        &mut rt,
        id,
        Msg::new("register").with("nickname", "alice".to_string()),
    ));
    assert!(
        reply.contains("registered as 'alice'"),
        "register reply: {reply}"
    );
    assert_eq!(rt.panics, 0, "guest panicked during register");

    // key_package runs the full deterministic MLS path inside the PVM:
    // build_client (BOOT_CONTEXT token -> HostRand -> VosCryptoProvider),
    // generate_key_package_message (mls-rs framing + the deterministic X25519
    // KEM), and the store snapshot back into rkyv state. The reply is the
    // KeyPackage hex-encoded for out-of-band transport.
    let hex = as_text(call(&mut rt, id, Msg::new("key_package")));
    assert_eq!(rt.panics, 0, "guest panicked minting a KeyPackage in the PVM");
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
/// neither on a cold first dispatch nor after a warm restart.
#[test]
fn messenger_pvm_tick_does_not_panic() {
    let Some(_) = messenger_elf() else { return };
    let (mut rt, id) = boot();
    // Cold first dispatch.
    send_tick(&mut rt, id);
    assert_eq!(rt.panics, 0, "tick trapped on the cold first dispatch");
    // After a warm restart (a prior mutating dispatch).
    let _ = call(&mut rt, id, Msg::new("seed").with("seed_bytes", vec![7u8; 32]));
    send_tick(&mut rt, id);
    assert_eq!(rt.panics, 0, "tick trapped after a warm restart");
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
    let _ = call(&mut rt, id, Msg::new("seed").with("seed_bytes", vec![7u8; 32]));
    let _ = call(&mut rt, id, Msg::new("register").with("nickname", "alice".to_string()));
    let _ = call(&mut rt, id, Msg::new("key_package")); // published_kp_count -> 1
    let joined = as_text(call(&mut rt, id, Msg::new("join").with("channel", "general".to_string())));
    assert!(joined.contains("watching"), "join reply: {joined}");

    let before = as_text(call(&mut rt, id, Msg::new("status")));
    assert!(before.contains("general"), "status before tick must list the channel: {before}");

    send_tick(&mut rt, id);
    assert_eq!(rt.panics, 0, "tick panicked");

    let after = as_text(call(&mut rt, id, Msg::new("status")));
    assert!(after.contains("general"), "channel LOST after a tick: {after}");
}

#[test]
fn messenger_pvm_create_via_external_resolve() {
    use vos::runtime::ExternalInvokeReply;
    let Some(_) = messenger_elf() else { return };
    let elf = messenger_elf().unwrap();
    let blob = grey_transpiler::link_elf(&elf).expect("transpile");
    let mut rt = VosRuntime::new();
    let blob_idx = rt.register_service_blob(blob);
    let id = rt.register_service(blob_idx);
    // Answer the messenger's `resolve` asks (to the registry) with a non-zero
    // service id, so `ensure_channel_agents` succeeds and the REAL `create`
    // handler reaches create_group — the daemon path the bare runtime otherwise
    // can't exercise (no registry).
    // resolve(name) -> a fake log service id (0x1234); post -> STATUS_OK (0).
    rt.set_external_invoke(Box::new(|_target: ServiceId, msg: &[u8]| {
        if msg.windows(7).any(|w| w == b"resolve") {
            Some(ExternalInvokeReply::Done(Value::U32(0x1234).encode()))
        } else if msg.windows(4).any(|w| w == b"post") {
            Some(ExternalInvokeReply::Done(Value::U32(0).encode()))
        } else {
            None
        }
    }));
    let _ = call(&mut rt, id, Msg::new("seed").with("seed_bytes", vec![7u8; 32]));
    let _ = call(&mut rt, id, Msg::new("register").with("nickname", "alice".to_string()));
    let r = as_text(call(&mut rt, id, Msg::new("create").with("channel", "general".to_string())));
    eprintln!("DIAG create via external resolve => {r}");
    assert_eq!(rt.panics, 0, "guest trapped during create");
    assert!(r.contains("created"), "create did not succeed: {r}");

    // Populate `messages` so history exercises the SAME path alice's does in
    // the e2e (status there shows "2 messages" yet history comes back empty).
    let s1 = as_text(call(
        &mut rt,
        id,
        Msg::new("send")
            .with("channel", "general".to_string())
            .with("text", "hello one".to_string()),
    ));
    eprintln!("DIAG send #1 => {s1}");
    let s2 = as_text(call(
        &mut rt,
        id,
        Msg::new("send")
            .with("channel", "general".to_string())
            .with("text", "hello two".to_string()),
    ));
    eprintln!("DIAG send #2 => {s2}");

    let st = as_text(call(&mut rt, id, Msg::new("status")));
    eprintln!("DIAG status => {st}");

    // history is the only handler with a u32 arg. Probe its raw reply bytes.
    let mut payload = vec![TAG_DYNAMIC];
    payload.extend_from_slice(
        &Msg::new("history")
            .with("channel", "general".to_string())
            .with("limit", 20u32)
            .encode(),
    );
    rt.send_to(id, payload);
    rt.run_blocking();
    let raw = rt.take_last_reply(id);
    eprintln!(
        "DIAG history raw reply => {:?} (panics={})",
        raw.as_ref().map(|b| (b.len(), <Value as Decode>::decode(b))),
        rt.panics
    );
    let raw = raw.expect("history produced NO reply");
    assert!(!raw.is_empty(), "history reply was EMPTY bytes");
    let txt = as_text(<Value as Decode>::decode(&raw));
    assert!(
        txt.contains("hello one") && txt.contains("hello two"),
        "history missing sent messages: {txt:?}"
    );
}
