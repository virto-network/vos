//! Thin RPC clients for the per-channel PVM actors.
//!
//! Everything here is the dynamic-`Msg` wire dance: build a named
//! message, `ask_dispatch` it over the host invoke path, decode
//! the `Value` reply, and rkyv-decode typed payloads with the row
//! types shared from the actor crates. No MLS, no policy — those
//! live in `mls`/`tick`; this module only moves bytes.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use msg_ctl::{CommitOutcome, CommitRow};
use msg_log::EnvelopeRow;
use vos::actors::context::ServiceId;
use vos::prelude::*;
use vos::value::{Msg, TAG_DYNAMIC, Value};

use crate::MsgrCtx;

/// The space registry's well-known local id.
const REGISTRY_ID: u32 = 0;

/// The per-space clock + verifiable-randomness service's instance name. Read by
/// [`chronos_beacon`] to fold the public beacon into the MLS CSPRNG hedge.
pub(crate) const CHRONOS_AGENT: &str = "chronos";

pub(crate) fn dyn_payload(msg: &Msg) -> Vec<u8> {
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

/// Send a dynamic [`Msg`] to `target` and return the decoded reply [`Value`],
/// or `None` if the target is unreachable / refused / replied undecodably.
///
/// The outbound-ask effect differs by build flavor: the host extension uses the
/// native `ask_dispatch` effect (returns the raw reply bytes, decoded here);
/// the PVM service actor has no `ask_dispatch` (it is `extension`-gated) and
/// uses `ask_raw`/`invoke_raw`, which returns the reply already decoded to a
/// `Value`. Both wrap the same `[TAG_DYNAMIC ‖ Msg]` payload, so every caller
/// below is flavor-agnostic.
async fn ask_value(ctx: &mut MsgrCtx, target: ServiceId, msg: &Msg) -> Option<Value> {
    #[cfg(not(target_arch = "riscv64"))]
    {
        let raw = ctx.ask_dispatch(target, &dyn_payload(msg)).await?;
        decode_value(&raw)
    }
    #[cfg(target_arch = "riscv64")]
    {
        ctx.ask_raw(target, &dyn_payload(msg)).await.ok()
    }
}

#[cfg(not(target_arch = "riscv64"))]
fn decode_value(bytes: &[u8]) -> Option<Value> {
    <Value as vos::Decode>::try_decode(bytes)
}

/// Extract the rkyv payload from a typed-handler reply
/// (`Value::Bytes`); `Value::Unit` maps to empty.
fn value_to_bytes(v: Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b),
        Value::Unit => Some(Vec::new()),
        _ => None,
    }
}

/// Extract a status byte from a `u8`-returning handler reply.
fn value_to_status(v: Value) -> Option<u8> {
    match v {
        Value::Bytes(b) if b.len() == 1 => Some(b[0]),
        other => other.as_u8(),
    }
}

/// Resolve an installed agent's instance name to its ServiceId via
/// the space registry. `Ok(0)` never escapes — an unknown name is
/// an error here.
pub(crate) async fn resolve(ctx: &mut MsgrCtx, name: &str) -> Result<u32, String> {
    let local_prefix = (ctx.id().0 >> 16) as u16;
    let msg = Msg::new("resolve")
        .with("name", name.to_string())
        .with("caller_prefix", local_prefix as u64);
    let value = ask_value(ctx, ServiceId(REGISTRY_ID), &msg)
        .await
        .ok_or_else(|| "registry unreachable".to_string())?;
    let id = match value {
        Value::U32(id) => id,
        Value::U64(id) => id as u32,
        Value::Bytes(b) if b.len() == 4 => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        _ => return Err("bad registry reply".into()),
    };
    if id == 0 {
        return Err(format!("agent '{name}' not installed"));
    }
    Ok(id)
}

/// `space-registry.agents` — the installed-agent catalog. Used to
/// clone an existing channel pair's program rows when creating a
/// channel dynamically. Ungated on the registry side.
pub(crate) async fn reg_agents(ctx: &mut MsgrCtx) -> Result<Vec<space_registry::AgentRow>, String> {
    let msg = Msg::new("agents");
    let value = ask_value(ctx, ServiceId(REGISTRY_ID), &msg)
        .await
        .ok_or_else(|| "registry unreachable".to_string())?;
    let inner = value_to_bytes(value).ok_or_else(|| "bad registry reply".to_string())?;
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    <Vec<space_registry::AgentRow> as vos::Decode>::try_decode(&inner)
        .ok_or_else(|| "bad registry agents payload".to_string())
}

/// `space-registry.install` — instantiate a new agent row, cloning
/// the program identity (name/version/hash) and consistency from
/// `template` under a fresh instance name + replication id.
///
/// The verb is Admin-gated and the host relays the real caller's
/// role bounded by our manifest `intra_caps`; a refusal surfaces
/// from `ask_dispatch` as `None`, indistinguishable from an
/// unreachable registry, so the error names both causes.
pub(crate) async fn reg_install(
    ctx: &mut MsgrCtx,
    instance_name: &str,
    template: &space_registry::AgentRow,
    replication_id: [u8; 32],
) -> Result<u8, String> {
    let msg = Msg::new("install")
        .with("instance_name", instance_name.to_string())
        .with("program_name", template.program_name.clone())
        .with("program_version", template.program_version.clone())
        .with("program_hash", template.program_hash.to_vec())
        .with("replication_id", replication_id.to_vec())
        .with("consistency", template.consistency as u64)
        .with("install_args", Vec::<u8>::new())
        .with("install_payloads", Vec::<u8>::new());
    let value = ask_value(ctx, ServiceId(REGISTRY_ID), &msg)
        .await
        .ok_or_else(|| {
            format!(
                "installing '{instance_name}' was refused or the registry is \
                 unreachable — creating a channel installs its agents, which \
                 needs an admin caller and a `space-registry:admin` intra-cap \
                 on the messenger"
            )
        })?;
    value_to_status(value).ok_or_else(|| "bad registry install reply".to_string())
}

/// `msg-log.post` — append one App envelope.
pub(crate) async fn log_post(
    ctx: &mut MsgrCtx,
    log_id: u32,
    epoch: u64,
    lamport: u64,
    ts_ms: u64,
    body: Vec<u8>,
) -> Result<(), String> {
    let msg = Msg::new("post")
        .with("kind", msg_log::ENVELOPE_KIND_APP as u64)
        .with("epoch", epoch)
        .with("lamport", lamport)
        .with("ts_ms", ts_ms)
        .with("to_hint", Vec::<u8>::new())
        .with("body", body);
    let value = ask_value(ctx, ServiceId(log_id), &msg)
        .await
        .ok_or_else(|| "msg-log unreachable".to_string())?;
    match value_to_status(value) {
        Some(msg_log::STATUS_OK) => Ok(()),
        Some(code) => Err(format!("msg-log refused the envelope (status {code})")),
        None => Err("bad msg-log reply".into()),
    }
}

/// `msg-log.history` — one page strictly after the cursor.
pub(crate) async fn log_history(
    ctx: &mut MsgrCtx,
    log_id: u32,
    after_lamport: u64,
    after_id: Vec<u8>,
    limit: u32,
) -> Result<Vec<EnvelopeRow>, String> {
    let msg = Msg::new("history")
        .with("after_lamport", after_lamport)
        .with("after_id", after_id)
        .with("limit", limit as u64);
    let value = ask_value(ctx, ServiceId(log_id), &msg)
        .await
        .ok_or_else(|| "msg-log unreachable".to_string())?;
    let inner = value_to_bytes(value).ok_or_else(|| "bad msg-log reply".to_string())?;
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    <Vec<EnvelopeRow> as vos::Decode>::try_decode(&inner)
        .ok_or_else(|| "bad msg-log history payload".to_string())
}

/// `msg-ctl.commit` — submit an MLS Commit for sequencing.
pub(crate) async fn ctl_commit(
    ctx: &mut MsgrCtx,
    ctl_id: u32,
    epoch: u64,
    ts_ms: u64,
    commit_body: Vec<u8>,
    welcome: Vec<u8>,
    welcome_hint: Vec<u8>,
) -> Result<CommitOutcome, String> {
    let msg = Msg::new("commit")
        .with("epoch", epoch)
        .with("ts_ms", ts_ms)
        .with("commit_body", commit_body)
        .with("welcome", welcome)
        .with("welcome_hint", welcome_hint);
    let value = ask_value(ctx, ServiceId(ctl_id), &msg)
        .await
        .ok_or_else(|| "msg-ctl unreachable".to_string())?;
    let inner = value_to_bytes(value).ok_or_else(|| "bad msg-ctl reply".to_string())?;
    <CommitOutcome as vos::Decode>::try_decode(&inner)
        .ok_or_else(|| "bad msg-ctl commit payload".to_string())
}

/// `msg-ctl.commits` — one page of the chain from `from_epoch`.
pub(crate) async fn ctl_commits(
    ctx: &mut MsgrCtx,
    ctl_id: u32,
    from_epoch: u64,
    limit: u32,
) -> Result<Vec<CommitRow>, String> {
    let msg = Msg::new("commits")
        .with("from_epoch", from_epoch)
        .with("limit", limit as u64);
    let value = ask_value(ctx, ServiceId(ctl_id), &msg)
        .await
        .ok_or_else(|| "msg-ctl unreachable".to_string())?;
    let inner = value_to_bytes(value).ok_or_else(|| "bad msg-ctl reply".to_string())?;
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    <Vec<CommitRow> as vos::Decode>::try_decode(&inner)
        .ok_or_else(|| "bad msg-ctl commits payload".to_string())
}

/// `msg-directory.publish_kp` — list a KeyPackage for claiming.
pub(crate) async fn dir_publish_kp(
    ctx: &mut MsgrCtx,
    dir_id: u32,
    owner: &str,
    kp: Vec<u8>,
) -> Result<(), String> {
    let msg = Msg::new("publish_kp")
        .with("owner", owner.to_string())
        .with("kp", kp);
    let value = ask_value(ctx, ServiceId(dir_id), &msg)
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    match value_to_status(value) {
        Some(msg_directory::STATUS_OK) => Ok(()),
        Some(code) => Err(format!(
            "msg-directory refused the key package (status {code})"
        )),
        None => Err("bad msg-directory reply".into()),
    }
}

/// `msg-directory.claim_kp` — consume one of `owner`'s published
/// KeyPackages. `Ok(None)` when they have none left.
pub(crate) async fn dir_claim_kp(
    ctx: &mut MsgrCtx,
    dir_id: u32,
    owner: &str,
) -> Result<Option<Vec<u8>>, String> {
    let msg = Msg::new("claim_kp").with("owner", owner.to_string());
    let value = ask_value(ctx, ServiceId(dir_id), &msg)
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    let bytes = value_to_bytes(value).ok_or_else(|| "bad msg-directory reply".to_string())?;
    Ok((!bytes.is_empty()).then_some(bytes))
}

/// `chronos.latest_final` — the 32-byte value of the latest *finalized*
/// (lagged) beacon round, for hedging into the MLS CSPRNG output branch
/// (HKDF `info`, never key material; see [`crate::host_rand`]). Deliberately
/// best-effort and infallible-ish: `None` when chronos is not installed in the
/// space, has no finalized round yet, or is unreachable — the caller then draws
/// with no hedge, which is a no-op on the stream (so absent chronos ⇒ no
/// behaviour change). Reads the *finalized* round, never the live head, so a
/// last-revealer cannot grind the value the messenger consumes.
///
/// The value is domain-bound to its round (`blake2b`) before it leaves here, so
/// the hedge can't be replayed across rounds and the raw beacon never enters
/// the CSPRNG directly. [`crate::mls::build_client_hedged`] folds the result
/// into the output branch.
pub(crate) async fn chronos_beacon(ctx: &mut MsgrCtx) -> Option<[u8; 32]> {
    let chronos_id = resolve(ctx, CHRONOS_AGENT).await.ok()?;
    let msg = Msg::new("latest_final");
    // `Option<BeaconRound>` over the wire: empty bytes = None (no finalized
    // round), populated = rkyv-encoded BeaconRound (see the macro's reply
    // encoding). Mirror the `dir_claim_kp` shape.
    let inner = value_to_bytes(ask_value(ctx, ServiceId(chronos_id), &msg).await?)?;
    if inner.is_empty() {
        return None;
    }
    let round = <chronos::BeaconRound as vos::Decode>::try_decode(&inner)?;
    Some(vos::crypto::blake2b_hash::<32>(
        b"vos-msg/beacon-hedge/v1",
        &[&round.round.to_le_bytes(), &round.beacon],
    ))
}

/// `msg-directory.release_kp` — return a claimed KeyPackage to the
/// pool after the invite it was claimed for was definitively
/// refused. Never call this on a transport-level failure — the
/// commit may have landed and the package would be re-armed
/// consumed.
pub(crate) async fn dir_release_kp(
    ctx: &mut MsgrCtx,
    dir_id: u32,
    owner: &str,
    hash: [u8; 32],
) -> Result<(), String> {
    let msg = Msg::new("release_kp")
        .with("owner", owner.to_string())
        .with("hash", hash.to_vec());
    let value = ask_value(ctx, ServiceId(dir_id), &msg)
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    match value_to_status(value) {
        Some(msg_directory::STATUS_OK) => Ok(()),
        Some(code) => Err(format!("msg-directory refused the release (status {code})")),
        None => Err("bad msg-directory reply".into()),
    }
}

/// `msg-directory.announce_channel`.
pub(crate) async fn dir_announce_channel(
    ctx: &mut MsgrCtx,
    dir_id: u32,
    name: &str,
    creator: &str,
) -> Result<u8, String> {
    let msg = Msg::new("announce_channel")
        .with("name", name.to_string())
        .with("creator", creator.to_string());
    let value = ask_value(ctx, ServiceId(dir_id), &msg)
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    value_to_status(value).ok_or_else(|| "bad msg-directory reply".to_string())
}

/// `msg-directory.channels` — one page of announcements.
pub(crate) async fn dir_channels(
    ctx: &mut MsgrCtx,
    dir_id: u32,
    from: u64,
    limit: u32,
) -> Result<Vec<msg_directory::ChannelRow>, String> {
    let msg = Msg::new("channels")
        .with("from", from)
        .with("limit", limit as u64);
    let value = ask_value(ctx, ServiceId(dir_id), &msg)
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    let inner = value_to_bytes(value).ok_or_else(|| "bad msg-directory reply".to_string())?;
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    <Vec<msg_directory::ChannelRow> as vos::Decode>::try_decode(&inner)
        .ok_or_else(|| "bad msg-directory channels payload".to_string())
}

// ── Hex (CLI-facing KeyPackage transport) ─────────────────────────

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xF) as u32, 16).unwrap());
    }
    out
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}
