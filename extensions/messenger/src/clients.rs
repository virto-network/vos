//! Thin RPC clients for the per-channel PVM actors.
//!
//! Everything here is the dynamic-`Msg` wire dance: build a named
//! message, `ask_dispatch` it over the host invoke path, decode
//! the `Value` reply, and rkyv-decode typed payloads with the row
//! types shared from the actor crates. No MLS, no policy — those
//! live in `mls`/`tick`; this module only moves bytes.

use msg_ctl::{CommitOutcome, CommitRow};
use msg_log::EnvelopeRow;
use vos::actors::context::ServiceId;
use vos::prelude::*;
use vos::value::{Msg, TAG_DYNAMIC, Value};

use crate::MsgrCtx;

pub(crate) fn dyn_payload(msg: &Msg) -> Vec<u8> {
    let encoded = msg.encode();
    let mut payload = Vec::with_capacity(1 + encoded.len());
    payload.push(TAG_DYNAMIC);
    payload.extend_from_slice(&encoded);
    payload
}

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
    const REGISTRY_ID: u32 = 0;
    let local_prefix = (ctx.id().0 >> 16) as u16;
    let msg = Msg::new("resolve")
        .with("name", name.to_string())
        .with("caller_prefix", local_prefix as u64);
    let raw = ctx
        .ask_dispatch(ServiceId(REGISTRY_ID), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "registry unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad registry reply".to_string())?;
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
    let raw = ctx
        .ask_dispatch(ServiceId(log_id), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "msg-log unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad msg-log reply".to_string())?;
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
    let raw = ctx
        .ask_dispatch(ServiceId(log_id), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "msg-log unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad msg-log reply".to_string())?;
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
    let raw = ctx
        .ask_dispatch(ServiceId(ctl_id), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "msg-ctl unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad msg-ctl reply".to_string())?;
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
    let raw = ctx
        .ask_dispatch(ServiceId(ctl_id), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "msg-ctl unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad msg-ctl reply".to_string())?;
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
    let raw = ctx
        .ask_dispatch(ServiceId(dir_id), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad msg-directory reply".to_string())?;
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
    let raw = ctx
        .ask_dispatch(ServiceId(dir_id), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad msg-directory reply".to_string())?;
    let bytes = value_to_bytes(value).ok_or_else(|| "bad msg-directory reply".to_string())?;
    Ok((!bytes.is_empty()).then_some(bytes))
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
    let raw = ctx
        .ask_dispatch(ServiceId(dir_id), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad msg-directory reply".to_string())?;
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
    let raw = ctx
        .ask_dispatch(ServiceId(dir_id), &dyn_payload(&msg))
        .await
        .ok_or_else(|| "msg-directory unreachable".to_string())?;
    let value = decode_value(&raw).ok_or_else(|| "bad msg-directory reply".to_string())?;
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
