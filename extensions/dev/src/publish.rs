//! publish() — turn a successful build into a registered program.
//!
//! Bridges the dev-project commit DAG and the space-registry's
//! program catalog. Given a build commit hash (typically returned
//! from a prior `compile()` call), the extension fetches the
//! recorded artifact, hands the bytes to the registry's blob
//! store, registers a `(name, version) -> hash` mapping with
//! `registry.publish`, and finally records an `INTENT_PUBLISH`
//! commit on the dev-project's `publishes` branch so the chain
//! "what got published, from which build, at what time" is
//! auditable.
//!
//! The PVM blob also lands in the operator's local
//! `~/.cache/vosx/blobs/` so `vosx space install` resolves the
//! hash without depending on a separate registry-fetch fallback.
//! The registry-side bytes still travel through the space's
//! consensus stream, so a peer joining tomorrow gets both the
//! catalog mapping and the bytes.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use dev_project::{BuildIntent, HASH_BYTES, HashResult, INTENT_PUBLISH, PublishIntent, STATUS_OK};
use vos::Encode;
use vos::actors::context::ServiceId;
use vos::log;
use vos::value::{Args, Msg, Value};

use crate::DevCtx;

use crate::compile::{
    COMPILE_STATUS_BAD_REPLY, COMPILE_STATUS_TRANSPORT, bytes_to_32_or_zero, decode_value,
    dyn_payload, fetch_commit, fetch_head, remote_commit,
};

/// `ServiceId::REGISTRY.0` — the space-registry is reachable as a
/// fixed raw id on every node regardless of prefix. Inline so the
/// extension doesn't need to depend on `vos::abi::service` types.
const REGISTRY_ID: u32 = 0;

// Status codes start at 30 so they don't collide with PVM-side
// status (0..=7), compile-side status (10..=19), or dep-resolve
// status (20..=22).
pub const PUBLISH_STATUS_BUILD_NOT_FOUND: u8 = 30;
pub const PUBLISH_STATUS_BUILD_FAILED: u8 = 31;
pub const PUBLISH_STATUS_BLOB_NOT_FOUND: u8 = 32;
/// Registry rejected the (name, version, hash) row for some
/// reason it didn't specialise. Distinct from the more specific
/// codes below (tag conflict, bad hash) — see [`map_registry_status`].
pub const PUBLISH_STATUS_REGISTRY_REJECTED: u8 = 33;
pub const PUBLISH_STATUS_RECORD_FAILED: u8 = 34;
pub const PUBLISH_STATUS_BAD_INTENT: u8 = 35;
pub const PUBLISH_STATUS_BAD_BUILD_TAG: u8 = 36;
/// Registry already has this (name, version) under a different
/// hash. Surfaced separately so the CLI can hint at `--allow-retag`
/// or version-bump workflows when that lands.
pub const PUBLISH_STATUS_TAG_CONFLICT: u8 = 37;
/// Registry rejected the hash as not 32 bytes — should never
/// fire because publish already validates length, but routed
/// through to keep the status pipeline honest.
pub const PUBLISH_STATUS_BAD_HASH: u8 = 38;

/// Translate a non-OK `space_registry` status into a
/// publish-domain status. Each registry code maps to a specific
/// publish variant so the CLI doesn't lose information; codes
/// the registry adds later fall through to the generic
/// REGISTRY_REJECTED bucket and the operator picks the detail
/// out of the daemon log.
fn map_registry_status(s: u8) -> u8 {
    // Mapped against space_registry::STATUS_* circa Phase 5.
    // Numeric values cross the FFI; mapping (not re-export)
    // keeps the dev extension free of a build-time dep on
    // space_registry's status constants.
    match s {
        1 => PUBLISH_STATUS_TAG_CONFLICT, // STATUS_TAG_CONFLICT
        6 => PUBLISH_STATUS_BAD_HASH,     // STATUS_BAD_HASH
        _ => PUBLISH_STATUS_REGISTRY_REJECTED,
    }
}

/// Publish a build's PVM blob under `(name, version)` in the space
/// registry. Returns the dev-project commit hash for the
/// `INTENT_PUBLISH` record on success.
pub async fn publish(
    ctx: &mut DevCtx,
    project_id: u32,
    build_commit: Vec<u8>,
    name: String,
    version: String,
) -> HashResult {
    // ── 1. Resolve the build commit
    let commit = match fetch_commit(ctx, project_id, &build_commit).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return HashResult {
                status: PUBLISH_STATUS_BUILD_NOT_FOUND,
                hash: Vec::new(),
            };
        }
        Err(status) => {
            return HashResult {
                status,
                hash: Vec::new(),
            };
        }
    };
    if commit.intent_tag != dev_project::INTENT_BUILD {
        return HashResult {
            status: PUBLISH_STATUS_BAD_BUILD_TAG,
            hash: Vec::new(),
        };
    }

    // ── 2. Decode the BuildIntent. The build must have succeeded;
    //    a failed build is replayable but not publishable.
    let intent = match <BuildIntent as vos::Decode>::try_decode(&commit.intent_data) {
        Some(i) => i,
        None => {
            return HashResult {
                status: PUBLISH_STATUS_BAD_INTENT,
                hash: Vec::new(),
            };
        }
    };
    if intent.ok != 1 {
        return HashResult {
            status: PUBLISH_STATUS_BUILD_FAILED,
            hash: Vec::new(),
        };
    }

    // ── 3. The build commit's `intent.artifact` already carries
    //    the empty-domain hash compile.rs computed when it wrote
    //    the PVM blob into the host-side blob cache. Both
    //    dev-project and space-registry would otherwise need to
    //    materialise the bytes through the 64KB PVM heap, which
    //    a typical ~150KB compiled actor doesn't fit; the local
    //    cache sidesteps that entirely. The hash here is the same
    //    one `space install` looks up via `cache_get`.
    let registry_hash = intent.artifact.to_vec();
    if registry_hash.len() != HASH_BYTES {
        return HashResult {
            status: COMPILE_STATUS_BAD_REPLY,
            hash: Vec::new(),
        };
    }
    // Sanity check: the blob the compile step wrote should still
    // be in the local cache. If it's not, the operator has manually
    // garbage-collected — surface a clean "not found" rather than
    // a silent missing-bytes install.
    let artifact = match fs::read(blob_cache_path(&registry_hash)) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HashResult {
                status: PUBLISH_STATUS_BLOB_NOT_FOUND,
                hash: Vec::new(),
            };
        }
    };
    let crdt = vos::metadata::from_elf(&artifact).is_some_and(|meta| meta.crdt);

    // ── 4. Register the program in the catalog. The catalog only
    //    needs the (name, version, hash) row — the actual bytes
    //    are already in the local blob cache from the compile
    //    step, which is where `space install` reads them.
    //
    //    On non-OK registry status, map the registry's code into
    //    the publish status namespace via `map_registry_status`.
    //    The CLI surfaces specific codes (tag conflict, bad
    //    hash) so the operator gets actionable diagnostics
    //    rather than a flat "rejected".
    match registry_publish(ctx, &name, &version, &registry_hash, crdt).await {
        Ok(s) if s == STATUS_OK => {}
        Ok(s) => {
            log::warn!("dev: registry.publish returned status {s}");
            return HashResult {
                status: map_registry_status(s),
                hash: Vec::new(),
            };
        }
        Err(status) => {
            return HashResult {
                status,
                hash: Vec::new(),
            };
        }
    }

    // ── 5. Record an INTENT_PUBLISH commit on the publishes
    //    branch.
    let publish_intent = PublishIntent {
        program_name: name,
        program_version: version,
        program_hash: bytes_to_32_or_zero(&registry_hash),
    };
    let intent_data = <PublishIntent as Encode>::encode(&publish_intent);

    let publishes_head = match fetch_head(ctx, project_id, "publishes").await {
        Ok(b) => b,
        Err(_) => {
            return HashResult {
                status: PUBLISH_STATUS_RECORD_FAILED,
                hash: Vec::new(),
            };
        }
    };

    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    match remote_commit(
        ctx,
        project_id,
        publishes_head,
        Vec::new(),
        Vec::new(),
        "publishes".to_string(),
        INTENT_PUBLISH,
        intent_data,
        Vec::new(),
        ts_ms,
        Vec::new(),
    )
    .await
    {
        Ok(commit_hash) => HashResult {
            status: STATUS_OK,
            hash: commit_hash,
        },
        Err(_) => HashResult {
            status: PUBLISH_STATUS_RECORD_FAILED,
            hash: Vec::new(),
        },
    }
}

/// Build the self-describing `publish` reply from a [`HashResult`].
/// Success carries the `publishes`-branch commit hash; any non-OK
/// status becomes a non-empty `error` (→ non-zero CLI exit) — the
/// member-refused relay, a not-yet-successful build, a missing blob,
/// etc. all surface here rather than as an opaque status byte.
pub fn publish_args(r: HashResult) -> Args {
    if r.status == STATUS_OK {
        Args::new()
            .with("ok", true)
            .with("status", 0u8)
            .with("publish_commit", r.hash)
    } else {
        let mut err = String::from("publish failed (status ");
        err.push_str(&r.status.to_string());
        err.push(')');
        Args::new()
            .with("ok", false)
            .with("status", r.status)
            .with("error", err)
    }
}

async fn registry_publish(
    ctx: &mut DevCtx,
    name: &str,
    version: &str,
    hash: &[u8],
    crdt: bool,
) -> Result<u8, u8> {
    let msg = Msg::new("publish")
        .with("name", name.to_string())
        .with("version", version.to_string())
        .with("hash", hash.to_vec())
        .with("crdt", crdt);
    let raw = ctx
        .ask_dispatch(ServiceId(REGISTRY_ID), &dyn_payload(&msg))
        .await
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    match value {
        Value::U8(s) => Ok(s),
        // Defensive: `register_extension_meta` returns U8 today;
        // some `#[msg]` codegen paths emit Bytes for primitive
        // returns when promoted. Accept either.
        Value::Bytes(b) if !b.is_empty() => Ok(b[0]),
        _ => Err(COMPILE_STATUS_BAD_REPLY),
    }
}

// ── Local blob cache (host-side storage) ────────────────────────────

/// Persist bytes into vosx's blob cache layout
/// (`paths::blob_cache_dir() / hex_hash`), keyed by the same
/// empty-domain blake2b `BlobHash::of` uses. Returns the hash so
/// the caller can record it in commits / catalog rows.
///
/// Called by the dev extension's compile step (storing the PVM
/// artifact bytes the cargo run produced); `vosx space install`
/// reads back from the same path via `cache_get`.
pub(crate) fn write_to_blob_cache(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let hash: [u8; HASH_BYTES] = vos::crypto::blake2b_hash(&[], &[bytes]);
    let dir = blob_cache_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let hex_name = hex_encode(&hash);
    let path = dir.join(&hex_name);

    // Atomic write: rename a sibling temp into place so a parallel
    // reader can't pick up a half-written file.
    let tmp = dir.join(format!("{hex_name}.partial-{}", std::process::id()));
    fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
    Ok(hash.to_vec())
}

/// Resolve the on-disk path for a given blob hash. Used by
/// `publish` as a defensive existence check before registering
/// the program in the catalog.
pub(crate) fn blob_cache_path(hash: &[u8]) -> PathBuf {
    blob_cache_dir().join(hex_encode(hash))
}

/// Mirror of `vosx::paths::blob_cache_dir`. The two have to stay
/// in lockstep — drift means same-node install can't find blobs
/// the dev extension just published. Kept inline (rather than
/// reusing vosx) so the extension stays free of a host-crate dep.
///
/// Matches vosx's `xdg_root` semantics exactly: accept whatever
/// `XDG_CACHE_HOME` resolves to (no absolute-path filtering),
/// fall back to `$HOME/.cache` and finally a relative `./.cache`
/// when neither is set.
fn blob_cache_dir() -> PathBuf {
    let from_home = || env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache"));
    let root = env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(from_home)
        .unwrap_or_else(|| PathBuf::from(".cache"));
    root.join("vosx").join("blobs")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(nibble(b >> 4));
        s.push(nibble(b & 0xF));
    }
    s
}

fn nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        _ => (b'a' + (n - 10)) as char,
    }
}
