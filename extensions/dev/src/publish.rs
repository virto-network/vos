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
use vos::extension::ServiceCtx;
use vos::log;
use vos::value::{Msg, Value};

use crate::compile::{
    COMPILE_STATUS_BAD_REPLY, COMPILE_STATUS_TRANSPORT, bytes_to_32_or_zero, decode_value,
    dyn_payload, fetch_blob, fetch_commit, fetch_head, remote_commit, value_to_bytes,
};

/// `ServiceId::REGISTRY.0` — the space-registry is reachable as a
/// fixed raw id on every node regardless of prefix. Inline so the
/// extension doesn't need to depend on `vos::abi::service` types.
const REGISTRY_ID: u32 = 0;

// Status codes start at 30 so they don't collide with PVM-side
// status (0..=6) or compile-side status (10..=19).
pub const PUBLISH_STATUS_BUILD_NOT_FOUND: u8 = 30;
pub const PUBLISH_STATUS_BUILD_FAILED: u8 = 31;
pub const PUBLISH_STATUS_BLOB_NOT_FOUND: u8 = 32;
pub const PUBLISH_STATUS_REGISTRY_REJECTED: u8 = 33;
pub const PUBLISH_STATUS_RECORD_FAILED: u8 = 34;
pub const PUBLISH_STATUS_BAD_INTENT: u8 = 35;
pub const PUBLISH_STATUS_BAD_BUILD_TAG: u8 = 36;

/// Publish a build's PVM blob under `(name, version)` in the space
/// registry. Returns the dev-project commit hash for the
/// `INTENT_PUBLISH` record on success.
pub fn publish(
    ctx: &ServiceCtx,
    project_id: u32,
    build_commit: Vec<u8>,
    name: String,
    version: String,
) -> HashResult {
    // ── 1. Resolve the build commit
    let commit = match fetch_commit(ctx, project_id, &build_commit) {
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

    // ── 3. Pull the PVM blob's bytes out of the project's object
    //    store. `intent.artifact` carries the dev-project blob hash
    //    (i.e. blake2b("vos-dev-project/blob/v1", bytes)), distinct
    //    from the empty-domain hash the registry uses.
    let blob = match fetch_blob(ctx, project_id, &intent.artifact) {
        Ok(Some(b)) => b,
        Ok(None) => {
            return HashResult {
                status: PUBLISH_STATUS_BLOB_NOT_FOUND,
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

    // ── 4. Re-key under the registry's empty-domain hash by
    //    uploading. The registry returns the canonical hash; we
    //    use it as the catalog key and also as the local-cache
    //    filename below.
    let registry_hash = match registry_upload_blob(ctx, &blob.bytes) {
        Ok(h) => h,
        Err(status) => {
            return HashResult {
                status,
                hash: Vec::new(),
            };
        }
    };
    if registry_hash.len() != HASH_BYTES {
        return HashResult {
            status: COMPILE_STATUS_BAD_REPLY,
            hash: Vec::new(),
        };
    }

    // ── 5. Mirror to the local blob cache so same-node `vosx space
    //    install` finds the bytes without falling back to a
    //    registry fetch (which install / up don't do yet). Failure
    //    is non-fatal — the registry still has the bytes.
    if let Err(e) = write_to_local_cache(&registry_hash, &blob.bytes) {
        log::warn!(
            "dev: failed to mirror blob to local cache ({e}); \
             registry upload still succeeded — install may need a manual blob cache hydrate"
        );
    }

    // ── 6. Register the program in the catalog.
    match registry_publish(ctx, &name, &version, &registry_hash) {
        Ok(s) if s == STATUS_OK => {}
        Ok(s) => {
            log::warn!("dev: registry.publish returned status {s}");
            return HashResult {
                status: PUBLISH_STATUS_REGISTRY_REJECTED,
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

    // ── 7. Record an INTENT_PUBLISH commit on the publishes
    //    branch.
    let publish_intent = PublishIntent {
        program_name: name,
        program_version: version,
        program_hash: bytes_to_32_or_zero(&registry_hash),
    };
    let intent_data = <PublishIntent as Encode>::encode(&publish_intent);

    let publishes_head = match fetch_head(ctx, project_id, "publishes") {
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
    ) {
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

// ── Registry wire calls ─────────────────────────────────────────────

fn registry_upload_blob(ctx: &ServiceCtx, bytes: &[u8]) -> Result<Vec<u8>, u8> {
    let msg = Msg::new("upload_blob").with("bytes", bytes.to_vec());
    let raw = ctx
        .ask_raw(REGISTRY_ID, &dyn_payload(&msg))
        .ok_or(COMPILE_STATUS_TRANSPORT)?;
    let value = decode_value(&raw).ok_or(COMPILE_STATUS_BAD_REPLY)?;
    value_to_bytes(value).ok_or(COMPILE_STATUS_BAD_REPLY)
}

fn registry_publish(ctx: &ServiceCtx, name: &str, version: &str, hash: &[u8]) -> Result<u8, u8> {
    let msg = Msg::new("publish")
        .with("name", name.to_string())
        .with("version", version.to_string())
        .with("hash", hash.to_vec());
    let raw = ctx
        .ask_raw(REGISTRY_ID, &dyn_payload(&msg))
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

// ── Local blob cache mirror ─────────────────────────────────────────

/// Replicate vosx's blob cache layout
/// (`paths::blob_cache_dir() / hex_hash`) so `space install` /
/// `space up` find the bytes without a registry-fallback lookup.
fn write_to_local_cache(hash: &[u8], bytes: &[u8]) -> std::io::Result<()> {
    let dir = blob_cache_dir();
    fs::create_dir_all(&dir)?;
    let hex_name = hex_encode(hash);
    let path = dir.join(&hex_name);

    // Atomic write: rename a sibling temp into place. Eliminates a
    // partial-write window where a parallel reader would see a
    // truncated cache entry.
    let tmp = dir.join(format!("{hex_name}.partial-{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Mirror of `vosx::paths::blob_cache_dir`. The two have to stay
/// in lockstep — drift means same-node install can't find blobs
/// the dev extension just published. Kept inline (rather than
/// reusing vosx) so the extension stays free of a host-crate dep.
fn blob_cache_dir() -> PathBuf {
    let root = if let Some(xdg) = env::var_os("XDG_CACHE_HOME") {
        let p = PathBuf::from(xdg);
        if p.is_absolute() {
            p
        } else {
            home_dir_or_dot().join(".cache")
        }
    } else {
        home_dir_or_dot().join(".cache")
    };
    root.join("vosx").join("blobs")
}

fn home_dir_or_dot() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
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
