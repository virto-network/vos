//! `space dag` — read-only DAG diagnostic for an installed
//! agent's CRDT redb.
//!
//! Opens `<data_dir>/agents/<svc_id>.redb` directly and prints:
//! - current roots (DAG tips after merge)
//! - total node count
//! - per-origin seq counters (one row per replica that's
//!   committed something)
//!
//! Limitation: the daemon holds the redb exclusively while
//! `space up` is running, so `space dag` errors out with a
//! "database already open" message in that case. Stop the
//! daemon (or wait for it to exit) and re-run.

use std::path::Path;

use redb::ReadableTable;
use vos::abi::service::ServiceId;

use crate::commands::space::endpoint;
use crate::spaces_index;

const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");
const STATE_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("state");
const ROOTS_KEY: &str = "crdt_roots";

pub fn run(space: &str, agent: &str) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, space)?.clone();
    let data_dir = std::path::PathBuf::from(&entry.data_dir);
    if !data_dir.exists() {
        anyhow::bail!("data dir does not exist: {}", data_dir.display());
    }

    let svc_id = resolve_svc_id(&data_dir, agent)?;
    let db_path = data_dir
        .join("agents")
        .join(format!("{:08x}.redb", svc_id.0));
    if !db_path.exists() {
        anyhow::bail!(
            "no redb at {} — '{agent}' not installed or never committed?",
            db_path.display(),
        );
    }

    let db = redb::Database::open(&db_path).map_err(|e| match e {
        redb::DatabaseError::DatabaseAlreadyOpen => anyhow::anyhow!(
            "{} is already open — stop `space up` for this space first \
             (the daemon owns the redb exclusively).",
            db_path.display(),
        ),
        other => anyhow::anyhow!("open {}: {other}", db_path.display()),
    })?;

    let txn = db.begin_read()?;

    // ── Roots ────────────────────────────────────────────────
    let roots: Vec<[u8; 32]> = match txn.open_table(STATE_TABLE) {
        Ok(t) => match t.get(ROOTS_KEY)? {
            Some(v) => decode_roots(v.value()).unwrap_or_default(),
            None => Vec::new(),
        },
        Err(redb::TableError::TableDoesNotExist(_)) => Vec::new(),
        Err(e) => return Err(anyhow::anyhow!("open state table: {e}")),
    };

    // ── DAG node iteration ──────────────────────────────────
    let mut node_count = 0usize;
    let mut origin_seq: std::collections::BTreeMap<[u8; 32], (u64, u64)> =
        std::collections::BTreeMap::new();
    if let Ok(table) = txn.open_table(DAG_TABLE) {
        for row in table.iter()? {
            let (_key, value) = row?;
            let bytes: &[u8] = value.value();
            node_count += 1;
            if let Some(event) = decode_crdt_event_from_dagnode(bytes) {
                let entry = origin_seq.entry(event.origin).or_insert((u64::MAX, 0));
                entry.0 = entry.0.min(event.seq);
                entry.1 = entry.1.max(event.seq);
            }
        }
    }

    println!("space '{}' — agent '{}' (svc:{:08x})", entry.name, agent, svc_id.0);
    println!("  data: {}", db_path.display());
    println!();
    println!("roots ({}):", roots.len());
    for r in &roots {
        println!("  {}", hex::encode(r));
    }
    println!();
    println!("dag nodes: {node_count}");
    if !origin_seq.is_empty() {
        println!();
        println!("by origin (one row per replica that has committed):");
        println!("  {:<66}  {:<8}  {:<8}", "ORIGIN", "MIN_SEQ", "MAX_SEQ");
        for (origin, (lo, hi)) in &origin_seq {
            println!("  {:<66}  {:<8}  {:<8}", hex::encode(origin), lo, hi);
        }
    }
    Ok(())
}

/// `agent` is `"registry"` (well-known REGISTRY id) or an
/// installed instance name (svc_id derived via the same scheme
/// `space up` uses to register agents — read the daemon's
/// prefix from `.endpoint` if present, else fall back to 0).
fn resolve_svc_id(data_dir: &Path, agent: &str) -> anyhow::Result<ServiceId> {
    if agent == "registry" {
        return Ok(ServiceId::REGISTRY);
    }
    // Need the daemon's prefix to derive the svc_id. The
    // .endpoint file has it; if it's missing (no daemon
    // running ever / data corruption), fall back to prefix=0.
    // Either way the lookup is local-disk-only — no daemon
    // contact needed.
    let prefix = match endpoint::read(data_dir)? {
        Some(ep) => ep.prefix,
        None => 0,
    };
    let raw = crate::commands::space::up::derive_instance_svc_id(agent, prefix);
    Ok(ServiceId(raw))
}

/// `DagNode` wire format: `[payload_len:u64 LE][payload][n_children:u64 LE][children...]`.
/// Strip the header, decode the payload as a `CrdtEvent`.
fn decode_crdt_event_from_dagnode(bytes: &[u8]) -> Option<vos::effect_log::CrdtEvent> {
    if bytes.len() < 8 {
        return None;
    }
    let payload_len = u64::from_le_bytes(bytes[..8].try_into().ok()?) as usize;
    if bytes.len() < 8 + payload_len {
        return None;
    }
    vos::effect_log::CrdtEvent::from_bytes(&bytes[8..8 + payload_len])
}

/// Decode the rkyv'd `Vec<Cid>` stored under
/// `STATE_TABLE/crdt_roots`. Wire format mirrors
/// `vos::commit::encode_roots`:
/// `[count:u64 LE][cid_bytes (32 each)...]`.
fn decode_roots(bytes: &[u8]) -> Option<Vec<[u8; 32]>> {
    if bytes.len() < 8 {
        return None;
    }
    let count = u64::from_le_bytes(bytes[..8].try_into().ok()?) as usize;
    if bytes.len() != 8 + count * 32 {
        return None;
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let s = 8 + i * 32;
        let mut cid = [0u8; 32];
        cid.copy_from_slice(&bytes[s..s + 32]);
        out.push(cid);
    }
    Some(out)
}
