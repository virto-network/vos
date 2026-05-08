//! `space dag` — DAG diagnostic for an installed agent.
//!
//! Two modes, picked automatically based on whether the
//! daemon's running:
//!
//! - **Live** (daemon up): connects via `DaemonClient`, asks
//!   the registry for the agent's replication_id, then fires
//!   a libp2p `FetchHeads` at the daemon to read its current
//!   roots. No node-count or per-origin breakdown — those
//!   would need a full DAG walk via repeated `FetchNode` and
//!   aren't worth the round-trips for a one-shot diagnostic.
//! - **Offline** (no daemon): opens the redb directly and
//!   prints roots, total node count, and per-origin
//!   `(min_seq, max_seq)`. Errors if the redb is locked.
//!
//! `<agent>` is `registry` (well-known REGISTRY id) or any
//! installed instance name.

use std::path::Path;
use std::time::Duration;

use redb::ReadableTable;
use vos::abi::service::ServiceId;

use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::{instance_service_id, registry_replication_id};
use crate::commands::space::endpoint;
use crate::spaces_index::{self, SpaceEntry};

const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");
const STATE_TABLE: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("state");
const ROOTS_KEY: &str = "crdt_roots";
const FETCH_HEADS_TIMEOUT: Duration = Duration::from_secs(5);

pub fn run(space: &str, agent: &str) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, space)?.clone();
    let data_dir = std::path::PathBuf::from(&entry.data_dir);
    if !data_dir.exists() {
        anyhow::bail!("data dir does not exist: {}", data_dir.display());
    }

    // Daemon up? Use the live path. Stale endpoint files (PID
    // dead) fall back to the offline read since the redb is
    // free.
    let live = match endpoint::read(&data_dir)? {
        Some(ep) if endpoint::is_alive(&ep) => true,
        _ => false,
    };

    if live {
        run_live(&entry, agent)
    } else {
        run_offline(&entry, &data_dir, agent)
    }
}

/// Daemon's running — query roots over libp2p via the
/// existing `FetchHeads` protocol.
fn run_live(entry: &SpaceEntry, agent: &str) -> anyhow::Result<()> {
    let space_id = entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id is not 32 bytes of hex"))?;
    let endpoint_data = endpoint::read(&std::path::PathBuf::from(&entry.data_dir))?
        .ok_or_else(|| anyhow::anyhow!("endpoint disappeared"))?;
    let daemon_peer: libp2p::PeerId = endpoint_data
        .peer_id
        .parse()
        .map_err(|e| anyhow::anyhow!("bad daemon peer_id: {e}"))?;
    let daemon_prefix = endpoint_data.prefix;

    DaemonClient::with_connect(&entry.name, |client| {
        let net = client
            .node()
            .network()
            .ok_or_else(|| anyhow::anyhow!("client has no network attached"))?;

        // Resolve the agent's replication_id. The registry's id
        // is derived deterministically from space_id (it isn't
        // stored in its own catalog); installed agents carry it
        // on their AgentRow.
        let (replication_id, svc_id) = if agent == "registry" {
            (
                registry_replication_id(&space_id),
                ServiceId::new(daemon_prefix, ServiceId::REGISTRY.local_id()),
            )
        } else {
            let row = client.agent(agent)?.ok_or_else(|| anyhow::anyhow!(
                "no agent named '{agent}' is installed in this space",
            ))?;
            (row.replication_id, instance_service_id(agent, daemon_prefix))
        };

        // FetchHeads: the daemon's NetworkService::sync_roots
        // reads its slot's redb roots and returns them. Same
        // protocol the CRDT sync ticker uses.
        let rx = net.send_fetch_heads(daemon_peer, replication_id);
        let roots = rx
            .recv_timeout(FETCH_HEADS_TIMEOUT)
            .map_err(|_| anyhow::anyhow!("FetchHeads from daemon timed out"))?;

        println!("space '{}' — agent '{}' (svc:{:08x}) [LIVE]", entry.name, agent, svc_id.0);
        println!("  replication_id: {}", hex::encode(replication_id));
        println!();
        println!("roots ({}):", roots.len());
        for r in &roots {
            println!("  {}", hex::encode(r));
        }
        println!();
        println!("node count: <not queried — live mode prints roots only;");
        println!("            stop the daemon and re-run for full node + origin stats>");
        Ok(())
    })
}

/// Daemon's down — read the redb directly. Fuller stats
/// (node count, per-origin seq range) but requires the redb
/// to be unlocked.
fn run_offline(entry: &SpaceEntry, data_dir: &Path, agent: &str) -> anyhow::Result<()> {
    let svc_id = resolve_svc_id_offline(data_dir, agent)?;
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
            "{} is already open — start `space up` to use the live mode, \
             or stop it for full offline stats.",
            db_path.display(),
        ),
        other => anyhow::anyhow!("open {}: {other}", db_path.display()),
    })?;

    let txn = db.begin_read()?;

    let roots: Vec<[u8; 32]> = match txn.open_table(STATE_TABLE) {
        Ok(t) => match t.get(ROOTS_KEY)? {
            Some(v) => decode_roots(v.value()).unwrap_or_default(),
            None => Vec::new(),
        },
        Err(redb::TableError::TableDoesNotExist(_)) => Vec::new(),
        Err(e) => return Err(anyhow::anyhow!("open state table: {e}")),
    };

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

    println!("space '{}' — agent '{}' (svc:{:08x}) [OFFLINE]", entry.name, agent, svc_id.0);
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
        println!("by origin:");
        println!("  {:<66}  {:<8}  {:<8}", "ORIGIN", "MIN_SEQ", "MAX_SEQ");
        for (origin, (lo, hi)) in &origin_seq {
            println!("  {:<66}  {:<8}  {:<8}", hex::encode(origin), lo, hi);
        }
    }
    Ok(())
}

fn resolve_svc_id_offline(data_dir: &Path, agent: &str) -> anyhow::Result<ServiceId> {
    if agent == "registry" {
        return Ok(ServiceId::REGISTRY);
    }
    let prefix = endpoint::read(data_dir)?.map(|ep| ep.prefix).unwrap_or(0);
    Ok(instance_service_id(agent, prefix))
}

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
