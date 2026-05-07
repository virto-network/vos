//! Genesis verification — confirms the local registry's first
//! commit matches the advertised space_id.
//!
//! After `space up` boots the registry, we expect either:
//! - **Creator**: the genesis CrdtEvent (seq=1) is in the redb
//!   from `space new`. `derive_space_id(cid)` must match the
//!   space_id we chose at creation, by definition.
//! - **Joiner**: the gossipsub sync layer pulls the genesis
//!   from peers; we wait for it briefly, then verify.
//!
//! On mismatch we error out — a joiner who got pointed at the
//! wrong space won't silently start contributing to it.
//! On no-genesis-yet (offline / no peers) we warn and continue
//! ("trust on first use" — the next `space up` retries).

use std::path::Path;
use std::time::{Duration, Instant};

use redb::ReadableTable;

const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");
const DEFAULT_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum VerifyOutcome {
    /// Genesis was found and matches the advertised space_id.
    Verified { genesis_cid: [u8; 32] },
    /// Genesis was found but its derived space_id doesn't match.
    Mismatch {
        genesis_cid: [u8; 32],
        derived: [u8; 32],
        advertised: [u8; 32],
    },
    /// No genesis CrdtEvent appeared in the wait window. The
    /// caller decides whether to keep going or bail.
    NoGenesisYet,
}

/// Poll the registry's redb for a seq=1 event whose CID
/// derives back to `advertised_space_id`. Returns once any
/// candidate matches, or after `wait` elapses with no match.
pub fn verify_genesis(
    registry_db_path: &Path,
    advertised_space_id: &[u8; 32],
) -> anyhow::Result<VerifyOutcome> {
    verify_with_timeout(registry_db_path, advertised_space_id, DEFAULT_WAIT)
}

pub fn verify_with_timeout(
    registry_db_path: &Path,
    advertised: &[u8; 32],
    wait: Duration,
) -> anyhow::Result<VerifyOutcome> {
    let deadline = Instant::now() + wait;
    let mut last_seen: Option<([u8; 32], [u8; 32])> = None;

    loop {
        if let Some((genesis_cid, derived)) = scan_for_genesis(registry_db_path)? {
            if &derived == advertised {
                return Ok(VerifyOutcome::Verified { genesis_cid });
            }
            last_seen = Some((genesis_cid, derived));
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    Ok(match last_seen {
        Some((genesis_cid, derived)) => VerifyOutcome::Mismatch {
            genesis_cid,
            derived,
            advertised: *advertised,
        },
        None => VerifyOutcome::NoGenesisYet,
    })
}

/// Scan the DAG table for a CrdtEvent with seq=1, return its
/// CID + the space_id it derives to. None if no such event
/// (yet).
fn scan_for_genesis(
    registry_db_path: &Path,
) -> anyhow::Result<Option<([u8; 32], [u8; 32])>> {
    let db = redb::Database::open(registry_db_path)
        .map_err(|e| anyhow::anyhow!("open {}: {e}", registry_db_path.display()))?;
    let txn = db
        .begin_read()
        .map_err(|e| anyhow::anyhow!("begin read: {e}"))?;
    let table = match txn.open_table(DAG_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => anyhow::bail!("open dag table: {e}"),
    };

    for row in table.iter().map_err(|e| anyhow::anyhow!("iter dag: {e}"))? {
        let (key, value) = row.map_err(|e| anyhow::anyhow!("read dag row: {e}"))?;
        let bytes: &[u8] = value.value();
        // DagNode wire format: [payload_len:u64 LE][payload][n_children:u64 LE][children...]
        if bytes.len() < 8 {
            continue;
        }
        let payload_len = u64::from_le_bytes(bytes[..8].try_into().unwrap()) as usize;
        if bytes.len() < 8 + payload_len {
            continue;
        }
        let payload = &bytes[8..8 + payload_len];
        let Some(event) = vos::effect_log::CrdtEvent::from_bytes(payload) else {
            continue;
        };
        if event.seq != 1 {
            continue;
        }
        let key_bytes: &[u8] = key.value();
        if key_bytes.len() != 32 {
            continue;
        }
        let mut cid = [0u8; 32];
        cid.copy_from_slice(key_bytes);
        let derived = space_registry::derive_space_id(&cid);
        return Ok(Some((cid, derived)));
    }
    Ok(None)
}
