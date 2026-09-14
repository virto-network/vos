//! Genesis verification — confirms the local registry's signing-root
//! commit matches the advertised space_id, ignoring empty initialization.
//!
//! After `space up` boots the registry, we expect either:
//! - **Creator**: the canonical `set_root` CrdtEvent is in the redb
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

pub fn verify_with_timeout(
    registry_db_path: &Path,
    advertised: &[u8; 32],
    wait: Duration,
) -> anyhow::Result<VerifyOutcome> {
    let deadline = Instant::now() + wait;
    let mut last_seen: Option<([u8; 32], [u8; 32])> = None;

    loop {
        if let Some((genesis_cid, derived)) = scan_for_genesis(registry_db_path, advertised)? {
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

/// Scan the DAG table for the canonical signing-root event and return
/// its CID + the space_id it derives to. Prefers the candidate whose
/// derived id equals `advertised` — there must be exactly one genuine
/// genesis, but a peer can offer another root-setting node whose CID
/// sorts lower (redb iterates by CID), so we cannot just take the first.
/// Returns the genuine genesis if present; otherwise the first root-setting
/// node (so the caller can report the mismatch); `None` if none exist.
fn scan_for_genesis(
    registry_db_path: &Path,
    advertised: &[u8; 32],
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

    // The first root-setting node seen (lowest CID), kept only to report a
    // genuine mismatch if no candidate matches `advertised`.
    let mut first_root: Option<([u8; 32], [u8; 32])> = None;
    for row in table.iter().map_err(|e| anyhow::anyhow!("iter dag: {e}"))? {
        let (key, value) = row.map_err(|e| anyhow::anyhow!("read dag row: {e}"))?;
        let Some(cid) = super::common::registry_genesis_cid(key.value(), value.value()) else {
            continue;
        };
        let derived = crate::commands::space::common::derive_space_id(&cid);
        // The genuine genesis is the one whose CID derives the advertised
        // space_id — return it regardless of CID sort order, so a forged
        // lower-CID root-setting sibling can't shadow it.
        if &derived == advertised {
            return Ok(Some((cid, derived)));
        }
        first_root.get_or_insert((cid, derived));
    }
    Ok(first_root)
}
