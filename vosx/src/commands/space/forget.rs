//! `space forget` — drop the local copy of a space.
//!
//! Wipes the per-space data directory and the spaces.toml
//! entry. The shared blob cache is untouched (other spaces may
//! reference the same blobs). The space stays alive on its
//! peers — this is a *local* removal, hence the `forget` verb
//! rather than `delete`.

use std::io::{self, Write};

use serde::Serialize;

use crate::output;
use crate::spaces_index;
use crate::{commands::space::space_lock::SpaceDataLock, paths};

pub struct Args {
    pub space: String,
    pub yes: bool,
}

#[derive(Serialize)]
struct ForgottenView<'a> {
    name: &'a str,
    space_id: &'a str,
    data_dir: &'a str,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, &args.space)?.clone();
    let space_id = entry
        .id_bytes()
        .ok_or_else(|| anyhow::anyhow!("space id in index is not 32 bytes of hex"))?;

    let data_dir = std::path::PathBuf::from(&entry.data_dir);

    if output::is_json() {
        // JSON mode is non-interactive; require --yes so a
        // misfire from a script can't drop user state. The
        // prompt path is text-mode only.
        if !args.yes {
            anyhow::bail!(
                "space forget in --format=json requires --yes (no interactive confirmation)",
            );
        }
    } else {
        println!("about to remove space '{}':", entry.name);
        println!("  space_id  = {}", entry.id);
        println!("  data_dir  = {}", data_dir.display());
        println!();
        println!("the shared blob cache is preserved — other spaces");
        println!("that reference the same blobs keep working.");

        if !args.yes {
            print!("\nproceed? [y/N] ");
            io::stdout().flush().ok();
            let mut buf = String::new();
            io::stdin().read_line(&mut buf)?;
            if !matches!(buf.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                println!("aborted.");
                return Ok(());
            }
        }
    }

    // Deletion is a mutation of the same state protected for the daemon,
    // backup, and restore. Re-resolve the index under its global transaction
    // lock after acquiring the immutable space-id lock so neither a running
    // daemon nor a concurrent restore can lose ownership underneath us.
    let _space_lock = SpaceDataLock::exclusive(&space_id)?;
    let index_path = paths::spaces_index_path();
    let _index_lock = spaces_index::ExclusiveIndexLock::acquire(&index_path)?;
    let mut index = spaces_index::load_from(&index_path)?;
    let current = index
        .spaces
        .iter()
        .find(|candidate| candidate.id == entry.id)
        .ok_or_else(|| {
            anyhow::anyhow!("space index changed while forget was acquiring its lock; retry")
        })?
        .clone();
    if current.data_dir != entry.data_dir || current.name != entry.name {
        anyhow::bail!("space index changed while forget was acquiring its lock; retry");
    }

    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir)
            .map_err(|e| anyhow::anyhow!("remove {}: {e}", data_dir.display()))?;
    }
    index.spaces.retain(|e| e.id != entry.id);
    spaces_index::save_to(&index, &index_path)?;

    if output::is_json() {
        output::print_json(&ForgottenView {
            name: &entry.name,
            space_id: &entry.id,
            data_dir: &entry.data_dir,
        });
    } else {
        println!("removed space '{}' from local store.", entry.name);
    }
    Ok(())
}
