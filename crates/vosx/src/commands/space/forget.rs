//! `space forget` — drop the local copy of a space.
//!
//! Wipes the per-space data directory and the spaces.toml
//! entry. The shared blob cache is untouched (other spaces may
//! reference the same blobs). The space stays alive on its
//! peers — this is a *local* removal, hence the `forget` verb
//! rather than `delete`.

use std::io::{self, Write};

use crate::spaces_index;

pub struct Args {
    pub space: String,
    pub yes: bool,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let mut index = spaces_index::load()?;
    let entry = spaces_index::find(&index, &args.space)?.clone();

    let data_dir = std::path::PathBuf::from(&entry.data_dir);
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

    if data_dir.exists() {
        std::fs::remove_dir_all(&data_dir)
            .map_err(|e| anyhow::anyhow!("remove {}: {e}", data_dir.display()))?;
    }
    index.spaces.retain(|e| e.id != entry.id);
    spaces_index::save(&index)?;

    println!("removed space '{}' from local store.", entry.name);
    Ok(())
}
