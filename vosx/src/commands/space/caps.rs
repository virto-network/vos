//! `space caps [<instance>]` — show the effective relay
//! `intra_caps` the running daemon loaded for each service
//! extension.
//!
//! These are *per-daemon host policy* (the role ceilings an
//! extension may relay to each target), not replicated registry
//! state — so they're read straight from the local endpoint
//! descriptor the daemon publishes at boot, no libp2p round-trip.
//! The descriptor is deleted on graceful shutdown, so a present
//! file means "this is what the currently-running daemon enforces".
//!
//! Output:
//!   - default: one line per extension, `name: cap, cap, …` (or
//!     `(none — relays as Unauthenticated)` for a deny-all relay).
//!   - `--format json`: `[{ "name", "caps": [...] }, …]`.

use crate::commands::space::endpoint;
use crate::output;
use crate::spaces_index;
use anyhow::anyhow;

pub fn run(space: &str, instance: Option<&str>) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = spaces_index::find(&index, space)?;
    let data_dir = std::path::PathBuf::from(&entry.data_dir);

    let ep = endpoint::read(&data_dir)?
        .filter(endpoint::is_alive)
        .ok_or_else(|| {
            anyhow!(
                "no daemon running for space '{}'. Start it with `vosx space up {}`.",
                entry.name,
                entry.name,
            )
        })?;

    // Filter to the requested instance, if any.
    let shown: Vec<&endpoint::ExtensionCaps> = match instance {
        Some(name) => {
            let hit = ep
                .extensions
                .iter()
                .find(|e| e.name == name)
                .ok_or_else(|| {
                    anyhow!(
                        "'{name}' is not a service extension this daemon loaded \
                         (relay caps only apply to service extensions; \
                         `vosx space caps {}` lists them all)",
                        entry.name,
                    )
                })?;
            vec![hit]
        }
        None => ep.extensions.iter().collect(),
    };

    if output::is_json() {
        output::print_json(&shown);
        return Ok(());
    }

    if shown.is_empty() {
        println!("(no service extensions with relay caps in this space)");
        return Ok(());
    }
    let width = shown.iter().map(|e| e.name.len()).max().unwrap_or(0);
    for e in shown {
        let rendered = if e.caps.is_empty() {
            "(none — relays as Unauthenticated)".to_string()
        } else {
            e.caps.join(", ")
        };
        println!("{:<width$}  {}", e.name, rendered, width = width);
    }
    Ok(())
}
