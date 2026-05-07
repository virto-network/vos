//! `space list` — print known spaces.

use crate::spaces_index;

pub fn run() -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    if index.spaces.is_empty() {
        println!("no spaces. create one with `vosx space new --name <n> --registry <source>`.");
        return Ok(());
    }

    println!("{:<16}  {:<24}  {}", "NAME", "CREATED", "ID");
    for entry in &index.spaces {
        // Print first 12 hex chars of the id for readability.
        let short_id: String = entry.id.chars().take(12).collect();
        println!(
            "{:<16}  {:<24}  {short_id}…",
            truncate(&entry.name, 16),
            entry.created_at,
        );
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
