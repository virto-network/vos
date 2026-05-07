//! `space info` — show metadata for a single space.

use std::path::PathBuf;

use crate::spaces_index;

pub fn run(query: Option<&str>) -> anyhow::Result<()> {
    let index = spaces_index::load()?;
    let entry = match query {
        Some(q) => spaces_index::find(&index, q)?,
        None => {
            // No arg → look for a space whose data_dir is the
            // current directory or one of its ancestors.
            let cwd = std::env::current_dir()?;
            match resolve_by_cwd(&index.spaces, &cwd) {
                Some(e) => e,
                None => anyhow::bail!(
                    "no space matches the current dir; pass a space name or id"
                ),
            }
        }
    };

    println!("name        {}", entry.name);
    println!("space_id    {}", entry.id);
    println!("created_at  {}", entry.created_at);
    println!("data_dir    {}", entry.data_dir);
    if entry.listen.is_empty() {
        println!("listen      (none — local-only)");
    } else {
        println!("listen");
        for a in &entry.listen {
            println!("  {a}");
        }
    }

    let space_path = PathBuf::from(&entry.data_dir);
    let agents_dir = space_path.join("agents");
    let count = match std::fs::read_dir(&agents_dir) {
        Ok(rd) => rd.flatten().count(),
        Err(_) => 0,
    };
    println!("agents      {count} (in {})", agents_dir.display());

    Ok(())
}

fn resolve_by_cwd<'a>(
    spaces: &'a [crate::spaces_index::SpaceEntry],
    cwd: &std::path::Path,
) -> Option<&'a crate::spaces_index::SpaceEntry> {
    spaces.iter().find(|e| {
        let p = PathBuf::from(&e.data_dir);
        cwd.starts_with(&p) || p == *cwd
    })
}
