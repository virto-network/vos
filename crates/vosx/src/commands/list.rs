//! `vosx ls [<manifest>]` — print the space's actors,
//! workers, and their declared messages. No execution; pure
//! introspection over the manifest + each entry's `.vos_meta`
//! ELF section.

use std::path::{Path, PathBuf};

use crate::manifest::Manifest;
use crate::util::print_actor_meta;

pub fn run(manifest: &Manifest, dir: &Path) {
    println!("space: {}", manifest.space);
    if let Some(v) = &manifest.version {
        println!("  version: {v}");
    }
    if let Some(hs) = &manifest.hyperspace {
        println!("  hyperspace: {hs}");
    }
    println!();

    for a in &manifest.agent {
        let role = format!(
            "agent {:?}{}",
            a.consistency,
            if a.provides.is_empty() { String::new() } else { format!(" provides={:?}", a.provides) },
        );
        let path = display_path(&a.name, &a.path, &a.service, dir);
        print_actor_meta(&a.name, &path, &role);

        for child in &a.actors {
            let role = format!(
                "actor (child of {}){}",
                a.name,
                if child.provides.is_empty() { String::new() } else { format!(" provides={:?}", child.provides) },
            );
            let path = display_path(&child.name, &child.path, &child.service, dir);
            print_actor_meta(&child.name, &path, &role);
        }
    }

    for w in &manifest.worker {
        let path = display_path(&w.name, &w.path, &w.service, dir);
        let role_tag = if w.provides.is_empty() {
            String::new()
        } else {
            format!(" provides={:?}", w.provides)
        };
        if path.exists() {
            println!("  {} (worker{role_tag}) — {}", w.name, path.display());
        } else {
            println!("  {} (worker{role_tag}) — not built ({})", w.name, path.display());
        }
    }
}

/// Same shape as `manifest::resolve_entry_path` but for read-
/// only `list`: never `die`s. `service` entries become a
/// display placeholder since registry resolution at list time
/// would require connecting to the hyperspace.
fn display_path(
    name: &str,
    path: &Option<PathBuf>,
    service: &Option<String>,
    dir: &Path,
) -> PathBuf {
    if let Some(p) = path {
        dir.join(p)
    } else if let Some(s) = service {
        PathBuf::from(format!("<service: {s}>"))
    } else {
        PathBuf::from(format!("<unspecified for '{name}'>"))
    }
}
