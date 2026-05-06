//! `vosx new <name>` — scaffold a new space.
//!
//! Generates `<name>/space.toml` plus a starter Raft-backed
//! actor crate so a newcomer can `cd <name> && cargo build &&
//! vosx up` to see something running.
//!
//! Currently the scaffold uses path deps on the in-checkout
//! `vos` crate — `vosx new` walks up from cwd looking for the
//! kunekt workspace root and writes a relative path into the
//! generated Cargo.toml. Run outside a checkout fails loudly
//! until `vos` is published to a registry.

use std::path::{Path, PathBuf};

use crate::util::die;

const TMPL_SPACE: &str = include_str!("../../templates/space.toml.tmpl");
const TMPL_ACTOR_LIB: &str = include_str!("../../templates/actor_lib.rs.tmpl");
const TMPL_ACTOR_CARGO: &str = include_str!("../../templates/actor_cargo.toml.tmpl");
const TMPL_ACTOR_CARGO_CFG: &str =
    include_str!("../../templates/actor_cargo_config.toml.tmpl");
const TMPL_RUST_TOOLCHAIN: &str =
    include_str!("../../templates/rust_toolchain.toml.tmpl");
const TMPL_TARGET_SPEC: &str = include_str!("../../templates/riscv64em-javm.json");

pub fn run(name: &str) {
    if name.is_empty() {
        die("vosx new: empty space name");
    }
    let root = PathBuf::from(name);
    // Refuse paths containing `..` segments — those would let a
    // typo escape the user's cwd in a way that's almost
    // certainly not what they meant. Plain relative paths
    // (`./demo`, `subdir/demo`) and absolute paths are fine.
    if root.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        die(&format!(
            "vosx new: refusing to scaffold at {name:?} — path contains '..' segments"
        ));
    }
    if root.exists() {
        die(&format!(
            "vosx new: {} already exists; refusing to overwrite",
            root.display(),
        ));
    }
    // Resolve the path-dep BEFORE creating any files so a "not
    // in a kunekt checkout" failure leaves no half-scaffolded
    // directory behind.
    let vos_path = locate_vos_path(&root).unwrap_or_else(|| {
        die(
            "vosx new: couldn't locate the kunekt workspace from cwd. \
             Run inside a kunekt checkout (or wait for vos to be published \
             to a registry)."
        )
    });

    let actor_root = root.join("actors").join("counter");
    let actor_src = actor_root.join("src");
    let actor_cargo_dir = actor_root.join(".cargo");
    if let Err(e) = std::fs::create_dir_all(&actor_src) {
        die(&format!("create {}: {e}", actor_src.display()));
    }
    if let Err(e) = std::fs::create_dir_all(&actor_cargo_dir) {
        die(&format!("create {}: {e}", actor_cargo_dir.display()));
    }

    write_file(&root.join("space.toml"), &subst(TMPL_SPACE, &[("name", name)]));
    write_file(
        &actor_root.join("Cargo.toml"),
        &subst(TMPL_ACTOR_CARGO, &[("vos_path", &vos_path)]),
    );
    write_file(&actor_src.join("lib.rs"), TMPL_ACTOR_LIB);
    write_file(&actor_cargo_dir.join("config.toml"), TMPL_ACTOR_CARGO_CFG);
    write_file(&actor_root.join("rust-toolchain.toml"), TMPL_RUST_TOOLCHAIN);
    write_file(&actor_root.join("riscv64em-javm.json"), TMPL_TARGET_SPEC);

    eprintln!("vosx: scaffolded space at {}", root.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!("  cd {}", root.display());
    eprintln!(
        "  (cd actors/counter && cargo +nightly -Zjson-target-spec build --release)"
    );
    eprintln!("  vosx up");
    eprintln!();
    eprintln!(
        "Building the actor needs the riscv64em-javm custom target — see");
    eprintln!("memory/reference_pvm_build.md for setup notes.");
}

fn write_file(path: &Path, content: &str) {
    if let Err(e) = std::fs::write(path, content) {
        die(&format!("write {}: {e}", path.display()));
    }
}

fn subst(template: &str, vars: &[(&str, &str)]) -> String {
    let mut s = template.to_string();
    for (k, v) in vars {
        s = s.replace(&format!("{{{{{k}}}}}"), v);
    }
    s
}

/// Walk from `<scaffold>/actors/counter/` up to find the
/// kunekt workspace root (the directory whose `Cargo.toml`
/// declares `vos` as a member). Returns the relative path
/// from the actor crate to `crates/vos`. The walk starts at
/// the scaffold root because the actor dir doesn't exist yet
/// at template-resolve time — relative paths are anchored at
/// `<scaffold>/actors/counter/`.
fn locate_vos_path(scaffold_root: &Path) -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let scaffold_abs = cwd.join(scaffold_root);
    let actor_abs = scaffold_abs.join("actors").join("counter");
    let mut dir: PathBuf = cwd.clone();
    loop {
        let candidate = dir.join("crates").join("vos").join("Cargo.toml");
        if candidate.exists() {
            // Relative path from the actor crate dir to crates/vos.
            // Use path separators that work on the build host.
            let vos_dir = dir.join("crates").join("vos");
            let rel = pathdiff(&actor_abs, &vos_dir)?;
            return Some(rel.to_string_lossy().replace('\\', "/").to_string());
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Lightweight `pathdiff` (avoids the `pathdiff` crate dep).
/// Returns the relative path from `from` to `to`, both absolute.
fn pathdiff(from: &Path, to: &Path) -> Option<PathBuf> {
    let from_components: Vec<_> = from.components().collect();
    let to_components: Vec<_> = to.components().collect();
    let common = from_components
        .iter()
        .zip(to_components.iter())
        .take_while(|(a, b)| a == b)
        .count();
    let mut out = PathBuf::new();
    for _ in common..from_components.len() {
        out.push("..");
    }
    for c in &to_components[common..] {
        out.push(c.as_os_str());
    }
    Some(out)
}
