//! `vosx new` v2 actor scaffolding.

use std::path::PathBuf;

use anyhow::{Context, bail};

pub fn run(path: PathBuf, crdt: bool) -> anyhow::Result<()> {
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("project path needs a UTF-8 file name"))?;
    let crate_name = name.replace('-', "_");

    std::fs::create_dir_all(path.join("src"))
        .with_context(|| format!("create {}", path.display()))?;
    std::fs::create_dir_all(path.join(".cargo"))?;
    std::fs::write(path.join("Cargo.toml"), cargo_toml(name))?;
    std::fs::write(path.join(".cargo/config.toml"), CONFIG)?;
    std::fs::write(path.join("rust-toolchain.toml"), TOOLCHAIN)?;
    std::fs::write(path.join("riscv64em-javm.json"), TARGET)?;
    std::fs::write(
        path.join("src/lib.rs"),
        if crdt {
            crdt_source(&crate_name)
        } else {
            counter_source(&crate_name)
        },
    )?;
    println!("created {}", path.display());
    println!("  cd {} && cargo actor", path.display());
    Ok(())
}

fn cargo_toml(name: &str) -> String {
    format!(
        r#"[workspace]

[package]
name = "{name}"
version = "0.1.0"
edition = "2024"

[features]
default = ["bin"]
bin = []

[lib]
crate-type = ["rlib", "cdylib"]

[target.'cfg(target_arch = "riscv64")'.dependencies]
vos = {{ version = "{}", default-features = false, features = ["macros", "service"] }}

[target.'cfg(not(target_arch = "riscv64"))'.dependencies]
vos = {{ version = "{}", default-features = false, features = ["macros", "extension"] }}

[profile.release]
opt-level = "s"
lto = true
panic = "abort"
"#,
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_VERSION"),
    )
}

fn counter_source(name: &str) -> String {
    format!(
        r#"//! {name}: an ordinary local actor.

use vos::prelude::*;

#[actor]
pub struct Counter {{
    count: u64,
}}

#[messages]
impl Counter {{
    fn new() -> Self {{
        Self {{ count: 0 }}
    }}

    #[msg]
    fn increment(&mut self, amount: u64) -> u64 {{
        self.count += amount;
        self.count
    }}

    #[msg]
    fn get(&self) -> u64 {{
        self.count
    }}
}}
"#,
    )
}

fn crdt_source(name: &str) -> String {
    format!(
        r#"//! {name}: an explicitly convergent shared actor.

use vos::prelude::*;

#[actor(crdt)]
pub struct SharedBoard {{
    title: crdt::Value<String>,
    tasks: crdt::Map<u64, String>,
    order: crdt::List<u64>,
    notes: crdt::Text,
    edits: crdt::Counter,

    #[crdt(const)]
    space: SpaceId,

    #[crdt(skip)]
    cache: Option<String>,
}}

#[messages]
impl SharedBoard {{
    fn new() -> Self {{
        Self {{
            title: crdt::Value::default(),
            tasks: crdt::Map::default(),
            order: crdt::List::default(),
            notes: crdt::Text::default(),
            edits: crdt::Counter::default(),
            space: SpaceId::ZERO,
            cache: None,
        }}
    }}

    #[msg]
    fn set_title(&mut self, title: String) {{
        self.title
            .set(title)
            .expect("CRDT mutations in actor methods have stable operation identities");
    }}

    #[msg]
    fn add_task(&mut self, id: u64, text: String) {{
        self.tasks
            .insert(id, text)
            .expect("CRDT mutations in actor methods have stable operation identities");
        self.order
            .push(id)
            .expect("CRDT mutations in actor methods have stable operation identities");
        self.edits
            .increment(1)
            .expect("CRDT mutations in actor methods have stable operation identities");
    }}

    #[msg]
    fn insert_note(&mut self, index: u32, text: String) {{
        self.notes
            .insert(index as usize, &text)
            .expect("CRDT mutations in actor methods have stable operation identities");
        self.edits
            .increment(1)
            .expect("CRDT mutations in actor methods have stable operation identities");
    }}

    #[msg]
    fn edit_count(&self) -> i64 {{
        self.edits.value()
    }}
}}
"#,
    )
}

const TOOLCHAIN: &str = r#"[toolchain]
channel = "nightly"
components = ["rust-src"]
"#;

const CONFIG: &str = r#"[target.riscv64em-javm]
rustflags = [
    "-Zunstable-options",
    "-Zcrate-attr=no_std",
    "-Zcrate-attr=no_main",
    "-Aduplicate-macro-attributes",
    "-Aunused-attributes",
]

[alias]
actor = "rustc --lib --crate-type bin -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --release --target riscv64em-javm.json"

[unstable]
json-target-spec = true
"#;

const TARGET: &str = r#"{
  "arch": "riscv64",
  "cpu": "generic-rv64",
  "crt-objects-fallback": "false",
  "data-layout": "e-m:e-p:64:64-i64:64-i128:128-n32:64-S64",
  "eh-frame-header": false,
  "emit-debug-gdb-scripts": false,
  "features": "+e,+m",
  "linker": "rust-lld",
  "linker-flavor": "ld.lld",
  "llvm-abiname": "lp64e",
  "llvm-target": "riscv64",
  "max-atomic-width": 0,
  "panic-strategy": "abort",
  "relocation-model": "pie",
  "target-pointer-width": 64,
  "singlethread": true,
  "exe-suffix": ".elf",
  "os": "none",
  "env": "javm",
  "pre-link-args": { "ld": ["--emit-relocs", "--unique"] }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_inject_platform_crate_attributes() {
        assert!(CONFIG.contains("-Zcrate-attr=no_std"));
        assert!(CONFIG.contains("-Zcrate-attr=no_main"));
        assert!(!counter_source("x").contains("#![no_std]"));
        let crdt = crdt_source("x");
        assert!(crdt.contains("#[actor(crdt)]"));
        assert!(crdt.contains("space: SpaceId"));
        assert!(crdt.contains("self.tasks"));
        assert!(crdt.contains("self.order"));
        assert!(crdt.contains("self.notes"));
        assert!(crdt.contains("self.edits"));
    }
}
