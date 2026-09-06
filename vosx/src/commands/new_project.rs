//! Portable AgentActor project scaffolding for `vosx actor new`.

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
    std::fs::write(path.join(".cargo/config.toml"), ACTOR_CONFIG)?;
    std::fs::write(path.join("pvm.ld"), PVM_LINKER_SCRIPT)?;
    std::fs::write(path.join("rust-toolchain.toml"), TOOLCHAIN)?;
    std::fs::write(path.join("riscv64em-vos.json"), TARGET)?;
    std::fs::write(
        path.join("src/lib.rs"),
        if crdt {
            merge_actor_source(&crate_name)
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
vos = {{ version = "{}", default-features = false, features = ["macros", "pvm"] }}

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
        r#"//! {name}: an actor with linear state.

use vos::prelude::*;

#[actor(agent)]
pub struct Counter {{
    count: u64,
}}

#[messages(agent)]
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

fn merge_actor_source(name: &str) -> String {
    format!(
        r#"//! {name}: an actor whose state can merge across replicas.

use vos::prelude::*;

#[actor(agent)]
pub struct SharedBoard {{
    title: crdt::Value<String>,
    tasks: crdt::Map<u64, String>,
    notes: crdt::Text,
    edits: crdt::Counter,
}}

#[messages(agent)]
impl SharedBoard {{
    fn new() -> Self {{
        Self {{
            title: crdt::Value::default(),
            tasks: crdt::Map::default(),
            notes: crdt::Text::default(),
            edits: crdt::Counter::default(),
        }}
    }}

    #[msg(merge)]
    fn set_title(&mut self, title: String) {{
        self.title
            .set(title)
            .expect("CRDT mutations in actor methods have stable operation identities");
    }}

    #[msg(merge)]
    fn add_task(&mut self, id: u64, text: String) {{
        self.tasks
            .insert(id, text)
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

const ACTOR_CONFIG: &str = r#"[target.riscv64em-vos]
rustflags = [
    "-Zunstable-options",
    "-Zcrate-attr=no_std",
    "-Zcrate-attr=no_main",
    "-Zremap-cwd-prefix=.",
    "-Aduplicate-macro-attributes",
    "-Aunused-attributes",
    "-Clink-arg=-Tpvm.ld",
]

[alias]
actor = "rustc --lib --crate-type bin -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --release --target riscv64em-vos.json"

[unstable]
json-target-spec = true
"#;

const PVM_LINKER_SCRIPT: &str = r#"/* Canonical portable AgentActor layout.
 *
 * Read-only and read-write data occupy distinct GP zones. The read-write
 * base follows the complete read-only image instead of assuming a fixed
 * maximum size.
 */

ENTRY(_start)

SECTIONS
{
    .rodata 0x10000 : { *(.rodata .rodata.* .srodata .srodata.*) }
    .data (0x20000 + ((SIZEOF(.rodata) + 0xffff) & ~0xffff)) :
        { *(.data .data.* .sdata .sdata.*) }
    .bss ALIGN(0x1000) : { *(.bss .bss.* .sbss .sbss.* COMMON) }
    .text 0x900000 : { *(.text .text.* .init .init.*) }

    /DISCARD/ : { *(.eh_frame .eh_frame_hdr .comment .riscv.attributes) }
}
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
  "env": "vos_pvm",
  "pre-link-args": { "ld": ["--emit-relocs", "--unique"] }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_template_uses_the_standard_program_layout() {
        assert!(ACTOR_CONFIG.contains("-Zcrate-attr=no_std"));
        assert!(ACTOR_CONFIG.contains("-Zcrate-attr=no_main"));
        assert!(ACTOR_CONFIG.contains("-Zremap-cwd-prefix=."));
        assert!(ACTOR_CONFIG.contains("-Clink-arg=-Tpvm.ld"));
        assert!(cargo_toml("x").contains(r#"features = ["macros", "pvm"]"#));
        assert!(!cargo_toml("x").contains(r#"features = ["macros", "service"]"#));
        assert!(PVM_LINKER_SCRIPT.contains("SIZEOF(.rodata)"));
        let source = counter_source("x");
        assert!(source.contains("#[actor(agent)]"));
        assert!(source.contains("#[messages(agent)]"));
    }

    #[test]
    fn merge_template_uses_the_signed_agent_lane_surface() {
        let source = merge_actor_source("x");
        assert!(source.contains("#[actor(agent)]"));
        assert!(source.contains("#[messages(agent)]"));
        assert!(source.contains("#[msg(merge)]"));
        assert!(source.contains("crdt::Value<String>"));
        assert!(!source.contains("#[actor(crdt)]"));
        assert!(!source.contains("#[crdt(const)]"));
        assert!(!source.contains("#[crdt(skip)]"));
    }
}
