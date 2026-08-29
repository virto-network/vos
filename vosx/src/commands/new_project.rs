//! Actor scaffolding for the service and standard-agent runtimes.

use std::path::PathBuf;

use anyhow::{Context, bail};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectTarget {
    Service,
    Agent,
}

pub fn run(path: PathBuf, crdt: bool, target: ProjectTarget) -> anyhow::Result<()> {
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
    std::fs::write(path.join("Cargo.toml"), cargo_toml(name, target))?;
    std::fs::write(
        path.join(".cargo/config.toml"),
        match target {
            ProjectTarget::Service => SERVICE_CONFIG,
            ProjectTarget::Agent => AGENT_CONFIG,
        },
    )?;
    if target == ProjectTarget::Agent {
        std::fs::write(path.join("pvm.ld"), PVM_LINKER_SCRIPT)?;
    }
    std::fs::write(path.join("rust-toolchain.toml"), TOOLCHAIN)?;
    std::fs::write(path.join("riscv64em-vos.json"), TARGET)?;
    std::fs::write(
        path.join("src/lib.rs"),
        match (target, crdt) {
            (ProjectTarget::Service, true) => service_crdt_source(&crate_name),
            (ProjectTarget::Agent, true) => agent_crdt_source(&crate_name),
            (_, false) => counter_source(&crate_name),
        },
    )?;
    println!("created {}", path.display());
    println!("  cd {} && cargo actor", path.display());
    Ok(())
}

fn cargo_toml(name: &str, target: ProjectTarget) -> String {
    let guest_feature = match target {
        ProjectTarget::Service => "service",
        ProjectTarget::Agent => "pvm",
    };
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
vos = {{ version = "{}", default-features = false, features = ["macros", "{guest_feature}"] }}

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

fn service_crdt_source(name: &str) -> String {
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
    space: [u8; 32],

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
            space: [0; 32],
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
    fn edit_count(&self) -> i64 {{
        self.edits.value()
    }}
}}
"#,
    )
}

fn agent_crdt_source(name: &str) -> String {
    format!(
        r#"//! {name}: an actor whose state can merge across replicas.

use vos::prelude::*;

#[actor]
pub struct SharedBoard {{
    title: crdt::Value<String>,
    tasks: crdt::Map<u64, String>,
    notes: crdt::Text,
    edits: crdt::Counter,
}}

#[messages]
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

const SERVICE_CONFIG: &str = r#"[target.riscv64em-vos]
rustflags = [
    "-Zunstable-options",
    "-Zcrate-attr=no_std",
    "-Zcrate-attr=no_main",
    "-Zremap-cwd-prefix=.",
    "-Aduplicate-macro-attributes",
    "-Aunused-attributes",
]

[alias]
actor = "rustc --lib --crate-type bin -Zbuild-std=core,alloc,compiler_builtins -Zbuild-std-features=compiler-builtins-mem --release --target riscv64em-vos.json"

[unstable]
json-target-spec = true
"#;

const AGENT_CONFIG: &str = r#"[target.riscv64em-vos]
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

const PVM_LINKER_SCRIPT: &str = r#"/* Canonical standard-agent actor layout.
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
    fn service_template_preserves_the_service_build_surface() {
        assert!(SERVICE_CONFIG.contains("-Zcrate-attr=no_std"));
        assert!(SERVICE_CONFIG.contains("-Zcrate-attr=no_main"));
        assert!(SERVICE_CONFIG.contains("-Zremap-cwd-prefix=."));
        assert!(!SERVICE_CONFIG.contains("-Clink-arg=-Tpvm.ld"));
        assert!(
            cargo_toml("x", ProjectTarget::Service).contains(r#"features = ["macros", "service"]"#)
        );
        assert!(
            !cargo_toml("x", ProjectTarget::Service).contains(r#"features = ["macros", "pvm"]"#)
        );
        assert!(!counter_source("x").contains("#![no_std]"));
        assert!(service_crdt_source("x").contains("#[actor(crdt)]"));
    }

    #[test]
    fn agent_template_uses_the_standard_program_layout() {
        assert!(AGENT_CONFIG.contains("-Zcrate-attr=no_std"));
        assert!(AGENT_CONFIG.contains("-Zcrate-attr=no_main"));
        assert!(AGENT_CONFIG.contains("-Zremap-cwd-prefix=."));
        assert!(AGENT_CONFIG.contains("-Clink-arg=-Tpvm.ld"));
        assert!(cargo_toml("x", ProjectTarget::Agent).contains(r#"features = ["macros", "pvm"]"#));
        assert!(PVM_LINKER_SCRIPT.contains("SIZEOF(.rodata)"));
    }

    #[test]
    fn merge_template_uses_the_signed_agent_lane_surface() {
        let source = agent_crdt_source("x");
        assert!(source.contains("#[actor]"));
        assert!(source.contains("#[msg(merge)]"));
        assert!(source.contains("crdt::Value<String>"));
        assert!(!source.contains("#[actor(crdt)]"));
        assert!(!source.contains("#[crdt(const)]"));
        assert!(!source.contains("#[crdt(skip)]"));
    }
}
