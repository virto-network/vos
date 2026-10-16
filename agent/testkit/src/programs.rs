//! The guest programs this repository builds (`just build-agent
//! build-test-actors`), linked or derived as an install derives them, and
//! their methods by name: for the tests and benches of the testkit and of
//! the node.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use vos_pvm_compiler::Derived;
use vos_wire::ids::{MethodId, ProgramHash};
use vos_wire::records::Derivation;
use vos_wire::schema::Schema;

/// A guest program's ELF, by its path under `agent/`.
fn guest(path: &str) -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(path);
    assert!(
        path.exists(),
        "{}: run `just build-agent build-test-actors`",
        path.display()
    );
    path
}

/// The default agent's ELF.
pub fn agent_elf() -> PathBuf {
    guest("default/target/riscv64em-vos/release/vos-agent.elf")
}

/// Test actor `name`'s ELF.
pub fn actor_elf(name: &str) -> PathBuf {
    guest(&format!(
        "test-actors/target/riscv64em-vos/release/{name}.elf"
    ))
}

fn read(elf: &Path) -> Vec<u8> {
    std::fs::read(elf).unwrap_or_else(|error| panic!("{}: {error}", elf.display()))
}

fn link(elf: &Path) -> Vec<u8> {
    vos_pvm_compiler::link_elf_spi(&read(elf)).expect("links")
}

/// Test actor `name`'s ELF, its package, as a crate builds it.
pub fn package(name: &str) -> Vec<u8> {
    read(&actor_elf(name))
}

/// Test actor `name`, derived from its ELF as an install derives it: its
/// program, its kernels by method, and its schema. Derived once a process.
pub fn derived(name: &str) -> Derived {
    static DERIVED: Mutex<BTreeMap<String, Derived>> = Mutex::new(BTreeMap::new());
    let mut derived = DERIVED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    derived
        .entry(name.to_string())
        .or_insert_with(|| vos_pvm_compiler::derive(&package(name)).expect("derives"))
        .clone()
}

/// The derivation an install of package `elf`, derived as `derived`, names.
pub fn derivation(elf: &[u8], derived: &Derived) -> Derivation {
    Derivation::new(
        elf,
        &derived.actor,
        &derived.kernels,
        derived.transpiler_version,
        derived.heap,
    )
}

/// The derivation of an actor program a test holds alone, linked or built:
/// no kernels, and no ELF it names.
pub fn bare(program: ProgramHash) -> Derivation {
    Derivation {
        program,
        kernels: Vec::new(),
        elf: [0; 32],
        transpiler: vos_pvm_compiler::TRANSPILER_VERSION,
        heap: 0,
    }
}

/// The kernel of test actor `name`'s attestable method `method`.
pub fn kernel(name: &str, method: &str) -> Vec<u8> {
    let derived = derived(name);
    let id = self::method(&derived.actor, method);
    derived
        .kernels
        .into_iter()
        .find(|(bound, _)| *bound == id.0)
        .map(|(_, kernel)| kernel)
        .unwrap_or_else(|| panic!("{name} has no attestable {method}"))
}

/// The default agent, linked.
pub fn agent() -> Vec<u8> {
    link(&agent_elf())
}

/// Test actor `name`, linked.
pub fn actor(name: &str) -> Vec<u8> {
    link(&actor_elf(name))
}

/// The default agent, linked, and the counter actor, linked and as its
/// package, the ELF an install takes.
pub struct Programs {
    pub agent: Vec<u8>,
    pub counter: Vec<u8>,
    pub counter_elf: Vec<u8>,
}

impl Programs {
    pub fn load() -> Self {
        Self {
            agent: agent(),
            counter: actor("counter"),
            counter_elf: package("counter"),
        }
    }

    /// The counter's method `name`.
    pub fn method(&self, name: &str) -> MethodId {
        method(&self.counter, name)
    }
}

/// The tag of an actor's table or committed map named `name`, as
/// `#[actor]` derives it.
pub fn table_tag(name: &str) -> u32 {
    vos_wire::ids::derive_id("vos/table/", name)
}

/// The schema `program` carries.
pub fn schema(program: &[u8]) -> Schema {
    let parsed = vos_pvm::spi::parse_standard_program(program).expect("a standard program");
    Schema::read(&parsed.ro_data).expect("its schema")
}

/// The id of `program`'s method `name`.
pub fn method(program: &[u8], name: &str) -> MethodId {
    schema(program)
        .method_id(name)
        .unwrap_or_else(|| panic!("no method {name}"))
}
