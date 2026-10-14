//! The guest programs this repository builds (`just build-agent
//! build-test-actors`), linked, and their methods by name: for the tests
//! and benches of the testkit and of the node.

use std::path::{Path, PathBuf};

use vos_wire::ids::MethodId;
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

fn link(elf: &Path) -> Vec<u8> {
    let bytes = std::fs::read(elf).unwrap_or_else(|error| panic!("{}: {error}", elf.display()));
    vos_pvm_compiler::link_elf_spi(&bytes).expect("links")
}

/// The default agent, linked.
pub fn agent() -> Vec<u8> {
    link(&agent_elf())
}

/// Test actor `name`, linked.
pub fn actor(name: &str) -> Vec<u8> {
    link(&actor_elf(name))
}

/// The default agent and the counter actor, linked.
pub struct Programs {
    pub agent: Vec<u8>,
    pub counter: Vec<u8>,
}

impl Programs {
    pub fn load() -> Self {
        Self {
            agent: agent(),
            counter: actor("counter"),
        }
    }

    /// The counter's method `name`.
    pub fn method(&self, name: &str) -> MethodId {
        method(&self.counter, name)
    }
}

/// The tag of an actor's table or committed map named `name`, as
/// `#[actor]` derives it: the first four bytes, big-endian, of BLAKE2b-256
/// over `vos/table/` and the name.
pub fn table_tag(name: &str) -> u32 {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let hash = Blake2b::<U32>::new()
        .chain_update(b"vos/table/")
        .chain_update(name.as_bytes())
        .finalize();
    u32::from_be_bytes(hash[..4].try_into().expect("four bytes"))
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
