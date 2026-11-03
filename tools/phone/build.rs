//! The release build of the light node's artifacts (`light-node.md` §4.4),
//! on the host: the default agent's program, linked, and the notes
//! actor's package, derived, from their ELFs (`just build-agent
//! build-test-actors`), written to `OUT_DIR` for `vos-phone light` to
//! embed. Without the ELFs both are empty, and `light` says so.
//!
//! A package is encoded as `vos_light::release::Package` encodes it: its
//! derivation, then its programs (`vos-light`'s test decodes one).

use std::path::Path;

use vos_wire::Encode;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let agent_elf = root.join("agent/programs/target/riscv64em-vos/release/vos-agent.elf");
    let notes_elf = root.join("agent/test-actors/target/riscv64em-vos/release/notes.elf");
    for elf in [&agent_elf, &notes_elf] {
        println!("cargo::rerun-if-changed={}", elf.display());
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let (agent, notes) = match (std::fs::read(&agent_elf), std::fs::read(&notes_elf)) {
        (Ok(agent), Ok(notes)) => {
            let derived = vos_pvm_compiler::derive(&notes).expect("the notes actor derives");
            (
                vos_pvm_compiler::link_elf_spi(&agent).expect("the agent links"),
                (derived.derivation(&notes), derived.programs()).encode(),
            )
        }
        _ => (Vec::new(), Vec::new()),
    };
    std::fs::write(out.join("agent.bin"), agent).unwrap();
    std::fs::write(out.join("notes.bin"), notes).unwrap();
}
