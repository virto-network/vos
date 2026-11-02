//! The release build of the light node's artifacts (`light-node.md` §4.4),
//! on the host: the default agent's program, linked, and the counter's
//! package, derived, from their ELFs (`just build-agent
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
    let counter_elf = root.join("agent/test-actors/target/riscv64em-vos/release/counter.elf");
    for elf in [&agent_elf, &counter_elf] {
        println!("cargo::rerun-if-changed={}", elf.display());
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let (agent, counter) = match (std::fs::read(&agent_elf), std::fs::read(&counter_elf)) {
        (Ok(agent), Ok(counter)) => {
            let derived = vos_pvm_compiler::derive(&counter).expect("the counter derives");
            let derivation = derived.derivation(&counter);
            let mut programs = vec![derived.actor];
            programs.extend(derived.kernels.into_iter().map(|(_, kernel)| kernel));
            (
                vos_pvm_compiler::link_elf_spi(&agent).expect("the agent links"),
                (derivation, programs).encode(),
            )
        }
        _ => (Vec::new(), Vec::new()),
    };
    std::fs::write(out.join("agent.bin"), agent).unwrap();
    std::fs::write(out.join("counter.bin"), counter).unwrap();
}
