//! The release build of the light node's artifacts (`light-node.md` §4.4),
//! on the host: the default agent's program, linked, and the notes
//! actor's package, derived, from their ELFs (`just build-agent
//! build-test-actors`), written to `OUT_DIR` for `vos-phone light` to
//! embed; and the stock kernels' release artifacts, `auth` and `owner`
//! from the credential actor's ELF (`just build-credentials`), for `run`,
//! with the arguments their reference programs return, the public
//! statements the device cells prove them on.
//! Without the ELFs they are empty, and the commands say so.
//!
//! A package is encoded as `vos_light::release::Package` encodes it: its
//! derivation, its programs, then its release, the notes actor's first
//! (`vos-light`'s test decodes one).

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
                (derived.derivation(), derived.programs(), 1u32).encode(),
            )
        }
        _ => (Vec::new(), Vec::new()),
    };
    std::fs::write(out.join("agent.bin"), agent).unwrap();
    std::fs::write(out.join("notes.bin"), notes).unwrap();
    let credentials_elf =
        root.join("agent/programs/target/riscv64em-vos/release/vos-credentials.elf");
    println!("cargo::rerun-if-changed={}", credentials_elf.display());
    let credentials = std::fs::read(&credentials_elf).ok();
    let derived = credentials
        .as_ref()
        .map(|elf| vos_pvm_compiler::derive(elf).expect("the credential actor derives"));
    for kernel in ["auth", "owner"] {
        let device = credentials
            .as_ref()
            .map(|elf| {
                vos_light::release::device(elf, kernel)
                    .expect("the stock kernel's release artifact")
                    .encode()
            })
            .unwrap_or_default();
        std::fs::write(out.join(format!("{kernel}.device")), device).unwrap();
        let input = derived
            .as_ref()
            .map(|derived| {
                let method = vos_light::method_id(kernel);
                let (_, reference, _) = derived
                    .references
                    .iter()
                    .find(|(bound, _, _)| *bound == method)
                    .expect("the stock kernel's reference");
                vos_pvm_recair::device::reference_arguments(reference)
                    .expect("the stock kernel's reference arguments")
            })
            .unwrap_or_default();
        std::fs::write(out.join(format!("{kernel}.input")), input).unwrap();
    }
}
