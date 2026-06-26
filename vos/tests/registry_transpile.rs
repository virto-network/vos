//! Space-registry PVM-actor transpile gate.
//!
//! The registry is a built-in PVM actor (`actors/space-registry`) whose ELF
//! ships bundled in `vosx/blobs/space_registry.elf` and is loaded by every
//! daemon. This gate cuts the crate to its no_std riscv64 `#[actor]` flavor
//! and checks the result links through `grey_transpiler::link_elf` — the same
//! transpile the daemon runs at load — so a codegen-breaking change to a
//! handler (e.g. the `node_role` raft-join admission probe) is caught here
//! rather than at first boot.
//!
//! The registry is its own workspace under `actors/`, so its ELF lands in the
//! crate-local target dir. Build it with
//! `just build-registry` (= `cd actors/space-registry && cargo +nightly actor`).
//! If the ELF is absent the test SKIPs loudly rather than failing the suite.

#[test]
fn registry_actor_elf_transpiles() {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path = format!(
        "{workspace}/../actors/space-registry/target/riscv64em-javm/release/space_registry.elf"
    );
    let elf = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!(
                "SKIP: space-registry ELF not built at {path}\n      \
                 run: just build-registry"
            );
            return;
        }
    };

    let blob = grey_transpiler::link_elf(&elf)
        .expect("the no_std space-registry PVM actor must transpile through link_elf");

    // The registry links the full members/auth-grants/agent-catalog handler
    // surface; a trivially-small blob would mean the code was dead-code-
    // eliminated rather than genuinely exercised.
    assert!(
        blob.len() > 64 * 1024,
        "expected a substantial space-registry PVM blob, got {} bytes",
        blob.len()
    );
}
