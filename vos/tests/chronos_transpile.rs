//! chronos PVM-actor transpile gate — the on-PVM coverage of the
//! ECVRF-over-Ristretto255 path (Elligator hash-to-curve, prove/verify, the
//! committee XOR-combine) that the retired `_chronos_crypto_spike` fixture used
//! to prove against a bespoke re-implementation. This gates the value that
//! actually ships: the real `chronos` actor's ELF (the `vrf` crate + the clock
//! + committee handlers) transpiled through `grey_transpiler::link_elf`.
//!
//! chronos is excluded from the host workspace (it builds with the actor
//! toolchain), so its ELF lands in the crate-local target dir. Build it with
//! `just build-actor chronos` (or `cd actors/chronos && cargo +nightly actor`). If the
//! ELF is absent the test SKIPs loudly rather than failing the suite.

#[test]
fn chronos_actor_elf_transpiles() {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path = format!("{workspace}/../actors/chronos/target/riscv64em-javm/release/chronos.elf");
    let elf = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!(
                "SKIP: chronos ELF not built at {path}\n      \
                 run: just build-actor chronos"
            );
            return;
        }
    };

    let blob = grey_transpiler::link_elf(&elf).expect(
        "the chronos PVM actor (ECVRF-over-Ristretto255 + Elligator hash-to-curve \
         + committee combine + the slot clock) must transpile through link_elf",
    );

    // chronos links curve25519-dalek's ristretto/Elligator code plus the round
    // protocol; a trivially-small blob would mean that path was dead-code
    // -eliminated rather than genuinely exercised.
    assert!(
        blob.len() > 256 * 1024,
        "expected a substantial chronos PVM blob, got {} bytes — did the \
         ristretto/ECVRF code get optimised away?",
        blob.len()
    );
}
