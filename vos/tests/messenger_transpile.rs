//! Messenger PVM-actor transpile gate — the make-or-break of the
//! deterministic no_std mls-rs → PVM-native port.
//!
//! Cuts the WHOLE messenger crate (`actors/messenger`) to a no_std
//! `#[actor]` riscv64 build flavor — the deterministic host-seeded MLS stack,
//! the custom storage + crypto providers, the channel-actor RPC clients, the
//! poll loop — and gates the resulting ELF through
//! `grey_transpiler::link_elf`. A clean transpile is the proof that the real
//! messenger runs as one portable PVM bytecode.
//!
//! The messenger is its own workspace under `actors/`, so its ELF lands in the
//! crate-local target dir. Build it with
//! `cd actors/messenger && cargo +nightly actor`. If the ELF is absent the
//! test SKIPs loudly rather than failing the suite.

#[test]
fn messenger_actor_elf_transpiles() {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path =
        format!("{workspace}/../actors/messenger/target/riscv64em-javm/release/messenger.elf");
    let elf = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!(
                "SKIP: messenger ELF not built at {path}\n      \
                 run: cd actors/messenger && cargo +nightly actor"
            );
            return;
        }
    };

    let blob = grey_transpiler::link_elf(&elf).expect(
        "the no_std messenger PVM actor (mls-rs + deterministic providers + \
         channel RPC + poll loop) must transpile through link_elf",
    );

    // The messenger links mls-rs's whole framing/codec/TreeKEM stack plus its
    // own crypto/storage/dispatch code; the PVM blob is large (megabytes). A
    // trivially-small blob would mean the flow was dead-code-eliminated rather
    // than genuinely exercising the messenger's code.
    assert!(
        blob.len() > 512 * 1024,
        "expected a substantial messenger PVM blob, got {} bytes — did the \
         actor's MLS/dispatch code get optimised away?",
        blob.len()
    );
}
