//! P2.0b — mls-rs own-code transpile gate (the "fold-in" open question of P2.0;
//! see docs/design/messaging-pvm-native.md "Library decision" + "P2.0").
//!
//! The OpenMLS → mls-rs migration's whole premise is that mls-rs makes `std` +
//! the non-optional `rayon` optional, so its framing/codec/TreeKEM code can run
//! as a no_std PVM actor. The dominant residual unknown was whether mls-rs's
//! *own* code transpiles through `grey_transpiler::link_elf`. `actors/_mls_spike`
//! is a minimal real ciphersuite-1 flow (two clients + create_group +
//! add-member commit + MlsMessage codec round-trip) built `--no-default-features`
//! to a riscv64em-javm ELF; this test transpiles that ELF and asserts a
//! substantial PVM blob comes out — the permanent regression guarding the
//! library decision against a future mls-rs / transpiler bump.
//!
//! The spike is `_`-prefixed and not built by the repo `justfile`; build it with
//! `cd actors/_mls_spike && cargo +nightly actor`. If the ELF is absent the test
//! SKIPs loudly rather than failing the suite.

#[test]
fn mls_rs_own_code_transpiles() {
    let workspace = env!("CARGO_MANIFEST_DIR");
    let path = format!(
        "{workspace}/../actors/_mls_spike/target/riscv64em-javm/release/mls_spike.elf"
    );
    let elf = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => {
            eprintln!(
                "SKIP: mls_spike ELF not built at {path}\n      \
                 run: cd actors/_mls_spike && cargo +nightly actor"
            );
            return;
        }
    };

    let blob = grey_transpiler::link_elf(&elf)
        .expect("mls-rs's own framing/codec/TreeKEM ELF must transpile through link_elf");

    // mls-rs's compiled framing/codec/tree code is large (~1.3 MiB PVM blob);
    // a trivially-small blob would mean the flow was dead-code-eliminated rather
    // than genuinely exercising mls-rs's own code.
    assert!(
        blob.len() > 256 * 1024,
        "expected a substantial mls-rs PVM blob, got {} bytes — did the spike's \
         create_group/commit flow get optimised away?",
        blob.len()
    );
}
