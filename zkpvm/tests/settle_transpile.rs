//! Does the settlement verifier ELF survive grey-transpilation to JAM PVM
//! bytecode? The transpiler rejects RISC-V instructions JAVM cannot execute
//! (e.g. atomic instructions, compressed insts, out-of-range registers), so a
//! clean `link_elf` is the bytecode-level proof that `settlement-verifier`'s
//! `settle.elf` is genuinely PVM-runnable — not just ELF-linkable.
//!
//! The ELF is built out-of-band (separate workspace + custom target) via
//! `just build-settle`. Skips (does not fail) if the ELF is absent, matching the
//! other ELF fixtures.

#[test]
fn settle_elf_transpiles_to_pvm() {
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/settlement-verifier/target/riscv64em-javm/release/settle.elf"
    );
    let elf = match std::fs::read(elf_path) {
        Ok(bytes) => bytes,
        Err(_) => {
            eprintln!("settle.elf absent ({elf_path}); run `just build-settle` first — skipping");
            return;
        }
    };

    let blob = grey_transpiler::link_elf(&elf)
        .expect("grey-transpile settle.elf to PVM bytecode");
    assert!(!blob.is_empty(), "transpiled PVM blob is empty");
    eprintln!(
        "settle.elf transpiled OK: {} ELF bytes -> {} PVM-blob bytes",
        elf.len(),
        blob.len()
    );
}
