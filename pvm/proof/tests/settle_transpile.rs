//! The settlement verifier links into a Gray Paper 0.8.0 standard program.
//! The compiler rejects RISC-V instructions the PVM cannot execute (atomics,
//! compressed instructions, out-of-range registers), so a clean link proves
//! `settle.elf` is PVM-runnable, not just ELF-linkable.
//!
//! The ELF is built by `just build-settle`; the test fails without it.

#[test]
fn settle_elf_links_to_a_standard_program() {
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/settlement-verifier/target/riscv64em-vos/release/settle.elf"
    );
    let elf = std::fs::read(elf_path)
        .unwrap_or_else(|error| panic!("settle.elf missing ({error}); run `just build-settle`"));
    let program = vos_pvm_compiler::link_elf_spi(&elf).expect("link settle.elf");
    assert!(!program.is_empty(), "linked program is empty");
    eprintln!(
        "settle.elf linked: {} ELF bytes -> {} program bytes",
        elf.len(),
        program.len()
    );
}
