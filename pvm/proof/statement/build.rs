//! The JAM refine program (`--features pvm-guest`, the PVM target) links
//! with the Gray Paper standard-program layout (`pvm/guest/pvm.ld`), so
//! `vos_pvm_compiler::link_elf_spi` takes its ELF. Every other build is
//! untouched.

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    let guest = std::env::var_os("CARGO_FEATURE_PVM_GUEST").is_some();
    if guest && target.starts_with("riscv64em") {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets the manifest dir");
        let script = std::path::Path::new(&manifest).join("../../guest/pvm.ld");
        println!("cargo:rustc-link-arg-bins=-T{}", script.display());
        println!("cargo:rerun-if-changed={}", script.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
