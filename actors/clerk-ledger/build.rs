fn main() {
    println!("cargo:rerun-if-changed=pvm.ld");
    if std::env::var_os("CARGO_FEATURE_AGENT").is_some()
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("riscv64")
    {
        // The legacy service artifact retains its existing linker layout.
        // Only the Agent package uses the standard PVM's separate GP zones.
        println!("cargo:rustc-link-arg=-Tpvm.ld");
    }
}
