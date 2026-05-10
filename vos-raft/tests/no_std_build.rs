//! Build-mode smoke test: verify that the crate compiles for
//! representative embedded targets with `--no-default-features`
//! (alloc only).
//!
//! This catches regressions to the no_std purity story — anything
//! that accidentally pulls in `std::collections`, `std::time`, or
//! a transitively-std-only dependency would otherwise only surface
//! when a downstream Embassy / firmware consumer breaks. Running
//! the embedded build at `cargo test` time catches it on the
//! contributor's machine instead.
//!
//! ## Skipped automatically when targets aren't installed
//!
//! The test detects the embedded target via `rustup target list`.
//! If the target isn't installed, the test prints a SKIP message
//! and exits clean — that lets contributors who haven't set up
//! cross-compilation still run the rest of the test suite.
//!
//! Suggested setup:
//!
//!   rustup target add thumbv7em-none-eabihf
//!   rustup target add riscv32imc-unknown-none-elf

use std::process::Command;

fn target_available(target: &str) -> bool {
    let out = match Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
    {
        Ok(o) => o,
        // No rustup → assume not available; skip cleanly.
        Err(_) => return false,
    };
    if !out.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().any(|l| l.trim() == target)
}

fn check_target(target: &str) {
    if !target_available(target) {
        eprintln!(
            "SKIP: target {target} not installed; \
             run `rustup target add {target}` to enable",
        );
        return;
    }
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "vos-raft",
            "--no-default-features",
            "--target",
            target,
        ])
        .status()
        .expect("cargo build invocation");
    assert!(
        status.success(),
        "vos-raft failed to build for {target} with --no-default-features — \
         a no_std purity regression is likely; run \
         `just check-no-std` for details",
    );
}

#[test]
fn builds_for_thumbv7em_none_eabihf() {
    check_target("thumbv7em-none-eabihf");
}

#[test]
fn builds_for_riscv32imc_unknown_none_elf() {
    check_target("riscv32imc-unknown-none-elf");
}
