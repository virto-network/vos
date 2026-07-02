//! PVM-actor no_std runtime shims.
//!
//! The riscv64em-javm target has no native atomics and no OS entropy.

/// `critical-section`: mls-rs's no_std build and the messenger's own
/// `spin::Mutex` storage emulate atomics through `portable-atomic`, which needs a
/// registered `critical_section::Impl`. The target is single-threaded with no
/// interrupts/preemption, so acquire/release are no-ops.
#[cfg(target_arch = "riscv64")]
struct SingleThreadCriticalSection;
#[cfg(target_arch = "riscv64")]
critical_section::set_impl!(SingleThreadCriticalSection);
#[cfg(target_arch = "riscv64")]
unsafe impl critical_section::Impl for SingleThreadCriticalSection {
    unsafe fn acquire() -> critical_section::RawRestoreState {}
    unsafe fn release(_: critical_section::RawRestoreState) {}
}

/// `getrandom`: every entropy draw the messenger makes flows through the
/// host-seeded `HostRand` (see `crate::host_rand`), so any `getrandom`/`OsRng`
/// reachable inside the PVM — only mls-rs's off-path `signature_key_generate`,
/// which the messenger never calls because it hands the Client a seed-derived
/// signer — is a misuse. Fail loudly rather than hand back predictable bytes.
#[cfg(target_arch = "riscv64")]
fn pvm_no_os_entropy(_buf: &mut [u8]) -> core::result::Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "riscv64")]
getrandom::register_custom_getrandom!(pvm_no_os_entropy);
