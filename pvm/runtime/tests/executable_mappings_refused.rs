//! A process that may not make written memory executable (`PR_SET_MDWE`,
//! as systemd's `MemoryDenyWriteExecute` sets it): the recompiler's
//! compile is refused with an error, never a crash. The setting is
//! irreversible for the process, so this test binary holds this test alone.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

/// `prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN)` (Linux 6.3).
const PR_SET_MDWE: libc::c_int = 65;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;

#[test]
fn compiling_where_written_memory_may_not_become_executable_is_an_error() {
    // SAFETY: prctl with integer arguments changes only this process's
    // policy for later mappings.
    let set = unsafe { libc::prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) };
    assert_eq!(set, 0, "PR_SET_MDWE: {}", std::io::Error::last_os_error());
    let compiled = vos_pvm::recompiler::compile_code(&[0; 16], &[1; 16], &[]);
    assert!(
        compiled.is_err(),
        "the executable flip is refused, and so is the compile"
    );
}
