//! A process whose file-size limit (`RLIMIT_FSIZE`) is below a guest
//! window's 4 GiB: building native guest memory is refused before the
//! `ftruncate` that would raise `SIGXFSZ` and end the process, and the
//! process runs programs on the interpreter. The limit is process-wide, so
//! this test binary holds this test alone.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use vos_pvm::PvmBackend;
use vos_pvm::backend::Unavailable;

#[test]
fn a_file_size_limit_below_a_window_runs_programs_interpreted() {
    // SAFETY: getrlimit and setrlimit read and write valid structs; the
    // hard limit is kept.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) },
        0
    );
    limit.rlim_cur = 1 << 30;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) }, 0);

    assert!(vos_pvm::backing::BackingStore::new(1 << 20).is_none());
    assert!(vos_pvm::backing::BackingStore::new(1 << 10).is_some());
    let choice = vos_pvm::backend::backend_choice().unwrap();
    assert_eq!(choice.backend, PvmBackend::ForceInterpreter);
    // The probe checks write tracking before it builds a guest window, so
    // a host without userfaultfd write-protect refuses the recompiler
    // there first.
    assert!(
        matches!(
            choice.unavailable,
            Some(Unavailable::GuestMemory | Unavailable::WriteTracking)
        ),
        "{:?}",
        choice.unavailable
    );
    assert!(matches!(
        vos_pvm::backend::compile(&[0], &[1], &[], PvmBackend::Default),
        Ok(vos_pvm::backend::CompiledProgram::Interpreter(_))
    ));
}
