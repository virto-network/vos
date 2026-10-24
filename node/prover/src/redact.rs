//! A panic while a proof is made prints where it happened and nothing of
//! its message: the message of a panic inside the prover (an assertion's
//! values, a formatted error) may hold a run's private values, and the
//! default hook writes it to standard error. While any proof is in flight
//! in the process, every thread's panic is printed so, as the prover's
//! pool threads are not told apart from the node's; outside one, the hook
//! installed before runs.
//!
//! The hook is installed once, at the first proof, over the one before it.
//! A `std::panic::set_hook` after that replaces it and so ends the
//! redaction for the process: nothing that links the prover may set a
//! panic hook once a proof has been made.

use std::panic::{AssertUnwindSafe, PanicHookInfo};
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The proofs in flight in the process.
static PROVING: AtomicUsize = AtomicUsize::new(0);
static HOOK: Once = Once::new();

/// `prove` run with panics' messages withheld, a panic caught.
pub(crate) fn proving<T>(prove: impl FnOnce() -> T) -> std::thread::Result<T> {
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if PROVING.load(Ordering::SeqCst) > 0 {
                eprintln!("{}", withheld(info));
            } else {
                previous(info);
            }
        }));
    });
    struct InFlight;
    impl Drop for InFlight {
        fn drop(&mut self) {
            PROVING.fetch_sub(1, Ordering::SeqCst);
        }
    }
    PROVING.fetch_add(1, Ordering::SeqCst);
    let _in_flight = InFlight;
    std::panic::catch_unwind(AssertUnwindSafe(prove))
}

fn withheld(info: &PanicHookInfo<'_>) -> String {
    let thread = std::thread::current();
    let at = info
        .location()
        .map_or_else(String::new, |location| format!(" at {location}"));
    format!(
        "thread '{}' panicked{at} while a proof was made: its message withheld",
        thread.name().unwrap_or("<unnamed>")
    )
}

#[cfg(test)]
mod tests {
    const SECRET: &str = "a-private-value-0x5eed";
    const CHILD: &str = "VOS_PROVER_REDACT_CHILD";

    /// The test binary run again as this test alone, its standard error
    /// read: a prover's panic, on its own thread and on another, shows its
    /// place and not its message; a panic after the proof, its message.
    #[test]
    fn a_panic_while_proving_withholds_its_message() {
        if std::env::var_os(CHILD).is_some() {
            let caught = super::proving(|| {
                std::thread::spawn(|| panic!("{SECRET} on a pool's thread"))
                    .join()
                    .ok();
                panic!("{SECRET} on the prover's thread")
            });
            assert!(caught.is_err());
            let _ = std::panic::catch_unwind(|| panic!("after the proof"));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "redact::tests::a_panic_while_proving_withholds_its_message",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains(SECRET), "{stderr}");
        assert_eq!(
            stderr.matches("while a proof was made").count(),
            2,
            "{stderr}"
        );
        assert!(stderr.contains("src/redact.rs"), "{stderr}");
        assert!(stderr.contains("after the proof"), "{stderr}");
    }
}
