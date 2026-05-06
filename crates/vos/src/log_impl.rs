//! Per-target [`log::Log`] implementations.
//!
//! Each build flavor of vos auto-installs the appropriate impl
//! at its entry point so user code can call `log::info!(...)`
//! without manual subscriber setup:
//!
//! - **PVM** (`feature = "pvm"`): writes formatted records to the
//!   `DEBUG_WRITE` hostcall (vosx surfaces these on stderr).
//!   Installed by `run_refine_service` on first refine call.
//! - **Worker** (`feature = "worker"`): writes formatted records
//!   to `std::io::stderr`. Installed by `vos_worker_create`. A
//!   downstream worker host that wants tracing integration can
//!   replace this with `LogTracer` (from `tracing-log`) before
//!   the worker is dispatched — `set_logger` is idempotent at
//!   the log-crate level.
//! - **WASM**: not installed by vos. WASM hosts vary
//!   (`console_log` for browsers, custom imports for WASI/edge),
//!   so the wasm bootstrap leaves logger installation to the
//!   embedder. Calls to `log::info!` are no-ops without an
//!   installed subscriber, which is safe by default.

mod pvm {
    use crate::abi::pvm::hostcalls::debug_write;
    use core::fmt::Write;
    use ::log::{Level, LevelFilter, Log, Metadata, Record};

    /// Per-record formatting buffer cap. Records longer than this
    /// are truncated; `DEBUG_WRITE` is best-effort diagnostics, not
    /// authoritative output. 1 KiB covers typical structured log
    /// lines comfortably.
    const FMT_CAP: usize = 1024;

    struct PvmLogger;

    impl Log for PvmLogger {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            // `log::set_max_level` already filters; if we're called
            // it means the level passed. No per-target filter here.
            true
        }

        fn log(&self, record: &Record<'_>) {
            let mut buf = [0u8; FMT_CAP];
            let pos = {
                let mut w = StackWriter { buf: &mut buf, pos: 0 };
                // Format: `[LEVEL target] message\n`. Target defaults
                // to module path which is informative without being
                // verbose.
                let _ = write!(
                    &mut w,
                    "[{} {}] {}\n",
                    level_tag(record.level()),
                    record.target(),
                    record.args(),
                );
                w.pos
            };
            debug_write(&buf[..pos]);
        }

        fn flush(&self) {}
    }

    fn level_tag(level: Level) -> &'static str {
        match level {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    /// `core::fmt::Write` adapter that fills a fixed-size buffer
    /// and silently drops anything past the end. PVM is
    /// single-threaded so this is reused per call without locking.
    struct StackWriter<'a> {
        buf: &'a mut [u8],
        pos: usize,
    }

    impl<'a> Write for StackWriter<'a> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let bytes = s.as_bytes();
            let take = self.buf.len().saturating_sub(self.pos).min(bytes.len());
            if take > 0 {
                self.buf[self.pos..self.pos + take].copy_from_slice(&bytes[..take]);
                self.pos += take;
            }
            Ok(())
        }
    }

    static LOGGER: PvmLogger = PvmLogger;

    /// Install the PVM logger. Idempotent — subsequent calls are
    /// no-ops, so warm restarts that re-enter `_start` don't error.
    ///
    /// Uses `set_logger_racy` / `set_max_level_racy` because the
    /// riscv64em-javm target lacks `target_has_atomic = "ptr"`
    /// (embedded profile, no atomic ops). PVM is single-threaded
    /// by construction, so the racy variants — which require the
    /// caller to guarantee no concurrent access — are sound here.
    pub fn install() {
        // SAFETY: PVM is single-threaded; `_start` runs to
        // completion before any other entry point. Cold start
        // calls this exactly once; warm restarts re-call it but
        // by that point no concurrent log emission is in flight.
        unsafe {
            let _ = ::log::set_logger_racy(&LOGGER);
            ::log::set_max_level_racy(LevelFilter::Trace);
        }
    }
}

/// Install the PVM `log::Log` implementation. Called by
/// `run_refine_service` so user actors don't need to opt in.
#[cfg(feature = "pvm")]
pub(crate) fn install_pvm_logger() {
    pvm::install();
}

// The worker-side `log::Log` impl lives in the user crate
// (emitted by `__vos_emit_worker_glue!`) rather than here. Two
// reasons: (1) the impl needs `std::io::stderr`, and vos's
// `worker` feature can't pull `std` without dragging in the
// heavy host-runtime deps (javm, libp2p, etc.) that hide behind
// vos's `std` feature; (2) the worker target is the user's
// cdylib build, where std is always available regardless of
// what features vos itself enables. Emitting in the user crate
// is the right scope.
