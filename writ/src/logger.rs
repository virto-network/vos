//! Very simple logging for single-threaded applications using the `log` facade.
//!
//! All log messages are written to stderr with `UnsafeCell` for zero-overhead
//! interior mutability.
//!

use log::{LevelFilter, Log, Metadata, Record};
use std::{cell::UnsafeCell, env, fmt};

#[cfg(feature = "_log_internal")]
const DEBUG_INTERNAL: bool = true;
#[cfg(not(feature = "_log_internal"))]
const DEBUG_INTERNAL: bool = false;
const RUNTIME_CRATE: &str = "wasync";

const fn crate_name() -> &'static str {
    const PATH: &str = module_path!();
    let bytes = PATH.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b':' && bytes[i + 1] == b':' {
            let (prefix, _) = bytes.split_at(i);
            return unsafe { std::str::from_utf8_unchecked(prefix) };
        }
        i += 1;
    }
    PATH
}

/// Initialize the logger with an optional minimum log level.
///
/// Defaults to `Debug` level if `None`. Returns error if logger already initialized.
pub fn init(
    writer: impl fmt::Write + 'static,
    level: Option<LevelFilter>,
) -> Result<(), log::SetLoggerError> {
    let level = level.unwrap_or(LevelFilter::Debug);
    let logger = SimpleLogger::new(writer, level);

    log::set_logger(Box::leak(Box::new(logger)))?;
    log::set_max_level(level);
    log::trace!("Logger initialized with level {level}");

    Ok(())
}

/// Simple logger implementation for single-threaded  environments.
///
/// Uses `UnsafeCell` for interior mutability instead of `Mutex` to avoid
/// synchronization overhead, since applications are single-threaded.
pub struct SimpleLogger<W> {
    level: LevelFilter,
    writer: UnsafeCell<W>,
}

// Safe because we know we're in a single-threaded environment
unsafe impl<W> Sync for SimpleLogger<W> {}
unsafe impl<W> Send for SimpleLogger<W> {}

impl<W> SimpleLogger<W> {
    fn new(writer: W, level: LevelFilter) -> Self {
        Self {
            level,
            writer: UnsafeCell::new(writer),
        }
    }
}

fn write_log_formatted(w: &mut impl fmt::Write, record: &Record) -> fmt::Result {
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds_today = s % 86400;
    let z = (s / 86400) as i32 + 719468; // Convert to days since year 0, Mar 1
    let era = if z >= 0 { z } else { z - 146096 } / 146097; // 400-year cycles
    let doe = (z - era * 146097) as u32; // Day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // Year of era [0, 399]
    let mut y = yoe as i32 + era * 400; // Year
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // Day of year (0-based)
    let mp = (5 * doy + 2) / 153; // Month index (0=Mar, 1=Apr, ..., 11=Feb)
    let d = doy - (153 * mp + 2) / 5 + 1; // Day of month
    let m = mp + if mp < 10 { 3 } else { !9 + 1 }; // Calendar month (1-12)
    y += if m <= 2 { 1 } else { 0 }; // Adjust year if Jan/Feb

    let h = seconds_today / 3600;
    let min = (seconds_today % 3600) / 60;
    let sec = seconds_today % 60;

    writeln!(
        w,
        "[{y:02}-{m:02}-{d:02} {h:02}:{min:02}:{sec:02}][{level}][{target}]\t{message}",
        level = record.level(),
        target = record.target(),
        message = record.args()
    )
}

impl<W: fmt::Write> Log for SimpleLogger<W> {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let target = metadata.target();
        if !DEBUG_INTERNAL
            && (target.starts_with(RUNTIME_CRATE) || target.starts_with(crate_name()))
        {
            return false;
        }
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let writer = unsafe { &mut *self.writer.get() };
        let _ = write_log_formatted(writer, record);
    }

    fn flush(&self) {
        let writer = unsafe { &mut *self.writer.get() };
        let _ = write!(writer, "");
    }
}

/// Get the log level from the RUST_LOG environment variable.
///
/// Supports: error, warn, info, debug, trace, off (case-insensitive).
/// Returns `None` if not set or invalid.
pub fn level_from_env() -> Option<LevelFilter> {
    env::var("RUST_LOG").ok().and_then(|s| {
        match s.to_lowercase().as_str() {
            "error" => Some(LevelFilter::Error),
            "warn" => Some(LevelFilter::Warn),
            "info" => Some(LevelFilter::Info),
            "debug" => Some(LevelFilter::Debug),
            "trace" => Some(LevelFilter::Trace),
            "off" => Some(LevelFilter::Off),
            _ => {
                // Try to parse as a more complex filter specification
                // For now, just default to None for complex filters
                None
            }
        }
    })
}
