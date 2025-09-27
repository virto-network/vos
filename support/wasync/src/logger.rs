//! Async-aware logging for WASI environments using the `log` facade.
//!
//! Provides a buffered logger optimized for single-threaded WASI environments.
//! All log messages are written to stderr with `UnsafeCell` for zero-overhead
//! interior mutability and `crate::block_on` for sync/async bridging.
//!
//! # Examples
//!
//! ```rust
//! use wasync::log::{init_logger, init_logger_from_env};
//! use log::{info, LevelFilter};
//!
//! // Default debug level
//! init_logger(None)?;
//!
//! // From RUST_LOG environment variable
//! init_logger_from_env()?;
//!
//! // Custom level
//! init_logger(Some(LevelFilter::Info))?;
//! # Ok::<(), log::SetLoggerError>(())
//! ```

use crate::io::{BufWriter, Stderr, Write, stderr};
use log::{LevelFilter, Log, Metadata, Record};
use std::{cell::UnsafeCell, env};

/// Logger implementation optimized for single-threaded WASI environments.
///
/// Uses `UnsafeCell` for interior mutability instead of `Mutex` to avoid
/// synchronization overhead, since WASI applications are single-threaded.
pub struct WasiLogger {
    level: LevelFilter,
    writer: UnsafeCell<BufWriter<Stderr>>,
}

// Safe because we know we're in a single-threaded WASI environment
// WASI applications don't have threads, so there's no risk of data races
unsafe impl Sync for WasiLogger {}

impl WasiLogger {
    fn new(level: LevelFilter) -> Self {
        Self {
            level,
            writer: UnsafeCell::new(BufWriter::new(stderr())),
        }
    }

    fn format_record(&self, record: &Record) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();

        format!(
            "[{timestamp}] [{level}] [{target}] {message}\n",
            timestamp = timestamp,
            level = record.level(),
            target = record.target(),
            message = record.args()
        )
    }

    async fn write_message_async(&self, message: String) -> Result<(), std::io::Error> {
        let writer = unsafe { &mut *self.writer.get() };

        // Write the entire message
        let bytes = message.as_bytes();
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let written = writer.write(remaining).await?;
            remaining = &remaining[written..];
        }

        // Flush to ensure the message is written immediately
        writer.flush().await?;
        Ok(())
    }
}

impl Log for WasiLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let message = self.format_record(record);

        // Use crate::block_on to execute the async write synchronously
        // Ignore errors in logging to avoid crashing the application
        let _ = crate::block_on(self.write_message_async(message));
    }

    fn flush(&self) {
        let _ = crate::block_on(async {
            let writer = unsafe { &mut *self.writer.get() };
            let _ = writer.flush().await;
        });
    }
}

/// Initialize the logger with an optional minimum log level.
///
/// Defaults to `Debug` level if `None`. Returns error if logger already initialized.
pub fn init(level: Option<LevelFilter>) -> Result<(), log::SetLoggerError> {
    let level = level.unwrap_or(LevelFilter::Debug);
    let logger = WasiLogger::new(level);

    log::set_logger(Box::leak(Box::new(logger)))?;
    log::set_max_level(level);

    Ok(())
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
