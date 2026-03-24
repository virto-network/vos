//! Actor ABI — the entry points every child PVM program exports.
//!
//! The executor loads child programs and calls these symbols. Children
//! don't need to know about this module directly — the `pvm-actors`
//! framework generates the glue. But the ABI is stable and simple
//! enough to implement by hand in any language.
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │ Executor                                        │
//! │                                                 │
//! │  1. init()           → child sets up state      │
//! │  2. handle(msg)      → deliver a message        │
//! │  3. poll()           → resume async work        │
//! │  4. drop()           → cleanup before unload    │
//! └─────────────────────────────────────────────────┘
//! ```

/// Status returned by `poll()` and `handle()`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The operation completed. Ready for the next message.
    Ready = 0,
    /// The actor yielded (async work in progress). Call `poll()` again.
    Pending = 1,
    /// The actor wants to stop.
    Done = 2,
    /// An error occurred. Error details available via `last_error()`.
    Error = 3,
}

/// Unique identifier for an actor within the executor.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ActorId(pub u32);

impl ActorId {
    /// The executor's own ID (used as "sender" for system messages).
    pub const EXECUTOR: Self = Self(0);
}

/// Entry point names as string constants (for symbol lookup).
pub mod symbols {
    /// `fn() -> u32` — Initialize actor state. Returns 0 on success.
    pub const INIT: &str = "init";

    /// `fn(msg_ptr: *const u8, msg_len: u32) -> Status`
    /// Deliver a message to the actor.
    pub const HANDLE: &str = "handle";

    /// `fn() -> Status` — Resume suspended async work.
    pub const POLL: &str = "poll";

    /// `fn()` — Cleanup before the program is unloaded.
    pub const DROP: &str = "drop";

    /// `fn(buf: *mut u8, buf_len: u32) -> u32`
    /// Read the last error message. Returns bytes written.
    pub const LAST_ERROR: &str = "last_error";
}
