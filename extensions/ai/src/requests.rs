//! Per-request state for streaming generation + the wire type
//! `poll_generation` returns.
//!
//! Architecture:
//!
//! - `begin_generate` mints a `request_id` (monotonic u64), stores
//!   a [`RequestState`] under it, and spawns a worker thread.
//! - The worker grabs the model mutex (blocking behind any prior
//!   worker) and runs `ModelHandle::generate_stream`, pushing each
//!   decoded chunk into the request's channel.
//! - `poll_generation` drains every available chunk into one
//!   [`GenerationChunk`] reply and reports `done = true` once the
//!   channel's sender has been dropped (i.e. the worker finished
//!   or panicked).
//!
//! Concurrency model: the model itself is single-instance behind a
//! mutex, so two concurrent `begin_generate` calls queue serially.
//! `poll_generation` doesn't touch the model — only the per-request
//! channel — so polling never blocks inference progress.
//!
//! Cleanup: a request entry is removed from the map the first time
//! `poll_generation` sees `done = true`. A caller who never polls
//! leaks the entry; v1 accepts that, GC is a follow-up.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;

use vos::value::Args;

/// What `poll_generation` returns on each tick. Encoded on the
/// wire as a `vos::value::Args` (three named keys: `text`, `done`,
/// `error`) rather than a custom rkyv struct so vosx doesn't have
/// to depend on this crate's heavy candle/tokenizers/hf-hub deps
/// just to decode the reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationChunk {
    /// Newly-emitted text since the previous poll. May be empty
    /// (worker is mid-token, or the loop hit EOS before the first
    /// token).
    pub text: String,
    /// `true` once the inference worker has finished. The caller
    /// should stop polling after observing this — the request id
    /// is gone from the map after this call returns.
    pub done: bool,
    /// Set when the worker thread errored. Carried alongside
    /// `done = true` so the caller distinguishes "finished
    /// cleanly" from "stopped because of an internal error".
    /// Empty on the happy path.
    pub error: String,
}

impl GenerationChunk {
    /// Encode for the wire. Three keys; the names are part of the
    /// public contract with the vosx CLI.
    pub fn to_args(&self) -> Args {
        Args::new()
            .with("text", self.text.clone())
            .with("done", self.done)
            .with("error", self.error.clone())
    }
}

/// One outstanding streaming request. Owned by the request map;
/// the worker thread holds the corresponding [`Sender<String>`]
/// (in an `Option` so it can be dropped explicitly on
/// completion) and is unaware of this struct directly.
pub(crate) struct RequestState {
    pub(crate) receiver: Mutex<Option<Receiver<String>>>,
    pub(crate) finished: AtomicBool,
    /// Populated by the worker on error before it drops the
    /// sender. Cleared on creation; the poll path reads it after
    /// observing the sender disconnected.
    pub(crate) error: Mutex<String>,
}

impl RequestState {
    pub(crate) fn new(receiver: Receiver<String>) -> Self {
        Self {
            receiver: Mutex::new(Some(receiver)),
            finished: AtomicBool::new(false),
            error: Mutex::new(String::new()),
        }
    }
}
