//! Resource caps. Centralized here so they're easy to find and tune;
//! eventually these should come from init args or env vars.

/// Hard cap on the request body size in bytes. Bodies larger than this
/// terminate with a 413 before the gateway allocates the full payload.
/// Picked to comfortably cover the JSON arg shape we accept and rule
/// out trivial OOM via Content-Length.
pub(crate) const MAX_BODY_BYTES: usize = 1 * 1024 * 1024;

/// Maximum concurrent transport-level connections per protocol
/// (TCP for hyper, QUIC for h3). New connections beyond this are
/// dropped. Each protocol has its own semaphore.
pub(crate) const MAX_CONCURRENT_CONNS: usize = 1024;

/// Capacity of the per-serve mpsc that ferries `Job`s from the
/// connection tasks to the actor handler. Once full, connection tasks
/// fail-fast with 503 (Retry-After) instead of growing memory.
pub(crate) const JOB_QUEUE_CAP: usize = 256;

/// Hard cap on the number of headers we copy out of an incoming
/// request. Hyper / h3 already enforce per-header and total-size
/// limits; this is a belt-and-suspenders guard against an attacker
/// who somehow stuffs a many-header request through.
pub(crate) const MAX_REQUEST_HEADERS: usize = 64;
