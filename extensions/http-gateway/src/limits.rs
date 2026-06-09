//! Resource caps for the HTTP/1.1 parser. Centralized here so they're
//! easy to find and tune; eventually these should come from init args.
//!
//! Connection-count backpressure is a host concern: the host owns the
//! accept loop and caps concurrent connection tasks
//! (`ExtensionConfig::serves_max`, default 1024).

/// Hard cap on the request body size in bytes. Bodies whose declared
/// `Content-Length` exceeds this terminate with `413` before the
/// gateway buffers the payload. Picked to comfortably cover the JSON
/// arg shape we accept and rule out trivial OOM via Content-Length.
pub(crate) const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Hard cap on the number of headers parsed out of an incoming request.
/// A request with more terminates with `431` — a belt-and-suspenders
/// guard against a header-flood, since the gateway parses the head by hand.
pub(crate) const MAX_REQUEST_HEADERS: usize = 64;

/// Hard cap on the request **head** (request line + all header lines, up
/// to and including the terminating blank line) in bytes. Bounds the
/// buffer a peer can force us to hold while it dribbles headers without
/// ever sending the `\r\n\r\n` terminator (slow-loris / header flood);
/// exceeding it terminates with `431`.
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;

/// How many bytes to request per `ctx.read` while filling the parse
/// buffer. One MTU-ish chunk keeps small requests to a single read
/// while still draining a large body promptly.
pub(crate) const READ_CHUNK: u32 = 16 * 1024;
