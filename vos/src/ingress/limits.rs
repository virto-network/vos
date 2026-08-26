//! Resource caps for the built-in HTTP/1.1 parser.

pub(crate) const MAX_HEADERS: usize = 64;
pub(crate) const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Hard cap on the request body size in bytes. Bodies whose declared
/// `Content-Length` exceeds this terminate with `413` before the
/// ingress buffers the payload. Picked to comfortably cover the JSON
/// arg shape we accept and rule out trivial OOM via Content-Length.
pub(crate) const MAX_BODY_BYTES: usize = 1024 * 1024;
