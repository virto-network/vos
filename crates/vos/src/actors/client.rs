//! Generated client support — error type shared by every
//! `#[messages]`-emitted client struct.
//!
//! When the `host` feature is set on a consumer crate of an
//! actor, `#[messages]` emits a `{Actor}Client` struct with one
//! method per `#[msg]`. Each method calls `VosNode::invoke` and
//! decodes the reply, returning `Result<HandlerReturnType,
//! ClientError>`. Different actors share this error so callers
//! can write generic error-handling.

use alloc::string::String;

/// Error returned by every macro-generated host client method.
#[derive(Debug)]
pub enum ClientError {
    /// `VosNode::invoke` returned `None` — target not registered,
    /// timed out, or the channel disconnected.
    Unreachable,
    /// Reply payload was a `Value` variant that didn't match
    /// the handler's declared return type. Carries a debug
    /// rendering of the actual value for diagnostics.
    UnexpectedReply(String),
    /// Reply payload was the right `Value` shape but couldn't
    /// be rkyv-decoded into the user-defined return type. Most
    /// often a version skew between the actor and the consumer.
    Decode,
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unreachable => write!(f, "client: target unreachable"),
            Self::UnexpectedReply(s) => write!(f, "client: unexpected reply: {s}"),
            Self::Decode => write!(f, "client: failed to decode reply"),
        }
    }
}

impl core::error::Error for ClientError {}
