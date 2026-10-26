//! A request over QUIC: one bidirectional stream, its frame written and
//! the stream finished, its answer read to the stream's end. quinn's own
//! API, so any runtime quinn runs on serves.

use crate::{Event, Framing, MAX_ANSWER, Reader, frame};

/// Why a request over QUIC got no answer.
#[derive(Debug)]
pub enum Failed {
    /// The connection or the stream failed.
    Stream(String),
    /// The node answered something that is not a frame.
    Unreadable,
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::Stream(why) => write!(f, "{why}"),
            Failed::Unreadable => write!(f, "an answer that is not a frame"),
        }
    }
}

impl std::error::Error for Failed {}

/// Send a request of `kind` holding `body` on its own stream of
/// `connection`: the answer frame's kind and body.
pub async fn request(
    connection: &quinn::Connection,
    kind: u16,
    body: &[u8],
) -> Result<(u16, Vec<u8>), Failed> {
    let failed = |error: &dyn std::fmt::Display| Failed::Stream(error.to_string());
    let (mut send, mut receive) = connection.open_bi().await.map_err(|e| failed(&e))?;
    send.write_all(&frame(Framing::Quic, kind, 0, body))
        .await
        .map_err(|e| failed(&e))?;
    send.finish().map_err(|e| failed(&e))?;
    let bytes = receive
        .read_to_end(Framing::Quic.header() + MAX_ANSWER as usize)
        .await
        .map_err(|e| failed(&e))?;
    let mut reader = Reader::answers(Framing::Quic);
    reader.push(&bytes);
    match reader.event() {
        Some(Event::Frame(frame)) => Ok((frame.kind, frame.body)),
        _ => Err(Failed::Unreadable),
    }
}
