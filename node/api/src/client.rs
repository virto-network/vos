//! A multiplexed client over a byte stream: requests in flight at once,
//! each under an id of its own, their answers matched back by id as they
//! come, in any order. Runtime-neutral: the caller spawns the reader.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use futures_lite::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Event, Framing, Reader, frame};

/// An answer frame's kind and body.
pub type Answer = (u16, Vec<u8>);

/// Why a request got no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Closed {
    /// The stream ended, or its framing failed, before the answer.
    Ended,
}

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the node API's stream ended before the answer")
    }
}

impl std::error::Error for Closed {}

type Pending = Mutex<Option<HashMap<u64, async_channel::Sender<Answer>>>>;

/// Requests over one byte stream. Cloned, it shares the stream.
#[derive(Clone)]
pub struct Multiplexed {
    writer: Arc<async_lock::Mutex<Box<dyn AsyncWrite + Send + Unpin>>>,
    /// The requests waiting, by id; none once the stream ended.
    pending: Arc<Pending>,
    next: Arc<AtomicU64>,
}

/// A client over `reader` and `writer`, the two halves of one stream, and
/// the reader's task, which the caller spawns: it ends with the stream.
pub fn multiplexed(
    reader: impl AsyncRead + Send + Unpin + 'static,
    writer: impl AsyncWrite + Send + Unpin + 'static,
) -> (Multiplexed, impl Future<Output = ()> + Send + 'static) {
    let client = Multiplexed {
        writer: Arc::new(async_lock::Mutex::new(Box::new(writer))),
        pending: Arc::new(Mutex::new(Some(HashMap::new()))),
        next: Arc::new(AtomicU64::new(1)),
    };
    let pending = Arc::clone(&client.pending);
    (client, read(reader, pending))
}

/// Read answers until the stream ends, each given to its request.
async fn read(mut stream: impl AsyncRead + Unpin, pending: Arc<Pending>) {
    let mut reader = Reader::answers(Framing::Stream);
    let mut chunk = vec![0u8; 64 << 10];
    loop {
        let read = match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        reader.push(&chunk[..read]);
        let mut failed = false;
        while let Some(event) = reader.event() {
            match event {
                Event::Frame(answer) => {
                    let waiting = pending
                        .lock()
                        .expect("the pending requests")
                        .as_mut()
                        .and_then(|pending| pending.remove(&answer.id));
                    if let Some(waiting) = waiting {
                        let _ = waiting.try_send((answer.kind, answer.body));
                    }
                }
                Event::Error { .. } => failed = true,
            }
        }
        if failed {
            break;
        }
    }
    // Every request still waiting ends with the stream.
    pending.lock().expect("the pending requests").take();
}

impl Multiplexed {
    /// Send a request of `kind` holding `body`: its answer, once it comes.
    pub async fn request(&self, kind: u16, body: &[u8]) -> Result<Answer, Closed> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = async_channel::bounded(1);
        match self.pending.lock().expect("the pending requests").as_mut() {
            Some(pending) => pending.insert(id, sender),
            None => return Err(Closed::Ended),
        };
        let bytes = frame(Framing::Stream, kind, id, body);
        let written = {
            let mut writer = self.writer.lock().await;
            match writer.write_all(&bytes).await {
                Ok(()) => writer.flush().await,
                Err(error) => Err(error),
            }
        };
        if written.is_err() {
            if let Some(pending) = self.pending.lock().expect("the pending requests").as_mut() {
                pending.remove(&id);
            }
            return Err(Closed::Ended);
        }
        receiver.recv().await.map_err(|_| Closed::Ended)
    }

    /// Whether the stream ended: no request can go.
    pub fn is_closed(&self) -> bool {
        self.pending.lock().expect("the pending requests").is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers out of order reach their requests by id.
    #[test]
    fn answers_reach_their_requests_by_id() {
        smol::block_on(async {
            let (ours, theirs) = smol::net::unix::UnixStream::pair().unwrap();
            let (client, reading) = multiplexed(ours.clone(), ours);
            let reading = smol::spawn(reading);
            let server = smol::spawn(async move {
                let mut theirs = theirs;
                let mut reader = Reader::requests(Framing::Stream, crate::Requests::All);
                let mut seen = Vec::new();
                let mut chunk = [0u8; 256];
                while seen.len() < 2 {
                    let read = theirs.read(&mut chunk).await.unwrap();
                    reader.push(&chunk[..read]);
                    while let Some(Event::Frame(request)) = reader.event() {
                        seen.push(request);
                    }
                }
                // The second answered first.
                for request in seen.iter().rev() {
                    let answer = frame(Framing::Stream, request.kind, request.id, &request.body);
                    theirs.write_all(&answer).await.unwrap();
                }
            });
            let first = client.request(crate::Kind::AgentInfo as u16, &[1, 0, 0, 0]);
            let second = client.request(crate::Kind::AgentInfo as u16, &[2, 0, 0, 0]);
            let (first, second) = futures_lite::future::zip(first, second).await;
            assert_eq!(first.unwrap().1, [1, 0, 0, 0]);
            assert_eq!(second.unwrap().1, [2, 0, 0, 0]);
            server.await;
            drop(client);
            reading.cancel().await;
        });
    }

    /// A stream that ends ends every request waiting on it.
    #[test]
    fn a_stream_that_ends_ends_its_requests() {
        smol::block_on(async {
            let (ours, theirs) = smol::net::unix::UnixStream::pair().unwrap();
            let (client, reading) = multiplexed(ours.clone(), ours);
            let reading = smol::spawn(reading);
            let asked = client.request(crate::Kind::Time as u16, &[]);
            drop(theirs);
            assert_eq!(asked.await, Err(Closed::Ended));
            reading.await;
            assert!(client.is_closed());
            assert_eq!(
                client.request(crate::Kind::Time as u16, &[]).await,
                Err(Closed::Ended)
            );
        });
    }
}
