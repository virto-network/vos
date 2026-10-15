//! The receiving side: peers' connections accepted, and their streams
//! read, each frame delivered with the peer it came from.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::executor::Tasks;
use super::{BULK_STREAMS, HEADER, Inner, STREAM_WINDOW, code};
use crate::tls;
use crate::{Class, Incoming, NodeKey, NodeNumber};

/// Accept peers' connections, for as long as the endpoint is open.
pub(super) async fn accept(inner: Arc<Inner>) {
    let mut serving = Tasks::default();
    while let Some(incoming) = inner.endpoint.accept().await {
        if !serving.spawn(&inner.spawner, serve(Arc::clone(&inner), incoming)) {
            return;
        }
    }
}

/// Read a peer's connection: every stream it opens, each frame delivered
/// with the peer its key is configured for.
async fn serve(inner: Arc<Inner>, incoming: quinn::Incoming) {
    let connection = match incoming.await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::debug!(%error, "a peer's handshake failed");
            return;
        }
    };
    let Some(key) = tls::peer_key(&connection) else {
        return;
    };
    let Some(from) = inner.peer_number(&key) else {
        connection.close(code::UNCONFIGURED, b"");
        return;
    };
    inner.dialed_in(from, tls::server_name(&connection));
    let peer = Arc::new(Reading {
        inner,
        connection: connection.clone(),
        key,
        from,
        bulk: smol::lock::Semaphore::new(BULK_STREAMS),
        turns: Mutex::new(HashMap::new()),
    });
    let mut reading = Tasks::default();
    while let Ok(stream) = connection.accept_uni().await {
        if !reading.spawn(&peer.inner.spawner, read(Arc::clone(&peer), stream)) {
            return;
        }
    }
}

/// A peer's connection being read.
struct Reading {
    inner: Arc<Inner>,
    connection: quinn::Connection,
    key: NodeKey,
    from: NodeNumber,
    /// Bulk frames read at once.
    bulk: smol::lock::Semaphore,
    turns: Turns,
}

/// A turn per id: a stream's frames are delivered only once the last
/// stream for the same id has delivered all of its own.
type Turns = Mutex<HashMap<(Class, u64), Arc<smol::lock::Mutex<()>>>>;

/// Read one stream's frames, as they arrive.
async fn read(peer: Arc<Reading>, mut stream: quinn::RecvStream) {
    let mut header = [0u8; HEADER];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }
    let Some(class) = Class::from_u8(header[0]) else {
        let _ = stream.stop(code::MALFORMED);
        return;
    };
    let id = u64::from_be_bytes(header[1..].try_into().expect("eight bytes"));
    if class.stream_per_frame() {
        frames(&peer, stream, class, id).await;
        return;
    }
    let turn = Arc::clone(
        peer.turns
            .lock()
            .expect("the turns")
            .entry((class, id))
            .or_default(),
    );
    let held = turn.lock_arc().await;
    frames(&peer, stream, class, id).await;
    drop(held);
    let mut turns = peer.turns.lock().expect("the turns");
    // Only the map and this stream hold the turn: no later stream waits
    // for this id, so forget it.
    if Arc::strong_count(&turn) == 2 {
        turns.remove(&(class, id));
    }
}

/// Deliver a stream's frames until it ends.
async fn frames(peer: &Reading, mut stream: quinn::RecvStream, class: Class, id: u64) {
    let limit = peer.inner.limits.of(class);
    loop {
        let mut length = [0u8; 4];
        if stream.read_exact(&mut length).await.is_err() {
            return;
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > limit {
            tracing::warn!(from = peer.from, ?class, length, "a frame over its bound");
            let _ = stream.stop(code::TOO_LARGE);
            return;
        }
        let _permit = if class.stream_per_frame() {
            Some(peer.bulk.acquire().await)
        } else {
            None
        };
        let Some(frame) = read_frame(&mut stream, length).await else {
            return;
        };
        if !peer.inner.configured(&peer.key, peer.from) {
            peer.connection.close(code::UNCONFIGURED, b"");
            return;
        }
        let incoming = Incoming {
            from: peer.from,
            stream: id,
            frame,
        };
        if !peer.inner.deliver.deliver(class, incoming).await {
            return;
        }
    }
}

/// A frame of `length` bytes, grown as its bytes arrive.
async fn read_frame(stream: &mut quinn::RecvStream, length: usize) -> Option<Vec<u8>> {
    let mut frame = Vec::with_capacity(length.min(STREAM_WINDOW as usize));
    while frame.len() < length {
        let chunk = stream.read_chunk(length - frame.len(), true).await.ok()??;
        frame.extend_from_slice(&chunk.bytes);
    }
    Some(frame)
}
