//! The receiving side: peers' connections accepted, and their streams
//! read, each frame delivered with the peer it came from.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::admit::Place;
use super::executor::Tasks;
use super::{HEADER, Inner, STREAM_WINDOW, code, within};
use crate::{Budgets, Class, Incoming, NodeKey, Streams, short, tls};

/// Streams of one connection that may break the protocol before it is
/// closed: limits may differ between nodes while a configuration changes,
/// so one need not close it.
const VIOLATIONS: u32 = 16;

/// Accept peers' connections, for as long as the endpoint is open.
pub(super) async fn accept(inner: Arc<Inner>) {
    let mut serving = Tasks::default();
    while let Some(incoming) = inner.endpoint.accept().await {
        // A sender proves its address first, so a flood from addresses
        // that are not its own holds no handshake.
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            continue;
        }
        let Some(place) = inner.admission.take(incoming.remote_address().ip()) else {
            incoming.refuse();
            continue;
        };
        if !serving.spawn(&inner.spawner, serve(Arc::clone(&inner), incoming, place)) {
            return;
        }
    }
}

/// Read a peer's connection: every stream it opens, each frame delivered
/// with the key it was authenticated with.
async fn serve(inner: Arc<Inner>, incoming: quinn::Incoming, place: Place) {
    let Some((connection, key)) = admitted(&inner, incoming).await else {
        place.keep().await;
        return;
    };
    drop(place);
    inner.dialed_in(&key, tls::server_name(&connection));
    let peer = Arc::new(Reading {
        assembling: Budgets::new(&inner.classes, inner.assembling),
        inner,
        connection: connection.clone(),
        key,
        turns: Turns::default(),
        violations: AtomicU32::new(0),
    });
    let mut reading = Tasks::default();
    while let Ok(stream) = connection.accept_uni().await {
        if !reading.spawn(&peer.inner.spawner, read(Arc::clone(&peer), stream)) {
            break;
        }
    }
    peer.inner.hung_up(&key, &connection);
}

/// `incoming`'s connection, its handshake done within its deadline, with
/// the key it was authenticated with: a key no peer has is closed.
async fn admitted(
    inner: &Inner,
    incoming: quinn::Incoming,
) -> Option<(quinn::Connection, NodeKey)> {
    let connection = match within(inner.admission.deadline(), incoming).await? {
        Ok(connection) => connection,
        Err(error) => {
            tracing::debug!(%error, "a peer's handshake failed");
            return None;
        }
    };
    let key = tls::peer_key(&connection)?;
    if !inner.dialed(key, &connection) {
        connection.close(code::UNCONFIGURED, b"");
        return None;
    }
    Some((connection, key))
}

/// A peer's connection being read.
struct Reading {
    inner: Arc<Inner>,
    connection: quinn::Connection,
    key: NodeKey,
    /// The bytes of the frames being read, per class.
    assembling: Arc<Budgets>,
    turns: Turns,
    /// Streams that broke the protocol.
    violations: AtomicU32,
}

impl Reading {
    /// A stream broke the protocol: the first is logged, and past
    /// [`VIOLATIONS`] the connection closes.
    /// `broken` is the class and length of a frame over its bound.
    fn violated(&self, broken: Option<(Class, usize)>) {
        let count = self.violations.fetch_add(1, Ordering::Relaxed);
        if count == 0 {
            tracing::warn!(
                from = short(&self.key),
                class = ?broken.map(|(class, _)| class),
                length = ?broken.map(|(_, length)| length),
                "a stream broke the protocol"
            );
        }
        if count + 1 >= VIOLATIONS {
            self.connection.close(code::MALFORMED, b"");
        }
    }
}

/// A turn per id: a stream's frames are delivered only once the stream
/// that took its id's turn before it has delivered all of its own. The
/// order is fixed when a stream's header is read, with no lock to race
/// for.
#[derive(Default)]
struct Turns {
    /// The last turn taken for each id.
    last: Mutex<HashMap<(Class, u64), Last>>,
    taken: AtomicU64,
}

/// An id's last turn: its number, and what closes when it ends.
type Last = (u64, smol::channel::Receiver<()>);

impl Turns {
    /// Wait for `key`'s turn, after the turns taken before.
    async fn take(&self, key: (Class, u64)) -> Turn<'_> {
        let (done, finished) = smol::channel::bounded::<()>(1);
        let number = self.taken.fetch_add(1, Ordering::Relaxed);
        let before = self
            .last
            .lock()
            .expect("the turns")
            .insert(key, (number, finished));
        let turn = Turn {
            turns: self,
            key,
            number,
            _done: done,
        };
        if let Some((_, before)) = before {
            // Closed when the turn before ends, whichever way.
            let _ = before.recv().await;
        }
        turn
    }
}

/// An id's turn, held until dropped.
struct Turn<'a> {
    turns: &'a Turns,
    key: (Class, u64),
    number: u64,
    /// Dropped with the turn, which lets the next one go.
    _done: smol::channel::Sender<()>,
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut last = self.turns.last.lock().expect("the turns");
        // No later turn was taken for this id: forget it.
        if last
            .get(&self.key)
            .is_some_and(|(number, _)| *number == self.number)
        {
            last.remove(&self.key);
        }
    }
}

/// Read one stream's frames, as they arrive.
async fn read(peer: Arc<Reading>, mut stream: quinn::RecvStream) {
    let mut header = [0u8; HEADER];
    if stream.read_exact(&mut header).await.is_err() {
        return;
    }
    let class = header[0];
    let Some(spec) = peer.inner.classes.get(class) else {
        let _ = stream.stop(code::MALFORMED);
        peer.violated(None);
        return;
    };
    let id = u64::from_be_bytes(header[1..].try_into().expect("eight bytes"));
    let _turn = match spec.streams {
        Streams::PerFrame => None,
        Streams::PerId => Some(peer.turns.take((class, id)).await),
    };
    frames(&peer, stream, class, id).await;
}

/// Deliver a stream's frames until it ends.
async fn frames(peer: &Reading, mut stream: quinn::RecvStream, class: Class, id: u64) {
    let limit = peer.inner.classes.max_frame(class);
    loop {
        let mut length = [0u8; 4];
        if stream.read_exact(&mut length).await.is_err() {
            return;
        }
        let length = u32::from_be_bytes(length) as usize;
        if length > limit {
            let _ = stream.stop(code::TOO_LARGE);
            peer.violated(Some((class, length)));
            return;
        }
        // Its bytes are taken before any is read or reserved.
        let _held = peer.assembling.hold(class, length).await;
        let Some(frame) = read_frame(&mut stream, length).await else {
            return;
        };
        if !peer.inner.configured(&peer.key) {
            peer.connection.close(code::UNCONFIGURED, b"");
            return;
        }
        let incoming = Incoming::new(peer.key, id, frame);
        if !peer.inner.deliver.deliver(class, incoming).await {
            return;
        }
    }
}

/// A frame of `length` bytes, its peer's budget already holding them,
/// grown as its bytes arrive.
async fn read_frame(stream: &mut quinn::RecvStream, length: usize) -> Option<Vec<u8>> {
    let mut frame = Vec::with_capacity(length.min(STREAM_WINDOW as usize));
    while frame.len() < length {
        let chunk = stream.read_chunk(length - frame.len(), true).await.ok()??;
        frame.extend_from_slice(&chunk.bytes);
    }
    Some(frame)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    /// A stream first polled between a turn's release and the poll of the
    /// stream that waited for it does not take the turn.
    #[test]
    fn a_turn_goes_to_the_stream_that_waited() {
        let executor = smol::LocalExecutor::new();
        let turns = Rc::new(Turns::default());
        let key = (2, 5);
        let order = Rc::new(RefCell::new(Vec::new()));
        let (release, released) = smol::channel::bounded::<()>(1);
        let reader = |name: &'static str| {
            let (turns, order) = (Rc::clone(&turns), Rc::clone(&order));
            async move {
                let _turn = turns.take(key).await;
                order.borrow_mut().push(name);
            }
        };
        // The first stream holds the turn until told to end; the second
        // waits for it.
        let first = executor.spawn({
            let turns = Rc::clone(&turns);
            async move {
                let _turn = turns.take(key).await;
                let _ = released.recv().await;
            }
        });
        let second = executor.spawn(reader("second"));
        while executor.try_tick() {}
        // The first ends, and a third stream arrives, in one pass.
        release.try_send(()).unwrap();
        let third = executor.spawn(reader("third"));
        while executor.try_tick() {}
        drop((first, second, third));
        assert_eq!(*order.borrow(), ["second", "third"]);
        // No turn is left behind.
        assert!(turns.last.lock().unwrap().is_empty());
    }
}
