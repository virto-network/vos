//! The sending side: a link per peer, which dials it and writes its
//! queued frames, each class and id on a stream of its own.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use smol::stream::StreamExt;

use super::executor::{Spawner, Tasks};
use super::{
    BULK_STREAMS, CRYPTO_ERRORS, DIAL, HEADER, Inner, MAX_BACKOFF, MIN_BACKOFF, SETTLED, code,
    within,
};
use crate::{Budgets, Class, Hold, Peer};

/// A frame on its way, holding its bytes in its peer's queue until it is
/// written or lost.
pub(super) struct Outgoing {
    pub(super) class: Class,
    pub(super) stream: u64,
    pub(super) frame: Vec<u8>,
    pub(super) _held: Hold,
    pub(super) queued: Instant,
}

/// The sending side to one peer: its queue, and the task that dials it and
/// writes.
pub(super) struct Link {
    pub(super) peer: Peer,
    pub(super) frames: smol::channel::Sender<Outgoing>,
    /// The bytes its queued frames hold, per class.
    pub(super) queued: Arc<Budgets>,
    /// The connection this node holds to the peer, while it does.
    pub(super) connection: Arc<Mutex<Option<quinn::Connection>>>,
    /// The name the peer last dialed in with.
    pub(super) incarnation: Option<String>,
    pub(super) task: smol::Task<()>,
}

impl Link {
    pub(super) fn spawn(inner: &Inner, peer: Peer) -> Self {
        let connection = Arc::default();
        let (frames, queued) = smol::channel::unbounded();
        let client = inner.identity.client(peer.key, Arc::clone(&inner.dialing));
        let dialing = Dialing {
            endpoint: inner.endpoint.clone(),
            client,
            address: peer.address,
            name: inner.name.clone(),
            quiet: inner.quiet,
            spawner: inner.spawner.clone(),
        };
        let task = inner
            .spawner
            .spawn(dialing.run(queued, Arc::clone(&connection)))
            .expect("the network's executor runs while it is open");
        Self {
            peer,
            frames,
            queued: Budgets::with(Class::ALL.map(|class| inner.limits.queue(class))),
            connection,
            incarnation: None,
            task,
        }
    }
}

/// What a link dials with.
struct Dialing {
    endpoint: quinn::Endpoint,
    client: quinn::ClientConfig,
    address: SocketAddr,
    name: String,
    quiet: Duration,
    spawner: Spawner,
}

impl Dialing {
    /// Dial the peer whenever there is something to send, and write to it
    /// until the connection closes.
    async fn run(
        self,
        queued: smol::channel::Receiver<Outgoing>,
        held: Arc<Mutex<Option<quinn::Connection>>>,
    ) {
        let address = self.address;
        let mut next = None;
        let mut backoff = MIN_BACKOFF;
        loop {
            if next.is_none() {
                let Ok(frame) = queued.recv().await else {
                    return;
                };
                next = Some(frame);
            }
            let dialed = self
                .endpoint
                .connect_with(self.client.clone(), address, &self.name);
            let connecting = match dialed {
                Ok(connecting) => connecting,
                Err(error) => {
                    tracing::warn!(%address, %error, "cannot dial a peer");
                    return;
                }
            };
            let timed_out = Err(quinn::ConnectionError::TimedOut);
            let connection = match within(DIAL, connecting).await.unwrap_or(timed_out) {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::debug!(%address, %error, "dial failed");
                    back_off(&mut backoff).await;
                    continue;
                }
            };
            *held.lock().expect("the connection") = Some(connection.clone());
            let connected = Instant::now();
            self.write(&connection, connected, &mut next, &queued).await;
            *held.lock().expect("the connection") = None;
            if refused(&connection) {
                // The peer took the handshake, then refused this node:
                // dialing again at once would only be refused again.
                tracing::debug!(%address, "a peer refused this node");
                back_off(&mut backoff).await;
            } else if connected.elapsed() < SETTLED {
                // Closed as soon as made: a handshake a frame would cost.
                back_off(&mut backoff).await;
            } else {
                backoff = MIN_BACKOFF;
            }
        }
    }

    /// Write queued frames on `connection`, just made, until it closes. A
    /// frame taken but not yet handed to a stream stays in `next`, for the
    /// next connection. A liveness frame queued before the connection was
    /// made is dropped: it would say, late, that its sender was alive
    /// then. One handed to a connection that outlives a cut is QUIC's to
    /// deliver, and may still arrive late, after the cut heals.
    async fn write(
        &self,
        connection: &quinn::Connection,
        connected: Instant,
        next: &mut Option<Outgoing>,
        queued: &smol::channel::Receiver<Outgoing>,
    ) {
        enum Event {
            Frame(Outgoing),
            Sweep,
            Done,
        }
        let mut streams: HashMap<(Class, u64), Writer> = HashMap::new();
        // Writers finishing their quiet streams. A new stream for the same
        // id opens only once its old one is finished and the peer has it
        // all.
        let mut retiring: HashMap<(Class, u64), smol::Task<()>> = HashMap::new();
        let every = (self.quiet / 2).max(Duration::from_millis(1));
        let mut sweep = smol::Timer::interval(every);
        let mut swept = Instant::now();
        let bulk = Arc::new(smol::lock::Semaphore::new(BULK_STREAMS));
        let mut sending = Tasks::default();
        loop {
            // Swept on time even while frames never stop coming.
            if swept.elapsed() >= every {
                retire(&mut streams, &mut retiring, self.quiet);
                swept = Instant::now();
            }
            let frame = match next.take() {
                Some(frame) => frame,
                None => {
                    let frame = async {
                        match queued.recv().await {
                            Ok(frame) => Event::Frame(frame),
                            Err(_) => Event::Done,
                        }
                    };
                    let closed = async {
                        connection.closed().await;
                        Event::Done
                    };
                    let swept = async {
                        sweep.next().await;
                        Event::Sweep
                    };
                    match frame.or(closed).or(swept).await {
                        Event::Frame(frame) => frame,
                        Event::Sweep => continue,
                        Event::Done => return,
                    }
                }
            };
            if frame.class == Class::Liveness && frame.queued < connected {
                continue;
            }
            if connection.close_reason().is_some() {
                *next = Some(frame);
                return;
            }
            if frame.class.stream_per_frame() {
                let connection = connection.clone();
                let bulk = Arc::clone(&bulk);
                let sent = async move {
                    let _permit = bulk.acquire().await;
                    let _ = write_bulk(&connection, frame).await;
                };
                if !sending.spawn(&self.spawner, sent) {
                    return;
                }
                continue;
            }
            let key = (frame.class, frame.stream);
            let frame = match streams.get_mut(&key) {
                Some(writer) => match writer.frames.try_send(frame) {
                    Ok(()) => {
                        writer.last = Instant::now();
                        continue;
                    }
                    // The stream failed: the frame goes on a new one.
                    Err(error) => error.into_inner(),
                },
                None => frame,
            };
            let previous = retiring.remove(&key);
            let Some(writer) = Writer::spawn(
                &self.spawner,
                connection.clone(),
                frame.class,
                frame.stream,
                previous,
            ) else {
                return;
            };
            let _ = writer.frames.try_send(frame);
            streams.insert(key, writer);
        }
    }
}

/// Wait `backoff`, then double it, up to [`MAX_BACKOFF`].
async fn back_off(backoff: &mut Duration) {
    smol::Timer::after(*backoff).await;
    *backoff = (*backoff * 2).min(MAX_BACKOFF);
}

/// Whether the peer closed `connection` refusing this node: a TLS alert
/// (its key was not taken), or the peer no longer configuring it.
fn refused(connection: &quinn::Connection) -> bool {
    match connection.close_reason() {
        Some(quinn::ConnectionError::ConnectionClosed(close)) => {
            CRYPTO_ERRORS.contains(&u64::from(close.error_code))
        }
        Some(quinn::ConnectionError::ApplicationClosed(close)) => {
            close.error_code == code::UNCONFIGURED
        }
        _ => false,
    }
}

/// Retire the writers of streams quiet for `quiet`: each writes what it
/// still holds, then finishes its stream, so the peer can grant another.
fn retire(
    streams: &mut HashMap<(Class, u64), Writer>,
    retiring: &mut HashMap<(Class, u64), smol::Task<()>>,
    quiet: Duration,
) {
    retiring.retain(|_, task| !task.is_finished());
    let now = Instant::now();
    let quieted = streams.extract_if(|_, writer| now.duration_since(writer.last) >= quiet);
    // Dropping its sender ends a writer's queue once drained.
    retiring.extend(quieted.map(|(key, writer)| (key, writer.task)));
}

/// A long-lived stream's writer, and when it was last handed a frame.
struct Writer {
    frames: smol::channel::Sender<Outgoing>,
    task: smol::Task<()>,
    last: Instant,
}

impl Writer {
    /// A writer for a new stream, opened once `previous`, the last stream
    /// for the same id, is finished and all acknowledged.
    fn spawn(
        spawner: &Spawner,
        connection: quinn::Connection,
        class: Class,
        stream: u64,
        previous: Option<smol::Task<()>>,
    ) -> Option<Self> {
        let (frames, queued) = smol::channel::unbounded::<Outgoing>();
        let task = spawner.spawn(async move {
            if let Some(previous) = previous {
                previous.await;
            }
            let written = async {
                let mut send = open(&connection, class, stream).await?;
                while let Ok(frame) = queued.recv().await {
                    write_frame(&mut send, &frame.frame).await.ok()?;
                }
                send.finish().ok()?;
                send.stopped().await.ok()?;
                Some(())
            };
            if written.await.is_none() {
                // Release what is queued here: the next frame for this
                // stream opens another.
                queued.close();
                while queued.try_recv().is_ok() {}
            }
        });
        Some(Self {
            frames,
            task: task?,
            last: Instant::now(),
        })
    }
}

/// A new stream for frames of `class` with id `stream`: sent by its
/// class's priority, its header written.
async fn open(
    connection: &quinn::Connection,
    class: Class,
    stream: u64,
) -> Option<quinn::SendStream> {
    let mut send = connection.open_uni().await.ok()?;
    send.set_priority(class.priority()).ok()?;
    let mut header = [0u8; HEADER];
    header[0] = class as u8;
    header[1..].copy_from_slice(&stream.to_be_bytes());
    send.write_all(&header).await.ok()?;
    Some(send)
}

async fn write_frame(send: &mut quinn::SendStream, frame: &[u8]) -> Result<(), quinn::WriteError> {
    let length = u32::try_from(frame.len()).expect("a frame within its class's bound");
    send.write_all(&length.to_be_bytes()).await?;
    send.write_all(frame).await
}

/// A bulk frame on a stream of its own, held until the peer has it all.
async fn write_bulk(connection: &quinn::Connection, frame: Outgoing) -> Option<()> {
    let mut send = open(connection, frame.class, frame.stream).await?;
    write_frame(&mut send, &frame.frame).await.ok()?;
    send.finish().ok()?;
    drop(frame);
    send.stopped().await.ok()?;
    Some(())
}
