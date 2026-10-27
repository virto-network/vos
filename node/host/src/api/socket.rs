//! The node API on a unix socket: frames with ids, read in order, each
//! request started as it arrives and answered when it is done, out of
//! order. The socket file's mode is the access.
//!
//! After a frame error the requests in flight run on, detached, and the
//! connection's place is given back as it closes: a local client that
//! fills its places and then sends a bad frame can have more requests
//! running than `api_connections × api_in_flight`, each to its end. The
//! socket's mode bounds who can.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::lock::{Mutex, Semaphore};
use smol::net::unix::{UnixListener, UnixStream};
use vos_api::{Event, Framing, Kind, Reader, Requests, error_frame, frame};

use super::{Api, LargePlace, Via};
use crate::timeout;

/// The most one read takes off the socket.
const CHUNK: usize = 64 << 10;

/// A bound socket, and the lock on its file held while it serves.
pub(crate) struct Bound {
    listener: UnixListener,
    _lock: std::fs::File,
}

/// The lock file beside a socket's.
fn lock_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// Bind the socket at `path`, its file given `mode`. The lock beside it
/// decides between two nodes given one path: the one holding it replaces
/// a stale socket file; the other is refused.
pub(crate) fn bind(path: &Path, mode: u32) -> Result<Bound, String> {
    let failed = |error: std::io::Error| format!("{}: {error}", path.display());
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path(path))
        .map_err(failed)?;
    if lock.try_lock().is_err() {
        return Err(format!("{}: another node serves it", path.display()));
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(failed)?
        }
        Ok(_) => return Err(format!("{}: a file that is not a socket", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(failed(error)),
    }
    // Bound beside it and given its mode first, then moved into place: no
    // one connects to it before its mode is the access.
    let mut name = path.as_os_str().to_owned();
    name.push(".binding");
    let binding = PathBuf::from(name);
    let _ = std::fs::remove_file(&binding);
    let listener = UnixListener::bind(&binding).map_err(failed)?;
    std::fs::set_permissions(&binding, std::fs::Permissions::from_mode(mode)).map_err(failed)?;
    std::fs::rename(&binding, path).map_err(failed)?;
    Ok(Bound {
        listener,
        _lock: lock,
    })
}

/// Serve `bound` until `stop` resolves, at most `connections` at once,
/// each with at most `in_flight` requests: past them, its next frame is
/// read only as one ends.
pub(crate) async fn serve(
    api: Arc<Api>,
    bound: Bound,
    connections: usize,
    in_flight: usize,
    deadline: Duration,
    stop: smol::channel::Receiver<()>,
) {
    let open = Arc::new(Semaphore::new(connections));
    let mut tasks: Vec<smol::Task<()>> = Vec::new();
    let accepting = async {
        while let Ok((stream, _)) = bound.listener.accept().await {
            tasks.retain(|task| !task.is_finished());
            let Some(place) = open.try_acquire_arc() else {
                continue;
            };
            let api = Arc::clone(&api);
            let runtime = Arc::clone(&api.inner.runtime);
            tasks.push(runtime.spawn(async move {
                let _place = place;
                if let Err(error) = connection(api, stream, in_flight, deadline).await {
                    tracing::debug!("an API connection ended: {error}");
                }
            }));
        }
    };
    smol::future::or(accepting, async {
        let _ = stop.recv().await;
    })
    .await;
    for task in tasks {
        task.cancel().await;
    }
}

/// One connection's frames, until it ends or a frame error closes it.
async fn connection(
    api: Arc<Api>,
    stream: UnixStream,
    in_flight: usize,
    deadline: Duration,
) -> std::io::Result<()> {
    let mut reading = stream.clone();
    let writer = Arc::new(Mutex::new(stream));
    let slots = Arc::new(Semaphore::new(in_flight.max(1)));
    let mut requests: Vec<smol::Task<()>> = Vec::new();
    let mut reader = Reader::requests(Framing::Stream, Requests::All);
    let mut chunk = vec![0u8; CHUNK];
    // When the frame part read began to arrive: it must end within the
    // deadline.
    let mut started: Option<Instant> = None;
    // The frame part read's place among the large bodies, if it is large.
    let mut large = None;
    loop {
        let read = match started {
            Some(started) => {
                let left = (started + deadline).saturating_duration_since(Instant::now());
                match timeout(left, reading.read(&mut chunk)).await {
                    Some(read) => read?,
                    None => return Err(std::io::ErrorKind::TimedOut.into()),
                }
            }
            None => reading.read(&mut chunk).await?,
        };
        if read == 0 {
            // A frame cut short is answered, if the client still reads;
            // the requests in flight are answered first.
            for request in requests {
                request.await;
            }
            if let Some(Event::Error { error, id }) = reader.finish() {
                let _ = writer
                    .lock()
                    .await
                    .write_all(&error_frame(Framing::Stream, id, error))
                    .await;
            }
            return Ok(());
        }
        reader.push(&chunk[..read]);
        while let Some(event) = reader.event() {
            match event {
                Event::Frame(request) => {
                    // A whole frame read: the next one's deadline runs from
                    // its own first byte.
                    started = None;
                    let slot = slots.acquire_arc().await;
                    requests.retain(|task| !task.is_finished());
                    let kind = Kind::from_u16(request.kind).expect("the reader's kinds");
                    let (api, writer) = (Arc::clone(&api), Arc::clone(&writer));
                    let runtime = Arc::clone(&api.inner.runtime);
                    let large = large.take().map(|place| Box::new(place) as LargePlace);
                    requests.push(runtime.spawn(async move {
                        let answer = api.handle(kind, request.body, Via::Socket, large).await;
                        let bytes = frame(Framing::Stream, request.kind, request.id, &answer);
                        // Written whole: an answer never interleaves another.
                        let _ = writer.lock().await.write_all(&bytes).await;
                        drop(slot);
                    }));
                }
                Event::Error { error, id } => {
                    // The requests in flight run on to their end, their
                    // answers unsent: an operator's command whose nonce is
                    // recorded is not cut short.
                    for request in requests.drain(..) {
                        request.detach();
                    }
                    let mut writer = writer.lock().await;
                    writer
                        .write_all(&error_frame(Framing::Stream, id, error))
                        .await?;
                    writer.flush().await?;
                    let _ = writer.shutdown(std::net::Shutdown::Both);
                    return Ok(());
                }
            }
        }
        started = match (reader.pending(), started) {
            (false, _) => None,
            (true, Some(started)) => Some(started),
            (true, None) => Some(Instant::now()),
        };
        // A large body is read only once it holds a place; its deadline
        // runs from then, as the wait is the node's.
        if large.is_none()
            && let Some(places) = api.large_places(&reader, Framing::Stream)
        {
            large = Some(places.acquire_arc().await);
            started = Some(Instant::now());
        }
    }
}
