//! Frames: a `u32` little-endian length of what follows, a `u16` kind,
//! on a byte stream a `u64` request id, then the body. Read without I/O:
//! a [`Reader`] takes bytes as they arrive and gives frames, or the frame
//! error to answer, checking each header before its body is kept.

use scale::Encode;

use crate::{FRAME_ERROR, FrameError, Kind};

/// The largest answer body a client takes: past it, the connection is
/// closed unread.
pub const MAX_ANSWER: u32 = 16 << 20;

/// Where frames travel: a QUIC stream holds one request and its answer;
/// a byte stream many, each with an id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    Quic,
    Stream,
}

impl Framing {
    /// The header's bytes: the length, the kind, and on a stream the id.
    pub const fn header(self) -> usize {
        match self {
            Framing::Quic => 6,
            Framing::Stream => 14,
        }
    }

    /// The header's bytes after the length, which the length counts.
    const fn rest(self) -> u32 {
        self.header() as u32 - 4
    }
}

/// A frame's header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The bytes after the length: the rest of the header, and the body.
    pub length: u32,
    pub kind: u16,
    /// The request's id: 0 over QUIC.
    pub id: u64,
}

impl Header {
    /// The header of a frame of `kind` holding `body` bytes.
    pub fn of(framing: Framing, kind: u16, id: u64, body: usize) -> Self {
        let length = u32::try_from(body)
            .ok()
            .and_then(|body| body.checked_add(framing.rest()))
            .expect("a body a frame can carry");
        Self { length, kind, id }
    }

    pub fn encode(&self, framing: Framing) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(framing.header());
        bytes.extend_from_slice(&self.length.to_le_bytes());
        bytes.extend_from_slice(&self.kind.to_le_bytes());
        if framing == Framing::Stream {
            bytes.extend_from_slice(&self.id.to_le_bytes());
        }
        bytes
    }

    /// The body's length, if the length holds the header's rest.
    pub fn body(&self, framing: Framing) -> Option<u32> {
        self.length.checked_sub(framing.rest())
    }
}

/// A frame whole: its kind's number, its id, its body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: u16,
    pub id: u64,
    pub body: Vec<u8>,
}

/// What a reader makes of the bytes so far.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Frame(Frame),
    /// A frame not taken: answer `error` under `id` (0 when the frame
    /// held none), then close unless it keeps the channel open.
    Error {
        error: FrameError,
        id: u64,
    },
}

/// Which requests a reader takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requests {
    /// Every kind: a node's.
    All,
    /// Only the kinds a relay passes on ([`Kind::relayed`]).
    Relayed,
}

#[derive(Clone, Copy, Debug)]
enum Mode {
    Requests(Requests),
    /// Answers of any kind, each at most [`MAX_ANSWER`].
    Answers,
}

/// Frames from bytes as they arrive. Each header is checked before its
/// body is kept: the length against the header, the kind against the
/// table, the body's length against its kind's limit; the first failure
/// is the reader's last event.
pub struct Reader {
    framing: Framing,
    mode: Mode,
    buffer: Vec<u8>,
    /// Where the next frame starts in `buffer`: the frames before it are
    /// taken, their bytes dropped when more arrive.
    at: usize,
    done: bool,
}

impl Reader {
    /// A reader of requests.
    pub fn requests(framing: Framing, requests: Requests) -> Self {
        Self::new(framing, Mode::Requests(requests))
    }

    /// A reader of answers: any kind, the frame error's too.
    pub fn answers(framing: Framing) -> Self {
        Self::new(framing, Mode::Answers)
    }

    fn new(framing: Framing, mode: Mode) -> Self {
        Self {
            framing,
            mode,
            buffer: Vec::new(),
            at: 0,
            done: false,
        }
    }

    /// Bytes that arrived.
    pub fn push(&mut self, bytes: &[u8]) {
        if !self.done {
            self.buffer.drain(..self.at);
            self.at = 0;
            self.buffer.extend_from_slice(bytes);
        }
    }

    /// Whether a frame is part read: its deadline runs.
    pub fn pending(&self) -> bool {
        !self.done && self.buffer.len() > self.at
    }

    /// The header of the frame part read, once its bytes arrived: after
    /// [`Reader::event`] gave `None`, one it checked.
    pub fn header(&self) -> Option<Header> {
        let bytes = self.buffer.get(self.at..).filter(|_| !self.done)?;
        let header = bytes.get(..self.framing.header())?;
        let id = match self.framing {
            Framing::Quic => 0,
            Framing::Stream => u64::from_le_bytes(header[6..14].try_into().expect("eight")),
        };
        Some(Header {
            length: u32::from_le_bytes(header[..4].try_into().expect("four bytes")),
            kind: u16::from_le_bytes(header[4..6].try_into().expect("two bytes")),
            id,
        })
    }

    /// The next frame, or the frame error that ends the reader; `None`
    /// until more bytes arrive.
    pub fn event(&mut self) -> Option<Event> {
        if self.done {
            return None;
        }
        let framing = self.framing;
        let bytes = &self.buffer[self.at..];
        if bytes.len() < 6 {
            return None;
        }
        let length = u32::from_le_bytes(bytes[..4].try_into().expect("four bytes"));
        let kind = u16::from_le_bytes(bytes[4..6].try_into().expect("two bytes"));
        if length < framing.rest() {
            return self.fail(FrameError::Truncated, 0);
        }
        if bytes.len() < framing.header() {
            return None;
        }
        let id = match framing {
            Framing::Quic => 0,
            Framing::Stream => u64::from_le_bytes(bytes[6..14].try_into().expect("eight")),
        };
        let header = Header { length, kind, id };
        let body = header.body(framing).expect("checked above");
        let limit = match self.mode {
            Mode::Answers => MAX_ANSWER,
            Mode::Requests(requests) => {
                let Some(known) = Kind::from_u16(kind) else {
                    return self.fail(FrameError::UnknownKind, id);
                };
                if requests == Requests::Relayed && !known.relayed() {
                    return self.fail(FrameError::NotRelayed, id);
                }
                known.limit()
            }
        };
        if body > limit {
            return self.fail(FrameError::Oversize { limit }, id);
        }
        let end = framing.header() + body as usize;
        if bytes.len() < end {
            return None;
        }
        let body = bytes[framing.header()..end].to_vec();
        self.at += end;
        Some(Event::Frame(Frame { kind, id, body }))
    }

    /// The peer ended its side: a frame part read is `Truncated`.
    pub fn finish(&mut self) -> Option<Event> {
        if !self.pending() {
            return None;
        }
        let bytes = &self.buffer[self.at..];
        let id = match self.framing {
            Framing::Stream if bytes.len() >= Framing::Stream.header() => {
                u64::from_le_bytes(bytes[6..14].try_into().expect("eight"))
            }
            _ => 0,
        };
        self.fail(FrameError::Truncated, id)
    }

    fn fail(&mut self, error: FrameError, id: u64) -> Option<Event> {
        self.done = true;
        self.buffer = Vec::new();
        Some(Event::Error { error, id })
    }
}

/// A frame of `kind` holding `body`.
pub fn frame(framing: Framing, kind: u16, id: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = Header::of(framing, kind, id, body.len()).encode(framing);
    bytes.extend_from_slice(body);
    bytes
}

/// The frame error `error`, answering request `id`.
pub fn error_frame(framing: Framing, id: u64, error: FrameError) -> Vec<u8> {
    frame(framing, FRAME_ERROR, id, &error.encode())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn headers_are_pinned() {
        let header = Header::of(Framing::Stream, Kind::Call as u16, 0x0102_0304_0506_0708, 3);
        assert_eq!(
            header.encode(Framing::Stream),
            [13, 0, 0, 0, 0x01, 0x01, 8, 7, 6, 5, 4, 3, 2, 1]
        );
        let header = Header::of(Framing::Quic, Kind::Time as u16, 0, 0);
        assert_eq!(header.encode(Framing::Quic), [2, 0, 0, 0, 0x02, 0x00]);
        assert_eq!(
            error_frame(Framing::Stream, 9, FrameError::UnknownKind),
            [11, 0, 0, 0, 0xff, 0xff, 9, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    fn read_all(reader: &mut Reader, chunks: &[&[u8]]) -> Vec<Event> {
        let mut events = Vec::new();
        for chunk in chunks {
            reader.push(chunk);
            while let Some(event) = reader.event() {
                events.push(event);
            }
        }
        events.extend(reader.finish());
        events
    }

    fn requests(framing: Framing) -> Reader {
        Reader::requests(framing, Requests::All)
    }

    #[test]
    fn a_length_below_the_header_is_truncated_with_no_id() {
        let mut bytes = 9u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(Kind::Time as u16).to_le_bytes());
        let events = read_all(&mut requests(Framing::Stream), &[&bytes]);
        assert_eq!(
            events,
            [Event::Error {
                error: FrameError::Truncated,
                id: 0
            }]
        );
        let events = read_all(&mut requests(Framing::Quic), &[&[1, 0, 0, 0, 2, 0]]);
        assert_eq!(
            events,
            [Event::Error {
                error: FrameError::Truncated,
                id: 0
            }]
        );
    }

    #[test]
    fn unknown_kinds_and_the_frame_errors_kind_are_unknown() {
        for kind in [0u16, FRAME_ERROR, crate::CREDENTIALED, 0x0300] {
            let events = read_all(
                &mut requests(Framing::Stream),
                &[&frame(Framing::Stream, kind, 7, &[])],
            );
            assert_eq!(
                events,
                [Event::Error {
                    error: FrameError::UnknownKind,
                    id: 7
                }],
                "{kind:#06x}"
            );
        }
    }

    #[test]
    fn a_body_past_its_limit_is_refused_from_the_header() {
        for kind in Kind::ALL {
            let limit = kind.limit();
            let header = Header::of(Framing::Stream, kind as u16, 3, limit as usize + 1);
            let mut reader = requests(Framing::Stream);
            reader.push(&header.encode(Framing::Stream));
            assert_eq!(
                reader.event(),
                Some(Event::Error {
                    error: FrameError::Oversize { limit },
                    id: 3
                }),
                "{kind:?}"
            );
            // At the limit, the reader waits for the body, if it has one.
            let header = Header::of(Framing::Quic, kind as u16, 0, limit as usize);
            let mut reader = requests(Framing::Quic);
            reader.push(&header.encode(Framing::Quic));
            if limit > 0 {
                assert_eq!(reader.event(), None, "{kind:?}");
                assert!(reader.pending());
                assert_eq!(reader.header(), Some(header));
            } else {
                assert!(matches!(reader.event(), Some(Event::Frame(_))));
            }
        }
    }

    #[test]
    fn a_relay_refuses_what_it_does_not_relay_before_its_body() {
        let mut reader = Reader::requests(Framing::Stream, Requests::Relayed);
        let header = Header::of(Framing::Stream, Kind::Call as u16, 5, 100);
        reader.push(&header.encode(Framing::Stream));
        assert_eq!(
            reader.event(),
            Some(Event::Error {
                error: FrameError::NotRelayed,
                id: 5
            })
        );
        let mut reader = Reader::requests(Framing::Stream, Requests::Relayed);
        reader.push(&frame(Framing::Stream, Kind::Time as u16, 6, &[]));
        assert!(matches!(
            reader.event(),
            Some(Event::Frame(Frame { id: 6, .. }))
        ));
    }

    #[test]
    fn a_frame_cut_short_is_truncated_at_the_end() {
        let bytes = frame(Framing::Stream, Kind::AgentInfo as u16, 4, &[1, 2, 3, 4]);
        let events = read_all(&mut requests(Framing::Stream), &[&bytes[..16]]);
        assert_eq!(
            events,
            [Event::Error {
                error: FrameError::Truncated,
                id: 4
            }]
        );
    }

    #[test]
    fn answers_take_any_kind_up_to_their_bound() {
        let mut reader = Reader::answers(Framing::Quic);
        reader.push(&error_frame(Framing::Quic, 0, FrameError::Truncated));
        assert_eq!(
            reader.event(),
            Some(Event::Frame(Frame {
                kind: FRAME_ERROR,
                id: 0,
                body: vec![2]
            }))
        );
        let mut reader = Reader::answers(Framing::Quic);
        reader
            .push(&Header::of(Framing::Quic, 1, 0, MAX_ANSWER as usize + 1).encode(Framing::Quic));
        assert!(matches!(
            reader.event(),
            Some(Event::Error {
                error: FrameError::Oversize { .. },
                ..
            })
        ));
    }

    /// A frame's kind and body, as a proptest draws them.
    fn frames() -> impl Strategy<Value = Vec<(u16, u64, Vec<u8>)>> {
        let kinds = prop::sample::select(vec![
            Kind::AgentInfo as u16,
            Kind::Schema as u16,
            Kind::Call as u16,
            Kind::Query as u16,
            Kind::Status as u16,
        ]);
        let one = (
            kinds,
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..4),
        )
            .prop_map(|(kind, id, body)| (kind, id, body));
        prop::collection::vec(one, 0..8)
    }

    proptest! {
        /// Frames split anywhere read as frames whole, in order.
        #[test]
        fn split_reads_give_the_same_frames(
            frames in frames(),
            cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..12),
            quic in any::<bool>(),
        ) {
            let framing = if quic { Framing::Quic } else { Framing::Stream };
            let mut bytes = Vec::new();
            let mut expected = Vec::new();
            for (kind, id, body) in &frames {
                let id = if quic { 0 } else { *id };
                bytes.extend(frame(framing, *kind, id, body));
                expected.push(Event::Frame(Frame { kind: *kind, id, body: body.clone() }));
            }
            let mut at: Vec<usize> = cuts.iter().map(|cut| cut.index(bytes.len() + 1)).collect();
            at.sort_unstable();
            let mut chunks = Vec::new();
            let mut from = 0;
            for to in at {
                chunks.push(&bytes[from..to]);
                from = to;
            }
            chunks.push(&bytes[from..]);
            prop_assert_eq!(read_all(&mut requests(framing), &chunks), expected);
        }

        /// Any bytes give frames, then at most one error, and never a body
        /// past its kind's limit.
        #[test]
        fn any_bytes_read_within_the_limits(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let events = read_all(&mut requests(Framing::Stream), &[&bytes]);
            for (at, event) in events.iter().enumerate() {
                match event {
                    Event::Frame(frame) => {
                        let kind = Kind::from_u16(frame.kind).expect("a known kind");
                        prop_assert!(frame.body.len() as u32 <= kind.limit());
                    }
                    Event::Error { .. } => prop_assert_eq!(at, events.len() - 1),
                }
            }
        }
    }
}
