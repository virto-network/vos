//! The blob store's index: its rows, their keys and their codecs.

use super::Keep;

/// The index's rows, by their first byte.
#[derive(Clone, Copy)]
#[repr(u8)]
pub(crate) enum IndexRow {
    /// Hash → segment, offset, length, when last put.
    Location = 0,
    /// Segment → the end of its indexed records, and where the last
    /// starts.
    Segment = 1,
    /// Hash ∥ agent → (): the agent keeps the blob, a program it runs.
    Pin = 2,
}

pub(super) fn location_key(hash: &[u8; 32]) -> Vec<u8> {
    [&[IndexRow::Location as u8][..], hash].concat()
}

pub(super) fn segment_key(segment: u64) -> Vec<u8> {
    [&[IndexRow::Segment as u8][..], &segment.to_be_bytes()].concat()
}

/// A segment row: the end of its indexed records, and where the last one
/// starts.
pub(super) fn segment_row(end: u64, last: Option<u64>) -> Vec<u8> {
    [end.to_be_bytes(), last.unwrap_or(u64::MAX).to_be_bytes()].concat()
}

pub(super) fn decode_segment_row(bytes: &[u8]) -> (u64, Option<u64>) {
    let field = |at: usize| {
        bytes
            .get(at..at + 8)
            .map(|field| u64::from_be_bytes(field.try_into().expect("8 bytes")))
    };
    (
        field(0).unwrap_or(0),
        field(8).filter(|&last| last != u64::MAX),
    )
}

pub(crate) fn pin_key(hash: &[u8; 32], agent: u32) -> Vec<u8> {
    [&[IndexRow::Pin as u8][..], hash, &agent.to_be_bytes()].concat()
}

/// Where a blob is, when it was last put or touched, and how it is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Location {
    pub(super) segment: u64,
    pub(super) offset: u64,
    pub(super) len: u64,
    pub(super) time: u64,
    pub(super) keep: Keep,
}

impl Location {
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = [self.segment, self.offset, self.len, self.time]
            .iter()
            .flat_map(|field| field.to_be_bytes())
            .collect();
        out.push(self.keep as u8);
        out
    }

    /// A row of 32 bytes, without its keep, reads as aged: the longer.
    pub(super) fn decode(bytes: &[u8]) -> Option<Self> {
        let field = |at: usize| Some(u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?));
        let keep = bytes
            .get(32)
            .map_or(Keep::Aged, |&byte| Keep::from_u8(byte));
        Some(Self {
            segment: field(0)?,
            offset: field(8)?,
            len: field(16)?,
            time: field(24)?,
            keep,
        })
    }
}
