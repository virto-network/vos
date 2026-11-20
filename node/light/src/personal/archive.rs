//! The key archive in envelopes: chunked and sealed, put back together as
//! it is read, and opened from the recovery scope under `R`.

use std::collections::BTreeMap;

use vos_abi::{Decode, Encode};
use vos_wire::personal::{Envelope, RECOVERY, RecoveryView, Scope};
use zeroize::Zeroizing;

use crate::group::Archive;
use crate::kit::{self, KitSecret};
use crate::sealed::{self, MAX_BODY};

/// A chunk of an archive: the hash of the archive's encoding, which part
/// of how many, and its bytes.
#[derive(Encode, Decode)]
struct Chunk {
    digest: [u8; 32],
    part: u16,
    parts: u16,
    bytes: Vec<u8>,
}

/// A chunk's encoding beyond its bytes: the digest, the two counts and the
/// bytes' length prefix, at most four.
const CHUNK_FRAMING: usize = 32 + 2 + 2 + 4;

/// The archive's bytes an envelope's chunk holds.
const CHUNK_BYTES: usize = MAX_BODY - CHUNK_FRAMING;

const _: () = assert!(CHUNK_BYTES < 1 << 30, "the length prefix stays four bytes");

/// The digest an archive's chunks name it by.
pub(super) fn archive_digest(encoding: &[u8]) -> [u8; 32] {
    crate::hash(b"vos/personal/archive-digest", &[encoding])
}

/// An archive's parts read so far: how many it has, those read, and the
/// position of its first part read.
type Parts = (u16, BTreeMap<u16, Zeroizing<Vec<u8>>>, u64);

/// Archives read in chunks, put back together, each one's parts by its
/// digest.
#[derive(Default)]
pub(super) struct Reassembly {
    parts: BTreeMap<[u8; 32], Parts>,
}

impl Reassembly {
    /// A chunk read at `position`: the archive it completes, with its
    /// digest, if it does.
    pub(super) fn add(&mut self, position: u64, body: &[u8]) -> Option<([u8; 32], Archive)> {
        let chunk = Chunk::decode_exact(body)?;
        if chunk.part >= chunk.parts {
            return None;
        }
        let (count, held, _) =
            self.parts
                .entry(chunk.digest)
                .or_insert((chunk.parts, BTreeMap::new(), position));
        if *count != chunk.parts {
            return None;
        }
        held.insert(chunk.part, Zeroizing::new(chunk.bytes));
        if held.len() < *count as usize {
            return None;
        }
        let (_, held, _) = self.parts.remove(&chunk.digest)?;
        let whole = Zeroizing::new(
            held.into_values()
                .flat_map(|part| part.to_vec())
                .collect::<Vec<u8>>(),
        );
        if archive_digest(&whole) != chunk.digest {
            return None;
        }
        Archive::decode_exact(&whole).map(|archive| (chunk.digest, archive))
    }

    /// The position before the first part of an archive not complete yet,
    /// which reading starts from again.
    pub(super) fn rewind(&self) -> Option<u64> {
        self.parts.values().map(|(_, _, first)| first - 1).min()
    }
}

/// `archive` sealed in chunks under `key` for `scope` at `epoch`, with its
/// digest.
pub(super) fn chunks(
    archive: &Archive,
    key: &[u8; 32],
    agent: &[u8; 32],
    scope: Scope,
    epoch: u64,
) -> ([u8; 32], Vec<Vec<u8>>) {
    let whole = Zeroizing::new(archive.encode());
    let digest = archive_digest(&whole);
    let pieces: Vec<&[u8]> = whole.chunks(CHUNK_BYTES).collect();
    let parts = u16::try_from(pieces.len()).expect("an archive under 3.6 GiB");
    let envelopes = pieces
        .into_iter()
        .enumerate()
        .map(|(part, bytes)| {
            let body = Zeroizing::new(
                Chunk {
                    digest,
                    part: part as u16,
                    parts,
                    bytes: bytes.to_vec(),
                }
                .encode(),
            );
            sealed::seal(key, agent, scope, epoch, &body).expect("a chunk fits an envelope")
        })
        .collect();
    (digest, envelopes)
}

/// The key recovery envelopes are sealed under: `R`'s, apart from every
/// other use of it.
pub fn recovery_key(r: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(crate::hash(b"vos/personal/recovery", &[r]))
}

/// What the recovery scope's `envelopes` of the agent whose identity is
/// `agent` hold under `R`: every complete archive in them, merged (the
/// naming secret and every scope key the devices sealed there), as a kit
/// reads it once a restore released `R2`; none if no envelope opens.
pub fn open_recovery(r: &[u8; 32], agent: &[u8; 32], envelopes: &[Envelope]) -> Option<Archive> {
    let key = recovery_key(r);
    let mut reassembly = Reassembly::default();
    let mut merged: Option<Archive> = None;
    for envelope in envelopes {
        let Ok((header, body)) = sealed::open(core::slice::from_ref(&*key), agent, &envelope.bytes)
        else {
            continue;
        };
        if header.scope != RECOVERY {
            continue;
        }
        if let Some((_, archive)) = reassembly.add(envelope.position, &body) {
            match &mut merged {
                Some(merged) => merged.merge(&archive),
                None => merged = Some(archive),
            }
        }
    }
    merged
}

/// What a kit recovers at the agent whose identity is `agent` once a
/// restore of it matured: `R1` opened from the entry of the kit's signing
/// key among those the restore replaced (`view` as the restore's device
/// reads it, `R2` released beside them), `R = R1 ⊕ R2`, and the recovery
/// scope's `envelopes` opened under it; none if the kit is not among them,
/// nothing was released, or no envelope opens.
pub fn recover(
    kit: &KitSecret,
    view: &RecoveryView,
    agent: &[u8; 32],
    envelopes: &[Envelope],
) -> Option<Archive> {
    let r2 = Zeroizing::new(view.released?);
    let signing = kit.key().signing;
    let entry = view
        .previous
        .iter()
        .find(|entry| entry.signing == signing)?;
    let r1 = kit.open_r1(entry, agent)?;
    let r = kit::join(&r1, &r2);
    open_recovery(&r, agent, envelopes)
}
