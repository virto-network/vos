//! A settlement window over witnessed rows: each pseudo-account's row at
//! both anchors, checked against the anchors' committed-map roots by a
//! vos-tree multiproof each, hashing at the compress level, then
//! `cipher_clerk::settlement::window` over the rows the proofs open.
//!
//! The tree's format is `vos_tree`'s (its crate documentation): a key's
//! row is keyed `H128(key) ‖ escape(key)`, a leaf commits
//! `H("vos/tree/value" ‖ salt ‖ value)`, and a [`BatchProof`]'s entries
//! are a pruned tree in pre-order. Every node here fits one or two BLAKE2b
//! blocks, which this crate fills itself and hands to the compression
//! precompile, rather than streaming them through `blake2b_hash`.
//!
//! [`BatchProof`]: https://docs.rs/vos-tree
//!
//! Only rows present at both anchors are supported: a pseudo-account
//! absent at the first anchor needs an absence claim, which this kernel
//! refuses.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use cipher_clerk::codec::{self, Codec};
use cipher_clerk::kernel::Value;
use cipher_clerk::settlement::{Anchor, NetFlow, Reads, window};
use cipher_clerk::types::Account;
use vos_pvm_precompiles::blake2b_compress;

/// The rows or a proof do not decode.
pub const MALFORMED: u8 = 1;
/// The rows are not in strictly increasing key order.
pub const UNORDERED: u8 = 2;
/// A row is absent at the first anchor, which this kernel cannot show.
pub const ABSENT: u8 = 3;
/// The proof at the first anchor refuses the rows.
pub const REFUSED_I: u8 = 4;
/// The proof at the second anchor refuses the rows.
pub const REFUSED_J: u8 = 5;
/// `window` refused the rows: this plus its error's index.
pub const WINDOW: u8 = 16;

const TAG_KEY: &[u8] = b"vos/tree/key";
const TAG_LEAF: &[u8] = b"vos/tree/leaf";
const TAG_VALUE: &[u8] = b"vos/tree/value";
const TAG_EMPTY: &[u8] = b"vos/tree/empty";
const MAX_KEY: usize = 8192;

/// "vos/tree", the first word of every tag.
const VOS_TREE: u64 = u64::from_le_bytes(*b"vos/tree");
/// "/branch", the rest of a branch's tag, in its block's second word.
const SLASH_BRANCH: u64 = u64::from_le_bytes([b'/', b'b', b'r', b'a', b'n', b'c', b'h', 0]);
/// "/leaf", the rest of a leaf's tag, in its block's second word.
const SLASH_LEAF: u64 = u64::from_le_bytes([b'/', b'l', b'e', b'a', b'f', 0, 0, 0]);

const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

/// BLAKE2b's state before the first block of an unkeyed 32-byte digest.
const H0: [u64; 8] = {
    let mut h = IV;
    h[0] ^= 0x0101_0020;
    h
};

/// A digest as its four little-endian words. Word arrays are aligned, so
/// they move in loads and stores of whole words, where a byte array on the
/// guest target, which has no misaligned access, takes a `memcpy`.
pub type Digest = [u64; 4];

/// One compression of `block` into `h`, through the precompile.
#[inline(always)]
fn compress(h: &mut [u64; 8], block: &[u64; 16], counter: usize, last: bool) {
    // SAFETY: the bytes of word arrays, little-endian on the PVM and on
    // every host this builds for, as BLAKE2b reads its words.
    let (h, block) = unsafe {
        (
            &mut *(h as *mut [u64; 8] as *mut [u8; 64]),
            &*(block as *const [u64; 16] as *const [u8; 128]),
        )
    };
    blake2b_compress(h, block, counter as u128, last);
}

/// BLAKE2b-256 of the first `len` bytes of `message`: whole blocks, zero
/// past `len`, one compression each.
#[inline(always)]
fn digest<const W: usize>(message: &[u64; W], len: usize) -> Digest {
    let mut h = H0;
    let blocks = len.div_ceil(128).max(1);
    for b in 0..blocks {
        let last = b + 1 == blocks;
        let block: &[u64; 16] = message[b * 16..b * 16 + 16].try_into().unwrap();
        compress(&mut h, block, if last { len } else { (b + 1) * 128 }, last);
    }
    [h[0], h[1], h[2], h[3]]
}

fn bytes_mut<const W: usize>(words: &mut [u64; W]) -> &mut [u8] {
    // SAFETY: a word array's own bytes.
    unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), W * 8) }
}

/// The digest's 32 bytes.
pub fn to_bytes(digest: &Digest) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, word) in out.chunks_exact_mut(8).zip(digest) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// The digest of 32 bytes.
pub fn of_bytes(bytes: &[u8]) -> Digest {
    let word = |k: usize| u64::from_le_bytes(bytes[k * 8..k * 8 + 8].try_into().unwrap());
    [word(0), word(1), word(2), word(3)]
}

/// BLAKE2b-256 of `tag ‖ parts…`, laid into a word buffer of up to two
/// blocks, longer messages streamed.
fn hash(tag: &[u8], parts: &[&[u8]]) -> Digest {
    let len = tag.len() + parts.iter().map(|part| part.len()).sum::<usize>();
    if len > 256 {
        return of_bytes(&vos_pvm_precompiles::blake2b_hash::<32>(tag, parts));
    }
    let mut message = [0u64; 32];
    let bytes = bytes_mut(&mut message);
    bytes[..tag.len()].copy_from_slice(tag);
    let mut at = tag.len();
    for part in parts {
        bytes[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    digest(&message, len)
}

/// A branch's hash at `level` over its children's, its block assembled
/// word by word: the tag's 15 bytes, the level's 2, then the children's
/// 32 each, from byte 17 on.
pub fn branch_hash(level: u16, left: &Digest, right: &Digest) -> Digest {
    let [high, low] = level.to_be_bytes();
    let block: [u64; 16] = [
        VOS_TREE,
        SLASH_BRANCH | (u64::from(high) << 56),
        u64::from(low) | (left[0] << 8),
        (left[0] >> 56) | (left[1] << 8),
        (left[1] >> 56) | (left[2] << 8),
        (left[2] >> 56) | (left[3] << 8),
        (left[3] >> 56) | (right[0] << 8),
        (right[0] >> 56) | (right[1] << 8),
        (right[1] >> 56) | (right[2] << 8),
        (right[2] >> 56) | (right[3] << 8),
        right[3] >> 56,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut h = H0;
    compress(&mut h, &block, 81, true);
    [h[0], h[1], h[2], h[3]]
}

/// A leaf's hash: the tag's 13 bytes, the key's length as 2, the key,
/// then its value's commitment, shifted into place word by word.
pub fn leaf_hash(key: &[u8], value: &Digest) -> Digest {
    let len = 15 + key.len() + 32;
    if len > 256 {
        let length = (key.len() as u16).to_be_bytes();
        return hash(TAG_LEAF, &[&length, key, &to_bytes(value)]);
    }
    let [high, low] = (key.len() as u16).to_be_bytes();
    let mut message = [0u64; 32];
    message[0] = VOS_TREE;
    message[1] = SLASH_LEAF | (u64::from(high) << 40) | (u64::from(low) << 48);
    bytes_mut(&mut message)[15..15 + key.len()].copy_from_slice(key);
    let at = 15 + key.len();
    let (word, shift) = (at / 8, (at % 8) * 8);
    for (k, part) in value.iter().enumerate() {
        if shift == 0 {
            message[word + k] = *part;
        } else {
            message[word + k] |= part << shift;
            message[word + k + 1] |= part >> (64 - shift);
        }
    }
    digest(&message, len)
}

/// A value's commitment under its salt.
pub fn value_hash(salt: &[u8; 16], value: &[u8]) -> Digest {
    hash(TAG_VALUE, &[salt, value])
}

/// `key` under the hashed transform: `H128(key) ‖ escape(key)`.
pub fn hashed_key(key: &[u8]) -> Vec<u8> {
    let digest = hash(TAG_KEY, &[key]);
    let mut out = Vec::with_capacity(16 + 2 * key.len() + 2);
    out.extend_from_slice(&digest[0].to_le_bytes());
    out.extend_from_slice(&digest[1].to_le_bytes());
    for &byte in key {
        if byte == 0 {
            out.extend_from_slice(&[0, 0xFF]);
        } else {
            out.push(byte);
        }
    }
    out.extend_from_slice(&[0, 0]);
    out
}

/// Bit `level` of `key`, most significant first within each byte.
fn bit(key: &[u8], level: u16) -> u8 {
    let level = usize::from(level);
    (key[level / 8] >> (7 - level % 8)) & 1
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn digest(&mut self) -> Option<Digest> {
        Some(of_bytes(self.take(32)?))
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

/// A branch whose children are being read.
struct Open {
    left: Digest,
    level: u16,
    side: u8,
    left_closed: bool,
}

/// Check a vos-tree batch proof, as its SCALE encoding, against `root` for
/// `claims`: keys in strictly increasing order, each present with its
/// value's commitment. The proof's opened leaves must be exactly the
/// claims, which a batch proof of present keys opens.
pub fn verify(proof: &[u8], root: &[u8; 32], claims: &[(&[u8], [u8; 32])]) -> bool {
    let claims: Vec<(&[u8], Digest)> = claims
        .iter()
        .map(|(key, commitment)| (*key, of_bytes(commitment)))
        .collect();
    verify_words(proof, &of_bytes(root), &claims)
}

fn verify_words(proof: &[u8], root: &Digest, claims: &[(&[u8], Digest)]) -> bool {
    verified(proof, root, claims).unwrap_or(false)
}

fn verified(proof: &[u8], root: &Digest, claims: &[(&[u8], Digest)]) -> Option<bool> {
    let mut reader = Reader(proof);
    let count = reader.u32()?;
    let mut open: Vec<Open> = Vec::with_capacity(64);
    let mut claim = 0;
    let mut last: Option<&[u8]> = None;
    let mut top: Option<Digest> = None;
    for _ in 0..count {
        if top.is_some() {
            return Some(false);
        }
        let (mut node, mut closed) = match reader.u8()? {
            0 => {
                let level = reader.u16()?;
                if open.last().is_some_and(|parent| level <= parent.level) {
                    return Some(false);
                }
                open.push(Open {
                    left: [0; 4],
                    level,
                    side: 0,
                    left_closed: false,
                });
                continue;
            }
            1 => (reader.digest()?, true),
            2 => {
                let key = reader.bytes()?;
                let value = reader.digest()?;
                let placed = open.iter().all(|branch| {
                    usize::from(branch.level) < key.len() * 8
                        && bit(key, branch.level) == branch.side
                });
                if key.is_empty()
                    || key.len() > MAX_KEY
                    || !placed
                    || last.is_some_and(|last| last >= key)
                {
                    return Some(false);
                }
                last = Some(key);
                match claims.get(claim) {
                    Some((claimed, commitment)) if *claimed == key && *commitment == value => {}
                    _ => return Some(false),
                }
                claim += 1;
                (leaf_hash(key, &value), false)
            }
            3 if count == 1 && claims.is_empty() => (hash(TAG_EMPTY, &[]), false),
            _ => return Some(false),
        };
        loop {
            match open.last_mut() {
                None => {
                    top = Some(node);
                    break;
                }
                Some(branch) if branch.side == 0 => {
                    branch.left = node;
                    branch.left_closed = closed;
                    branch.side = 1;
                    break;
                }
                Some(branch) => {
                    // A canonical proof closes a branch it does not open.
                    if branch.left_closed && closed {
                        return Some(false);
                    }
                    node = branch_hash(branch.level, &branch.left, &node);
                    closed = false;
                    open.pop();
                }
            }
        }
    }
    Some(reader.0.is_empty() && open.is_empty() && top == Some(*root) && claim == claims.len())
}

/// One pseudo-account's witnessed row: its value bytes (cipher-clerk's
/// encoding of the account) and leaf salt at the second anchor, and at
/// the first when present.
pub struct WitnessRow<'a> {
    pub salt_j: [u8; 16],
    pub value_j: &'a [u8],
    pub at_i: Option<([u8; 16], &'a [u8])>,
}

/// The rows' encoding the kernel takes: a `u32` count, then per row its
/// salt and `u16`-prefixed value at the second anchor, a presence byte,
/// and its salt and value at the first.
pub fn encode_rows(rows: &[WitnessRow<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    let put = |out: &mut Vec<u8>, salt: &[u8; 16], value: &[u8]| {
        out.extend_from_slice(salt);
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
    };
    for row in rows {
        put(&mut out, &row.salt_j, row.value_j);
        match row.at_i {
            None => out.push(0),
            Some((salt, value)) => {
                out.push(1);
                put(&mut out, &salt, value);
            }
        }
    }
    out
}

struct Row {
    key: Vec<u8>,
    at_j: Account<Value>,
    commitment_j: Digest,
    at_i: Option<(Account<Value>, Digest)>,
}

fn read_value(reader: &mut Reader<'_>) -> Option<(Account<Value>, Digest)> {
    let salt = reader.array::<16>()?;
    let len = reader.u16()? as usize;
    let bytes = reader.take(len)?;
    let account = codec::from_bytes::<Account<Value>>(bytes)?;
    Some((account, value_hash(&salt, bytes)))
}

fn read_rows(bytes: &[u8]) -> Option<Vec<Row>> {
    let mut reader = Reader(bytes);
    let count = reader.u32()? as usize;
    let mut rows = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let (at_j, commitment_j) = read_value(&mut reader)?;
        let at_i = match reader.u8()? {
            0 => None,
            1 => Some(read_value(&mut reader)?),
            _ => return None,
        };
        rows.push(Row {
            key: hashed_key(&at_j.id.0),
            at_j,
            commitment_j,
            at_i,
        });
    }
    reader.0.is_empty().then_some(rows)
}

/// The window statement over witnessed rows, or why there is none.
#[allow(clippy::too_many_arguments)]
pub fn statement(
    space: [u8; 32],
    window_i: u64,
    root_i: [u8; 32],
    window_j: u64,
    root_j: [u8; 32],
    rows: &[u8],
    proof_i: &[u8],
    proof_j: &[u8],
) -> Result<NetFlow, u8> {
    let rows = read_rows(rows).ok_or(MALFORMED)?;
    if !rows.windows(2).all(|pair| pair[0].key < pair[1].key) {
        return Err(UNORDERED);
    }
    let mut claims_i = Vec::with_capacity(rows.len());
    let mut claims_j = Vec::with_capacity(rows.len());
    for row in &rows {
        let (_, commitment_i) = row.at_i.as_ref().ok_or(ABSENT)?;
        claims_i.push((row.key.as_slice(), *commitment_i));
        claims_j.push((row.key.as_slice(), row.commitment_j));
    }
    if !verify_words(proof_i, &of_bytes(&root_i), &claims_i) {
        return Err(REFUSED_I);
    }
    if !verify_words(proof_j, &of_bytes(&root_j), &claims_j) {
        return Err(REFUSED_J);
    }
    drop((claims_i, claims_j));
    let reads: Vec<Reads> = rows
        .into_iter()
        .map(|row| Reads {
            at_i: row.at_i.map(|(account, _)| account),
            at_j: row.at_j,
        })
        .collect();
    window(
        space,
        Anchor {
            window: window_i,
            root: root_i,
        },
        Anchor {
            window: window_j,
            root: root_j,
        },
        &reads,
    )
    .map_err(|error| WINDOW + error as u8)
}

/// The kernel's output: a status byte, then on success (`0`) the
/// statement's encoding.
#[allow(clippy::too_many_arguments)]
pub fn settle(
    space: [u8; 32],
    window_i: u64,
    root_i: [u8; 32],
    window_j: u64,
    root_j: [u8; 32],
    rows: &[u8],
    proof_i: &[u8],
    proof_j: &[u8],
) -> Vec<u8> {
    match statement(
        space, window_i, root_i, window_j, root_j, rows, proof_i, proof_j,
    ) {
        Ok(flow) => {
            let mut out = vec![0];
            flow.encode(&mut out);
            out
        }
        Err(status) => vec![status],
    }
}
