//! `format::MASKED_WRAP`'s bytes: a fixed layout
//! (`vos_pvm_proof::format::ProofBytes::FixedLayout`).
//!
//! The fields in a fixed order, every integer little-endian at its width,
//! no varints; a vector whose length the proof chooses a `u32` count, then
//! its items, and one whose length the format fixes its items alone. Each
//! count is checked against the format's pin (equal) or bound (at most), and
//! against the bytes left, before anything is allocated for it; nothing
//! follows the last field. An M31 limb is a `u32` below `p`. So a proof has
//! one encoding: decode and [`encode`] are inverse on every byte string
//! decode accepts, and `encode` refuses a proof the layout cannot hold (a
//! column of other samples than the format's, a tree's queried columns of
//! unequal lengths).
//!
//! In order:
//! - the header: the format (`u32`); the log sizes (3 `u32`); the
//!   configuration: PoW bits, queries, log blowup, log last layer, fold step
//!   (`u32` each) and the lifting log size (`u32` 0 and `u32` 0 for none, 1
//!   and the size for some). Each the format's, or [`Error::Format`], the
//!   format checked first; then the interaction PoW nonce (`u64`) and the 3
//!   claimed sums (4 limbs each);
//! - the 4 commitments (32 bytes each);
//! - the sampled values: 4 trees, each its columns (pinned), each column
//!   the samples the format fixes for it ([`crate::masked::samples`]: 0, 1
//!   or 2), 4 limbs each;
//! - the 4 trees' Merkle decommitments: each its witness hashes;
//! - the queried values: 4 trees, each its columns (pinned) and one count of
//!   values a column (at most a query), then the columns' values, a limb
//!   each;
//! - the PoW nonce (`u64`);
//! - FRI's first layer, then its inner layers (their count pinned): each its
//!   witness values (4 limbs each), its Merkle witness hashes and its
//!   commitment; then the last layer's coefficients (their count pinned),
//!   as Stwo stores them (bit-reversed), 4 limbs each.
//!
//! A count over its pin or bound is [`Error::Shape`], a count the bytes
//! left cannot hold, a short read or a byte after the last field
//! [`Error::Decode`], a limb at or above `p` [`Error::Noncanonical`].

use alloc::vec::Vec;

use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo::core::fri::{FriLayerProof, FriProof};
use stwo::core::pcs::TreeVec;
use stwo::core::pcs::quotients::CommitmentSchemeProof;
use stwo::core::poly::line::LinePoly;
use stwo::core::proof::StarkProof;
use stwo::core::vcs::blake2b_hash::Blake2bHash;
use stwo::core::vcs_lifted::blake2b_merkle::Blake2bMerkleHasher;
use stwo::core::vcs_lifted::verifier::MerkleDecommitmentLifted;

use crate::masked::{CONFIG, FORMAT, FRI_ROUNDS, LOG_DEGREE_BOUND, TREES, samples};
use crate::{Error, LOG_SIZES, MAX_PROOF_BYTES, TREE_WIDTHS, WrapProof};

/// A hash's bytes.
const HASH: usize = 32;
/// An M31 limb's.
const LIMB: usize = 4;

/// The most values a queried column has: one a query.
const MAX_QUERIES: usize = CONFIG.fri_config.n_queries;
/// The tallest tree's height: FRI's degree bound under the blowup.
const HEIGHT: usize = (LOG_DEGREE_BOUND + CONFIG.fri_config.log_blowup_factor) as usize;
/// The most hashes a Merkle witness holds: a sibling a query a level.
const MAX_WITNESS_HASHES: usize = MAX_QUERIES * HEIGHT;
/// The most values a FRI layer's witness holds: the rest of each query's
/// folding coset.
const MAX_FRI_WITNESS: usize = MAX_QUERIES << CONFIG.fri_config.fold_step;
/// FRI's inner layers: its rounds after the first.
const INNER_LAYERS: usize = FRI_ROUNDS.len() - 1;
/// The last layer's coefficients.
const LAST_LAYER: usize = 1 << CONFIG.fri_config.log_last_layer_degree_bound;

/// The header after the format: the log sizes, then the configuration in the
/// layout's order, no lifting log size. `format::MASKED_WRAP`'s, word for word.
const HEADER: [u32; 10] = [
    LOG_SIZES[0],
    LOG_SIZES[1],
    LOG_SIZES[2],
    CONFIG.pow_bits,
    CONFIG.fri_config.n_queries as u32,
    CONFIG.fri_config.log_blowup_factor,
    CONFIG.fri_config.log_last_layer_degree_bound,
    CONFIG.fri_config.fold_step,
    0,
    0,
];

/// The bytes not yet read.
struct Reader<'a> {
    bytes: &'a [u8],
}

/// The limbs a basic block reads. The PVM charges a block for its loads'
/// latency and its branch whatever its width, so a block reads eight limbs,
/// their bounds checked without a branch, rather than a block a limb.
const BLOCK: usize = 8;

/// `bytes`' limbs pushed onto `out`; false with one at or above `p`.
fn read_limbs(bytes: &[[u8; LIMB]], out: &mut Vec<BaseField>) -> bool {
    let (blocks, rest) = bytes.as_chunks::<BLOCK>();
    let mut canonical = true;
    for block in blocks {
        let words = block.map(u32::from_le_bytes);
        canonical &= words.iter().fold(true, |below, &word| below & (word < P));
        out.extend(words.map(BaseField::from_u32_unchecked));
    }
    for limb in rest {
        let word = u32::from_le_bytes(*limb);
        canonical &= word < P;
        out.push(BaseField::from_u32_unchecked(word));
    }
    canonical
}

/// `bytes`' QM31s pushed onto `out`; false with a limb at or above `p`.
fn read_secures(
    bytes: &[[[u8; LIMB]; SECURE_EXTENSION_DEGREE]],
    out: &mut Vec<SecureField>,
) -> bool {
    let mut canonical = true;
    for value in bytes {
        let words = value.map(u32::from_le_bytes);
        canonical &= words.iter().fold(true, |below, &word| below & (word < P));
        out.push(SecureField::from_m31_array(
            words.map(BaseField::from_u32_unchecked),
        ));
    }
    canonical
}

fn hash_of(bytes: &[u8; HASH]) -> Blake2bHash {
    Blake2bHash(*bytes)
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let (taken, rest) = self.bytes.split_at_checked(len).ok_or(Error::Decode)?;
        self.bytes = rest;
        Ok(taken)
    }

    fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        let (taken, rest) = self.bytes.split_first_chunk::<N>().ok_or(Error::Decode)?;
        self.bytes = rest;
        Ok(taken)
    }

    fn u32(&mut self) -> Result<u32, Error> {
        self.array().map(|bytes| u32::from_le_bytes(*bytes))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        self.array().map(|bytes| u64::from_le_bytes(*bytes))
    }

    /// A count of at most `bound` items, `Shape` over it.
    fn count(&mut self, bound: usize) -> Result<usize, Error> {
        match usize::try_from(self.u32()?) {
            Ok(count) if count <= bound => Ok(count),
            _ => Err(Error::Shape("a count over its bound")),
        }
    }

    /// A count that must be `pinned`, `Shape` (`what`) otherwise.
    fn pinned(&mut self, pinned: usize, what: &'static str) -> Result<usize, Error> {
        match usize::try_from(self.u32()?) {
            Ok(count) if count == pinned => Ok(count),
            _ => Err(Error::Shape(what)),
        }
    }

    /// The bytes of `count` items of `N` bytes, refused before any
    /// allocation when the bytes left cannot hold them.
    fn items<const N: usize>(&mut self, count: usize) -> Result<&'a [[u8; N]], Error> {
        let len = count.checked_mul(N).ok_or(Error::Decode)?;
        let (items, rest) = self.take(len)?.as_chunks::<N>();
        if !rest.is_empty() {
            return Err(Error::Decode);
        }
        Ok(items)
    }

    fn secures(&mut self, count: usize) -> Result<Vec<SecureField>, Error> {
        let limbs = count
            .checked_mul(SECURE_EXTENSION_DEGREE)
            .ok_or(Error::Decode)?;
        let (values, _) = self
            .items::<LIMB>(limbs)?
            .as_chunks::<SECURE_EXTENSION_DEGREE>();
        let mut secures = Vec::with_capacity(count);
        if !read_secures(values, &mut secures) {
            return Err(Error::Noncanonical);
        }
        Ok(secures)
    }

    fn hashes(&mut self, count: usize) -> Result<Vec<Blake2bHash>, Error> {
        Ok(self.items::<HASH>(count)?.iter().map(hash_of).collect())
    }

    fn hash(&mut self) -> Result<Blake2bHash, Error> {
        self.array().map(hash_of)
    }

    fn witness(&mut self) -> Result<Vec<Blake2bHash>, Error> {
        let count = self.count(MAX_WITNESS_HASHES)?;
        self.hashes(count)
    }

    fn fri_layer(&mut self) -> Result<FriLayerProof<Blake2bMerkleHasher>, Error> {
        let count = self.count(MAX_FRI_WITNESS)?;
        let fri_witness = self.secures(count)?;
        let hash_witness = self.witness()?;
        Ok(FriLayerProof {
            fri_witness,
            decommitment: MerkleDecommitmentLifted { hash_witness },
            commitment: self.hash()?,
        })
    }

    /// Tree `tree`'s sampled values: its `width` columns (pinned), each the
    /// samples the format fixes for it.
    fn sampled_tree(&mut self, tree: usize, width: usize) -> Result<Vec<Vec<SecureField>>, Error> {
        let width = self.pinned(width, "a tree's sampled columns")?;
        let mut columns = Vec::with_capacity(width);
        for column in 0..width {
            columns.push(self.secures(samples(tree, column))?);
        }
        Ok(columns)
    }

    /// A tree's queried values: its `width` columns (pinned) and one count
    /// of values a column, at most a query each, then the columns' values.
    fn queried_tree(&mut self, width: usize) -> Result<Vec<Vec<BaseField>>, Error> {
        let width = self.pinned(width, "a tree's queried columns")?;
        let rows = self.count(MAX_QUERIES)?;
        let limbs = self.items::<LIMB>(width.checked_mul(rows).ok_or(Error::Decode)?)?;
        let mut columns = Vec::with_capacity(width);
        let mut canonical = true;
        // `rows` limbs a column; none at all when `rows` is 0, so the chunk
        // size 1 then reads nothing.
        let mut chunks = limbs.chunks_exact(rows.max(1));
        for _ in 0..width {
            let mut values = Vec::with_capacity(rows);
            if let Some(limbs) = chunks.next() {
                canonical &= read_limbs(limbs, &mut values);
            }
            columns.push(values);
        }
        if !canonical {
            return Err(Error::Noncanonical);
        }
        Ok(columns)
    }
}

/// The `format::MASKED_WRAP` proof in `bytes` (the module's layout).
pub(crate) fn decode(bytes: &[u8]) -> Result<WrapProof, Error> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(Error::Length);
    }
    let reader = &mut Reader { bytes };
    if reader.u32()? != FORMAT {
        return Err(Error::Format);
    }
    for pinned in HEADER {
        if reader.u32()? != pinned {
            return Err(Error::Format);
        }
    }
    let interaction_pow = reader.u64()?;
    let claimed_sums = reader.secures(3)?.try_into().map_err(|_| Error::Decode)?;

    let count = reader.pinned(TREES, "four commitments")?;
    let commitments = reader.hashes(count)?;
    reader.pinned(TREES, "four trees of sampled values")?;
    let mut sampled_values = Vec::with_capacity(TREES);
    for (tree, width) in TREE_WIDTHS.into_iter().enumerate() {
        sampled_values.push(reader.sampled_tree(tree, width)?);
    }
    let count = reader.pinned(TREES, "four decommitments")?;
    let mut decommitments = Vec::with_capacity(count);
    for _ in 0..count {
        decommitments.push(MerkleDecommitmentLifted {
            hash_witness: reader.witness()?,
        });
    }
    reader.pinned(TREES, "four trees of queried values")?;
    let mut queried_values = Vec::with_capacity(TREES);
    for width in TREE_WIDTHS {
        queried_values.push(reader.queried_tree(width)?);
    }
    let proof_of_work = reader.u64()?;
    let first_layer = reader.fri_layer()?;
    let count = reader.pinned(INNER_LAYERS, "FRI's inner layers")?;
    let mut inner_layers = Vec::with_capacity(count);
    for _ in 0..count {
        inner_layers.push(reader.fri_layer()?);
    }
    let count = reader.pinned(LAST_LAYER, "FRI's last layer")?;
    let last_layer_poly = LinePoly::new(reader.secures(count)?);
    if !reader.bytes.is_empty() {
        return Err(Error::Decode);
    }

    Ok(WrapProof {
        format_version: FORMAT,
        log_sizes: LOG_SIZES,
        interaction_pow,
        claimed_sums,
        stark_proof: StarkProof(CommitmentSchemeProof {
            config: CONFIG,
            commitments: TreeVec(commitments),
            sampled_values: TreeVec(sampled_values),
            decommitments: TreeVec(decommitments),
            queried_values: TreeVec(queried_values),
            proof_of_work,
            fri_proof: FriProof {
                first_layer,
                inner_layers,
                last_layer_poly,
            },
        }),
    })
}

/// The bytes written.
struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// A count: a vector longer than `u32` holds is written as `u32::MAX`,
    /// which no decode accepts.
    fn count(&mut self, count: usize) {
        self.u32(u32::try_from(count).unwrap_or(u32::MAX));
    }

    fn base(&mut self, value: &BaseField) {
        self.u32(value.0);
    }

    fn secure(&mut self, value: &SecureField) {
        for limb in value.to_m31_array() {
            self.base(&limb);
        }
    }

    fn hash(&mut self, hash: &Blake2bHash) {
        self.bytes.extend_from_slice(&hash.0);
    }

    fn hashes(&mut self, hashes: &[Blake2bHash]) {
        self.count(hashes.len());
        hashes.iter().for_each(|hash| self.hash(hash));
    }

    fn fri_layer(&mut self, layer: &FriLayerProof<Blake2bMerkleHasher>) {
        self.count(layer.fri_witness.len());
        layer
            .fri_witness
            .iter()
            .for_each(|value| self.secure(value));
        self.hashes(&layer.decommitment.hash_witness);
        self.hash(&layer.commitment);
    }
}

/// The bytes reserved for an encoding: a masked wrap's proof is about 150 KB.
const CAPACITY: usize = 160 << 10;

/// `proof` in the module's layout; `None` for a proof it cannot hold: a
/// column of other samples than the format fixes, or a tree whose queried
/// columns differ in length.
pub(crate) fn encode(proof: &WrapProof) -> Option<Vec<u8>> {
    let stark = &proof.stark_proof;
    let config = &stark.config;
    let mut writer = Writer {
        bytes: Vec::with_capacity(CAPACITY),
    };
    writer.u32(proof.format_version);
    for &log_size in &proof.log_sizes {
        writer.u32(log_size);
    }
    writer.u32(config.pow_bits);
    writer.count(config.fri_config.n_queries);
    writer.u32(config.fri_config.log_blowup_factor);
    writer.u32(config.fri_config.log_last_layer_degree_bound);
    writer.u32(config.fri_config.fold_step);
    let lifting = match config.lifting_log_size {
        None => [0, 0],
        Some(size) => [1, size],
    };
    for word in lifting {
        writer.u32(word);
    }
    writer.u64(proof.interaction_pow);
    for value in &proof.claimed_sums {
        writer.secure(value);
    }

    writer.count(stark.commitments.len());
    for hash in stark.commitments.iter() {
        writer.hash(hash);
    }
    writer.count(stark.sampled_values.len());
    for (tree, columns) in stark.sampled_values.iter().enumerate() {
        writer.count(columns.len());
        for (column, values) in columns.iter().enumerate() {
            if values.len() != samples(tree, column) {
                return None;
            }
            for value in values {
                writer.secure(value);
            }
        }
    }
    writer.count(stark.decommitments.len());
    for decommitment in stark.decommitments.iter() {
        writer.hashes(&decommitment.hash_witness);
    }
    writer.count(stark.queried_values.len());
    for columns in stark.queried_values.iter() {
        let rows = columns.first().map_or(0, Vec::len);
        if columns.iter().any(|values| values.len() != rows) {
            return None;
        }
        writer.count(columns.len());
        writer.count(rows);
        for value in columns.iter().flatten() {
            writer.base(value);
        }
    }
    writer.u64(stark.proof_of_work);
    let fri = &stark.fri_proof;
    writer.fri_layer(&fri.first_layer);
    writer.count(fri.inner_layers.len());
    for layer in &fri.inner_layers {
        writer.fri_layer(layer);
    }
    writer.count(fri.last_layer_poly.iter().count());
    for value in fri.last_layer_poly.iter() {
        writer.secure(value);
    }
    Some(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::masked::FORMAT;

    fn encode_ok(proof: &WrapProof) -> Vec<u8> {
        encode(proof).expect("the layout holds it")
    }

    /// A change to a proof.
    type Change = fn(&mut WrapProof);
    /// A change setting a limb.
    type SetLimb = fn(&mut WrapProof, BaseField);

    /// A proof of the masked wrap's header and shape, its every vector the
    /// least its pins allow: each column one sample and one queried value, each
    /// witness empty or of one item. Small, so every byte of it can be cut.
    fn smallest() -> WrapProof {
        let value = |i: u32| SecureField::from_u32_unchecked(i, i + 1, i + 2, i + 3);
        let hash = |i: u8| Blake2bHash([i; 32]);
        let layer = |i: u8| FriLayerProof {
            fri_witness: alloc::vec![value(u32::from(i))],
            decommitment: MerkleDecommitmentLifted {
                hash_witness: alloc::vec![hash(i)],
            },
            commitment: hash(i + 1),
        };
        WrapProof {
            format_version: FORMAT,
            log_sizes: LOG_SIZES,
            interaction_pow: 0x0102_0304_0506_0708,
            claimed_sums: [value(1), value(2), value(3)],
            stark_proof: StarkProof(CommitmentSchemeProof {
                config: CONFIG,
                commitments: TreeVec((0..4).map(hash).collect()),
                sampled_values: TreeVec(
                    TREE_WIDTHS
                        .iter()
                        .enumerate()
                        .map(|(tree, &width)| {
                            (0..width)
                                .map(|i| alloc::vec![value(i as u32); samples(tree, i)])
                                .collect()
                        })
                        .collect(),
                ),
                decommitments: TreeVec(
                    (0..4)
                        .map(|i| MerkleDecommitmentLifted {
                            hash_witness: alloc::vec![hash(i); usize::from(i)],
                        })
                        .collect(),
                ),
                queried_values: TreeVec(
                    TREE_WIDTHS
                        .iter()
                        .map(|&width| {
                            (0..width as u32)
                                .map(|i| alloc::vec![BaseField::from(i)])
                                .collect()
                        })
                        .collect(),
                ),
                proof_of_work: 77,
                fri_proof: FriProof {
                    first_layer: layer(10),
                    inner_layers: (11..14).map(layer).collect(),
                    last_layer_poly: LinePoly::new((0..64).map(value).collect()),
                },
            }),
        }
    }

    fn assert_decode_err(bytes: &[u8], expected: fn(&Error) -> bool, what: &str) {
        match decode(bytes) {
            Ok(_) => panic!("{what}: decoded"),
            Err(error) => assert!(expected(&error), "{what}: {error}"),
        }
    }

    /// Decode and encode are inverse: the bytes re-encode to themselves.
    #[test]
    fn the_layout_round_trips() {
        let bytes = encode_ok(&smallest());
        let decoded = decode(&bytes).unwrap();
        assert_eq!(encode_ok(&decoded), bytes);
        assert_eq!(decoded.stark_proof.config, CONFIG);
    }

    /// Every truncation is refused as undecodable, and so is any byte after
    /// the last field.
    #[test]
    fn every_truncation_and_trailing_byte_is_refused() {
        let bytes = encode_ok(&smallest());
        for len in 0..bytes.len() {
            assert_decode_err(
                &bytes[..len],
                |error| matches!(error, Error::Decode),
                "a truncation",
            );
        }
        for byte in [0, 1, 0xff] {
            let mut longer = bytes.clone();
            longer.push(byte);
            assert_decode_err(
                &longer,
                |error| matches!(error, Error::Decode),
                "a trailing byte",
            );
        }
        let mut long = bytes;
        long.resize(MAX_PROOF_BYTES + 1, 0);
        assert_decode_err(&long, |error| matches!(error, Error::Length), "too long");
    }

    /// The header is the format's: its number, its log sizes and every
    /// field of its configuration, or the proof is of another format.
    #[test]
    fn another_header_is_another_format() {
        let base = smallest();
        let cases: [(&str, Change); 8] = [
            ("the format", |p| p.format_version = 28),
            ("a log size", |p| p.log_sizes[1] = 16),
            ("the PoW bits", |p| p.stark_proof.0.config.pow_bits = 20),
            ("the queries", |p| {
                p.stark_proof.0.config.fri_config.n_queries = 23
            }),
            ("the blowup", |p| {
                p.stark_proof.0.config.fri_config.log_blowup_factor = 6
            }),
            ("the last layer", |p| {
                p.stark_proof
                    .0
                    .config
                    .fri_config
                    .log_last_layer_degree_bound = 5
            }),
            ("the fold step", |p| {
                p.stark_proof.0.config.fri_config.fold_step = 2
            }),
            ("a lifting log size", |p| {
                p.stark_proof.0.config.lifting_log_size = Some(22)
            }),
        ];
        for (what, change) in cases {
            let mut proof = base.clone();
            change(&mut proof);
            assert_decode_err(
                &encode_ok(&proof),
                |error| matches!(error, Error::Format),
                what,
            );
        }
        let mut bytes = encode_ok(&base);
        // The lifting words other than none's.
        bytes[36] = 2;
        assert_decode_err(
            &bytes,
            |error| matches!(error, Error::Format),
            "a lifting flag",
        );
    }

    /// Every count is its pin or within its bound, else the shape is
    /// refused, before anything is allocated for it.
    #[test]
    fn every_count_is_pinned_or_bounded() {
        let base = smallest();
        let cases: [(&str, Change); 11] = [
            ("a commitment more", |p| {
                p.stark_proof.0.commitments.push(Blake2bHash::default())
            }),
            ("a tree of samples fewer", |p| {
                p.stark_proof.0.sampled_values.pop();
            }),
            ("a sampled column fewer", |p| {
                p.stark_proof.0.sampled_values[1].pop();
            }),
            ("a salt's column more", |p| {
                p.stark_proof.0.sampled_values[3].push(Vec::new())
            }),
            ("a decommitment fewer", |p| {
                p.stark_proof.0.decommitments.pop();
            }),
            ("a Merkle witness too long", |p| {
                p.stark_proof.0.decommitments[0].hash_witness =
                    alloc::vec![Blake2bHash::default(); MAX_WITNESS_HASHES + 1]
            }),
            ("a queried column fewer", |p| {
                p.stark_proof.0.queried_values[3].pop();
            }),
            ("a value a query too many", |p| {
                for column in &mut p.stark_proof.0.queried_values[0] {
                    column.push(BaseField::default());
                    column.resize(25, BaseField::default());
                }
            }),
            ("an inner layer more", |p| {
                let extra = p.stark_proof.0.fri_proof.inner_layers[0].clone();
                p.stark_proof.0.fri_proof.inner_layers.push(extra)
            }),
            ("a FRI witness too long", |p| {
                p.stark_proof.0.fri_proof.first_layer.fri_witness =
                    alloc::vec![SecureField::default(); MAX_FRI_WITNESS + 1]
            }),
            ("a last layer of 32", |p| {
                p.stark_proof.0.fri_proof.last_layer_poly =
                    LinePoly::new(alloc::vec![SecureField::default(); 32])
            }),
        ];
        for (what, change) in cases {
            let mut proof = base.clone();
            change(&mut proof);
            assert_decode_err(
                &encode_ok(&proof),
                |error| matches!(error, Error::Shape(_)),
                what,
            );
        }
        // A count no bytes follow: refused before its items are allocated.
        let mut bytes = encode_ok(&base);
        let at = 4 * (1 + 3 + 7) + 8 + 3 * LIMB * SECURE_EXTENSION_DEGREE;
        bytes.truncate(at + 4 + TREES * HASH + 4);
        bytes.extend_from_slice(&(TREE_WIDTHS[0] as u32).to_le_bytes());
        assert_decode_err(
            &bytes,
            |error| matches!(error, Error::Decode),
            "a count unbacked",
        );
    }

    /// A limb at or above `p` is refused, so no value has two encodings.
    #[test]
    fn a_noncanonical_limb_is_refused() {
        let base = smallest();
        let p = BaseField::from_u32_unchecked(P);
        let cases: [(&str, SetLimb); 5] = [
            ("a claimed sum", |w, p| {
                w.claimed_sums[0] = SecureField::from_m31_array([p; 4])
            }),
            ("a sampled value", |w, p| {
                w.stark_proof.0.sampled_values[1][1][0] = SecureField::from_m31_array([p; 4])
            }),
            ("a queried value", |w, p| {
                w.stark_proof.0.queried_values[2][0][0] = p
            }),
            ("a FRI witness value", |w, p| {
                w.stark_proof.0.fri_proof.inner_layers[1].fri_witness[0] =
                    SecureField::from_m31_array([p; 4])
            }),
            ("a last-layer coefficient", |w, p| {
                w.stark_proof.0.fri_proof.last_layer_poly[5] = SecureField::from_m31_array([p; 4])
            }),
        ];
        for (what, change) in cases {
            let mut proof = base.clone();
            change(&mut proof, p);
            assert_decode_err(
                &encode_ok(&proof),
                |error| matches!(error, Error::Noncanonical),
                what,
            );
        }
    }

    /// The layout holds no column of other samples than the format fixes
    /// and no tree of queried columns of unequal lengths: `encode` refuses
    /// them, and no decode produces them.
    #[test]
    fn encode_refuses_what_the_layout_cannot_hold() {
        let base = smallest();
        let cases: [(&str, Change); 3] = [
            ("a sample more", |p| {
                p.stark_proof.0.sampled_values[2][0].push(SecureField::default())
            }),
            ("a salt sampled", |p| {
                p.stark_proof.0.sampled_values[1][380].push(SecureField::default())
            }),
            ("a queried column longer", |p| {
                p.stark_proof.0.queried_values[1][7].push(BaseField::default())
            }),
        ];
        for (what, change) in cases {
            let mut proof = base.clone();
            change(&mut proof);
            assert!(encode(&proof).is_none(), "{what}");
        }
    }
}
