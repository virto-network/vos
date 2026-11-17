//! The proof format registry: the entries' plain data, defined once in
//! `vos_pvm_recair_air::format` (which the final verifier reads too) and
//! re-exported here, and each entry's security count at its reference shape
//! ([`COUNTS`]).
//!
//! A proof's `format_version` names an entry here, and the entry decides, at
//! run time, the proof's channel, its parameters and its encodings: one
//! verifier build reads every admitted format, and a prover is told which
//! format to produce.
//!
//! | number | proofs | channel | log blowup, queries, PoW, fold step, last layer, interaction PoW | floors | at its reference shape |
//! |---|---|---|---|---|---|
//! | 32 | leaves and folds | Poseidon2-M31 | 2, 44, 20, 1, 0, 8 | 100 / 60 | 108 / 63 |
//! | 39 | the final wrap, masked | Blake2b-256 | 5, 24, 26, 3, 6, 8, affine DEEP batching | 100 / 80 | 146 / 82 |
//! | 41 | segments | Poseidon2-M31 | 2, 40, 24, 1, 0, 8 | 100 / 60 | 104 / 62 |
//! | 47 | device proofs, masked, the per-program CPU and the word ledger | Blake2s-M31 | 2, 47, 16, 1, 0, 8, affine DEEP batching | 100 / 60 | 110 / 62 |
//!
//! - **The segment AIR** is the one every segment, leaf and device format
//!   names: 41 and 47 name its current form, one chip set the node's
//!   segments and the device shape share (the CPU acknowledging the
//!   Poseidon2 call, the Poseidon2 chip, the logical right shifts through
//!   the multiplication, no column a constraint pins to zero), and 32's
//!   leaves verify it. 32 and 39 prove the recursion AIR
//!   (`vos-pvm-recair-air`). A number not in [`REGISTRY`] is refused as
//!   unregistered, and 28, 44 and 46 as retired ([`RETIRED`]), never
//!   reused; 48 is the tests' second
//!   device format (`vos-pvm-recair`'s `device::TEST_FORMAT`), never
//!   registered.
//! - **Every format** takes exactly its parameters, mixes the boundary
//!   states as the boundary chips' bytes and grinds its interaction PoW
//!   before the relation challenges. 47 is the device format: a space's
//!   ingress verifies device proofs against the program it computes from
//!   the installed kernel (`vos-pvm-recair`'s `device`), its CPU the
//!   program's columns (`chips::CpuColumns::of_code`) and its memory ledger a row a
//!   word (`chips::WordMemoryChip`). 46 is retired and never reused: its
//!   ledger of a row a byte does not keep a byte one group, so its memory
//!   argument is unsound. 32 is internal
//!   ([`Status::Internal`]), registered and refused: `vos-pvm-recair` proves
//!   and verifies its proofs natively, pinning each circuit by its hash, and no verifier
//!   outside the recursion reads a leaf or a fold. 39 is admitted: the
//!   masked wrap, `vos-pvm-recair`'s masked prover on the fork's Blake2b-256
//!   channel and `vos-pvm-final-verifier`'s masked verifier, fold step 3
//!   reviewed in the fork, its bytes a fixed layout
//!   ([`ProofBytes::FixedLayout`]); it is the one final format. A segment
//!   verifier takes only a segment format ([`admitted_segment`]).
//! - **The inner formats** grind 8 bits of interaction PoW. Segments (41)
//!   take 40 queries and 24 bits of PoW: 62.81 proven bits on 41's own
//!   reference (every chip, the Poseidon2 chip among them, at 2^20 rows),
//!   the query term binding, and 104 conjectured. A kernel leaf's rows grow
//!   with the segment's width times its queries, and 4 fewer queries keep
//!   the leaf's `p2` under 2^16 with room. Leaves and folds (32) take 44
//!   queries and 20 bits: a fold verifies under half the recursion AIR's
//!   shape.
//! - **The device format** (47) is counted on the device shape's masked
//!   reference ([`DEVICE_REFERENCE`]: every chip a device program may hold,
//!   the full CPU among them, at `2^17` rows, the most install, the prover
//!   and the verifier admit); a per-program CPU's cut drops columns and
//!   constraints, which only raises the count. It takes blowup 4, 47
//!   queries, PoW 16 and affine batching (62.82
//!   proven bits): at a small program's shape every blowup costs the same
//!   cells, and PoW 16's grind keeps a short tail on a phone; with `h = 256`
//!   (`proving.md` §5, how large `h` must be): every device chip reveals at
//!   most 149 rows at 47 queries, so `h = 256` holds the masking's
//!   condition without its factor two, every chip's floor at 2^10 rows.
//!   The candidates measured are in `proving.md` §4.
//! - **The wrap** (39) is the recursion AIR under masking variant (c)
//!   (`proving.md` §5; [`crate::security`] counts it): every main and
//!   interaction column masked to twice its rows' degree, the preprocessed
//!   ones left as they are, the composition committed whole at four times the
//!   tallest component's rows and sampled at `π(z)`, R2's blinding, a FRI mask
//!   of eight columns and salted trees. Its FRI runs at blowup 32 with 24
//!   queries: 146 / 82 (82.70), the query term binding; 23 queries is the
//!   least that clears 80 (80.84). Blowup 64 at 20 queries counts 81.74, its
//!   DEEP batching term binding, at twice the prover's memory. It needs DEEP
//!   batching with an independent coefficient a sampled value
//!   ([`DeepBatching::Affine`]) for its proven 80: Stwo batches by powers of
//!   one coefficient, whose error is the batched values' count times a
//!   proximity-gap error that grows with the blowup, and batched by powers
//!   it caps at 76.98 at blowup 32 and 74.48 at blowup 64. The fork batches
//!   affinely when a configuration asks ([`FormatParams::batching`]).
//!   Batching is not in a proof's bytes: a verifier sets it from the format
//!   ([`Format::verifier_config`]). Its proofs are a fixed layout
//!   ([`ProofBytes::FixedLayout`]).
//! - **[`Format::masking`]** says what a format's proofs are: masking a
//!   format's proofs is a format change. A masked format pins its masking
//!   ([`Masking`]): its salt and FRI-mask columns and its randomizer's size,
//!   which a prover and a verifier take from the format, never from a
//!   proof.
//! - **The bit counts** ([`COUNTS`]) are [`crate::security`]'s, at each
//!   entry's reference shape. The segment's and the recursion's verifiers count again at the
//!   proof's own shape and refuse a proof below either floor; the masked
//!   formats' (39, 47) do not: their shapes are pinned at or under the
//!   reference shape (a fixed layout, a device program's log sizes at most
//!   `DEVICE_MAX_LOG_SIZE`), and every term of
//!   the count is monotone in the shape, so the reference's count bounds
//!   every proof's.

pub use vos_pvm_recair_air::format::*;

use crate::security::{SecurityBits, SecurityShape};

mod reference;

pub use reference::{
    DEVICE_REFERENCE, LEAF_FOLD_REFERENCE, MASKED_WRAP_REFERENCE, SEGMENT_REFERENCE,
};

/// A registered format's security count: the shape it is counted at, and
/// [`crate::security::security_bits`] there, pinned by the format tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Count {
    /// The format's number.
    pub number: u32,
    /// The shape [`Count::bits`] is counted at.
    pub reference: SecurityShape,
    pub bits: SecurityBits,
}

impl Count {
    /// Whether the count clears both of `floor`'s.
    pub const fn meets(&self, floor: &SecurityFloor) -> bool {
        self.bits.conjectured >= floor.conjectured && self.bits.proven >= floor.proven
    }
}

/// Every registered format's count, in [`REGISTRY`]'s order.
pub const COUNTS: [Count; 4] = [
    Count {
        number: LEAF_FOLD.number,
        reference: LEAF_FOLD_REFERENCE,
        bits: SecurityBits {
            conjectured: 108,
            proven: 63,
        },
    },
    Count {
        number: MASKED_WRAP.number,
        reference: MASKED_WRAP_REFERENCE,
        bits: SecurityBits {
            conjectured: 146,
            proven: 82,
        },
    },
    Count {
        number: SEGMENT.number,
        reference: SEGMENT_REFERENCE,
        bits: SecurityBits {
            conjectured: 104,
            proven: 62,
        },
    },
    Count {
        number: DEVICE_PROOF.number,
        reference: DEVICE_REFERENCE,
        bits: SecurityBits {
            conjectured: 110,
            proven: 62,
        },
    },
];

/// `format`'s count; `None` for a format the registry does not hold.
pub fn count(format: &Format) -> Option<&'static Count> {
    COUNTS.iter().find(|count| count.number == format.number)
}

#[cfg(test)]
mod masked_tests;

#[cfg(test)]
mod tests;
