//! Each format's reference shape: the shape its bit counts are taken at.

use crate::security::SecurityShape;

/// Every segment AIR's widest relation (`Blake2bCompression`, 265 limbs),
/// rounded up.
pub(super) const SEGMENT_RELATION_WIDTH: u64 = 265;
/// The recursion AIR's one relation, `Gate`: an address and four limbs.
const RECURSION_RELATION_WIDTH: u64 = 5;

/// Every chip of the segment AIR at 2^20 rows (`framework_access`'s
/// `security_shape` of the full component set; a test recomputes it).
pub const SEGMENT_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 20,
    log_trace_length: 20,
    log_composition_degree_bound: 21,
    sampled_values: 11_091,
    max_samples_per_column: 3,
    constraints: 5_750,
    logup_fractions: 1_837_105_152,
    relation_width: SEGMENT_RELATION_WIDTH,
    composition_point_doublings: 0,
};

/// The device format's reference, format 47's: the device set
/// (`vos_pvm_proof::device`) with every chip a device program may hold, the
/// full CPU among them, at `2^17` rows (`device::DEVICE_MAX_LOG_SIZE`, which
/// install enforces), masked under variant (c): its columns at degree bound
/// 2^18, the composition whole at 2^19, sampled at `π(z)`; 7,470 values in
/// the DEEP batch, 4,309 constraints, every fraction a masked row evaluates
/// (the blinding's among them), the widest relation's 265 limbs. A
/// per-program CPU's cut has fewer of both. A test in `vos-pvm-recair`
/// derives it from the built set.
pub const DEVICE_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 19,
    log_trace_length: 18,
    log_composition_degree_bound: 19,
    sampled_values: 7_470,
    max_samples_per_column: 3,
    constraints: 4_309,
    logup_fractions: 156_106_752,
    relation_width: SEGMENT_RELATION_WIDTH,
    composition_point_doublings: 1,
};

/// The recursion AIR's padded shape (`recursion-air.md` §0, §1.2): `p2`,
/// `qm31` and `h8` at 2^16, 2^17 and 2^16 rows; 458 columns, each counted at
/// two DEEP values (an upper bound: the batch holds 486), a column at most
/// three; 313 constraints of degree 3; 5, 4 and 6 fractions a row.
pub const LEAF_FOLD_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 18,
    log_trace_length: 17,
    log_composition_degree_bound: 19,
    sampled_values: 2 * 458,
    max_samples_per_column: 3,
    constraints: 313,
    logup_fractions: (5 << 16) + (4 << 17) + (6 << 16),
    relation_width: RECURSION_RELATION_WIDTH,
    composition_point_doublings: 0,
};

/// The wrap (`recursion-air.md` §7): the same AIR at 2^14, 2^15 and 2^11
/// rows.
pub(crate) const WRAP_REFERENCE: SecurityShape = SecurityShape {
    log_degree_bound: 16,
    log_trace_length: 15,
    log_composition_degree_bound: 17,
    logup_fractions: (5 << 14) + (4 << 15) + (6 << 11),
    ..LEAF_FOLD_REFERENCE
};

/// The values the masked wrap's DEEP quotient batches, exactly: one for
/// each sampled column (57 preprocessed, 373 main and 40 interaction
/// columns, the composition's 4 whole and the FRI mask's 8; the salts are
/// never sampled), and two more for each of the 28 columns read at the
/// previous row, `p2`'s 16 and each component's running sum, sampled twice
/// and given a periodicity value.
const MASKED_WRAP_DEEP_VALUES: u64 = (57 + 373 + 40 + 4 + 8) + 2 * (16 + 3 * 4);

/// The wrap masked under variant (c), format 39's reference: the AIR of
/// [`WRAP_REFERENCE`] at its tallest component's 2^15 rows, its columns at
/// degree bound 2^16, its composition whole at 2^17 and sampled at `π(z)`
/// ([`SecurityShape::variant_c`]), plus what the masking commits beside it:
/// the shape of the built masked components, which a test derives. The batch
/// is counted exactly (`MASKED_WRAP_DEEP_VALUES`); it enters only the count
/// by powers. R2's blinding adds a fraction a row a component on a relation
/// nothing else uses: `p2`'s pairs with its lone fraction, and `qm31`'s and
/// `h8`'s take a new pair column and its constraint each.
pub const MASKED_WRAP_REFERENCE: SecurityShape = SecurityShape {
    sampled_values: MASKED_WRAP_DEEP_VALUES,
    constraints: WRAP_REFERENCE.constraints + 2,
    logup_fractions: (6 << 14) + (5 << 15) + (7 << 11),
    ..WRAP_REFERENCE.variant_c()
};
