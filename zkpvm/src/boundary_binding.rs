//! Boundary public-input binding: verifier-side recomputation of the
//! boundary chips' logup claimed sums from `proof.{initial,final}_state`.
//!
//! `RegisterMemoryBoundaryChip`, `RegisterMemoryClosingChip` and
//! `ProgramBoundaryChip` emit ONLY boundary tuples into their relations,
//! so each one's per-component claimed sum is a closed-form function of
//! the public boundary states and the Fiat-Shamir-drawn lookup elements:
//!
//! ```text
//! program_boundary  = 1/⟨z,(init_ts, init_pc)⟩ − 1/⟨z,(final_ts, final_pc)⟩
//! register_boundary = Σ_r 1/⟨z,(r, initial_regs[r], 0)⟩
//! register_closing  = Σ_r 1/⟨z,(r, final_regs[r],  final_ts)⟩
//! ```
//!
//! Equating each chip's `proof.claimed_sums` entry against these values
//! binds `proof.{initial,final}_state` to the committed boundary CHIP
//! COLUMNS:
//!
//! - The logup AIR binds the claimed sum to the committed interaction
//!   trace (the sum appears inside the final logup constraint, checked
//!   at the OODS point), and the interaction trace is constraint-bound
//!   to the committed main columns — so the claimed sum equals
//!   Σ multiplicity/⟨z, committed tuple⟩ over the chip's rows.
//! - The lookup elements `z` are drawn AFTER both the main-trace
//!   commitment and the boundary-state transcript mix, so by
//!   Schwartz–Zippel two distinct tuple multisets agree on the drawn
//!   elements only with negligible probability. The equality therefore
//!   forces the committed boundary tuples to be exactly the public
//!   tuples.
//!
//! This is the same public-input idiom stwo's state-machine example
//! uses (claimed sums checked against `combine` of the public input).
//! It adds no columns and no constraints, so the preprocessed-trace
//! commitment — the program identity — is unchanged.
//!
//! SCOPE — this is the metadata→column half of the binding. Whether the
//! committed boundary COLUMNS equal the trace's TRUE boundary state is a
//! separate, per-field question:
//!
//! - **pc / timestamp: fully bound.** `ProgramBoundaryChip`'s
//!   (init_pc, init_ts) / (final_pc, final_ts) columns are pinned to the
//!   trace by CpuChip's `#[mask_next_row]` program-execution chaining +
//!   telescoping. So pc/timestamp are genuine bound public inputs.
//! - **registers: fully bound (v6).** The
//!   `RegisterMemory{Boundary,Closing}Chip` register columns are pinned
//!   to the trace by `RegisterMemoryChip` read-consistency, which is now
//!   sound against a from-scratch prover: a cross-row `#[mask_next_row]`
//!   `prev_value` binding, a range-checked `(reg, ts)` sortedness gadget,
//!   and an `is_write` tuple limb together force the closing read's value
//!   — and hence the voucher io-hash in `final_state.registers[9..13]` —
//!   to equal the trace's actual final register state. Combined with the
//!   metadata→column binding here, registers are a fully bound public
//!   input (gate: `tests/ledger_readconsistency_gate.rs`).
//!   `memory_commitment` has no committed column and stays OUTSIDE this
//!   binding entirely.
//!
//! A consequence of the closing-chip equality: a proof over an EMPTY
//! trace (no steps, all-zero boundary metadata) is now rejected — the
//! closing chip emits no tuples (claimed sum 0) while the expected sum
//! over thirteen (r, 0, 0) tuples is non-zero. (Empty proofs previously
//! verified: the boundary chip's thirteen (r, 0, 0) seeds were exactly
//! cancelled by the ledger's ts=0 initial-write rows, so the relation
//! balanced with no closing emissions; the closing-chip equality is what
//! now rejects them. Empty traces assert nothing useful anyway.)

use alloc::vec::Vec;

use num_traits::Zero;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::Relation;

use crate::lookups::{
    AllLookupElements, ProgramExecutionLookupElements, RegisterMemoryLookupElements,
};
use crate::proof::SegmentState;

/// Positions of the three boundary-binding chips within a proof's
/// ACTIVE component order (the order `claimed_sums` is indexed by).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundaryChipPositions {
    pub register_boundary: usize,
    pub register_closing: usize,
    pub program_boundary: usize,
}

/// Locate the three boundary-binding chips in a proof's active-component
/// order from its `component_mask` (bit i ⇔ `BASE_COMPONENTS[i]` active;
/// position = rank among set bits). Returns `None` when any of the three
/// is missing — such a proof cannot bind its boundary states and must be
/// rejected by verifiers that read them. All three chips are
/// unconditionally active in the production prove path.
pub fn boundary_positions_in_mask(mask: u32) -> Option<BoundaryChipPositions> {
    let pos = |idx: usize| -> Option<usize> {
        (mask & (1u32 << idx) != 0).then(|| (mask & ((1u32 << idx) - 1)).count_ones() as usize)
    };
    Some(BoundaryChipPositions {
        register_boundary: pos(crate::chip_idx::REGISTER_MEMORY_BOUNDARY)?,
        register_closing: pos(crate::chip_idx::REGISTER_MEMORY_CLOSING)?,
        program_boundary: pos(crate::chip_idx::PROGRAM_BOUNDARY)?,
    })
}

/// Check the boundary-binding equalities for one proof: each boundary
/// chip's claimed sum must equal the value recomputed from the public
/// boundary states. `claimed_sums` is in active-component order.
///
/// Errors are static strings the caller wraps into
/// `VerificationError::InvalidStructure`.
pub fn check_boundary_claimed_sums(
    initial: &SegmentState,
    final_state: &SegmentState,
    lookup_elements: &AllLookupElements,
    claimed_sums: &[SecureField],
    positions: &BoundaryChipPositions,
) -> Result<(), &'static str> {
    let reg_elements: &RegisterMemoryLookupElements = lookup_elements.as_ref();
    let prog_elements: &ProgramExecutionLookupElements = lookup_elements.as_ref();

    let claimed = |pos: usize| -> Result<SecureField, &'static str> {
        claimed_sums
            .get(pos)
            .copied()
            .ok_or("boundary chip position out of claimed_sums bounds")
    };

    let expected = expected_register_file_sum(&initial.registers, 0, 1, reg_elements)
        .ok_or("degenerate lookup combination for initial register state")?;
    if claimed(positions.register_boundary)? != expected {
        return Err("initial_state.registers do not match the committed boundary columns");
    }

    let expected = expected_register_file_sum(
        &final_state.registers,
        final_state.timestamp,
        0,
        reg_elements,
    )
    .ok_or("degenerate lookup combination for final register state")?;
    if claimed(positions.register_closing)? != expected {
        return Err("final_state registers/timestamp do not match the committed closing columns");
    }

    let expected = expected_program_boundary_sum(initial, final_state, prog_elements)
        .ok_or("degenerate lookup combination for boundary pc/timestamp")?;
    if claimed(positions.program_boundary)? != expected {
        return Err("boundary pc/timestamp do not match the committed program-boundary columns");
    }

    Ok(())
}

/// Expected claimed sum of `ProgramBoundaryChip`: one produced
/// `(initial_ts, initial_pc)` tuple and one consumed
/// `(final_ts, final_pc)` tuple. Mirrors the chip's emission order —
/// timestamp limbs then pc limbs.
pub fn expected_program_boundary_sum(
    initial: &SegmentState,
    final_state: &SegmentState,
    elements: &ProgramExecutionLookupElements,
) -> Option<SecureField> {
    let tuple = |pc: u32, ts: u64| -> Vec<BaseField> {
        let mut t = Vec::with_capacity(12);
        t.extend(le_byte_limbs_u64(ts));
        t.extend(le_byte_limbs_u32(pc));
        t
    };
    let produced = inv_combined(prog_combine(
        elements,
        &tuple(initial.pc, initial.timestamp),
    ))?;
    let consumed = inv_combined(prog_combine(
        elements,
        &tuple(final_state.pc, final_state.timestamp),
    ))?;
    Some(produced - consumed)
}

/// Expected claimed sum of one register-file boundary chip: thirteen
/// produced `(reg, value, ts)` tuples. `ts` is 0 for
/// `RegisterMemoryBoundaryChip` (the initial seeds) and the closing
/// timestamp (= `final_state.timestamp`, one past the last step) for
/// `RegisterMemoryClosingChip`.
pub fn expected_register_file_sum(
    registers: &[u64; 13],
    ts: u64,
    is_write: u64,
    elements: &RegisterMemoryLookupElements,
) -> Option<SecureField> {
    let ts_limbs = le_byte_limbs_u64(ts);
    let mut sum = SecureField::zero();
    for (reg, &val) in registers.iter().enumerate() {
        let mut t = Vec::with_capacity(18);
        t.push(BaseField::from(reg as u32));
        t.extend(le_byte_limbs_u64(val));
        t.extend(ts_limbs);
        // is_write is the last tuple limb (1 for the initial-write boundary
        // seeds, 0 for the closing reads) — matches the chips' 18-limb tuple.
        t.push(BaseField::from(is_write as u32));
        sum += inv_combined(<RegisterMemoryLookupElements as Relation<
            BaseField,
            SecureField,
        >>::combine(elements, &t))?;
    }
    Some(sum)
}

fn prog_combine(elements: &ProgramExecutionLookupElements, tuple: &[BaseField]) -> SecureField {
    <ProgramExecutionLookupElements as Relation<BaseField, SecureField>>::combine(elements, tuple)
}

/// `1 / combined`, or `None` when the combination is zero. Zero needs a
/// tuple lying on the drawn lookup-element hyperplane — negligible for
/// honestly-drawn elements, and the boundary states are mixed into the
/// transcript BEFORE the elements are drawn, so a prover cannot steer
/// into it. Callers treat `None` as a verification failure.
fn inv_combined(combined: SecureField) -> Option<SecureField> {
    (!combined.is_zero()).then(|| combined.inverse())
}

fn le_byte_limbs_u64(v: u64) -> [BaseField; 8] {
    core::array::from_fn(|i| BaseField::from(((v >> (8 * i)) & 0xff) as u32))
}

fn le_byte_limbs_u32(v: u32) -> [BaseField; 4] {
    core::array::from_fn(|i| BaseField::from((v >> (8 * i)) & 0xff))
}
