//! Poseidon2Chip — the Poseidon2 call (`0x402`, `slice-7-mobile.md` pin H),
//! one permutation a row, in the shared chip set (formats 41 and 43).
//!
//! A row is a served call at its step's timestamp:
//!
//! - **The call:** it CONSUMES `(ts, φ7, φ8)` in the `Poseidon2Call`
//!   relation, which the shared chip set's CPU produces from the call's row
//!   (`CpuP2Chip`), so a row is a call and a call has its row.
//! - **The input:** 64 bytes at `φ7 + i`, each a PRODUCED read of the memory
//!   ledger at the call's timestamp; four bytes a word, little-endian. Each
//!   word is below p: its top byte below 128 (`Range256` of it and of it
//!   plus 128) and its bytes' sum not `3·255 + 127` (an inverse witnesses
//!   it), the bytes being bytes because every ledger write is one (each
//!   writer range-checks what it writes). So a word the live call refuses,
//!   p itself included, has no row.
//! - **The permutation:** `vos_pvm_poseidon2`'s, its S-box `y⁵` as two
//!   columns (`a = y²`, `out = a²·y`), every constraint of degree at most 3,
//!   as the recursion AIR's `p2` (`vos_pvm_recair_air::p2`), unchained.
//! - **The output:** its first eight words, each written as four bytes at
//!   `φ8 + j` (32 PRODUCED writes at the call's timestamp), each byte
//!   range-checked, the top byte below 128 and the word not p, so the bytes
//!   are the word's one canonical encoding.
//!
//! The addresses `ptr + i` are four limbs: limb 0 `ptr₀ + i − 256·c_i` with
//! `c_i` a boolean carry, limbs 1..3 the pointer's or, when `c_i = 1`, those of
//! `(ptr >> 8) + 1`, an increment with boolean carries. Whatever the carries,
//! the increment's limbs sum to `(ptr >> 8) + 1` and the address's to the
//! integer `ptr + i`, every identity being over small integers. So the
//! ledger's 16-bit halves of a row's address either are the true address's,
//! and the row joins that byte's group and reads or writes it there, or one
//! of them lies outside `[0, 2^16)`, which no `ts = 0` write's halves do (its
//! limbs are bytes): such a row can join no group and start none, and the
//! proof does not balance. A wrong carry buys nothing, so limb 0 needs no
//! range check, unlike BLAKE2b's chip, whose carries are pinned by one.
//!
//! Every fraction is its own interaction column (`Logup::Single`): the
//! addresses are of degree 2.

use crate::prelude::*;
use core::array::from_fn;
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};
use vos_pvm_poseidon2::{
    EXTERNAL_ROUND_CONSTS, FULL_ROUNDS, INTERNAL_ROUND_CONSTS, N_HALF_FULL_ROUNDS, N_STATE,
    apply_external_round_matrix, apply_internal_round_matrix,
};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::framework::{BuiltInComponent, Logup};
use crate::lookups::{
    MemoryAccessLookupElements, Poseidon2CallLookupElements, Range256LookupElements,
};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

pub struct Poseidon2Chip;

/// The input's bytes: sixteen words of four.
const INPUT_BYTES: usize = 64;
/// The output's bytes: eight words of four.
const OUTPUT_BYTES: usize = 32;
/// The S-boxes a permutation applies, two columns each.
const SBOXES: usize = vos_pvm_recair_air::p2::N_SBOXES;
/// `3·255 + 127`: a word's bytes' sum exactly when the word is p.
const P_BYTE_SUM: u32 = 3 * 255 + 127;

#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// The call's timestamp, 8 LE limbs.
    #[size = 8]
    Ts,
    /// φ7, the input's address, 4 LE limbs.
    #[size = 4]
    InPtr,
    /// φ8, the output's address, 4 LE limbs.
    #[size = 4]
    OutPtr,
    /// The input's bytes.
    #[size = 64]
    Input,
    /// The output's bytes.
    #[size = 32]
    Output,
    /// Each S-box's `a = y²` and `out = a²·y`, in the permutation's order:
    /// the first half of the S-boxes' columns, then the second.
    #[size = 142]
    SboxLow,
    #[size = 142]
    SboxHigh,
    /// The carry out of limb 0 of `φ7 + i`.
    #[size = 64]
    InCarry,
    /// The carry out of limb 0 of `φ8 + j`.
    #[size = 32]
    OutCarry,
    /// Limbs 0..3 of `(φ7 >> 8) + 1`.
    #[size = 3]
    InInc,
    /// The carries out of that increment's limbs 0 and 1.
    #[size = 2]
    InIncCarry,
    /// Limbs 0..3 of `(φ8 >> 8) + 1`.
    #[size = 3]
    OutInc,
    /// The carries out of that increment's limbs 0 and 1.
    #[size = 2]
    OutIncCarry,
    /// Each input word's `1 / (bytes' sum − P_BYTE_SUM)`.
    #[size = 16]
    InputNotP,
    /// Each output word's `1 / (bytes' sum − P_BYTE_SUM)`.
    #[size = 8]
    OutputNotP,
    /// 1 on a call's row, 0 on padding.
    #[size = 1]
    IsReal,
}

const _: () = assert!(2 * SBOXES == 284);

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "p2call"]
pub enum PreprocessedColumn {}

/// `ptr + i` for `i < N` as byte limbs, over values of type `F`.
struct Addresses<F, const N: usize> {
    ptr: [F; 4],
    carry: [F; N],
    inc: [F; 3],
}

impl<F, const N: usize> Addresses<F, N>
where
    F: Clone
        + core::ops::Add<Output = F>
        + core::ops::Sub<Output = F>
        + core::ops::Mul<Output = F>
        + From<BaseField>,
{
    /// The four limbs of `ptr + i`.
    fn address(&self, i: usize) -> [F; 4] {
        let c = self.carry[i].clone();
        let limb = |k: usize| {
            self.ptr[k].clone() + c.clone() * (self.inc[k - 1].clone() - self.ptr[k].clone())
        };
        [
            self.ptr[0].clone() + F::from(BaseField::from(i as u32))
                - F::from(BaseField::from(256u32)) * c.clone(),
            limb(1),
            limb(2),
            limb(3),
        ]
    }
}

/// A word's value from its four LE bytes.
fn word<F>(bytes: &[F]) -> F
where
    F: Clone + core::ops::Add<Output = F> + core::ops::Mul<Output = F> + From<BaseField>,
{
    bytes
        .iter()
        .rev()
        .cloned()
        .reduce(|high, low| low + high * F::from(BaseField::from(256u32)))
        .expect("four bytes")
}

/// A word's bytes' sum.
fn byte_sum<F: Clone + core::ops::Add<Output = F>>(bytes: &[F]) -> F {
    bytes
        .iter()
        .cloned()
        .reduce(|a, b| a + b)
        .expect("four bytes")
}

/// The permutation of `input` over the S-box columns `sboxes`: two
/// constraints an S-box; the permutation's output.
fn permutation<E: EvalAtRow>(
    eval: &mut E,
    input: [E::F; N_STATE],
    sboxes: &[E::F],
) -> [E::F; N_STATE] {
    let base =
        |value: vos_pvm_poseidon2::M31| E::F::from(BaseField::from_u32_unchecked(value.value()));
    let mut columns = sboxes.chunks_exact(2);
    let mut sbox = |eval: &mut E, y: E::F| {
        let [a, out] = columns.next().expect("an S-box's columns") else {
            unreachable!()
        };
        eval.add_constraint(a.clone() - y.clone() * y.clone());
        eval.add_constraint(out.clone() - a.clone() * a.clone() * y);
        out.clone()
    };
    let mut state = input;
    apply_external_round_matrix(&mut state);
    let full_round = |eval: &mut E,
                      state: &mut [E::F; N_STATE],
                      round: usize,
                      sbox: &mut dyn FnMut(&mut E, E::F) -> E::F| {
        for j in 0..N_STATE {
            let y = eval.add_intermediate(state[j].clone() + base(EXTERNAL_ROUND_CONSTS[round][j]));
            state[j] = sbox(eval, y);
        }
        apply_external_round_matrix(state);
    };
    for round in 0..N_HALF_FULL_ROUNDS {
        full_round(eval, &mut state, round, &mut sbox);
    }
    for &constant in &INTERNAL_ROUND_CONSTS {
        let y = eval.add_intermediate(state[0].clone() + base(constant));
        state[0] = sbox(eval, y);
        apply_internal_round_matrix::<_, BaseField>(&mut state);
        for word in state.iter_mut() {
            *word = eval.add_intermediate(word.clone());
        }
    }
    for round in N_HALF_FULL_ROUNDS..FULL_ROUNDS {
        full_round(eval, &mut state, round, &mut sbox);
    }
    state
}

impl BuiltInComponent for Poseidon2Chip {
    const LOGUP: Logup = Logup::Single;
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = (
        Poseidon2CallLookupElements,
        MemoryAccessLookupElements,
        Range256LookupElements,
    );

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        (call, memory, range): &Self::LookupElements,
    ) {
        let ts = crate::trace::trace_eval!(trace_eval, Column::Ts);
        let in_ptr = crate::trace::trace_eval!(trace_eval, Column::InPtr);
        let out_ptr = crate::trace::trace_eval!(trace_eval, Column::OutPtr);
        let input = crate::trace::trace_eval!(trace_eval, Column::Input);
        let output = crate::trace::trace_eval!(trace_eval, Column::Output);
        let sboxes: Vec<E::F> = crate::trace::trace_eval!(trace_eval, Column::SboxLow)
            .into_iter()
            .chain(crate::trace::trace_eval!(trace_eval, Column::SboxHigh))
            .collect();
        let in_carry = crate::trace::trace_eval!(trace_eval, Column::InCarry);
        let out_carry = crate::trace::trace_eval!(trace_eval, Column::OutCarry);
        let in_inc = crate::trace::trace_eval!(trace_eval, Column::InInc);
        let in_inc_carry = crate::trace::trace_eval!(trace_eval, Column::InIncCarry);
        let out_inc = crate::trace::trace_eval!(trace_eval, Column::OutInc);
        let out_inc_carry = crate::trace::trace_eval!(trace_eval, Column::OutIncCarry);
        let input_not_p = crate::trace::trace_eval!(trace_eval, Column::InputNotP);
        let output_not_p = crate::trace::trace_eval!(trace_eval, Column::OutputNotP);
        let [is_real] = crate::trace::trace_eval!(trace_eval, Column::IsReal);

        let one = E::F::one();
        let constant = |value: u32| E::F::from(BaseField::from(value));
        for bit in core::iter::once(&is_real)
            .chain(&in_carry)
            .chain(&out_carry)
            .chain(&in_inc_carry)
            .chain(&out_inc_carry)
        {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
        }
        // `(ptr >> 8) + 1`, exactly, on a call's row.
        for (ptr, inc, carry) in [
            (&in_ptr, &in_inc, &in_inc_carry),
            (&out_ptr, &out_inc, &out_inc_carry),
        ] {
            eval.add_constraint(
                is_real.clone()
                    * (inc[0].clone() + constant(256) * carry[0].clone()
                        - ptr[1].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_real.clone()
                    * (inc[1].clone() + constant(256) * carry[1].clone()
                        - ptr[2].clone()
                        - carry[0].clone()),
            );
            eval.add_constraint(
                is_real.clone() * (inc[2].clone() - ptr[3].clone() - carry[1].clone()),
            );
        }

        // The permutation of the input's words; its output's first eight
        // words are the output bytes', each canonical.
        let words: [E::F; N_STATE] = from_fn(|j| word(&input[4 * j..4 * j + 4]));
        let state = permutation(eval, words, &sboxes);
        for j in 0..OUTPUT_BYTES / 4 {
            eval.add_constraint(
                is_real.clone() * (word(&output[4 * j..4 * j + 4]) - state[j].clone()),
            );
        }
        for (bytes, not_p) in input
            .chunks_exact(4)
            .zip(&input_not_p)
            .chain(output.chunks_exact(4).zip(&output_not_p))
        {
            eval.add_constraint(
                is_real.clone()
                    * ((byte_sum(bytes) - constant(P_BYTE_SUM)) * not_p.clone() - one.clone()),
            );
        }

        // The call; the input's reads and the output's writes; the bytes'
        // ranges.
        let mut tuple: Vec<E::F> = ts.to_vec();
        tuple.extend(in_ptr.iter().cloned());
        tuple.extend(out_ptr.iter().cloned());
        eval.add_to_relation(RelationEntry::new(call, (-is_real.clone()).into(), &tuple));
        let reads = Addresses::<E::F, INPUT_BYTES> {
            ptr: in_ptr,
            carry: in_carry,
            inc: in_inc,
        };
        let writes = Addresses::<E::F, OUTPUT_BYTES> {
            ptr: out_ptr,
            carry: out_carry,
            inc: out_inc,
        };
        let access = |address: [E::F; 4], value: &E::F, is_write: bool| -> Vec<E::F> {
            let mut tuple = address.to_vec();
            tuple.push(value.clone());
            tuple.extend(ts.iter().cloned());
            tuple.push(if is_write { E::F::one() } else { E::F::zero() });
            tuple.push(E::F::zero());
            tuple
        };
        for (i, byte) in input.iter().enumerate() {
            let tuple = access(reads.address(i), byte, false);
            eval.add_to_relation(RelationEntry::new(memory, is_real.clone().into(), &tuple));
        }
        for (j, byte) in output.iter().enumerate() {
            let tuple = access(writes.address(j), byte, true);
            eval.add_to_relation(RelationEntry::new(memory, is_real.clone().into(), &tuple));
        }
        for (from_output, byte, plus_128) in range_checks() {
            let byte = if from_output {
                &output[byte]
            } else {
                &input[byte]
            };
            let value = if plus_128 {
                byte.clone() + constant(128)
            } else {
                byte.clone()
            };
            eval.add_to_relation(RelationEntry::new(range, is_real.clone().into(), &[value]));
        }
    }
}

/// What a call's row range-checks, in order, as `(output, byte, plus 128)`:
/// each input word's top byte, and it plus 128; each output byte, and each
/// output word's top byte plus 128.
fn range_checks() -> impl Iterator<Item = (bool, usize, bool)> {
    let input =
        (0..INPUT_BYTES / 4).flat_map(|w| [(false, 4 * w + 3, false), (false, 4 * w + 3, true)]);
    let output = (0..OUTPUT_BYTES / 4).flat_map(|w| {
        (0..4)
            .map(move |k| (true, 4 * w + k, false))
            .chain([(true, 4 * w + 3, true)])
    });
    input.chain(output)
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for Poseidon2Chip {
    fn generate_main_trace_min(
        &self,
        side_note: &mut SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let ops = &side_note.poseidon2_ops;
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(ops.len()).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let mut columns = [vos_pvm_poseidon2::M31::ZERO; vos_pvm_recair_air::p2::main::M];
        let to_base = |value: vos_pvm_poseidon2::M31| BaseField::from_u32_unchecked(value.value());
        let not_p = |bytes: &[u8]| {
            // A word that is p has none: its row's constraint fails.
            let sum: u32 = bytes.iter().map(|&byte| u32::from(byte)).sum();
            if sum == P_BYTE_SUM {
                BaseField::zero()
            } else {
                (BaseField::from(sum) - BaseField::from(P_BYTE_SUM)).inverse()
            }
        };
        let mut range: Vec<u8> = Vec::new();
        for row in 0..trace.num_rows() {
            let Some(op) = ops.get(row) else {
                // A padding row holds the permutation of zero.
                vos_pvm_recair_air::p2::permutation_columns(
                    [vos_pvm_poseidon2::M31::ZERO; N_STATE],
                    &mut columns,
                );
                let sboxes: Vec<BaseField> =
                    columns[N_STATE..].iter().map(|&v| to_base(v)).collect();
                trace.fill_columns_base_field(row, &sboxes[..SBOXES], Column::SboxLow);
                trace.fill_columns_base_field(row, &sboxes[SBOXES..], Column::SboxHigh);
                continue;
            };
            // A word is read as the field reads it: a word at or above p
            // (which the live call refuses) reduced, its row's range checks
            // failing.
            let input: [vos_pvm_poseidon2::M31; N_STATE] = from_fn(|j| {
                vos_pvm_poseidon2::M31::new(
                    u32::from_le_bytes(op.input[4 * j..4 * j + 4].try_into().expect("four bytes"))
                        % vos_pvm_poseidon2::P,
                )
            });
            vos_pvm_recair_air::p2::permutation_columns(input, &mut columns);
            let sboxes: Vec<BaseField> = columns[N_STATE..].iter().map(|&v| to_base(v)).collect();
            trace.fill_columns(row, op.ts, Column::Ts);
            trace.fill_columns(row, op.in_ptr.to_le_bytes(), Column::InPtr);
            trace.fill_columns(row, op.out_ptr.to_le_bytes(), Column::OutPtr);
            trace.fill_columns_bytes(row, &op.input, Column::Input);
            trace.fill_columns_bytes(row, &op.output, Column::Output);
            trace.fill_columns_base_field(row, &sboxes[..SBOXES], Column::SboxLow);
            trace.fill_columns_base_field(row, &sboxes[SBOXES..], Column::SboxHigh);
            let carries = |ptr: u32, n: usize| -> Vec<BaseField> {
                (0..n)
                    .map(|i| BaseField::from(u32::from((ptr & 0xff) as usize + i >= 256)))
                    .collect()
            };
            trace.fill_columns_base_field(row, &carries(op.in_ptr, INPUT_BYTES), Column::InCarry);
            trace.fill_columns_base_field(
                row,
                &carries(op.out_ptr, OUTPUT_BYTES),
                Column::OutCarry,
            );
            let increment = |ptr: u32| -> ([BaseField; 3], [BaseField; 2]) {
                let [_, p1, p2, p3] = ptr.to_le_bytes().map(u32::from);
                let (inc0, e0) = ((p1 + 1) & 0xff, (p1 + 1) >> 8);
                let (inc1, e1) = ((p2 + e0) & 0xff, (p2 + e0) >> 8);
                let inc2 = p3 + e1;
                (
                    [inc0, inc1, inc2].map(BaseField::from),
                    [e0, e1].map(BaseField::from),
                )
            };
            let (inc, carry) = increment(op.in_ptr);
            trace.fill_columns_base_field(row, &inc, Column::InInc);
            trace.fill_columns_base_field(row, &carry, Column::InIncCarry);
            let (inc, carry) = increment(op.out_ptr);
            trace.fill_columns_base_field(row, &inc, Column::OutInc);
            trace.fill_columns_base_field(row, &carry, Column::OutIncCarry);
            let input_not_p: Vec<BaseField> = op.input.chunks_exact(4).map(not_p).collect();
            let output_not_p: Vec<BaseField> = op.output.chunks_exact(4).map(not_p).collect();
            trace.fill_columns_base_field(row, &input_not_p, Column::InputNotP);
            trace.fill_columns_base_field(row, &output_not_p, Column::OutputNotP);
            trace.fill_columns(row, true, Column::IsReal);
            // A value past a byte (a top byte of 128 or more) has no entry:
            // its lookup does not balance.
            range.extend(range_checks().filter_map(|(from_output, byte, plus_128)| {
                let byte = if from_output {
                    op.output[byte]
                } else {
                    op.input[byte]
                };
                u8::try_from(u32::from(byte) + if plus_128 { 128 } else { 0 }).ok()
            }));
        }
        for value in range {
            side_note.add_range256(value);
        }
        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: &ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        use stwo::prover::backend::simd::m31::PackedBaseField;

        let mut logup = LogupTraceBuilder::single(component_trace.log_size());
        let call: &Poseidon2CallLookupElements = lookup_elements.as_ref();
        let memory: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let range: &Range256LookupElements = lookup_elements.as_ref();
        let column = |column: Column| -> Vec<crate::trace::component::FinalizedColumn<'_>> {
            component_trace.original_columns(column).collect()
        };
        let ts = column(Column::Ts);
        let in_ptr = column(Column::InPtr);
        let out_ptr = column(Column::OutPtr);
        let input = column(Column::Input);
        let output = column(Column::Output);
        let in_carry = column(Column::InCarry);
        let out_carry = column(Column::OutCarry);
        let in_inc = column(Column::InInc);
        let out_inc = column(Column::OutInc);
        let is_real = column(Column::IsReal);

        let mut tuple = ts.clone();
        tuple.extend(in_ptr.iter().cloned());
        tuple.extend(out_ptr.iter().cloned());
        logup.add_to_relation_with(call, [is_real[0].clone()], |[r]| (-r).into(), &tuple);

        for (ptr, carry, inc, values, is_write) in [
            (&in_ptr, &in_carry, &in_inc, &input, false),
            (&out_ptr, &out_carry, &out_inc, &output, true),
        ] {
            for i in 0..values.len() {
                let (ptr, carry, inc, value, ts) = (
                    ptr.clone(),
                    carry[i].clone(),
                    inc.clone(),
                    values[i].clone(),
                    ts.clone(),
                );
                logup.add_to_relation_computed(
                    memory,
                    [is_real[0].clone()],
                    |[r]| r.into(),
                    15,
                    move |v| {
                        let addresses = Addresses::<PackedBaseField, 1> {
                            ptr: from_fn(|k| ptr[k].at(v)),
                            carry: [carry.at(v)],
                            inc: from_fn(|k| inc[k].at(v)),
                        };
                        let mut address = addresses.address(0);
                        address[0] += PackedBaseField::broadcast(BaseField::from(i as u32));
                        let mut tuple = address.to_vec();
                        tuple.push(value.at(v));
                        tuple.extend(ts.iter().map(|limb| limb.at(v)));
                        tuple.push(if is_write {
                            PackedBaseField::one()
                        } else {
                            PackedBaseField::zero()
                        });
                        tuple.push(PackedBaseField::zero());
                        tuple
                    },
                );
            }
        }
        for (from_output, byte, plus_128) in range_checks() {
            let column = if from_output {
                output[byte].clone()
            } else {
                input[byte].clone()
            };
            let shift =
                PackedBaseField::broadcast(BaseField::from(if plus_128 { 128u32 } else { 0 }));
            logup.add_to_relation_computed(
                range,
                [is_real[0].clone()],
                |[r]| r.into(),
                1,
                move |v| vec![column.at(v) + shift],
            );
        }
        logup.finalize()
    }
}
