//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::SimdBackend,
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

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

        let Logup::SingleThenPairs { singles, .. } = Self::LOGUP else {
            unreachable!("the chip's batching")
        };
        let mut logup = LogupTraceBuilder::single_then_pairs(component_trace.log_size(), singles);
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

        let mut call_tuple = ts.clone();
        call_tuple.extend(in_ptr.iter().cloned());
        call_tuple.extend(out_ptr.iter().cloned());

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
        logup.add_to_relation_with(call, [is_real[0].clone()], |[r]| (-r).into(), &call_tuple);
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
