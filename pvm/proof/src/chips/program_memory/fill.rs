//! The chip's trace generation, the prover's half.

use super::pin::chip_log_size;
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

impl BuiltInProverComponent for ProgramMemoryChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        self.preprocessed_trace(log_size, side_note)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = chip_log_size(side_note.code.len()).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for row in 0..num_rows {
            let pc = row as u32;
            let mult = side_note
                .program_memory_counts
                .get(&pc)
                .copied()
                .unwrap_or(0);
            trace.fill_columns(row, BaseField::from(mult), Column::Multiplicity);
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
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let prog_mem: &ProgramMemoryLookupElements = lookup_elements.as_ref();
        let pc = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Pc);
        let opcode =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Opcode);
        let skip_len =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::SkipLen);
        let reg_a =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegA);
        let reg_b =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegB);
        let reg_d =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::RegD);
        let imm = crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::Imm);
        let flag_bytes = FLAG_BYTES
            .map(|column| component_trace.preprocessed_base_column::<1, _>(column)[0].clone());
        let imm_y_canon =
            crate::trace::preprocessed_base_column!(component_trace, PreprocessedColumn::ImmYCanon);
        let branch_target_canon = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::BranchTargetCanon
        );
        let host_call_precompile_dispatch = crate::trace::preprocessed_base_column!(
            component_trace,
            PreprocessedColumn::HostCallPrecompileDispatch
        );
        let mult = crate::trace::original_base_column!(component_trace, Column::Multiplicity);

        // Build the 37-limb tuple from preprocessed columns.
        let mut tuple: Vec<_> = pc.to_vec();
        tuple.push(opcode[0].clone());
        tuple.push(skip_len[0].clone());
        tuple.push(reg_a[0].clone());
        tuple.push(reg_b[0].clone());
        tuple.push(reg_d[0].clone());
        tuple.extend_from_slice(&imm);
        tuple.extend(flag_bytes);
        tuple.extend_from_slice(&imm_y_canon);
        tuple.extend_from_slice(&branch_target_canon);
        tuple.push(host_call_precompile_dispatch[0].clone());

        // Producer (negative multiplicity).
        logup.add_to_relation_with(prog_mem, [mult[0].clone()], |[m]| (-m).into(), &tuple);

        logup.finalize()
    }
}
