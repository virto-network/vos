//! The two chips' trace generation, the prover's half.

use super::*;
use crate::core::step::NUM_REGS;
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

impl BuiltInProverComponent for DeviceBoundaryChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, side_note: &SideNote) -> FinalizedTrace {
        self.preprocessed_trace(log_size, side_note)
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(NUM_REGS).max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let final_ts = crate::chips::register_memory_closing::closing_ts_for(side_note);
        for (row, &value) in side_note.final_regs.iter().enumerate() {
            trace.fill_columns(row, value, Column::FinalValue);
            trace.fill_columns(row, final_ts, Column::FinalTs);
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
        use crate::trace::component::FinalizedColumn;
        let mut logup = LogupTraceBuilder::new(component_trace.log_size());
        let registers: &RegisterMemoryLookupElements = lookup_elements.as_ref();
        let execution: &ProgramExecutionLookupElements = lookup_elements.as_ref();
        let io: &IoHashLookupElements = lookup_elements.as_ref();
        let final_value = crate::trace::original_base_column!(component_trace, Column::FinalValue);
        let final_ts = crate::trace::original_base_column!(component_trace, Column::FinalTs);
        let pre = |column: PreprocessedColumn| -> Vec<FinalizedColumn<'_>> {
            let offset = column.offset();
            component_trace.preprocessed_trace[offset..offset + column.size()]
                .iter()
                .map(Into::into)
                .collect()
        };
        let is_register = pre(PreprocessedColumn::IsRegister);
        let register = pre(PreprocessedColumn::Register);
        let is_first = pre(PreprocessedColumn::IsFirst);
        let is_io = pre(PreprocessedColumn::IsIo);
        let constant = |value: BaseField| FinalizedColumn::Constant(value);

        let mut write = register.clone();
        write.extend(pre(PreprocessedColumn::InitialValue));
        write.extend((0..WORD_SIZE).map(|_| constant(BaseField::zero())));
        write.push(constant(BaseField::one()));
        logup.add_to_relation_with(registers, [is_register[0].clone()], |[r]| r.into(), &write);
        let mut close = register.clone();
        close.extend(final_value.iter().cloned());
        close.extend(final_ts.iter().cloned());
        close.push(constant(BaseField::zero()));
        logup.add_to_relation_with(registers, [is_register[0].clone()], |[r]| r.into(), &close);

        let mut entry: Vec<FinalizedColumn<'_>> = limbs::<BaseField, WORD_SIZE>(ENTRY_TIMESTAMP)
            .map(constant)
            .to_vec();
        entry.extend(limbs::<BaseField, 4>(u64::from(ENTRY_PC)).map(constant));
        logup.add_to_relation_with(execution, [is_first[0].clone()], |[f]| f.into(), &entry);
        let mut halt: Vec<FinalizedColumn<'_>> = final_ts.to_vec();
        halt.extend(limbs::<BaseField, 4>(u64::from(HALT_PC)).map(constant));
        logup.add_to_relation_with(execution, [is_first[0].clone()], |[f]| (-f).into(), &halt);

        let mut output = register;
        output.extend(final_value.iter().cloned());
        logup.add_to_relation_with(io, [is_io[0].clone()], |[i]| (-i).into(), &output);
        logup.finalize()
    }
}

impl BuiltInProverComponent for DeviceIoChip {
    const IS_PRODUCER: bool = false;

    fn generate_preprocessed_trace(&self, log_size: u32, _side_note: &SideNote) -> FinalizedTrace {
        let mut trace = TraceBuilder::<IoPreprocessedColumn>::new(log_size);
        for (row, register) in IO_REGISTERS.enumerate() {
            trace.fill_columns(row, true, IoPreprocessedColumn::IsIo);
            trace.fill_columns(
                row,
                BaseField::from(register as u32),
                IoPreprocessedColumn::Register,
            );
        }
        trace.finalize_bit_reversed()
    }

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let log_size =
            crate::trace::utils::ceil_log2_at_least_lanes(IO_REGISTERS.len()).max(min_log_size);
        let mut trace = TraceBuilder::<IoColumn>::new(log_size);
        for (row, register) in IO_REGISTERS.enumerate() {
            trace.fill_columns(row, side_note.final_regs[register], IoColumn::Value);
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
        let mut logup = LogupTraceBuilder::new(component_trace.log_size());
        let io: &IoHashLookupElements = lookup_elements.as_ref();
        let value = crate::trace::original_base_column!(component_trace, IoColumn::Value);
        let is_io =
            crate::trace::preprocessed_base_column!(component_trace, IoPreprocessedColumn::IsIo);
        let register = crate::trace::preprocessed_base_column!(
            component_trace,
            IoPreprocessedColumn::Register
        );
        let mut output = register.to_vec();
        output.extend(value.iter().cloned());
        logup.add_to_relation_with(io, [is_io[0].clone()], |[i]| i.into(), &output);
        logup.finalize()
    }
}
