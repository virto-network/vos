use num_traits::{One, Zero};
use stwo::{
    core::{
        fields::{m31::BaseField, qm31::SecureField},
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use zkpvm_air_column::{AirColumn, PreprocessedAirColumn};
use zkpvm_core::step::WORD_SIZE;
use zkpvm_trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
    eval::TraceEval,
};

use crate::{
    framework::BuiltInComponent,
    lookups::{AllLookupElements, LogupTraceBuilder, Range256LookupElements},
    side_note::SideNote,
};

/// CpuChip: proves correct sequencing and ALU execution for every PVM step.
///
/// For Phase 1, this is a monolithic chip that handles:
/// - Timestamp monotonicity (timestamp increases by 1 each row)
/// - PC → opcode validation (program memory lookup)
/// - Register read/write (register memory lookups)
/// - ALU: wrapping Add64 (ra = rb + rd)
/// - Range checks on all byte limbs
pub struct CpuChip;

/// Column layout for the CPU chip.
/// All 64-bit values stored as 8 × 8-bit limbs (little-endian).
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Timestamp (8 limbs).
    #[size = 8]
    #[mask_next_row]
    Timestamp,
    /// Program counter (4 limbs, u32).
    #[size = 4]
    #[mask_next_row]
    Pc,
    /// Next PC (4 limbs, u32).
    #[size = 4]
    NextPc,
    /// Opcode byte (1 column).
    #[size = 1]
    Opcode,
    /// Skip length (1 column).
    #[size = 1]
    SkipLen,
    /// Register A index (destination/source, 1 column).
    #[size = 1]
    RegA,
    /// Register B index (source 1, 1 column).
    #[size = 1]
    RegB,
    /// Register D index (source 2, 1 column for three-reg ops).
    #[size = 1]
    RegD,
    /// Value of register A before execution (8 limbs).
    #[size = 8]
    ValA,
    /// Value of register B before execution (8 limbs).
    #[size = 8]
    ValB,
    /// Value of register D before execution (8 limbs, for three-reg ops).
    #[size = 8]
    ValD,
    /// Result value written to register A (8 limbs).
    #[size = 8]
    Result,
    /// Carry flags for addition (8 limbs, each 0 or 1).
    #[size = 8]
    Carry,
    /// Flag: is this a padding row (1 = pad, 0 = real step).
    #[size = 1]
    IsPadding,
    /// Timestamp of register A read (8 limbs).
    #[size = 8]
    RegAReadTs,
    /// Timestamp of register B read (8 limbs).
    #[size = 8]
    RegBReadTs,
    /// Timestamp of register D read (8 limbs).
    #[size = 8]
    RegDReadTs,
    /// Flag: register A is written (1 = write, 0 = no write).
    #[size = 1]
    RegAWritten,
    /// Gas remaining after step (8 limbs).
    #[size = 8]
    Gas,
    /// Flag: this instruction is Add64 (opcode 200).
    #[size = 1]
    IsAdd64,
}

/// Preprocessed columns (none for now — we'll use preprocessed trace for program validation later).
#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "cpu"]
pub enum PreprocessedColumn {}

impl BuiltInComponent for CpuChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = Range256LookupElements;

    fn generate_preprocessed_trace(
        &self,
        _log_size: u32,
        _side_note: &SideNote,
    ) -> FinalizedTrace {
        FinalizedTrace::empty()
    }

    fn generate_main_trace(&self, side_note: &mut SideNote) -> FinalizedTrace {
        let num_steps = side_note.num_steps();
        let log_size = (num_steps as f64).log2().ceil().max(LOG_N_LANES as f64) as u32;
        let log_size = log_size.max(LOG_N_LANES);

        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        // Collect range check bytes separately to avoid borrow conflict
        let mut range_bytes: Vec<u8> = Vec::new();

        for (row, step) in side_note.steps.iter().enumerate() {
            // Timestamp
            trace.fill_columns(row, step.timestamp, Column::Timestamp);

            // PC (u32 as 4 bytes)
            let pc_bytes = step.pc.to_le_bytes();
            trace.fill_columns_bytes(row, &pc_bytes, Column::Pc);

            // Next PC
            let next_pc_bytes = step.next_pc.to_le_bytes();
            trace.fill_columns_bytes(row, &next_pc_bytes, Column::NextPc);

            // Opcode
            trace.fill_columns(row, step.opcode as u8, Column::Opcode);

            // Skip length
            trace.fill_columns(row, step.skip_len as u8, Column::SkipLen);

            // Register indices + values from decoded step
            // For ThreeReg ops: ra=source1, rb=source2, rd=destination
            trace.fill_columns(row, step.reg_a as u8, Column::RegA);
            trace.fill_columns(row, step.reg_b as u8, Column::RegB);
            trace.fill_columns(row, step.reg_d as u8, Column::RegD);

            // ValA = regs_before[reg_a] (source 1 or dest for non-3reg)
            // ValB = regs_before[reg_a] (source 1, used in Add64 constraint)
            // ValD = regs_before[reg_b] (source 2, used in Add64 constraint)
            trace.fill_columns(row, step.regs_before[step.reg_a], Column::ValA);
            trace.fill_columns(row, step.regs_before[step.reg_a], Column::ValB);
            trace.fill_columns(row, step.regs_before[step.reg_b], Column::ValD);

            // Result = regs_after[reg_d] (destination for three-reg, or reg_a for others)
            let dest_reg = if step.reg_d != 0 || matches!(step.opcode.category(), javm::instruction::InstructionCategory::ThreeReg) {
                step.reg_d
            } else {
                step.reg_a
            };
            let result = step.regs_after[dest_reg];
            trace.fill_columns(row, result, Column::Result);

            // Carry flags for Add64: result = val_b + val_d
            let val_b_bytes = step.regs_before[step.reg_a].to_le_bytes();
            let val_d_bytes = step.regs_before[step.reg_b].to_le_bytes();
            let result_bytes = result.to_le_bytes();
            let mut carry = [0u8; WORD_SIZE];
            let mut c: u16 = 0;
            for i in 0..WORD_SIZE {
                let sum = val_b_bytes[i] as u16 + val_d_bytes[i] as u16 + c;
                carry[i] = (sum >> 8) as u8;
                c = carry[i] as u16;
            }
            trace.fill_columns_bytes(row, &carry, Column::Carry);

            trace.fill_columns(row, false, Column::IsPadding);

            trace.fill_columns(row, step.timestamp, Column::RegAReadTs);
            trace.fill_columns(row, step.timestamp, Column::RegBReadTs);
            trace.fill_columns(row, step.timestamp, Column::RegDReadTs);

            let written = step.reg_write.is_some();
            trace.fill_columns(row, written, Column::RegAWritten);

            trace.fill_columns(row, step.gas_after, Column::Gas);

            let is_add64 = step.opcode == javm::instruction::Opcode::Add64;
            trace.fill_columns(row, is_add64, Column::IsAdd64);

            // Range checks: only result bytes (must match constraint contributions)
            for &b in &result_bytes {
                range_bytes.push(b);
            }
        }

        // Apply range checks
        for &b in &range_bytes {
            side_note.add_range256(b);
        }

        // Fill padding rows
        let last_ts = side_note.steps.last().map(|s| s.timestamp).unwrap_or(0);
        for row in num_steps..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
            let ts = last_ts + (row - num_steps + 1) as u64;
            trace.fill_columns(row, ts, Column::Timestamp);
        }

        trace.finalize()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: ComponentTrace,
        _side_note: &SideNote,
        lookup_elements: &AllLookupElements,
    ) -> (
        ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
        SecureField,
    ) {
        let log_size = component_trace.log_size();
        let mut logup = LogupTraceBuilder::new(log_size);

        let is_pad = zkpvm_trace::original_base_column!(component_trace, Column::IsPadding);
        let range256: &Range256LookupElements = lookup_elements.as_ref();

        // Range256 lookups for result bytes (positive contribution: mult = 1 - is_pad)
        let result = zkpvm_trace::original_base_column!(component_trace, Column::Result);
        for col in &result {
            logup.add_to_relation_with(
                range256,
                [is_pad[0].clone()],
                |[pad]| {
                    use stwo::prover::backend::simd::m31::PackedBaseField;
                    (PackedBaseField::one() - pad).into()
                },
                &[col.clone()],
            );
        }

        logup.finalize()
    }

    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &Range256LookupElements,
    ) {
        let is_pad = zkpvm_trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();
        let is_add64 = zkpvm_trace::trace_eval!(trace_eval, Column::IsAdd64);

        // --- Add64 constraint (gated on IsAdd64 flag) ---
        let val_b = zkpvm_trace::trace_eval!(trace_eval, Column::ValB);
        let val_d = zkpvm_trace::trace_eval!(trace_eval, Column::ValD);
        let result = zkpvm_trace::trace_eval!(trace_eval, Column::Result);
        let carry = zkpvm_trace::trace_eval!(trace_eval, Column::Carry);

        let f256 = E::F::from(BaseField::from(256u32));

        for i in 0..WORD_SIZE {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                carry[i - 1].clone()
            };
            let constraint = result[i].clone() + carry[i].clone() * f256.clone()
                - val_b[i].clone()
                - val_d[i].clone()
                - carry_in;
            eval.add_constraint(is_add64[0].clone() * constraint);
        }

        // Range256 checks for result byte limbs
        for i in 0..WORD_SIZE {
            eval.add_to_relation(RelationEntry::new(
                lookup_elements,
                is_real.clone().into(),
                &[result[i].clone()],
            ));
        }

        eval.finalize_logup_in_pairs();
    }
}

