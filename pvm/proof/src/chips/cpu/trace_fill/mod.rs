//! CpuChip main-trace generation.
//!
//! Holds the per-step witness fill: for every traced PVM step, write
//! the corresponding row of every CpuChip column.  The column shapes
//! mirror the constraints defined in `cpu/constraints/`
//! one-to-one — if you add a column there, the fill for it lives
//! here.
//!
//! Lookup multiplicities (`SideNote::range256_counts`,
//! `bitwise_and_counts`, `power_of_two_counts`, `popcount_counts`,
//! `bitcount_counts`, `program_memory_counts`, `jump_table_counts`)
//! are charged here as a side-effect of writing the consumer rows;
//! the producer chips read them in `generate_main_trace`.

use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::simd::m31::LOG_N_LANES;

use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_WITNESS_INPUT};
use crate::core::step::{PvmStep, WORD_SIZE};
use crate::side_note::SideNote;
use crate::trace::builder::{FinalizedTrace, TraceBuilder};

use super::classify::{OpcodeFlags, classify_opcode, dest_reg, uses_immediate};
use super::columns::Column;
use super::reg_access::{StepRegAccesses, access_shape, step_reg_accesses};

mod alu;
mod bitmanip;
mod compare;
mod control;
mod divrem;
mod helpers;
mod host_call;
mod memory;
mod operands;
mod shift;

use bitmanip::BitCounts;
use compare::Compare;
use divrem::DivRem;
use host_call::HostCall;
use operands::Operands;
use shift::Shift;

/// What a row's fill writes: the trace, the side note's records and
/// counts, and the lookups counted once the rows are filled.
struct Sinks<'a> {
    trace: &'a mut TraceBuilder<Column>,
    side_note: &'a mut SideNote,
    range_bytes: &'a mut Vec<u8>,
    bitwise_and_bytes: &'a mut Vec<(u8, u8)>,
}

/// The step a row holds, and its instruction's flags.
#[derive(Clone, Copy)]
struct Step<'a> {
    row: usize,
    step: &'a PvmStep,
    flags: OpcodeFlags,
}

/// Carry chain for `NextTimestamp = Timestamp + 1`: carry i is 1 iff
/// limbs 0..=i of `ts` are all 0xff (the increment overflows through
/// them).  Limb 7 has no outgoing carry.
fn fill_ts_carry(trace: &mut TraceBuilder<Column>, row: usize, ts: u64) {
    let mut carry = [0u8; 7];
    let mut all_ff = true;
    for (i, c) in carry.iter_mut().enumerate() {
        all_ff = all_ff && ((ts >> (8 * i)) & 0xff) == 0xff;
        *c = all_ff as u8;
    }
    trace.fill_columns_bytes(row, &carry, Column::TsCarry);
}

pub(super) fn generate_main_trace(side_note: &mut SideNote, min_log_size: u32) -> FinalizedTrace {
    let num_steps = side_note.num_steps();
    let log_size = (num_steps as f64).log2().ceil().max(LOG_N_LANES as f64) as u32;
    let log_size = log_size.max(LOG_N_LANES).max(min_log_size);

    let mut trace = TraceBuilder::<Column>::new(log_size);
    let num_rows = trace.num_rows();
    let mut range_bytes: Vec<u8> = Vec::new();
    let mut bitwise_and_bytes: Vec<(u8, u8)> = Vec::new();

    let steps = core::mem::take(&mut side_note.steps);
    let mut out = Sinks {
        trace: &mut trace,
        side_note,
        range_bytes: &mut range_bytes,
        bitwise_and_bytes: &mut bitwise_and_bytes,
    };
    for (row, step) in steps.iter().enumerate() {
        let flags = classify_opcode(step.opcode);
        fill_row(&mut out, Step { row, step, flags });
    }
    side_note.steps = steps;

    for &b in &range_bytes {
        side_note.add_range256(b);
    }
    for &(a, b) in &bitwise_and_bytes {
        side_note.add_bitwise_and(a, b);
    }

    // Diagnostic scaffolding.  Set CPU_DUMP=1 in the env to dump
    // row-0 + row-1 helper values to stderr; useful for spot-checking
    // that witness fill matches expected algebraic values.
    if std::env::var("CPU_DUMP").is_ok() {
        use crate::air_column::AirColumn;
        let cols_to_dump: &[(&str, Column)] = &[
            ("IsReal", Column::IsPadding), // is_real = 1 - is_padding
            ("IsAdd", Column::IsAdd),
            ("Is32Bit", Column::Is32Bit),
            ("IsTruncated", Column::IsTruncated),
            ("ValBIsReg", Column::ValBIsReg),
            ("ValDIsReg", Column::ValDIsReg),
            ("Phi7Bool", Column::Phi7Bool),
            ("IsAdd64bitH", Column::IsAdd64bitH),
            ("Real32bitH", Column::Real32bitH),
            ("ValBIsRegH", Column::ValBIsRegH),
            ("ValBIsRegNotTruncH", Column::ValBIsRegNotTruncH),
            ("ValDIsImmH", Column::ValDIsImmH),
            ("NonShiftGateH", Column::NonShiftGateH),
            ("NonShiftGateNotTruncH", Column::NonShiftGateNotTruncH),
            ("RealNotPhi7BoolH", Column::RealNotPhi7BoolH),
            ("RealPhi7BoolH", Column::RealPhi7BoolH),
            ("Phi7TimesInvH", Column::Phi7TimesInvH),
            ("IsRealTrapH", Column::IsRealTrapH),
            ("Is64bitPopcountHiH", Column::Is64bitPopcountHiH),
            ("DivSActivePartialH", Column::DivSActivePartialH),
            ("IsDivSNotDbzH", Column::IsDivSNotDbzH),
            ("IsShiftCNotRotrH", Column::IsShiftCNotRotrH),
            ("ValDByteIndicatorH", Column::ValDByteIndicatorH),
            ("ValDByteIndMinus1H", Column::ValDByteIndMinus1H),
            ("PartNZTimesIndH", Column::PartNZTimesIndH),
            ("ValDPartialNZ", Column::ValDPartialNZ),
            ("ValDByteInv", Column::ValDByteInv),
            ("ValD", Column::ValD),
            ("ValB", Column::ValB),
            ("CmpLtFlag", Column::CmpLtFlag),
            ("CmpLtSFlag", Column::CmpLtSFlag),
            ("EqFlag", Column::EqFlag),
            ("BranchTaken", Column::BranchTaken),
            ("ValDIsZero", Column::ValDIsZero),
            ("DivByZero", Column::DivByZero),
            ("SignsDiffH", Column::SignsDiffH),
            ("IsCmpVdzH", Column::IsCmpVdzH),
            ("CpuDivActiveH", Column::CpuDivActiveH),
            ("GateDivH", Column::GateDivH),
            ("GateRemH", Column::GateRemH),
            ("DivActiveQuotH", Column::DivActiveQuotH),
            ("DivActiveRemH", Column::DivActiveRemH),
            ("DivRemOp", Column::DivRemOp),
            ("IsDivRem", Column::IsDivRem),
            ("IsDivRemTimesVdzH", Column::IsDivRemTimesVdzH),
            ("DbzActiveH", Column::DbzActiveH),
            ("DbzActiveQuotH", Column::DbzActiveQuotH),
            ("DbzActiveRemH", Column::DbzActiveRemH),
            ("DbzActiveRem64H", Column::DbzActiveRem64H),
            ("CmpLtValBH", Column::CmpLtValBH),
            ("CmpLtValDH", Column::CmpLtValDH),
            ("IsBranchTakenH", Column::IsBranchTakenH),
            ("IsCmovIzVdzH", Column::IsCmovIzVdzH),
            ("IsCmovNzNotVdzH", Column::IsCmovNzNotVdzH),
            ("IsCmpOrBranchEqH", Column::IsCmpOrBranchEqH),
            ("MemByteActive", Column::MemByteActive),
            ("MemByteActiveMonoH", Column::MemByteActiveMonoH),
            ("MemAddrCarry", Column::MemAddrCarry),
            ("IsLoadLocalNotActiveH", Column::IsLoadLocalNotActiveH),
            ("IsImmAltNotTruncH", Column::IsImmAltNotTruncH),
            ("IsImmAltTruncH", Column::IsImmAltTruncH),
            ("Is32ShiftCH", Column::Is32ShiftCH),
            ("ValDPartialNZMsb", Column::ValDPartialNZMsb),
            ("ValDPartialNZMsbLo", Column::ValDPartialNZMsbLo),
            ("PartNZMsbTimesIndH", Column::PartNZMsbTimesIndH),
            ("PartNZMsbLoTimesIndH", Column::PartNZMsbLoTimesIndH),
            ("TzLo4H", Column::TzLo4H),
            ("TzHi4H", Column::TzHi4H),
            ("Lz64H", Column::Lz64H),
            ("Lz32H", Column::Lz32H),
            ("IsTzb64H", Column::IsTzb64H),
            ("IsTzb32H", Column::IsTzb32H),
            ("IsLzb64H", Column::IsLzb64H),
            ("IsLzb32H", Column::IsLzb32H),
            ("ValRPartialNZ", Column::ValRPartialNZ),
            ("ValRByteInv", Column::ValRByteInv),
            ("ValRByteIndicatorH", Column::ValRByteIndicatorH),
            ("ValRByteIndMinus1H", Column::ValRByteIndMinus1H),
            ("ValRPartNZTimesIndH", Column::ValRPartNZTimesIndH),
            ("DivRemainder", Column::DivRemainder),
            ("IsAdd32bitH", Column::IsAdd32bitH),
            ("IsSubNotNegaddH", Column::IsSubNotNegaddH),
            ("IsSubNegaddH", Column::IsSubNegaddH),
            ("IsSub64NotNegaddH", Column::IsSub64NotNegaddH),
            ("IsSub64NegaddH", Column::IsSub64NegaddH),
            ("IsSub32bitH", Column::IsSub32bitH),
            ("IsMul32bitH", Column::IsMul32bitH),
            ("IsDivRem32bitH", Column::IsDivRem32bitH),
        ];
        for &(name, col) in cols_to_dump {
            let off = col.offset();
            let sz = col.size();
            eprint!("DUMP row 0 {}: ", name);
            for k in 0..sz {
                let v = trace.cols[off + k][0];
                eprint!("[{}]={:?} ", k, v);
            }
            eprintln!();
        }
        // Also dump row 1.
        for &(name, col) in cols_to_dump {
            let off = col.offset();
            let sz = col.size();
            eprint!("DUMP row 1 {}: ", name);
            for k in 0..sz {
                let v = trace.cols[off + k][1];
                eprint!("[{}]={:?} ", k, v);
            }
            eprintln!();
        }
    }

    let last_ts = side_note.steps.last().map(|s| s.timestamp).unwrap_or(0);
    for row in num_steps..num_rows {
        let ts = last_ts + (row - num_steps + 1) as u64;
        trace.fill_columns(row, true, Column::IsPadding);
        trace.fill_columns(row, ts, Column::Timestamp);
        trace.fill_columns(row, ts + 1, Column::NextTimestamp);
        fill_ts_carry(&mut trace, row, ts);
        // Its six zero flag bytes, looked up as every row's are.
        side_note.byte_to_bits_counts[0] += 6;
        // GateDivH = (DivRemOp - 2)·(DivRemOp - 3).  Constraint is
        // unconditional (no is_real gate); on padding rows DivRemOp = 0,
        // so GateDivH must be filled with (0 - 2)·(0 - 3) = 6.  Other
        // helpers reduce to zero when their cofactors are zero on
        // padding, so they don't need an explicit fill.
        trace.fill_columns_base_field(
            row,
            &[stwo::core::fields::m31::BaseField::from(6u32)],
            Column::GateDivH,
        );
    }

    trace.finalize_bit_reversed()
}

/// The low `N` bits of `value`, least significant first.
fn bits<const N: usize>(value: u64) -> [u8; N] {
    debug_assert!(value >> N == 0, "{value} exceeds {N} bits");
    core::array::from_fn(|i| ((value >> i) & 1) as u8)
}

/// One step's row, section by section.
fn fill_row(out: &mut Sinks, s: Step) {
    let ops = operands::operands(out, s);
    alu::add_sub(out, s, &ops);
    let mul = alu::mul(s, &ops);
    alu::bitwise(out, s, &ops);
    let cmp = compare::compare(out, s, &ops);
    alu::mul_entry(out, s, &ops, &mul, &cmp);
    let shift = shift::shift(out, s, &ops);
    operands::flag_columns(out, s);
    let branch_taken = control::branch(out, s, &cmp);
    control::jumps(out, s, &ops);
    bitmanip::sign_extend(out, s, &ops);
    let div = divrem::divrem(out, s, &ops);
    compare::sign_nibbles(out, s, &ops, &cmp, &div);
    memory::memory_flags(out, s);
    let counts = bitmanip::bit_counts(out, s, &ops);
    memory::memory(out, s, &ops);
    let host = host_call::host_call(out, s, &ops);
    let accesses = operands::register_accesses(out, s, &ops);
    helpers::helpers(out, s, &ops, &cmp, &div, &counts, branch_taken);
    let is_truncated = operands::register_values(out, s, &shift, &accesses);
    operands::range_checks(out, s, &ops, &cmp);
    operands::flag_bytes(out, s);
    helpers::selectors(out, s, &shift, &host, &accesses, is_truncated);
    helpers::residual(out, s, &shift, &div, &counts);
    host_call::disposition(out, s);
}
