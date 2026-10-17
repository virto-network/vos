#![cfg(feature = "debug-internals")]

//! Negative AIR gates for CpuChip's arithmetic, control flow, padding and
//! store values, and for the instruction table it fetches from.
//!
//! Every forgery is a malicious prover's edit of an honest trace,
//! consistent with every constraint that does not bind the column it
//! changes; the ledgers and lookup tables follow whatever the forged rows
//! claim, as a forger would build them. A gate whose refusal is a chip's
//! own constraint checks that chip; one whose refusal is a lookup's checks
//! the logup balance of every chip.

use stwo::core::channel::Blake2sChannel;
use stwo::core::fields::m31::BaseField;
use vos_pvm::PVM_REGISTER_COUNT;
use vos_pvm::instruction::Opcode;
use vos_pvm::interpreter::Interpreter;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::SideNote;
use vos_pvm_proof::chips::cpu::Column as Cpu;
use vos_pvm_proof::chips::program_memory::Column as ProgramMemory;
use vos_pvm_proof::chips::register_memory::Column as Ledger;
use vos_pvm_proof::chips::{CpuChip, ProgramMemoryChip};
use vos_pvm_proof::core::tracing::{ECALL_BLAKE2B_COMPRESS, TracingPvm};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::harness::{MachineProverComponent, base_components};
use vos_pvm_proof::trace::component::ComponentTrace;

/// The forgery targets, one instruction each, φ1 = 100, φ2 = 7 and
/// φ3 = φ4 = 42:
///
/// ```text
///    0  Add64        φ5 = φ1 + φ2
///    3  Min          φ6 = min(φ1, φ2)
///    6  Max          φ7 = max(φ1, φ2)
///    9  BranchEq     φ3 = φ4 → 13           (taken)
///   12  Trap
///   13  BranchNe     φ3 ≠ φ4 → 20           (not taken)
///   16  BranchLeUImm φ3 ≤ 42 → 21           (taken)
///   20  Trap
///   21  StoreImmU64  [0x2_0000] = −2^31 + 1
///   30  Trap
/// ```
fn side_note() -> SideNote {
    let instructions: [&[u8]; 10] = [
        &[Opcode::Add64 as u8, 0x21, 5],
        &[Opcode::Min as u8, 0x21, 6],
        &[Opcode::Max as u8, 0x21, 7],
        &[Opcode::BranchEq as u8, 0x43, 4],
        &[Opcode::Trap as u8],
        &[Opcode::BranchNe as u8, 0x43, 7],
        &[Opcode::BranchLeUImm as u8, 0x13, 42, 5],
        &[Opcode::Trap as u8],
        &[
            Opcode::StoreImmU64 as u8,
            3,
            0x00,
            0x00,
            0x02,
            0x01,
            0x00,
            0x00,
            0x80,
        ],
        &[Opcode::Trap as u8],
    ];
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    for instruction in instructions {
        bitmask.push(1);
        bitmask.extend(std::iter::repeat_n(0, instruction.len() - 1));
        code.extend_from_slice(instruction);
    }
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[1] = 100;
    registers[2] = 7;
    registers[3] = 42;
    registers[4] = 42;
    let memory = vec![0; 0x3_0000];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        registers,
        memory.clone(),
        10_000,
    );
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), vos_pvm::ExitReason::Panic);
    let steps = tracer.into_trace();
    let pcs: Vec<u32> = steps.iter().map(|step| step.pc).collect();
    assert_eq!(pcs, [0, 3, 6, 9, 13, 16, 21, 30]);
    assert_eq!(steps[0].regs_after[5], 107);
    assert_eq!(steps[1].regs_after[6], 7);
    assert_eq!(steps[2].regs_after[7], 100);
    let store = steps[6].mem_write.as_ref().expect("the store");
    assert_eq!(store.value, 0xffff_ffff_8000_0001);
    SideNote::new(steps, code, bitmask)
        .with_initial_regs(registers)
        .with_memory(memory)
}

fn assert_chip<C: MachineProverComponent + ?Sized>(
    chip: &C,
    trace: &ComponentTrace,
    side_note: &SideNote,
) {
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    chip.draw_lookup_elements(&mut lookup_elements, channel.into());
    let (interaction_trace, claimed_sum) =
        chip.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
    chip.debug_assert_constraints(trace, &interaction_trace, &lookup_elements, claimed_sum);
}

/// Stwo's assertion evaluator panics before finalizing its LogupAtRow when a
/// constraint fails, whose Drop guard aborts a double panic: the forged
/// trace runs in a child process, and refusal is its failure. `true` in
/// the child, which goes on to the forgery.
fn in_child(test_name: &str) -> bool {
    const CHILD: &str = "VOS_CPU_SOUNDNESS_GATE_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let status = std::process::Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg(test_name)
        .env(CHILD, "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run the forged trace in a child process");
    assert!(
        !status.success(),
        "SOUNDNESS GAP: the forged trace was accepted"
    );
    false
}

/// Where a trace of `log_size` keeps its logical row `row`: the trace
/// builder stores rows in the circle domain's bit-reversed order.
fn stored(log_size: u32, row: usize) -> usize {
    let rows: Vec<BaseField> = (0..1u32 << log_size).map(BaseField::from).collect();
    let order = vos_pvm_proof::trace::utils::finalize_columns(vec![rows]);
    order[0]
        .as_slice()
        .iter()
        .position(|&at| at == BaseField::from(row as u32))
        .expect("a row of the trace")
}

fn set_field(trace: &mut ComponentTrace, offset: usize, row: usize, value: BaseField) {
    let at = stored(trace.log_size, row);
    trace.original_trace[offset].as_mut_slice()[at] = value;
}

fn set(trace: &mut ComponentTrace, offset: usize, row: usize, value: u32) {
    set_field(trace, offset, row, BaseField::from(value));
}

fn get(trace: &ComponentTrace, offset: usize, row: usize) -> BaseField {
    trace.original_trace[offset].as_slice()[stored(trace.log_size, row)]
}

fn set_bytes(trace: &mut ComponentTrace, column: Cpu, row: usize, bytes: &[u8]) {
    for (i, &byte) in bytes.iter().enumerate() {
        set(trace, column.offset() + i, row, byte.into());
    }
}

/// The real row of the step at `pc`.
fn row_at(trace: &ComponentTrace, pc: u32) -> usize {
    (0..1usize << trace.log_size)
        .find(|&row| {
            get(trace, Cpu::IsPadding.offset(), row) == BaseField::from(0u32)
                && (0..4).all(|i| {
                    get(trace, Cpu::Pc.offset() + i, row) == BaseField::from((pc >> (8 * i)) & 0xff)
                })
        })
        .expect("the step's row")
}

/// Forge CpuChip's row of the step at `pc` with `edit`; CpuChip refuses it.
fn forge(test_name: &str, pc: u32, edit: impl FnOnce(&mut ComponentTrace, usize)) {
    forge_with(test_name, side_note(), |trace| {
        let row = row_at(trace, pc);
        edit(trace, row);
    });
}

fn forge_with(test_name: &str, mut side_note: SideNote, edit: impl FnOnce(&mut ComponentTrace)) {
    let mut trace = CpuChip.generate_component_trace(&mut side_note);
    assert_chip(&CpuChip, &trace, &side_note);
    if !in_child(test_name) {
        return;
    }
    edit(&mut trace);
    assert_chip(&CpuChip, &trace, &side_note);
}

// ── H-CARRY ────────────────────────────────────────────────────────────

/// `Add64 φ5 = φ1 + φ2` writing 999, its carries solved byte by byte in the
/// field: `c_i = (b_i + d_i + c_{i−1} − r_i) / 256`. Every byte identity
/// holds and every result byte is a byte, so only the carries' booleanity
/// refuses it.
#[test]
fn an_add_s_carries_are_bits() {
    forge("an_add_s_carries_are_bits", 0, |trace, row| {
        let forged = 999u64.to_le_bytes();
        set_bytes(trace, Cpu::Result, row, &forged);
        let inverse = BaseField::from(256u32).inverse();
        let mut carry = BaseField::from(0u32);
        for (i, &result) in forged.iter().enumerate() {
            let sum = get(trace, Cpu::ValB.offset() + i, row)
                + get(trace, Cpu::ValD.offset() + i, row)
                + carry;
            carry = (sum - BaseField::from(u32::from(result))) * inverse;
            set_field(trace, Cpu::Carry.offset() + i, row, carry);
        }
    });
}

// ── H-PADEMIT ──────────────────────────────────────────────────────────

/// A padding row writing φ2 := 100 at timestamp 1: its result-write flag
/// set, the flag byte that recomposes it set to match, its result and
/// register those of the write. The register ledger then holds a write no
/// step made.
#[test]
fn a_padding_row_emits_nothing() {
    forge_with("a_padding_row_emits_nothing", side_note(), |trace| {
        let row = (0..1usize << trace.log_size)
            .find(|&row| get(trace, Cpu::IsPadding.offset(), row) == BaseField::from(1u32))
            .expect("a padding row");
        set_bytes(trace, Cpu::Timestamp, row, &1u64.to_le_bytes());
        set(trace, Cpu::ResultIsReg.offset(), row, 1);
        set(trace, Cpu::RegA.offset(), row, 2);
        set(trace, Cpu::ResultRegIdx.offset(), row, 2);
        set_bytes(trace, Cpu::Result, row, &100u64.to_le_bytes());
        set(trace, Cpu::FlagByte6.offset(), row, 8);
    });
}

/// `Add64` with `IsPadding = 2`: its realness `1 − IsPadding` is −1, which
/// turns its step's consumption of `(ts, pc)` into a production. Every
/// helper the realness multiplies changes sign with it, so every
/// constraint homogeneous in the realness still holds.
#[test]
fn padding_is_a_bit() {
    forge("padding_is_a_bit", 0, |trace, row| {
        set(trace, Cpu::IsPadding.offset(), row, 2);
        for column in [
            Cpu::Real32bitH,
            Cpu::ValBIsRegH,
            Cpu::ValBIsRegNotTruncH,
            Cpu::ValBIsRegTruncH,
            Cpu::ValDIsImmH,
            Cpu::NonShiftGateH,
            Cpu::NonShiftGateNotTruncH,
            Cpu::NonShiftGateTruncH,
            Cpu::RealShiftCH,
            Cpu::IsRotateRGateH,
            Cpu::RealNotPhi7BoolH,
            Cpu::RealPhi7BoolH,
            Cpu::IsRealTrapH,
        ] {
            let value = get(trace, column.offset(), row);
            set_field(trace, column.offset(), row, -value);
        }
    });
}

/// `IsPadding = 2` on a padding row, whose flag bytes are zero, so no
/// flag-zeroing constraint can refuse it: its realness is −1 and every
/// helper the realness multiplies is negated. Its `(ts, pc)` consumption
/// becomes a production, its instruction fetch a production of the zero
/// tuple at its pc. Only the booleanity of `IsPadding` refuses it.
#[test]
fn padding_is_a_bit_on_a_padding_row() {
    forge_with("padding_is_a_bit_on_a_padding_row", side_note(), |trace| {
        // The last row: its predecessor is padding too, so no Trap's
        // terminal check sees it; its realness −1 revives the val_d
        // zero-test, which it satisfies with ValDIsZero = 1 (val_d is 0).
        let row = (1usize << trace.log_size) - 1;
        assert_eq!(
            get(trace, Cpu::IsPadding.offset(), row),
            BaseField::from(1u32)
        );
        assert_eq!(
            get(trace, Cpu::IsPadding.offset(), row - 1),
            BaseField::from(1u32)
        );
        set(trace, Cpu::IsPadding.offset(), row, 2);
        set(trace, Cpu::ValDIsZero.offset(), row, 1);
        // Its realness −1 revives the sequential-pc chain: pc 0 continues at 1.
        set(trace, Cpu::NextPc.offset(), row, 1);
        // The helpers the realness multiplies, as their definitions give
        // them at realness −1 on a row whose every flag is 0.
        let minus_one = -BaseField::from(1u32);
        for column in [
            Cpu::ValDIsImmH,
            Cpu::NonShiftGateH,
            Cpu::NonShiftGateNotTruncH,
            Cpu::RealNotPhi7BoolH,
        ] {
            set_field(trace, column.offset(), row, minus_one);
        }
    });
}

// ── H-BREQ ─────────────────────────────────────────────────────────────

/// `BranchEq φ3 = φ4` on equal operands falling through to 12.
#[test]
fn an_equal_branch_eq_is_taken() {
    forge("an_equal_branch_eq_is_taken", 9, |trace, row| {
        set(trace, Cpu::BranchTaken.offset(), row, 0);
        set(trace, Cpu::IsBranchTakenH.offset(), row, 0);
        set_bytes(trace, Cpu::NextPc, row, &12u32.to_le_bytes());
    });
}

/// `BranchNe φ3 ≠ φ4` on equal operands jumping to 20.
#[test]
fn an_equal_branch_ne_falls_through() {
    forge("an_equal_branch_ne_falls_through", 13, |trace, row| {
        set(trace, Cpu::BranchTaken.offset(), row, 1);
        set(trace, Cpu::IsBranchTakenH.offset(), row, 1);
        set_bytes(trace, Cpu::NextPc, row, &20u32.to_le_bytes());
    });
}

/// `BranchLeUImm φ3 ≤ 42` on equal operands claiming them unequal, so it
/// falls through to 20.
#[test]
fn equal_operands_are_equal() {
    forge("equal_operands_are_equal", 16, |trace, row| {
        set(trace, Cpu::EqFlag.offset(), row, 0);
        set(trace, Cpu::IsCmpOrBranchEqH.offset(), row, 0);
        set(trace, Cpu::BranchTaken.offset(), row, 0);
        set(trace, Cpu::IsBranchTakenH.offset(), row, 0);
        set_bytes(trace, Cpu::NextPc, row, &20u32.to_le_bytes());
    });
}

// ── H-MINMAX ───────────────────────────────────────────────────────────

/// `Min φ6 = min(φ1, φ2)` writing 999.
#[test]
fn a_signed_min_is_its_lesser_operand() {
    forge("a_signed_min_is_its_lesser_operand", 3, |trace, row| {
        set_bytes(trace, Cpu::Result, row, &999u64.to_le_bytes());
    });
}

/// `Max φ7 = max(φ1, φ2)` writing 0xdead_beef.
#[test]
fn a_signed_max_is_its_greater_operand() {
    forge("a_signed_max_is_its_greater_operand", 6, |trace, row| {
        set_bytes(trace, Cpu::Result, row, &0xdead_beefu64.to_le_bytes());
    });
}

// ── H-STIMM64 ──────────────────────────────────────────────────────────

/// `StoreImmU64` storing 0xdead_beef in the high word of −2^31 + 1.
#[test]
fn a_store_immediate_s_high_word_is_the_instruction_s() {
    forge(
        "a_store_immediate_s_high_word_is_the_instruction_s",
        21,
        |trace, row| {
            for (i, byte) in [0xef, 0xbe, 0xad, 0xde].into_iter().enumerate() {
                set(trace, Cpu::MemValue.offset() + 4 + i, row, byte);
            }
        },
    );
}

// ── H-TRAPPC ───────────────────────────────────────────────────────────

/// The trap at 30 continuing at the halt address, so the segment's final
/// pc presents its panic as a halt.
#[test]
fn a_trap_stays_at_its_pc() {
    forge("a_trap_stays_at_its_pc", 30, |trace, row| {
        set_bytes(trace, Cpu::NextPc, row, &0xffff_0000u32.to_le_bytes());
    });
}

// ── L-PCCARRY ──────────────────────────────────────────────────────────

/// `Add64` at 0 continuing at 3 written with a carry of 2 out of its low
/// byte: `(3 − 512, 2, 0, 0)`, the same field value in other limbs.
#[test]
fn a_pc_carry_is_a_bit() {
    forge("a_pc_carry_is_a_bit", 0, |trace, row| {
        set(trace, Cpu::PcCarry.offset(), row, 2);
        set_field(
            trace,
            Cpu::NextPc.offset(),
            row,
            BaseField::from(3u32) - BaseField::from(512u32),
        );
        set(trace, Cpu::NextPc.offset() + 1, row, 2);
    });
}

// ── G4-4 ───────────────────────────────────────────────────────────────

/// A BLAKE2b compression of the state at `H` with the zero block at
/// `H + 64`, written back to `H`, then a trap.
fn blake2b_side_note() -> SideNote {
    const H: u64 = 0x2_0000;
    let memory = vec![0u8; 0x3_0000];
    let mut code = vec![Opcode::Ecalli as u8];
    code.extend_from_slice(&ECALL_BLAKE2B_COMPRESS.to_le_bytes());
    code.push(Opcode::Trap as u8);
    let mut bitmask = vec![0; code.len()];
    bitmask[0] = 1;
    bitmask[code.len() - 1] = 1;
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    registers[7] = H;
    registers[8] = H + 64;
    registers[10] = 1;
    let pvm = Interpreter::new(code, bitmask, vec![], registers, memory.clone(), 10_000);
    let mut tracer = TracingPvm::new(pvm);
    let _ = tracer.run_with_precompiles();
    tracer
        .into_side_note()
        .with_initial_regs(registers)
        .with_memory(memory)
}

/// The compression's `h` pointer φ7 read as `2^32 + H`: the machine refuses
/// a pointer past 32 bits, so its call is not served, but the call's tuple
/// carries the pointer's low four bytes only.
#[test]
fn a_compression_s_pointers_are_32_bit() {
    forge_with(
        "a_compression_s_pointers_are_32_bit",
        blake2b_side_note(),
        |trace| {
            let row = row_at(trace, 0);
            assert_eq!(
                get(trace, Cpu::IsBlakeEcall.offset(), row),
                BaseField::from(1u32)
            );
            set(trace, Cpu::Phi10.offset() + 4, row, 1);
        },
    );
}

// ── H-NOOP ─────────────────────────────────────────────────────────────

/// The instruction table serving the zero tuple at pc 1, inside `Add64`'s
/// encoding: a step fetching it, its opcode 0 and every flag 0, is a no-op
/// that only advances its pc.
#[test]
fn only_an_instruction_start_is_fetched() {
    let mut side_note = side_note();
    let _ = CpuChip.generate_component_trace(&mut side_note);
    let mut trace = ProgramMemoryChip.generate_component_trace(&mut side_note);
    assert_chip(&ProgramMemoryChip, &trace, &side_note);
    if !in_child("only_an_instruction_start_is_fetched") {
        return;
    }
    let at = stored(trace.log_size, 1);
    trace.original_trace[ProgramMemory::Multiplicity.offset()].as_mut_slice()[at] =
        BaseField::from(2u32);
    assert_chip(&ProgramMemoryChip, &trace, &side_note);
}

// ── L-TSLIMB ───────────────────────────────────────────────────────────

/// 300 `Fallthrough`s, then a trap: steps with no register or memory
/// access, at timestamps 1 to 301.
fn fallthrough_side_note() -> SideNote {
    let mut code = vec![Opcode::Fallthrough as u8; 300];
    code.push(Opcode::Trap as u8);
    let bitmask = vec![1; code.len()];
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        [0; PVM_REGISTER_COUNT],
        vec![0; 1 << 16],
        10_000,
    );
    let mut tracer = TracingPvm::new(pvm);
    assert_eq!(tracer.run(), vos_pvm::ExitReason::Panic);
    let mut side_note = tracer.into_side_note();
    vos_pvm_proof::prepare_side_note_for_verification(&mut side_note);
    side_note.ingest_memory_pages();
    side_note
}

/// The step at timestamp 255 hands its successor the timestamp 256 as the
/// limbs `(256, 0, …)` rather than `(0, 1, …)`: the same field value, its
/// carry withheld, its successor carrying it on. Each row's carry chain
/// holds, and the two rows' `(ts, pc)` tuples still meet, so only a range
/// check on the limbs refuses it, a lookup: the gate checks every chip and
/// the logup balance of the whole trace.
#[test]
fn a_timestamp_s_limbs_are_bytes() {
    let mut side_note = fallthrough_side_note();
    let components = base_components();
    let mut traces: Vec<ComponentTrace> = components
        .iter()
        .map(|component| component.generate_component_trace(&mut side_note))
        .collect();
    assert!(accepts(components, &traces, &side_note), "the honest trace");
    if !in_child("a_timestamp_s_limbs_are_bytes") {
        return;
    }
    let cpu = &mut traces[0];
    let row = (0..1usize << cpu.log_size)
        .find(|&row| {
            get(cpu, Cpu::IsPadding.offset(), row) == BaseField::from(0u32)
                && get(cpu, Cpu::Timestamp.offset(), row) == BaseField::from(255u32)
        })
        .expect("the step at timestamp 255");
    set(cpu, Cpu::NextTimestamp.offset(), row, 256);
    set(cpu, Cpu::NextTimestamp.offset() + 1, row, 0);
    set(cpu, Cpu::TsCarry.offset(), row, 0);
    let successor = row + 1;
    assert_eq!(
        get(cpu, Cpu::Timestamp.offset() + 1, successor),
        BaseField::from(1u32)
    );
    set(cpu, Cpu::Timestamp.offset(), successor, 256);
    set(cpu, Cpu::Timestamp.offset() + 1, successor, 0);
    set(cpu, Cpu::TsCarry.offset(), successor, 1);
    // The successor's register reads carry its limbs into the register
    // ledger, which orders by their field value, unchanged.
    let ledger = &mut traces[vos_pvm_proof::chip_idx::REGISTER_MEMORY];
    let mut moved = 0;
    for row in 0..1usize << ledger.log_size {
        let ts = Ledger::Ts0.offset();
        if get(ledger, ts, row) == BaseField::from(0u32)
            && get(ledger, ts + 1, row) == BaseField::from(1u32)
            && get(ledger, Ledger::IsPadding.offset(), row) == BaseField::from(0u32)
        {
            set(ledger, ts, row, 256);
            set(ledger, ts + 1, row, 0);
            moved += 1;
        }
    }
    assert_eq!(moved, 2, "the successor's two register reads");
    assert!(accepts(components, &traces, &side_note));
}

/// Whether every chip's constraints hold on `traces` and their logup sums
/// balance.
fn accepts(
    components: &[&dyn MachineProverComponent],
    traces: &[ComponentTrace],
    side_note: &SideNote,
) -> bool {
    use num_traits::Zero;
    let mut lookup_elements = AllLookupElements::default();
    let channel = &mut Blake2sChannel::default();
    for component in components {
        component.draw_lookup_elements(&mut lookup_elements, channel.into());
    }
    let mut total = stwo::core::fields::qm31::SecureField::zero();
    for (component, trace) in components.iter().zip(traces) {
        let (interaction_trace, claimed_sum) =
            component.generate_interaction_trace(trace.clone(), side_note, &lookup_elements);
        component.debug_assert_constraints(
            trace,
            &interaction_trace,
            &lookup_elements,
            claimed_sum,
        );
        total += claimed_sum;
    }
    total.is_zero()
}
