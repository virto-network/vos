//! The word ledger (`docs/design/proving.md` §8): a device program's memory
//! a row a word; its accesses' byte tuples, at any width and alignment,
//! bound to the bytes the word holds, its first touch and its closing read
//! a word's.

use stwo::core::channel::MerkleChannel;
use stwo::core::fields::m31::BaseField;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::verifier::VerificationError;
use vos_pvm::instruction::Opcode;
use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_device::masked::{
    DeviceProgram, device_shape, install, prove_device, prove_device_forced, verify_device,
};
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::chips::word_memory::{self, boundary};
use vos_pvm_proof::device::{WORD_BYTES, device_chip, device_chips_of_mask};
use vos_pvm_proof::format::Format;
use vos_pvm_proof::masked::MaskedDeviceTrace;
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_proof::side_note::SideNote;
use vos_pvm_recair::masked::{Checks, MaskRng};

use crate::support::{HEAP, RO_BASE, RO_DATA, RW_BASE, RW_DATA, io_and_halt};

type P2 = P2MerkleChannel;
type Program = DeviceProgram<<P2 as MerkleChannel>::H>;

/// The device gates' format.
fn word() -> Format {
    crate::support::format()
}

/// The heap area the mixed kernel works in, past a word the read-write
/// data's last word shares an access with.
const AREA: u32 = HEAP + 0x100;

/// A two-register instruction with an immediate, by opcode:
/// `rd ← [ra + imm]` for a load, `[ra + imm] ← rd` for a store.
fn indirect(asm: &mut Assembler, opcode: Opcode, rd: Reg, ra: Reg, imm: i32) {
    asm.emit_raw(opcode as u8, true);
    asm.emit_raw(rd as u8 | (ra as u8) << 4, false);
    for byte in imm.to_le_bytes() {
        asm.emit_raw(byte, false);
    }
}

/// A register and an immediate address, by opcode.
fn direct(asm: &mut Assembler, opcode: Opcode, rd: Reg, address: u32) {
    asm.emit_raw(opcode as u8, true);
    asm.emit_raw(rd as u8, false);
    for byte in address.to_le_bytes() {
        asm.emit_raw(byte, false);
    }
}

/// The loads of [`mixed`], each into T1: its opcode and its address.
const LOADS: [(Opcode, u32); 9] = [
    // a byte of a word written whole, then in part
    (Opcode::LoadIndU8, AREA + 4),
    // a signed half across the part written
    (Opcode::LoadIndI16, AREA + 3),
    // a word across two words, written across them
    (Opcode::LoadIndU32, AREA + 6),
    // eight bytes across two words, at no alignment
    (Opcode::LoadIndU64, AREA + 12),
    // a word no access wrote: its first touch's zeros
    (Opcode::LoadIndU64, AREA + 24),
    // the high half of a word written in part
    (Opcode::LoadIndU32, AREA + 20),
    // the read-write data's first word, from the data table
    (Opcode::LoadU64, RW_BASE),
    // a byte and a word of the read-only data, the word across two
    (Opcode::LoadU8, RO_BASE + 5),
    (Opcode::LoadU32, RO_BASE + 6),
];

/// A kernel of every access width at aligned and unaligned addresses,
/// stores across a word's end and across two regions' (the read-write
/// data's last word and the heap's first), sub-word stores into a word
/// written whole and loads of bytes of words written at other widths:
/// [`LOADS`], each into T1, after the stores of T0's eight bytes.
fn mixed() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_ro_data(RO_DATA.to_vec())
        .set_rw_data(RW_DATA.to_vec())
        .set_heap_pages(1)
        .set_stack_pages(1);
    asm.load_imm_64(Reg::T0, 0x8877_6655_4433_2211)
        .load_imm(Reg::S0, AREA as i32);
    for (opcode, offset) in [
        (Opcode::StoreIndU64, 0),
        (Opcode::StoreIndU16, 3),
        (Opcode::StoreIndU32, 6),
        (Opcode::StoreIndU64, 13),
        (Opcode::StoreIndU8, 41),
    ] {
        indirect(&mut asm, opcode, Reg::T0, Reg::S0, offset);
    }
    asm.store_u64(Reg::T0, HEAP - 4);
    for (opcode, address) in LOADS {
        match opcode {
            Opcode::LoadU64 | Opcode::LoadU8 | Opcode::LoadU32 => {
                direct(&mut asm, opcode, Reg::T1, address)
            }
            _ => indirect(&mut asm, opcode, Reg::T1, Reg::S0, (address - AREA) as i32),
        }
    }
    io_and_halt(&mut asm);
    asm.build()
}

/// [`mixed`]'s run.
fn mixed_run() -> SideNote {
    vos_pvm_proof::kernel::trace_kernel(&mixed(), &[], 10_000)
        .expect("halts")
        .side_note
}

/// The program of [`mixed`] under `format`.
fn mixed_program(format: &Format) -> Program {
    let (active, log_sizes) = device_shape(format, &mixed(), &mut mixed_run()).expect("a shape");
    install::<P2>(format, &mixed(), active, &log_sizes).expect("installs")
}

/// The run with load `k` of [`LOADS`] reading its low byte's bit 0
/// flipped (bit 0 of the register too, whatever the load's extension): the
/// byte tuple it puts, its register and every
/// step that reads the register until the halt clears it, so the CPU's
/// rows hold and only the memory ledger's read is wrong.
fn forged_load(k: usize) -> SideNote {
    let mut side_note = mixed_run();
    let (_, address) = LOADS[k];
    let at = side_note
        .steps
        .iter()
        .position(|step| {
            step.mem_read
                .as_ref()
                .is_some_and(|read| read.address == address && step.reg_write.is_some())
        })
        .expect("the load's step");
    let register = side_note.steps[at].reg_write.expect("its register");
    let read = side_note.steps[at].mem_read.as_mut().expect("its read");
    read.value ^= 1;
    let forged = side_note.steps[at].regs_after[register] ^ 1;
    side_note.steps[at].regs_after[register] = forged;
    for step in &mut side_note.steps[at + 1..] {
        step.regs_before[register] = forged;
        if step.reg_write == Some(register) {
            break;
        }
        step.regs_after[register] = forged;
    }
    side_note
}

/// A forged run whose trace breaks a constraint under `format`: the honest
/// prover refuses it, and its proof forced past the prover's check is
/// refused by the verifier.
fn refused_as_a_broken_constraint(
    format: &Format,
    program: &Program,
    side_note: impl Fn() -> SideNote,
) {
    let error = prove_device::<P2>(format, program, &mut side_note(), MaskRng::Seeded(7))
        .expect_err("the prover refuses");
    assert!(
        matches!(error, vos_pvm_device::Error::Unsatisfied),
        "{error:?}"
    );
    let proof = forced(format, program, &mut side_note(), |_| {});
    let outcome = verify_device::<P2>(format, program, &proof);
    assert!(
        matches!(
            outcome,
            Err(Error::Stark(VerificationError::OodsNotMatching))
        ),
        "{outcome:?}"
    );
}

/// `side_note`'s run proved under `program` with the prover's check of the
/// constraints off, its trace through `tamper` first.
fn forced(
    format: &Format,
    program: &Program,
    side_note: &mut SideNote,
    tamper: impl FnOnce(&mut MaskedDeviceTrace),
) -> crate::support::Proof<P2> {
    prove_device_forced::<P2>(
        format,
        program,
        side_note,
        MaskRng::Seeded(7),
        tamper,
        |_, _| {},
        Checks {
            constraints: false,
            public_unblinded: true,
        },
    )
    .expect("a forced proof")
    .0
}

/// A chip's columns in a traced device run, read and changed by natural
/// row.
struct Chip<'a> {
    columns: &'a mut Vec<stwo::prover::backend::simd::column::BaseColumn>,
    log_size: u32,
}

impl Chip<'_> {
    fn of<'a>(trace: &'a mut MaskedDeviceTrace, program: &Program, chip: usize) -> Chip<'a> {
        let position = device_chips_of_mask(program.active)
            .position(|active| active == chip)
            .expect("the chip");
        let log_size = trace.log_sizes[position];
        let columns = trace.main_columns_mut().nth(position).expect("its columns");
        Chip { columns, log_size }
    }

    fn rows(&self) -> usize {
        1 << self.log_size
    }

    fn at(&self, row: usize) -> usize {
        bit_reverse_index(
            coset_index_to_circle_domain_index(row, self.log_size),
            self.log_size,
        )
    }

    fn get(&self, column: usize, row: usize) -> u32 {
        self.columns[column].as_slice()[self.at(row)].0
    }

    fn set(&mut self, column: usize, row: usize, value: u32) {
        let at = self.at(row);
        self.columns[column].as_mut_slice()[at] = BaseField::from(value);
    }

    /// Every row's columns, in natural order.
    fn natural(&self) -> Vec<Vec<u32>> {
        (0..self.rows())
            .map(|row| {
                (0..self.columns.len())
                    .map(|column| self.get(column, row))
                    .collect()
            })
            .collect()
    }

    /// Writes `rows`, in natural order.
    fn write(&mut self, rows: &[Vec<u32>]) {
        for (row, values) in rows.iter().enumerate() {
            for (column, &value) in values.iter().enumerate() {
                self.set(column, row, value);
            }
        }
    }
}

/// The word ledger's rows, by natural row: each real row's address.
fn ledger_addresses(ledger: &Chip<'_>) -> Vec<Option<u32>> {
    use word_memory::Column;
    (0..ledger.rows())
        .map(|row| {
            (ledger.get(Column::IsPadding.offset(), row) == 0).then(|| {
                (0..4).fold(0, |address, limb| {
                    address | ledger.get(Column::Address.offset() + limb, row) << (8 * limb)
                })
            })
        })
        .collect()
}

/// The kernel of every width proves under the word ledger, its loads the
/// bytes the stores left.
#[test]
fn every_width_and_alignment_proves_under_the_word_ledger() {
    let run = mixed_run();
    let loaded: Vec<u64> = LOADS
        .iter()
        .map(|&(_, address)| {
            let step = run
                .steps
                .iter()
                .find(|step| step.mem_read.as_ref().is_some_and(|r| r.address == address))
                .expect("the load");
            step.regs_after[step.reg_write.expect("a load writes")]
        })
        .collect();
    let mut memory = [0u8; 64];
    for (offset, bytes) in [
        (0, &0x8877_6655_4433_2211u64.to_le_bytes()[..]),
        (3, &[0x11, 0x22]),
        (6, &[0x11, 0x22, 0x33, 0x44]),
        (13, &0x8877_6655_4433_2211u64.to_le_bytes()[..]),
        (41, &[0x11]),
    ] {
        memory[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    let le = |at: usize, n: usize| {
        memory[at..at + n]
            .iter()
            .rev()
            .fold(0u64, |value, &byte| value << 8 | u64::from(byte))
    };
    let ro = |at: usize, n: usize| {
        RO_DATA[at..at + n]
            .iter()
            .rev()
            .fold(0u64, |value, &byte| value << 8 | u64::from(byte))
    };
    assert_eq!(
        loaded,
        [
            le(4, 1),
            le(3, 2) as i16 as i64 as u64,
            le(6, 4),
            le(12, 8),
            0,
            le(20, 4),
            u64::from_le_bytes(RW_DATA),
            ro(5, 1),
            ro(6, 4),
        ]
    );
    let word = word();
    let program = mixed_program(&word);
    for seed in [1, 2] {
        let (proof, _) =
            prove_device::<P2>(&word, &program, &mut mixed_run(), MaskRng::Seeded(seed))
                .expect("proves");
        verify_device::<P2>(&word, &program, &proof).expect("verifies");
    }
}

/// A load reading other than the bytes its word holds is refused, whatever
/// its width and alignment: a byte of a word written whole then in part, a
/// word across two words, eight unaligned bytes, a word never written, and
/// the data's first touches.
#[test]
fn a_forged_load_is_refused() {
    let format = word();
    let program = mixed_program(&format);
    for k in 0..LOADS.len() {
        refused_as_a_broken_constraint(&format, &program, || forged_load(k));
    }
}

/// A write that changes a byte it takes no lane of is refused: the mixed
/// kernel's byte store (lane 1 of its word) with lane 3 changed too, the
/// change carried to the word's closing read and its boundary's last
/// bytes, so every relation balances and only the write's constraint is
/// broken.
#[test]
fn a_write_past_its_lanes_is_refused() {
    use word_memory::Column;
    let format = word();
    let program = mixed_program(&format);
    let target = AREA + 40;
    let tamper = |trace: &mut MaskedDeviceTrace| {
        {
            let mut ledger = Chip::of(trace, &program, device_chip::MEMORY);
            let addresses = ledger_addresses(&ledger);
            let rows: Vec<usize> = (0..ledger.rows())
                .filter(|&row| addresses[row] == Some(target))
                .collect();
            assert_eq!(rows.len(), 3, "the start, the store and the closing read");
            let lane = |column: Column| column.offset() + 3;
            assert_eq!(ledger.get(Column::Active.offset() + 1, rows[1]), 1);
            for &row in &rows[1..] {
                let value = ledger.get(lane(Column::Value), row);
                ledger.set(lane(Column::Value), row, value + 1);
            }
            let prev = ledger.get(lane(Column::PrevValue), rows[2]);
            ledger.set(lane(Column::PrevValue), rows[2], prev + 1);
        }
        let mut boundary = Chip::of(trace, &program, device_chip::DEVICE_MEMORY);
        let address = |row: usize| {
            (0..29).fold(0u32, |address, bit| {
                address
                    | boundary.get(boundary::Column::AddressBits.offset() + bit, row) << (bit + 3)
            })
        };
        let row = (0..boundary.rows())
            .find(|&row| address(row) == target)
            .expect("the word's boundary row");
        let last = boundary::Column::Last.offset() + 3;
        let value = boundary.get(last, row);
        boundary.set(last, row, value + 1);
    };
    let proof = forced(&format, &program, &mut mixed_run(), tamper);
    let outcome = verify_device::<P2>(&format, &program, &proof);
    assert!(
        matches!(
            outcome,
            Err(Error::Stark(VerificationError::OodsNotMatching))
        ),
        "{outcome:?}"
    );
}

/// A word's boundary row twice puts two first touches and two closing
/// reads for one group, which takes one of each: the proof does not
/// balance, every constraint held.
#[test]
fn a_word_touched_twice_at_the_boundary_is_refused() {
    use boundary::Column;
    let format = word();
    let program = mixed_program(&format);
    let tamper = |trace: &mut MaskedDeviceTrace| {
        let mut boundary = Chip::of(trace, &program, device_chip::DEVICE_MEMORY);
        let padding = (0..boundary.rows())
            .find(|&row| boundary.get(Column::IsReal.offset(), row) == 0)
            .expect("a padding row");
        // A heap word's row: its first touch zeros, no data-table lookup.
        let heap = (0..padding)
            .find(|&row| boundary.get(Column::RegionSelect.offset() + 3, row) == 1)
            .expect("a heap word");
        for column in 0..boundary.columns.len() {
            let value = boundary.get(column, heap);
            boundary.set(column, padding, value);
        }
    };
    let proof = forced(&format, &program, &mut mixed_run(), tamper);
    let outcome = verify_device::<P2>(&format, &program, &proof);
    assert!(matches!(outcome, Err(Error::Logup)), "{outcome:?}");
}

/// A word's group moved off its word (every row's address one byte up, so
/// its lanes name the bytes of two words) is refused: its ends' word
/// tuples are no boundary row's, and its lanes' byte tuples no access's.
#[test]
fn a_misaligned_group_is_refused() {
    use word_memory::Column;
    let format = word();
    let program = mixed_program(&format);
    let tamper = |trace: &mut MaskedDeviceTrace| {
        let mut ledger = Chip::of(trace, &program, device_chip::MEMORY);
        let addresses = ledger_addresses(&ledger);
        for (row, address) in addresses.into_iter().enumerate() {
            if address == Some(AREA) {
                let low = ledger.get(Column::Address.offset(), row);
                ledger.set(Column::Address.offset(), row, low + 1);
            }
        }
    };
    let proof = forced(&format, &program, &mut mixed_run(), tamper);
    let outcome = verify_device::<P2>(&format, &program, &proof);
    assert!(
        matches!(
            outcome,
            Err(Error::Logup | Error::Stark(VerificationError::OodsNotMatching))
        ),
        "{outcome:?}"
    );
}

/// A lane taken on padding, outside every group, is refused: no byte tuple
/// is consumed where no consistency binds it.
#[test]
fn a_lane_taken_on_padding_is_refused() {
    use word_memory::Column;
    let format = word();
    let program = mixed_program(&format);
    let tamper = |trace: &mut MaskedDeviceTrace| {
        let mut ledger = Chip::of(trace, &program, device_chip::MEMORY);
        let padding = (0..ledger.rows())
            .find(|&row| ledger.get(Column::IsPadding.offset(), row) == 1)
            .expect("a padding row");
        ledger.set(Column::Active.offset(), padding, 1);
    };
    let proof = forced(&format, &program, &mut mixed_run(), tamper);
    let outcome = verify_device::<P2>(&format, &program, &proof);
    assert!(
        matches!(
            outcome,
            Err(Error::Logup | Error::Stark(VerificationError::OodsNotMatching))
        ),
        "{outcome:?}"
    );
}

/// A first touch of a word's byte no access reaches is the layout's too:
/// a heap byte of a word the kernel writes in part, nonzero in its machine
/// before the run, is refused.
#[test]
fn an_untouched_byte_of_a_touched_word_is_bound() {
    let forged = || {
        vos_pvm_proof::kernel::trace_forged_kernel(&mixed(), &[], 10_000, |memory| {
            memory.init_copy(AREA + 46, &[1]);
        })
        .expect("halts")
        .side_note
    };
    assert!(
        forged()
            .steps
            .iter()
            .flat_map(|step| step.mem_read.iter().chain(&step.mem_write))
            .all(
                |access| !(access.address..access.address + u32::from(access.size))
                    .contains(&(AREA + 46))
            )
    );
    let format = word();
    refused_as_a_broken_constraint(&format, &mixed_program(&format), forged);
}

/// Padding between real rows is refused: the ledger's rows turned so its
/// padding lies inside, every cyclic neighbour kept, so each relation
/// balances and every other constraint holds. Padding anywhere would let a
/// word's accesses split into two groups, its writes in one and its reads
/// in the other, two boundary rows for the word giving each its ends.
#[test]
fn padding_between_real_rows_is_refused() {
    use word_memory::Column;
    let format = word();
    let program = mixed_program(&format);
    let tamper = |trace: &mut MaskedDeviceTrace| {
        pad_inside(
            trace,
            &program,
            device_chip::MEMORY,
            Column::IsPadding.offset(),
        );
    };
    let proof = forced(&format, &program, &mut mixed_run(), tamper);
    let outcome = verify_device::<P2>(&format, &program, &proof);
    assert!(
        matches!(
            outcome,
            Err(Error::Stark(VerificationError::OodsNotMatching))
        ),
        "{outcome:?}"
    );
}

/// `chip`'s rows turned so that its padding lies between real rows, every
/// cyclic neighbour kept: each relation balances as before and every
/// constraint relating a row to the next holds where it held. Asserts the
/// turn leaves real rows on both sides of the padding.
fn pad_inside(trace: &mut MaskedDeviceTrace, program: &Program, chip: usize, is_padding: usize) {
    let mut ledger = Chip::of(trace, program, chip);
    let mut rows = ledger.natural();
    let real = rows.iter().filter(|row| row[is_padding] == 0).count();
    rows.rotate_left(real / 2);
    let n = rows.len();
    assert!(real >= 2 && rows[0][is_padding] == 0 && rows[n - 1][is_padding] == 0);
    assert!(rows.iter().any(|row| row[is_padding] == 1));
    ledger.write(&rows);
}

/// Padding between the register ledger's real rows is accepted, and is
/// sound: every real row after a padding row starts a register's chain,
/// which must be that register's `ts = 0` write (`ChainStartH`), and
/// `DeviceBoundaryChip` produces one a register on preprocessed rows; so a
/// register's rows are one chain wherever padding lies. A chain split by
/// padding, its second half with no write to start it, is refused
/// (`register_ledger_gate`'s `a_read_follows_its_register_s_writes`).
#[test]
fn register_ledger_padding_between_real_rows_is_harmless() {
    use vos_pvm_proof::chips::register_memory::Column;
    let format = word();
    let program = mixed_program(&format);
    let tamper = |trace: &mut MaskedDeviceTrace| {
        pad_inside(
            trace,
            &program,
            device_chip::REGISTER_MEMORY,
            Column::IsPadding.offset(),
        );
    };
    let proof = forced(&format, &program, &mut mixed_run(), tamper);
    verify_device::<P2>(&format, &program, &proof).expect("one chain a register");
}

/// An inner row that takes no lane is refused: a read's row repeated after
/// it with no lane, its timestamp the read's, every relation balanced and
/// every other constraint held. Such rows, their timestamps bound by no
/// access, could carry the sort key around the field and order a read
/// before the write it should see.
#[test]
fn a_laneless_inner_row_is_refused() {
    use word_memory::Column;
    let format = word();
    let program = mixed_program(&format);
    let tamper = |trace: &mut MaskedDeviceTrace| {
        let mut ledger = Chip::of(trace, &program, device_chip::MEMORY);
        let mut rows = ledger.natural();
        let flag = |row: &Vec<u32>, column: Column| row[column.offset()] == 1;
        let read = rows
            .iter()
            .position(|row| {
                !flag(row, Column::IsPadding)
                    && !flag(row, Column::IsStart)
                    && !flag(row, Column::IsClosing)
                    && !flag(row, Column::IsWrite)
            })
            .expect("an inner read");
        let n = rows.len();
        assert!(flag(&rows[n - 2], Column::IsPadding), "two padding rows");
        let mut repeated = rows[read].clone();
        let span = |column: Column| column.offset()..column.offset() + column.size();
        for at in span(Column::Active).chain(span(Column::LaneInv)) {
            repeated[at] = 0;
        }
        let value = rows[read][span(Column::Value)].to_vec();
        repeated[span(Column::PrevValue)].copy_from_slice(&value);
        let original = &mut rows[read];
        original[Column::IsSameAddrNext.offset()] = 1;
        for at in span(Column::AdvLoH)
            .chain(span(Column::AdvHiH))
            .chain(span(Column::OrderBits))
            .chain(span(Column::IsGroupStart))
            .chain(span(Column::IsGroupEnd))
        {
            original[at] = 0;
        }
        rows.insert(read + 1, repeated);
        rows.pop();
        rows[n - 1][Column::IsGroupStart.offset()] = 1;
        ledger.write(&rows);
    };
    let proof = forced(&format, &program, &mut mixed_run(), tamper);
    let outcome = verify_device::<P2>(&format, &program, &proof);
    assert!(
        matches!(
            outcome,
            Err(Error::Stark(VerificationError::OodsNotMatching))
        ),
        "{outcome:?}"
    );
}

const _: () = assert!(WORD_BYTES == 8 && AREA.is_multiple_of(8));
