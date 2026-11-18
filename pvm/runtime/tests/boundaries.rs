//! Gray Paper v0.8.0 boundaries at the public API, from raw bytes: every
//! program below is written out byte by byte, never through the crate's
//! writer, and every expected outcome is read from the text (`pvm.tex`'s
//! `deblob`, Ψ and Ψ_M; `serialization.tex`'s fixed-length encoding;
//! `definitions.tex`'s `W_C`). Each case runs on the interpreter and, where
//! the host has it, the recompiler. `VECTORS.md` lists them.

use vos_pvm::refine::{Machine, MemoryModel, OutputError, PreparedProgram, RefineError};
use vos_pvm::{ExitReason, PvmBackend};

/// The backends this host runs.
fn backends() -> Vec<PvmBackend> {
    let mut backends = vec![PvmBackend::ForceInterpreter];
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        backends.push(PvmBackend::ForceRecompiler);
    }
    backends
}

/// A standard program of no read-only data, `rw` read-write data, no heap,
/// one stack page and `code`, a compact code blob: `E_3(0) ⌢ E_3(|rw|) ⌢
/// E_2(0) ⌢ E_3(4096) ⌢ rw ⌢ E_4(|code|) ⌢ code`.
fn standard(rw: &[u8], code: &[u8]) -> Vec<u8> {
    let mut blob = vec![0, 0, 0];
    blob.extend_from_slice(&(rw.len() as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&[0, 0, 0x00, 0x10, 0x00]);
    blob.extend_from_slice(rw);
    blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
    blob.extend_from_slice(code);
    blob
}

/// `blob` loaded with no arguments and `gas` on `backend`, run to its exit.
fn run(blob: &[u8], gas: u64, backend: PvmBackend) -> vos_pvm::refine::Invocation {
    let mut machine = Machine::load_with_backend(blob, &[], gas, MemoryModel::Auto, backend)
        .unwrap_or_else(|error| panic!("{backend:?}: {error}"));
    let exit = machine.try_resume().expect("the backend runs");
    machine.finish(exit)
}

// ── deblob: the jump table's width ──────────────────────────────────────

/// A dynamic jump through jump-table entry 0, written `width` bytes wide as
/// `entry`:
///
/// ```text
/// 0: load_imm φ2, 2    51 02 02
/// 3: jump_ind φ2, 0    50 02        djump(2): the entry's target
/// 5: jump_ind φ0, 0    50 00        djump(halt address): a halt
/// ```
///
/// The bitmask is 1001010, packed 0x29.
fn djump_through(width: u8, entry: &[u8]) -> Vec<u8> {
    assert_eq!(entry.len(), usize::from(width));
    let mut code = vec![1, width, 7];
    code.extend_from_slice(entry);
    code.extend_from_slice(&[51, 2, 2, 50, 2, 50, 0, 0x29]);
    standard(&[], &code)
}

/// An entry naming pc 5 halts at every width that holds it, padded or not;
/// zero width names pc 0 and loops; an entry past 2^32 is no block start
/// and panics; one past 2^64 (a nonzero ninth byte) is no blob at all.
#[test]
fn jump_entries_read_at_their_blobs_width() {
    let entry = |width: usize, low: u8| {
        let mut entry = vec![0u8; width];
        if width > 0 {
            entry[0] = low;
        }
        entry
    };
    for backend in backends() {
        for width in [1u8, 2, 3, 4, 5, 8, 9, 32] {
            let invocation = run(
                &djump_through(width, &entry(width.into(), 5)),
                1_000,
                backend,
            );
            assert_eq!(
                invocation.exit,
                ExitReason::Halt,
                "{backend:?}, width {width}"
            );
        }
        let looping = run(&djump_through(0, &[]), 1_000, backend);
        assert_eq!(
            looping.exit,
            ExitReason::OutOfGas,
            "{backend:?}: pc 0 again"
        );
        for width in [5u8, 8] {
            let mut past = entry(width.into(), 5);
            past[4] = 1;
            let invocation = run(&djump_through(width, &past), 1_000, backend);
            assert_eq!(
                invocation.exit,
                ExitReason::Panic,
                "{backend:?}, width {width}"
            );
        }
    }
    let mut past_a_register = entry(9, 5);
    past_a_register[8] = 1;
    assert_eq!(
        PreparedProgram::new(&djump_through(9, &past_a_register)).err(),
        Some(RefineError::InvalidBlob)
    );
}

/// The `machine` host call's reader is `deblob` too: an inner machine of a
/// padded table is created, and runs as its one-byte twin does.
#[test]
fn an_inner_machine_takes_a_padded_table() {
    let mut machines = vos_pvm::inner::InnerMachines::new();
    for width in [1u8, 2, 6] {
        let mut code = vec![1, width, 1, 0];
        code.extend(std::iter::repeat_n(0, usize::from(width) - 1));
        code.extend_from_slice(&[0, 1]);
        assert!(vos_pvm::spi::deblob(&code, 0).is_some(), "width {width}");
        assert!(machines.create(&code, 0).is_ok(), "width {width}");
    }
}

// ── Ψ: the entry counter ────────────────────────────────────────────────

/// `load_prepared_at` and a pool's load at `entry`, on every backend: the
/// exit, the gas used, the counter and φ7.
fn entered(blob: &[u8], entry: u32, gas: u64) -> Vec<(ExitReason, u64, u32, u64)> {
    let mut outcomes = Vec::new();
    for backend in backends() {
        let prepared = PreparedProgram::new_with_backend(blob, backend).expect("prepares");
        let mut machine =
            Machine::load_prepared_at(&prepared, entry, &[], gas, MemoryModel::Auto).unwrap();
        let exit = machine.try_resume().unwrap();
        let invocation = machine.finish(exit);
        outcomes.push((
            invocation.exit,
            invocation.gas_used,
            invocation.pc,
            invocation.registers[7],
        ));
        let pool = vos_pvm::pool::OuterMachines::new(blob, backend).expect("admitted");
        let mut machine = pool.load(entry, &[], gas).unwrap();
        let exit = machine.try_resume().unwrap();
        let invocation = machine.finish(exit);
        outcomes.push((
            invocation.exit,
            invocation.gas_used,
            invocation.pc,
            invocation.registers[7],
        ));
    }
    outcomes
}

/// φ7 at entry: the argument window's base.
const ARGUMENTS: u64 = (1 << 32) - (1 << 16) - (1 << 24);

/// An entry `deblob` refuses, past the code or on an operand byte, is Ψ's
/// panic before any step: no gas, the counter 0, the registers as laid
/// out, whatever the gas.
#[test]
fn an_entry_that_is_no_instruction_start_panics_uncharged() {
    // Five traps, 00 00 00 00 00, all instruction starts (0x1f): entry 5
    // is the code's length, accumulate's entry.
    let traps = standard(&[], &[0, 1, 5, 0, 0, 0, 0, 0, 0x1f]);
    for gas in [1, 5, 1_000] {
        for outcome in entered(&traps, 5, gas) {
            assert_eq!(outcome, (ExitReason::Panic, 0, 0, ARGUMENTS), "gas {gas}");
        }
    }
    // load_imm φ7, 2 (51 07 02); jump_ind φ0 (50 00), bitmask 10010: 1 and
    // 2 are operand bytes.
    let program = standard(&[], &[0, 1, 5, 51, 7, 2, 50, 0, 0x09]);
    for entry in [1, 2, 4, 5, u32::MAX] {
        for outcome in entered(&program, entry, 1_000) {
            assert_eq!(
                outcome,
                (ExitReason::Panic, 0, 0, ARGUMENTS),
                "entry {entry}"
            );
        }
    }
}

/// An instruction start inside a block is a valid entry: the run starts
/// there, past the block's first instruction, on every backend alike.
#[test]
fn an_interior_instruction_start_is_entered() {
    let program = standard(&[], &[0, 1, 5, 51, 7, 2, 50, 0, 0x09]);
    let from_start = entered(&program, 0, 1_000);
    let interior = entered(&program, 3, 1_000);
    for (start, inside) in from_start.iter().zip(&interior) {
        assert_eq!((&start.0, start.3), (&ExitReason::Halt, 2));
        assert_eq!(inside.0, ExitReason::Halt);
        assert_eq!(inside.3, ARGUMENTS, "the load skipped");
        assert!(inside.1 > 0, "a funded run");
    }
    assert!(
        interior.windows(2).all(|pair| pair[0] == pair[1]),
        "{interior:?}"
    );
}

// ── Code and service sizes ──────────────────────────────────────────────

/// 2^21 + 1 one-byte traps, every byte an instruction start: `E(0) ⌢
/// E_1(1) ⌢ E(2^21 + 1)`, the natural in four bytes (0xe0, then E_3 of it),
/// the code, and the bitmask packed, its last byte's one bit set.
fn traps() -> Vec<u8> {
    const TRAPS: usize = (1 << 21) + 1;
    let mut code = vec![0, 1, 0xe0, 0x01, 0x00, 0x20];
    code.resize(code.len() + TRAPS, 0);
    code.resize(code.len() + TRAPS / 8, 0xff);
    code.push(0x01);
    code
}

/// A program of 2^21 + 1 one-byte traps, 2,359,319 bytes: past the
/// recompiler's native bound and within the service-code bound. The
/// interpreter runs it as the text does; the recompiler refuses it as its
/// own resource, a backend error and no guest outcome.
#[test]
fn code_past_the_native_bound_is_the_recompilers_alone() {
    let blob = standard(&[], &traps());
    assert_eq!(blob.len(), 2_359_319);
    assert!(vos_pvm::spi::parse_standard_program(&blob).is_some());
    assert!(vos_pvm::spi::service_fits(&blob));
    let invocation = run(&blob, 1_000, PvmBackend::ForceInterpreter);
    assert_eq!(invocation.exit, ExitReason::Panic, "the first trap");
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        assert_eq!(
            Machine::load_with_backend(
                &blob,
                &[],
                1_000,
                MemoryModel::Auto,
                PvmBackend::ForceRecompiler
            )
            .err(),
            Some(RefineError::Backend)
        );
    }
}

/// A service's code is admitted up to `W_C`, 4,000,000 bytes, its whole
/// blob counted.
#[test]
fn a_service_is_admitted_up_to_the_service_code_bound() {
    let code = [0, 1, 1, 0, 1];
    let at = |len: usize| standard(&vec![0; len - 11 - 4 - code.len()], &code);
    let fits = at(4_000_000);
    assert_eq!(fits.len(), 4_000_000);
    assert!(vos_pvm::pool::OuterMachines::new(&fits, PvmBackend::ForceInterpreter).is_ok());
    let past = at(4_000_001);
    assert!(vos_pvm::spi::parse_standard_program(&past).is_some());
    assert!(matches!(
        vos_pvm::pool::OuterMachines::new(&past, PvmBackend::ForceInterpreter),
        Err(vos_pvm::pool::PoolError::ServiceTooBig)
    ));
}

// ── Ψ_M: a halt's output ────────────────────────────────────────────────

/// Read-write data at 0x2_0000: 01 02 03 04.
const RW: [u8; 4] = [1, 2, 3, 4];

/// load_imm_64 φ7, `address` (20 07 + 8 bytes); load_imm_64 φ8, `len`;
/// jump_ind φ0 (50 00): a halt with the output φ8 bytes at φ7.
fn halting_with(address: u64, len: u64) -> Vec<u8> {
    let mut code = vec![0, 1, 22, 20, 7];
    code.extend_from_slice(&address.to_le_bytes());
    code.extend_from_slice(&[20, 8]);
    code.extend_from_slice(&len.to_le_bytes());
    code.extend_from_slice(&[50, 0]);
    // Starts at 0, 10 and 20: 00000000 01 | 00000000 01 | 00 → 0x01, 0x04,
    // 0x10.
    code.extend_from_slice(&[0x01, 0x04, 0x10]);
    standard(&RW, &code)
}

/// A zero length is the empty string whatever φ7; an unreadable range,
/// past 2^32 among them, is the empty string; a readable one is its bytes,
/// past an embedder's bound its own refusal.
#[test]
fn a_halts_output_is_the_gray_papers() {
    for backend in backends() {
        for address in [0, 0x2_0000, u64::from(u32::MAX), u64::MAX] {
            let invocation = run(&halting_with(address, 0), 1_000, backend);
            assert_eq!(invocation.exit, ExitReason::Halt);
            assert_eq!(invocation.output(0), Ok(Vec::new()), "{address:#x}");
        }
        for (address, len) in [
            (0, 1),
            (0x3_0000, 4),
            (0x2_0000, 1 << 20),
            (0x2_0000, u64::MAX),
            (u64::MAX, 1),
            (u64::from(u32::MAX), 2),
        ] {
            let invocation = run(&halting_with(address, len), 1_000, backend);
            assert_eq!(invocation.exit, ExitReason::Halt);
            assert_eq!(
                invocation.output(0),
                Ok(Vec::new()),
                "{backend:?}: {address:#x}+{len}"
            );
        }
        let invocation = run(&halting_with(0x2_0000, 4), 1_000, backend);
        assert_eq!(invocation.output(4), Ok(RW.to_vec()));
        assert_eq!(invocation.output(3), Err(OutputError::TooLong));
        assert_eq!(invocation.output_bounded(3), None);
        let trapped = run(&standard(&[], &[0, 1, 1, 0, 1]), 1_000, backend);
        assert_eq!(trapped.output(4096), Err(OutputError::NotHalted));
    }
}

/// A pooled machine whose entry panicked uncharged goes back to its pool
/// and runs again from a valid entry.
#[test]
fn a_pooled_machine_runs_again_after_an_uncharged_panic() {
    let program = standard(&[], &[0, 1, 5, 51, 7, 2, 50, 0, 0x09]);
    for backend in backends() {
        let pool = vos_pvm::pool::OuterMachines::new(&program, backend).expect("admitted");
        let mut machine = pool.load(1, &[], 1_000).unwrap();
        let exit = machine.try_resume().unwrap();
        pool.restore(machine.finish(exit));
        assert_eq!(pool.idle(), 1, "{backend:?}");
        let mut machine = pool.load(0, &[], 1_000).unwrap();
        let exit = machine.try_resume().unwrap();
        let invocation = machine.finish(exit);
        assert_eq!(invocation.exit, ExitReason::Halt, "{backend:?}");
        assert_eq!(invocation.registers[7], 2, "{backend:?}");
    }
}

// ── Operand decoding at its edges (`pvm.tex`, A.5) ───────────────────────

/// A compact code blob of `code`, no jump table, instructions at `starts`.
fn compact(code: &[u8], starts: &[usize]) -> Vec<u8> {
    let mut packed = vec![0u8; code.len().div_ceil(8)];
    for &start in starts {
        packed[start / 8] |= 1 << (start % 8);
    }
    let mut blob = vec![0, 0, u8::try_from(code.len()).unwrap()];
    blob.extend_from_slice(code);
    blob.extend_from_slice(&packed);
    blob
}

/// `code` as a standard program with a page of read-write data, through
/// the loader's `deblob` and the production memory path on every backend:
/// its exit, gas used, registers and first read-write byte, alike on each.
/// The gas each case pins is its one block's cost, which both backends
/// charge; the block-gas corpus (`vectors-v080-gas`) holds the cost model
/// itself to independently derived values.
fn decoded(code: &[u8], starts: &[usize]) -> (ExitReason, u64, [u64; 13], u8) {
    let blob = standard(&[0xAA], &compact(code, starts));
    assert!(
        vos_pvm::spi::parse_standard_program(&blob).is_some(),
        "deblob takes it"
    );
    let outcomes: Vec<_> = backends()
        .into_iter()
        .map(|backend| {
            let invocation = run(&blob, 1_000, backend);
            let mut byte = [0u8];
            invocation.memory().read_bytes(0x2_0000, &mut byte);
            (
                invocation.exit,
                invocation.gas_used,
                invocation.registers,
                byte[0],
            )
        })
        .collect();
    assert!(
        outcomes.windows(2).all(|pair| pair[0] == pair[1]),
        "{outcomes:?}"
    );
    outcomes[0].clone()
}

/// A register nibble above 12 names φ12 (`r = min(12, nibble)`): a
/// `move_reg` reading nibble 14 copies φ12, and one writing nibble 15
/// writes it.
///
/// ```text
/// 0: load_imm φ12, 0x34   51 0c 34
/// 3: move_reg φ7, φ14→12  64 e7
/// 5: load_imm φ8, 9       51 08 09
/// 8: move_reg φ15→12, φ8  64 8f
/// a: jump_ind φ0, 0       32 00      a halt
/// ```
#[test]
fn a_register_nibble_above_twelve_names_twelve() {
    let code = [51, 12, 0x34, 100, 0xe7, 51, 8, 9, 100, 0x8f, 50, 0];
    let (exit, gas, registers, _) = decoded(&code, &[0, 3, 5, 8, 10]);
    assert_eq!(exit, ExitReason::Halt);
    assert_eq!((registers[7], registers[12]), (0x34, 9));
    assert_eq!(gas, 23);
}

/// Operand bytes past an instruction's skip are the following bytes, and
/// past the code zeros (`ζ = c ⌢ [0, 0, ...]`): a `load_imm` of skip 0
/// takes its register from the next opcode's low nibble (`load_imm`, 51:
/// φ3) and an empty immediate; a trailing `jump_ind` of skip 0 reads φ0
/// from past the code, and halts.
///
/// ```text
/// 0: load_imm φ3, 9       51 03 09
/// 3: load_imm φ(51 & 15)  51          φ3 = 0
/// 4: load_imm φ7, 5       51 07 05
/// 7: jump_ind φ0, 0       32          its operand past the code
/// ```
#[test]
fn operand_bytes_past_the_skip_and_the_code_are_read_as_the_text_says() {
    let code = [51, 3, 9, 51, 51, 7, 5, 50];
    let (exit, gas, registers, _) = decoded(&code, &[0, 3, 4, 7]);
    assert_eq!(exit, ExitReason::Halt);
    assert_eq!((registers[3], registers[7]), (0, 5));
    assert_eq!(gas, 22);
}

/// `load_imm_64` reads its eight immediate bytes whatever its skip
/// (`ν_X = E⁻¹_8(ζ_{ı+2..+8})`): with a skip of 3 it takes the next
/// instruction's bytes, then zeros past the code.
///
/// ```text
/// 0: load_imm_64 φ7, ...  14 07 11 22
/// 4: jump_ind φ0, 0       32 00
/// ```
#[test]
fn load_imm_64_reads_eight_bytes_past_a_short_skip() {
    let code = [20, 7, 0x11, 0x22, 50, 0];
    let (exit, gas, registers, _) = decoded(&code, &[0, 4]);
    assert_eq!(exit, ExitReason::Halt);
    assert_eq!(registers[7], 0x0032_2211);
    assert_eq!(gas, 22);
}

/// An immediate-length field of 5 to 7 is 4 (`l_X = min(4, field)`): a
/// `store_imm_u8` whose field says 5, 6 or 7 reads a four-byte address and
/// stores the byte after it; a `store_imm_ind_u8` with the field in its
/// high nibble reads a four-byte offset.
///
/// ```text
/// 0: store_imm_u8 [0x2_0000], 0x7f        1e 0f 00 00 02 00 7f  (field f & 7)
/// 7: load_imm φ2, 0x2_0000                33 02 00 00 02
/// c: store_imm_ind_u8 [φ2 + 0], 0x55      46 f2 00 00 00 00 55  (field f >> 4 & 7)
/// 13: jump_ind φ0, 0                      32 00
/// ```
#[test]
fn an_immediate_length_field_past_four_reads_four() {
    for field in [5u8, 6, 7] {
        let code = [
            30,
            field,
            0,
            0,
            2,
            0,
            0x7f,
            51,
            2,
            0,
            0,
            2,
            70,
            2 | field << 4,
            0,
            0,
            0,
            0,
            0x55,
            50,
            0,
        ];
        let stored_first = decoded(
            &code[..7]
                .iter()
                .chain(&[50, 0])
                .copied()
                .collect::<Vec<_>>(),
            &[0, 7],
        );
        assert_eq!(stored_first.0, ExitReason::Halt, "field {field}");
        assert_eq!(
            stored_first.3, 0x7f,
            "field {field}: the address's four bytes"
        );
        let (exit, gas, _, byte) = decoded(&code, &[0, 7, 12, 19]);
        assert_eq!(exit, ExitReason::Halt, "field {field}");
        assert_eq!(byte, 0x55, "field {field}: the offset's four bytes");
        assert_eq!(gas, 26, "field {field}");
    }
}
