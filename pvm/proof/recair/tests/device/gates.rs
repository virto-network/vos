//! The device shape's acceptance and forgery gates
//! (`docs/design/proving.md` §8): every run below is the kernel's
//! own but for the one property its gate forges, so the refusal is that
//! property's. A constraint a forged trace breaks is refused by the honest
//! prover and, its proof forced past the prover's check, by the verifier
//! (`OodsNotMatching`); a relation it unbalances, by the verifier's logup
//! total.

use std::panic::{AssertUnwindSafe, catch_unwind};

use num_traits::{One, Zero};
use stwo::core::channel::MerkleChannel;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::utils::{bit_reverse_index, coset_index_to_circle_domain_index};
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;
use stwo::core::verifier::VerificationError;
use stwo::prover::ProvingError;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_final_verifier::Error;
use vos_pvm_final_verifier::masked::{Claim, verify_masked};
use vos_pvm_proof::AirColumn;
use vos_pvm_proof::chips::poseidon2;
use vos_pvm_proof::core::ecall::ECALL_WITNESS_INPUT;
use vos_pvm_proof::device::{device_chip, device_chips_of_mask};
use vos_pvm_proof::format::{ChannelKind, Format};
use vos_pvm_proof::framework_access::AllLookupElements;
use vos_pvm_proof::kernel::{PERM_RW, trace_forged_kernel, trace_kernel_to_exit};
use vos_pvm_proof::masked::{DeviceComponents, device_bound_sums, device_public_values};
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::side_note::SideNote;
use vos_pvm_recair::ProveError;
use vos_pvm_recair::masked::device::{
    DeviceProgram, DeviceProver, device_format, device_shape, install, prove_device,
    prove_device_forced, verify_device,
};
use vos_pvm_recair::masked::{Checks, MaskRng};
use vos_pvm_recair_air::masked::MaskedComponents;

use crate::support::{
    HEAP, IO, Proof, RO_BASE, STACK_TOP, blob, format, io_and_halt, io_bytes, program, prove, run,
    small_format, the_program, verify, witness,
};

type P2 = P2MerkleChannel;

/// `side_note`'s run proved under `program` with the prover's check of the
/// constraints off, `blind` changing the blinding fractions: a forged proof.
fn forced(
    program: &DeviceProgram<<P2 as MerkleChannel>::H>,
    side_note: &mut SideNote,
    blind: impl Fn(&AllLookupElements, &mut [vos_pvm_recair::trace::FirstRowFraction]),
    checks: Checks,
) -> Proof<P2> {
    prove_device_forced::<P2>(
        &format(),
        program,
        side_note,
        MaskRng::Seeded(7),
        |_| {},
        blind,
        checks,
    )
    .expect("a forced proof")
    .0
}

/// The prover's own check off.
const UNCHECKED: Checks = Checks {
    constraints: false,
    public_unblinded: true,
};

/// A forged run whose trace breaks a constraint: the honest prover refuses
/// it, and its forced proof is refused by the verifier.
fn refused_as_a_broken_constraint(
    program: &DeviceProgram<<P2 as MerkleChannel>::H>,
    side_note: impl Fn() -> SideNote,
) {
    let error = prove_device::<P2>(&format(), program, &mut side_note(), MaskRng::Seeded(7))
        .expect_err("the prover refuses");
    assert!(
        matches!(
            error,
            ProveError::Stwo(ProvingError::ConstraintsNotSatisfied)
        ),
        "{error:?}"
    );
    let proof = forced(program, &mut side_note(), |_, _| {}, UNCHECKED);
    assert!(
        matches!(
            verify_device::<P2>(&format(), program, &proof),
            Err(Error::Stark(VerificationError::OodsNotMatching))
        ),
        "{:?}",
        verify_device::<P2>(&format(), program, &proof)
    );
}

/// A forged run whose trace holds every constraint but unbalances a
/// relation: its proof is refused by the verifier's logup total.
fn refused_as_unbalanced(
    program: &DeviceProgram<<P2 as MerkleChannel>::H>,
    mut side_note: SideNote,
) {
    let (proof, _) = prove_device::<P2>(&format(), program, &mut side_note, MaskRng::Seeded(7))
        .expect("the constraints hold");
    assert!(
        matches!(
            verify_device::<P2>(&format(), program, &proof),
            Err(Error::Logup)
        ),
        "{:?}",
        verify_device::<P2>(&format(), program, &proof)
    );
}

/// [`blob`]'s run on witness 1 with its machine's memory changed first.
fn forged_run(blob: &[u8], forge: impl FnOnce(&mut vos_pvm_proof::kernel::Memory)) -> SideNote {
    trace_forged_kernel(blob, &witness(1), 10_000, forge)
        .expect("halts")
        .side_note
}

/// A run of the device kernel, its Poseidon2 call among its steps, proves
/// under its program and verifies on both channels, stating the kernel's
/// io-hash; another witness proves under the same program.
#[test]
fn a_device_run_proves_and_verifies() {
    fn accepted<MC: MerkleChannel>(format: &Format)
    where
        SimdBackend: BackendForChannel<MC>,
    {
        let program = program::<MC>(format, &blob());
        assert_ne!(program.active & 1 << device_chip::POSEIDON2, 0);
        for seed in [1, 2] {
            let (proof, stats) = prove::<MC>(
                format,
                &program,
                &blob(),
                &witness(seed),
                MaskRng::Seeded(seed),
            )
            .expect("proves");
            assert_eq!(stats.attempts, 1);
            assert_eq!(proof.io, io_bytes());
            verify_device::<MC>(format, &program, &proof).expect("verifies");
        }
    }
    accepted::<P2>(&format());
    accepted::<Blake2sMerkleChannel>(&small_format(ChannelKind::Blake2s, 6, 4));
}

/// A prover installed once proves as the per-proof path does, byte for
/// byte under one seed, its preprocessed tree committed at install and
/// borrowed by every proof; two proofs in a row from it both verify.
#[test]
fn an_installed_prover_proves_as_the_per_proof_path() {
    let format = format();
    let mut reference = run(&blob(), &witness(0));
    let (active, log_sizes) = device_shape(&format, &blob(), &mut reference).expect("a shape");
    let prover =
        DeviceProver::<P2>::install(&format, &blob(), active, &log_sizes).expect("installs");
    assert_eq!(prover.program().circuit, the_program().circuit);
    for seed in [3, 4] {
        let (installed, _) = prover
            .prove(&mut run(&blob(), &witness(seed)), MaskRng::Seeded(seed))
            .expect("proves");
        let (per_proof, _) = prove::<P2>(
            &format,
            the_program(),
            &blob(),
            &witness(seed),
            MaskRng::Seeded(seed),
        )
        .expect("proves");
        assert_eq!(format!("{installed:?}"), format!("{per_proof:?}"));
        verify_device::<P2>(&format, prover.program(), &installed).expect("verifies");
    }
}

/// The program is the kernel's, never a run's: its chips are those its code
/// reaches whatever the witness, two witnesses give one shape, and a chip
/// set that is not the code's or a log size under its floor is refused at
/// install.
#[test]
fn the_program_is_the_kernels() {
    let format = format();
    let [a, b] = [1, 2].map(|seed| {
        device_shape(&format, &blob(), &mut run(&blob(), &witness(seed))).expect("a shape")
    });
    assert_eq!(a, b);
    let (active, log_sizes) = a;
    let extra = active | 1 << device_chip::MUL;
    let mut sizes = log_sizes.clone();
    sizes.insert(0, 8);
    assert!(install::<P2>(&format, &blob(), extra, &sizes).is_err());
    let mut under = log_sizes.clone();
    under[0] -= 1;
    assert!(install::<P2>(&format, &blob(), active, &under).is_err());
}

/// A program past the device format's reference (a chip above
/// `DEVICE_MAX_LOG_SIZE`) or under a floor, however it was made, is refused
/// at install, by the prover and by the verifier, which refuses an honest
/// proof checked against it.
#[test]
fn a_program_outside_the_formats_count_is_refused() {
    use vos_pvm_proof::device::DEVICE_MAX_LOG_SIZE;
    let format = format();
    let honest = the_program();
    let (proof, _) =
        prove::<P2>(&format, honest, &blob(), &witness(1), MaskRng::Seeded(5)).expect("proves");
    verify::<P2>(&format, honest, &proof).expect("verifies");
    let mut tall = honest.clone();
    tall.log_sizes[0] = DEVICE_MAX_LOG_SIZE + 1;
    let mut short = honest.clone();
    short.log_sizes[0] = vos_pvm_recair::masked::device::device_floors(&format, honest.active)
        .expect("floors")[0]
        - 1;
    assert!(install::<P2>(&format, &blob(), tall.active, &tall.log_sizes).is_err());
    for program in [&tall, &short] {
        assert!(matches!(
            verify::<P2>(&format, program, &proof),
            Err(Error::Format)
        ));
        assert!(matches!(
            prove::<P2>(&format, program, &blob(), &witness(1), MaskRng::Seeded(5)),
            Err(ProveError::TraceShape(_))
        ));
    }
}

/// A chip the code reaches and the run never uses proves at its program's
/// log size, every row padding: a kernel whose multiplication follows its
/// halt.
#[test]
fn an_unused_chip_proves_at_its_pinned_size() {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1);
    io_and_halt(&mut asm);
    // mul_64 φ2 = φ3·φ4 after the halt, then a trap: in the code, never
    // run.
    for (byte, start) in [(202u8, true), (3 | 4 << 4, false), (2, false)] {
        asm.emit_raw(byte, start);
    }
    asm.trap();
    let kernel = asm.build();
    let program = program_of(&kernel);
    assert_ne!(program.active & 1 << device_chip::MUL, 0);
    let mut side_note = vos_pvm_proof::kernel::trace_kernel(&kernel, &[], 10_000)
        .expect("halts")
        .side_note;
    assert!(side_note.steps.iter().all(|step| step.opcode as u8 != 202));
    let (proof, _) = prove_device::<P2>(&format(), &program, &mut side_note, MaskRng::Seeded(9))
        .expect("proves");
    verify_device::<P2>(&format(), &program, &proof).expect("verifies");
}

/// A run that needs more rows of a chip than its program's log size is
/// refused by the prover, never proved at a larger shape: a kernel reading
/// up to 1,024 witness bytes, its program sized by a 16-byte run.
#[test]
fn a_run_past_the_programs_shape_is_refused() {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1)
        .add_imm_64(Reg::S0, Reg::SP, -1024)
        .move_reg(Reg::A0, Reg::S0)
        .load_imm(Reg::A1, 1024)
        .ecalli(ECALL_WITNESS_INPUT);
    io_and_halt(&mut asm);
    let kernel = asm.build();
    let format = format();
    let short = |len: usize| {
        vos_pvm_proof::kernel::trace_kernel(&kernel, &vec![7; len], 1_000_000)
            .expect("halts")
            .side_note
    };
    let (active, log_sizes) = device_shape(&format, &kernel, &mut short(16)).expect("a shape");
    let program = install::<P2>(&format, &kernel, active, &log_sizes).expect("installs");
    let (proof, _) =
        prove_device::<P2>(&format, &program, &mut short(16), MaskRng::Seeded(3)).expect("proves");
    verify_device::<P2>(&format, &program, &proof).expect("verifies");
    let error = prove_device::<P2>(&format, &program, &mut short(1000), MaskRng::Seeded(3))
        .expect_err("past the shape");
    assert!(
        matches!(&error, ProveError::Segment(message) if message.contains("its shape")),
        "{error:?}"
    );
}

/// A first touch of a data byte other than the data table's is refused: the
/// read-only byte the kernel reads, changed in its machine before the run.
#[test]
fn a_data_byte_other_than_the_tables_is_refused() {
    let side_note = forged_run(&blob(), |memory| memory.init_copy(RO_BASE + 3, &[0x99]));
    refused_as_unbalanced(the_program(), side_note);
}

/// A nonzero first touch of the stack or the heap is refused: a stack byte
/// the witness input overwrites, and the heap word the kernel writes.
#[test]
fn a_nonzero_first_touch_of_the_stack_or_heap_is_refused() {
    let stack = || {
        forged_run(&blob(), |memory| {
            memory.init_copy(STACK_TOP - 128 + 5, &[1]);
        })
    };
    assert_eq!(
        stack().steps[0].regs_before[1],
        u64::from(STACK_TOP),
        "the stack's top, below which the kernel's buffer is"
    );
    refused_as_a_broken_constraint(the_program(), stack);
    let heap = || forged_run(&blob(), |memory| memory.init_copy(HEAP + 9, &[1]));
    refused_as_a_broken_constraint(the_program(), heap);
}

/// A touch outside the regions is refused: a kernel reading a page between
/// the read-only and the read-write data, which its machine maps.
#[test]
fn a_touch_outside_the_regions_is_refused() {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1).load_u8(Reg::T0, 0x2_0010);
    io_and_halt(&mut asm);
    let kernel = asm.build();
    let program = program_of(&kernel);
    let side_note = || {
        trace_forged_kernel(&kernel, &[], 10_000, |memory| {
            assert!(memory.set_page_range(0x20, 1, PERM_RW));
        })
        .expect("halts")
        .side_note
    };
    refused_as_a_broken_constraint(&program, side_note);
}

/// A write to a read-only page is refused: a kernel storing into its
/// read-only data, its machine's page made writable.
#[test]
fn a_write_to_a_read_only_page_is_refused() {
    let mut asm = Assembler::new();
    asm.set_ro_data(vec![1; 16])
        .set_stack_pages(1)
        .load_imm(Reg::T0, 5)
        .store_u8(Reg::T0, RO_BASE + 2);
    io_and_halt(&mut asm);
    let kernel = asm.build();
    let program = program_of(&kernel);
    let side_note = || {
        trace_forged_kernel(&kernel, &[], 10_000, |memory| {
            assert!(memory.set_page_range((RO_BASE / 0x1000) as usize, 1, PERM_RW));
        })
        .expect("halts")
        .side_note
    };
    refused_as_a_broken_constraint(&program, side_note);
}

/// A kernel's program from a run on no input: the forgery gates' small
/// kernels, which read none.
fn program_of(kernel: &[u8]) -> DeviceProgram<<P2 as MerkleChannel>::H> {
    let format = format();
    let mut reference = vos_pvm_proof::kernel::trace_kernel(kernel, &[], 10_000)
        .unwrap_or_else(|_| {
            // A kernel whose honest run faults is shaped by its forged one.
            trace_forged_kernel(kernel, &[], 10_000, |memory| {
                assert!(memory.set_page_range(0x20, 1, PERM_RW));
                assert!(memory.set_page_range((RO_BASE / 0x1000) as usize, 1, PERM_RW));
            })
            .expect("halts")
        })
        .side_note;
    let (active, log_sizes) = device_shape(&format, kernel, &mut reference).expect("a shape");
    install::<P2>(&format, kernel, active, &log_sizes).expect("installs")
}

/// A second segment is refused: the kernel's run from its sixth step, its
/// registers, pc and timestamp there, its memory as the first five left
/// it. Its entry is not the program's, and its prover's trace does not
/// balance.
#[test]
fn a_second_segment_is_refused() {
    let full = run(&blob(), &witness(1));
    let steps = full.steps.len();
    let call = full
        .steps
        .iter()
        .position(|step| step.timestamp == full.poseidon2_ops[0].ts)
        .expect("the call's step");
    let second = || SegmentCursor::new(&full).side_note(call + 1, steps);
    let result = prove_device::<P2>(&format(), the_program(), &mut second(), MaskRng::Seeded(7));
    if let Ok((proof, _)) = result {
        assert!(matches!(
            verify_device::<P2>(&format(), the_program(), &proof),
            Err(Error::Logup)
        ));
    }
    let proof = forced(the_program(), &mut second(), |_, _| {}, UNCHECKED);
    let outcome = verify_device::<P2>(&format(), the_program(), &proof);
    assert!(matches!(outcome, Err(Error::Logup)), "{outcome:?}");
}

/// A run that traps instead of halting is refused: a kernel that sets its
/// io-hash and traps, under its own program. Its last step produces no
/// `(ts, HALT_PC)` for DeviceBoundaryChip's halt to consume.
#[test]
fn a_trapping_run_is_refused() {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1);
    for (register, word) in [Reg::A2, Reg::A3, Reg::A4, Reg::A5].into_iter().zip(IO) {
        asm.load_imm(register, word as i32);
    }
    asm.trap();
    let kernel = asm.build();
    let trapped = || {
        let (side_note, exit) = trace_kernel_to_exit(&kernel, &[], 10_000).expect("runs");
        assert_eq!(exit, vos_pvm::ExitReason::Panic);
        side_note
    };
    let format = format();
    let (active, log_sizes) = device_shape(&format, &kernel, &mut trapped()).expect("a shape");
    let program = install::<P2>(&format, &kernel, active, &log_sizes).expect("installs");
    refused_as_unbalanced(&program, trapped());
}

/// A Poseidon2 output that is not the permutation's is refused: the call's
/// first output byte changed in the run, the ledger's write with it.
#[test]
fn a_poseidon2_output_not_the_permutations_is_refused() {
    refused_as_a_broken_constraint(the_program(), || {
        let mut side_note = run(&blob(), &witness(1));
        side_note.poseidon2_ops[0].output[0] ^= 1;
        side_note
    });
}

/// A Poseidon2 output word written non-canonically is refused: an input
/// whose permutation's first word is 0, that word written as p's bytes,
/// which the field reads as 0 too, so only the word's encoding is wrong.
/// The honest run on that input proves.
#[test]
fn a_non_canonical_poseidon2_output_word_is_refused() {
    use vos_pvm_poseidon2::P;
    let input = input_whose_first_output_word_is_zero();
    let (proof, _) = prove::<P2>(
        &format(),
        the_program(),
        &blob(),
        &input,
        MaskRng::Seeded(8),
    )
    .expect("proves");
    verify_device::<P2>(&format(), the_program(), &proof).expect("verifies");
    refused_as_a_broken_constraint(the_program(), || {
        let mut side_note = run(&blob(), &input);
        let output = &mut side_note.poseidon2_ops[0].output;
        assert_eq!(output[..4], [0; 4]);
        output[..4].copy_from_slice(&P.to_le_bytes());
        side_note
    });
}

/// 64 witness bytes, sixteen words below p, whose permutation's first word
/// is 0: the permutation inverted from the state `0, 1, .., 15`.
fn input_whose_first_output_word_is_zero() -> Vec<u8> {
    use vos_pvm_poseidon2::{
        EXTERNAL_ROUND_CONSTS, INTERNAL_ROUND_CONSTS, M31, N_HALF_FULL_ROUNDS, N_STATE, P,
        apply_external_round_matrix, apply_internal_round_matrix, permute,
    };
    fn pow(base: M31, exponent: u64) -> M31 {
        (0..64).rev().fold(M31::ONE, |acc, bit| {
            let acc = acc * acc;
            if exponent >> bit & 1 == 1 {
                acc * base
            } else {
                acc
            }
        })
    }
    // `5 · ROOT ≡ 1 (mod p − 1)`: `x ↦ x^ROOT` inverts the S-box.
    const ROOT: u64 = 1_717_986_917;
    // `x` with `linear(x) = y`, by elimination over the map's matrix.
    fn solve(linear: fn(&mut [M31; N_STATE]), y: [M31; N_STATE]) -> [M31; N_STATE] {
        let mut rows = [[M31::ZERO; N_STATE + 1]; N_STATE];
        for k in 0..N_STATE {
            let mut unit = [M31::ZERO; N_STATE];
            unit[k] = M31::ONE;
            linear(&mut unit);
            for (row, value) in rows.iter_mut().zip(unit) {
                row[k] = value;
            }
        }
        for (row, value) in rows.iter_mut().zip(y) {
            row[N_STATE] = value;
        }
        for col in 0..N_STATE {
            let pivot = (col..N_STATE)
                .find(|&row| rows[row][col] != M31::ZERO)
                .expect("an invertible map");
            rows.swap(col, pivot);
            let inverse = pow(rows[col][col], u64::from(P) - 2);
            rows[col] = rows[col].map(|value| value * inverse);
            let pivot_row = rows[col];
            for (row, values) in rows.iter_mut().enumerate() {
                let factor = values[col];
                if row != col && factor != M31::ZERO {
                    for (value, &pivot) in values.iter_mut().zip(&pivot_row) {
                        *value = *value - factor * pivot;
                    }
                }
            }
        }
        rows.map(|row| row[N_STATE])
    }
    let external = |state: &mut [M31; N_STATE]| apply_external_round_matrix(state);
    let internal = |state: &mut [M31; N_STATE]| apply_internal_round_matrix::<M31, M31>(state);
    let undo_full = |state: &mut [M31; N_STATE], constants: &[M31; N_STATE]| {
        *state = solve(external, *state);
        for (word, &constant) in state.iter_mut().zip(constants) {
            *word = pow(*word, ROOT) - constant;
        }
    };
    let target: [M31; N_STATE] = core::array::from_fn(|j| M31::new(j as u32));
    let mut state = target;
    for constants in EXTERNAL_ROUND_CONSTS[N_HALF_FULL_ROUNDS..].iter().rev() {
        undo_full(&mut state, constants);
    }
    for &constant in INTERNAL_ROUND_CONSTS.iter().rev() {
        state = solve(internal, state);
        state[0] = pow(state[0], ROOT) - constant;
    }
    for constants in EXTERNAL_ROUND_CONSTS[..N_HALF_FULL_ROUNDS].iter().rev() {
        undo_full(&mut state, constants);
    }
    state = solve(external, state);
    let input = state;
    permute(&mut state);
    assert_eq!(state, target);
    input
        .iter()
        .flat_map(|word| word.value().to_le_bytes())
        .collect()
}

/// A wrong address carry is refused: the call's row with the carry out of
/// its first input address's low byte set where the address does not
/// overflow it. The limbs still sum to the address, but its ledger halves
/// are not the address's and one is negative, so the read joins no group:
/// every constraint holds and the memory ledger does not balance.
#[test]
fn a_wrong_address_carry_is_refused() {
    let program = the_program();
    let side_note = || run(&blob(), &witness(1));
    assert!(side_note().poseidon2_ops[0].in_ptr & 0xff < 0x100 - 64);
    let position = device_chips_of_mask(program.active)
        .position(|chip| chip == device_chip::POSEIDON2)
        .expect("the Poseidon2 chip");
    let tamper = |trace: &mut vos_pvm_proof::masked::MaskedDeviceTrace| {
        let log_size = trace.log_sizes[position];
        let columns = trace.main_columns_mut().nth(position).expect("the chip");
        let row = bit_reverse_index(coset_index_to_circle_domain_index(0, log_size), log_size);
        columns[poseidon2::Column::InCarry.offset()].as_mut_slice()[row] = BaseField::from(1);
    };
    let (proof, _) = prove_device_forced::<P2>(
        &format(),
        program,
        &mut side_note(),
        MaskRng::Seeded(7),
        tamper,
        |_, _| {},
        Checks::ALL,
    )
    .expect("every constraint holds");
    let outcome = verify_device::<P2>(&format(), program, &proof);
    assert!(matches!(outcome, Err(Error::Logup)), "{outcome:?}");
}

/// The run with its Poseidon2 call's first input word `word`: the witness
/// input's bytes, the call's and its output the permutation's of the word
/// as the field reads it, so only the word's range is wrong.
fn with_input_word(word: u32) -> SideNote {
    use vos_pvm_poseidon2::{M31, N_STATE, P};
    let mut side_note = run(&blob(), &witness(1));
    let bytes = word.to_le_bytes();
    let step = side_note
        .steps
        .iter_mut()
        .find(|step| step.witness.is_some())
        .expect("the witness input's step");
    step.witness.as_mut().expect("its bytes").bytes[..4].copy_from_slice(&bytes);
    let op = &mut side_note.poseidon2_ops[0];
    op.input[..4].copy_from_slice(&bytes);
    let mut state: [M31; N_STATE] = core::array::from_fn(|j| {
        M31::new(u32::from_le_bytes(op.input[4 * j..4 * j + 4].try_into().unwrap()) % P)
    });
    vos_pvm_poseidon2::permute(&mut state);
    for (bytes, word) in op.output.chunks_exact_mut(4).zip(&state) {
        bytes.copy_from_slice(&word.value().to_le_bytes());
    }
    side_note
}

/// An input word at or above p is refused, p itself included: p, whose
/// bytes' sum has no inverse, and 2^31 + 5, whose top byte is past 127.
#[test]
fn an_input_word_at_or_above_p_is_refused() {
    refused_as_a_broken_constraint(the_program(), || with_input_word(vos_pvm_poseidon2::P));
    refused_as_unbalanced(the_program(), with_input_word((1 << 31) + 5));
}

/// A call without its row is refused: the run's Poseidon2 call served and
/// acknowledged by the CPU, the chip's row (and its memory accesses) gone.
#[test]
fn a_call_without_its_row_is_refused() {
    let mut side_note = run(&blob(), &witness(1));
    side_note.poseidon2_ops.clear();
    refused_as_unbalanced(the_program(), side_note);
}

/// The public sums: an io-hash other than the run's is refused, and so is a
/// forced proof that blinds DeviceIoChip's claimed sum (the blinding still
/// summing to zero, every constraint held).
#[test]
fn the_io_hash_is_bound() {
    let format = format();
    let program = the_program();
    let (honest, _) =
        prove::<P2>(&format, program, &blob(), &witness(1), MaskRng::Seeded(4)).expect("proves");
    let mut other = honest.clone();
    other.io[0] ^= 1;
    assert!(matches!(
        verify_device::<P2>(&format, program, &other),
        Err(Error::InteractionPow | Error::Logup)
    ));
    let blinded = forced(
        program,
        &mut run(&blob(), &witness(1)),
        |_, _| {},
        Checks {
            constraints: true,
            public_unblinded: false,
        },
    );
    assert!(matches!(
        verify_device::<P2>(&format, program, &blinded),
        Err(Error::Logup)
    ));
}

/// The program is the transcript's: a proof verified against another
/// program's chips mixed after the header, or another program's root, is
/// refused; the claimed sums and the io-hash read under the honest header
/// verify.
#[test]
fn the_program_is_mixed_into_the_transcript() {
    let format = format();
    let program = the_program();
    let (proof, _) =
        prove::<P2>(&format, program, &blob(), &witness(1), MaskRng::Seeded(5)).expect("proves");
    let verify_under = |header: &[u64]| {
        let (masked, layout) = device_format(&format, program, header).expect("the format");
        let public = device_public_values(&proof.io);
        let zero = |_: &AllLookupElements| SecureField::zero();
        let bound = |relations: &AllLookupElements, sums: &[SecureField]| {
            device_bound_sums(program.active, &proof.io, relations, sums)
        };
        let claim = Claim {
            log_sizes: &program.log_sizes,
            circuit: Some(program.circuit),
            public: &public,
            public_sum: Some(&zero),
            bound_sums: Some(&bound),
            interaction_pow: proof.proof.interaction_pow,
            claimed_sums: &proof.proof.claimed_sums,
        };
        catch_unwind(AssertUnwindSafe(|| {
            verify_masked::<P2, DeviceComponents>(
                &masked,
                &claim,
                &layout,
                proof.proof.stark_proof.clone(),
            )
        }))
        .unwrap_or(Err(Error::Format))
    };
    verify_under(&program.header()).expect("the honest header");
    let [tag, active] = program.header();
    assert!(verify_under(&[tag, active ^ 1 << device_chip::MUL]).is_err());
    assert!(verify_under(&[tag]).is_err());
    let mut other = program.clone();
    other.circuit = install::<P2>(
        &format,
        &blob_with_other_data(),
        program.active,
        &program.log_sizes,
    )
    .expect("installs")
    .circuit;
    assert!(matches!(
        verify_device::<P2>(&format, &other, &proof),
        Err(Error::Circuit)
    ));
}

/// The kernel with other read-only data: another program of the same chips
/// and sizes.
fn blob_with_other_data() -> Vec<u8> {
    let mut blob = blob();
    let program = vos_pvm_program::parse_standard_program(&blob).expect("standard");
    let at = blob
        .windows(program.ro_data.len())
        .position(|window| window == program.ro_data.as_slice())
        .expect("the read-only data in the blob");
    blob[at] ^= 1;
    blob
}

/// A tampered proof is refused, never a panic: a claimed sum, a sample, the
/// interaction PoW, the io-hash.
#[test]
fn a_tampered_proof_is_refused() {
    let format = format();
    let program = the_program();
    let (honest, _) =
        prove::<P2>(&format, program, &blob(), &witness(1), MaskRng::Seeded(6)).expect("proves");
    type Mutation = Box<dyn Fn(&mut Proof<P2>)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|p| p.proof.claimed_sums[0] += SecureField::one()),
        Box::new(|p| p.proof.interaction_pow ^= 1),
        Box::new(|p| p.proof.stark_proof.0.sampled_values[1][0][0] += SecureField::one()),
        Box::new(|p| p.proof.stark_proof.0.sampled_values[2][3][0] += SecureField::one()),
        Box::new(|p| p.io[31] ^= 0x80),
        Box::new(|p| p.proof.claimed_sums.pop().map(drop).unwrap_or(())),
    ];
    for (k, mutate) in mutations.iter().enumerate() {
        let mut proof = honest.clone();
        mutate(&mut proof);
        let outcome = catch_unwind(AssertUnwindSafe(|| verify::<P2>(&format, program, &proof)));
        assert!(matches!(outcome, Ok(Err(_))), "mutation {k}: {outcome:?}");
    }
}

/// The masked device set's public sum is DeviceIoChip's alone.
#[test]
fn the_io_hash_is_the_one_public_sum() {
    let program = the_program();
    let layout = DeviceComponents::layout(program.active, &program.log_sizes).expect("laid out");
    let position = vos_pvm_proof::device::device_chips_of_mask(program.active)
        .position(|chip| chip == device_chip::DEVICE_IO);
    assert_eq!(
        layout.public_sums(),
        position.into_iter().collect::<Vec<_>>()
    );
}

/// Masked acceptance at the device candidates' parameters
/// (`device-params.md`): blowup 4 with 43 queries (`h = 512`, every chip at
/// `2^11` rows at least) and blowup 2 with 86 (`h = 1,024`, `2^12`), and the
/// device format's, blowup 4 with 47 (`h = 256`, `2^10`), on Blake2s; R1 in
/// one attempt, within the `4·2 + 3q` rows a column reveals, two witnesses
/// under one program.
#[cfg(feature = "heavy-gates")]
#[test]
fn heavy_device_proofs_verify_at_the_device_parameters() {
    for (log_blowup, queries, log_mask_rows, floor) in
        [(2, 43, 9, 11), (1, 86, 10, 12), (2, 47, 8, 10)]
    {
        let format = Format {
            params: vos_pvm_proof::format::FormatParams {
                log_blowup,
                ..small_format(ChannelKind::Blake2s, log_mask_rows, queries).params
            },
            ..small_format(ChannelKind::Blake2s, log_mask_rows, queries)
        };
        let program = program::<Blake2sMerkleChannel>(&format, &blob());
        assert!(program.log_sizes.iter().all(|&log_size| log_size >= floor));
        for seed in [1, 2] {
            let (proof, stats) = prove::<Blake2sMerkleChannel>(
                &format,
                &program,
                &blob(),
                &witness(seed),
                MaskRng::Seeded(seed),
            )
            .expect("proves");
            verify_device::<Blake2sMerkleChannel>(&format, &program, &proof).expect("verifies");
            assert_eq!(stats.attempts, 1);
            assert!(stats.revealed_rows <= 8 + 3 * queries, "{stats:?}");
            assert!(stats.revealed_rows <= 1 << log_mask_rows, "{stats:?}");
        }
    }
}

/// A kernel shifting a word right by 3 and by 0 (`ShloRImm64`), the
/// results its io-hash's first two words: through MUL, so its device shape
/// holds MUL and no DIVREM.
fn shift_kernel() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_stack_pages(1);
    asm.load_imm_64(Reg::T0, 0x8123_4567_89ab_cdef);
    for (register, amount) in [(Reg::A2, 3u8), (Reg::A3, 0)] {
        // ShloRImm64: `register = T0 >> amount`, the destination in the
        // register byte's low nibble, the source in its high one.
        asm.emit_raw(152, true);
        asm.emit_raw(register as u8 | (Reg::T0 as u8) << 4, false);
        asm.emit_raw(amount, false);
    }
    for (register, word) in [Reg::A4, Reg::A5].into_iter().zip(IO) {
        asm.load_imm(register, word as i32);
    }
    asm.load_imm(Reg::T0, 0).jump_ind(Reg::RA, 0);
    asm.build()
}

/// A logical right shift's result other than its multiplication's high
/// word (its low word when the amount is 0) is refused on the device
/// shape: the shift by 3's result, and the shift by 0's, each changed in
/// the run and every later step's register file with it. The honest run's
/// shape holds MUL and no DIVREM.
#[test]
fn a_logical_right_shifts_forged_result_is_refused() {
    use vos_pvm_proof::device::device_chip::{DIVREM, MUL};
    let kernel = shift_kernel();
    let program = program_of(&kernel);
    assert_ne!(program.active & 1 << MUL, 0);
    assert_eq!(program.active & 1 << DIVREM, 0);
    let honest = || {
        vos_pvm_proof::kernel::trace_kernel(&kernel, &[], 10_000)
            .expect("halts")
            .side_note
    };
    prove_device::<P2>(&format(), &program, &mut honest(), MaskRng::Seeded(7))
        .expect("the honest run proves");
    for register in [Reg::A2 as usize, Reg::A3 as usize] {
        refused_as_a_broken_constraint(&program, || {
            let mut side_note = honest();
            let at = side_note
                .steps
                .iter()
                .position(|step| step.reg_write == Some(register))
                .expect("the shift's step");
            let forged = side_note.steps[at].regs_after[register] ^ 1 << 40;
            side_note.steps[at].regs_after[register] = forged;
            for step in &mut side_note.steps[at + 1..] {
                step.regs_before[register] = forged;
                step.regs_after[register] = forged;
            }
            side_note
        });
    }
}
