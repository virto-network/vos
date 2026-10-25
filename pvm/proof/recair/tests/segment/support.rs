//! The small kernels, the masked formats and the prove and verify helpers
//! the segment's gates share.

use stwo::core::channel::MerkleChannel;
use stwo::core::pcs::DeepBatching;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::format::{ChannelKind, Format, FormatParams, Masking, SEGMENT};
use vos_pvm_proof::segment::SegmentCursor;
use vos_pvm_proof::side_note::SideNote;
use vos_pvm_recair::ProveError;
use vos_pvm_recair::masked::segment::{SegmentProof, prove_segment, verify_segment};
use vos_pvm_recair::masked::{MaskRng, MaskStats};

/// The small kernel's io-hash words, φ9..12.
pub const IO: [u32; 4] = [0x4433_2211, 0x0807_0605, 0x7f00_00ff, 0x9abc_def0];

/// The other kernel's: φ9 one more.
pub const IO_OTHER: [u32; 4] = [0x4433_2212, 0x0807_0605, 0x7f00_00ff, 0x9abc_def0];

/// A standard program that sets φ8 (the output's length) to 0 and φ9..12 to
/// `io`, sums φ9 and φ12 into φ7 and clears φ7 again (a value no boundary
/// state holds), then returns to φ0, the halt address.
pub fn blob(io: [u32; 4]) -> Vec<u8> {
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    let load = |register: u8, value: u32, code: &mut Vec<u8>, bitmask: &mut Vec<u8>| {
        code.extend_from_slice(&[51, register]);
        code.extend_from_slice(&value.to_le_bytes());
        bitmask.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
    };
    for (register, value) in [(8u8, 0u32)].into_iter().chain((9..13).zip(io)) {
        load(register, value, &mut code, &mut bitmask);
    }
    // add_64 φ7 = φ9 + φ12, then φ7 = 0.
    code.extend_from_slice(&[200, 9 | 12 << 4, 7]);
    bitmask.extend_from_slice(&[1, 0, 0]);
    load(7, 0, &mut code, &mut bitmask);
    code.extend_from_slice(&[50, 0]);
    bitmask.extend_from_slice(&[1, 0]);
    vos_pvm_program::build_standard_program(&vos_pvm_program::StandardProgram {
        ro_data: vec![],
        rw_data: vec![],
        heap_pages: 1,
        stack_size: 4096,
        code: vos_pvm_program::CodeBlob {
            jump_table: vec![],
            code,
            bitmask,
        },
    })
    .expect("a standard program")
}

/// The value φ7 holds between the sum and its clearing: no boundary
/// state's.
pub fn secret(io: [u32; 4]) -> u64 {
    let extend = |word: u32| word as i32 as i64 as u64;
    extend(io[0]).wrapping_add(extend(io[3]))
}

/// The kernel of `io`'s whole run, one segment.
pub fn run(io: [u32; 4]) -> SideNote {
    let trace = vos_pvm_proof::kernel::trace_kernel(&blob(io), &[], 1_000).expect("halts");
    let steps = trace.side_note.steps.len();
    SegmentCursor::new(&trace.side_note).side_note(0, steps)
}

/// The chips the kernel's run activates.
pub fn active(side_note: &SideNote) -> u32 {
    vos_pvm_proof::active_component_mask(side_note)
}

/// A masked segment format of no registered number on `channel`: blowup 4,
/// `n_queries` queries, `h = 2^log_mask_rows`, 8 salts a tree and an `R` of
/// 8.
pub fn small_format(channel: ChannelKind, log_mask_rows: u32, n_queries: usize) -> Format {
    Format {
        number: 0x7e58,
        channel,
        params: FormatParams {
            log_blowup: 2,
            n_queries,
            pow_bits: 4,
            fold_step: 1,
            log_last_layer: 0,
            interaction_pow_bits: 4,
            batching: DeepBatching::Affine,
        },
        masked: true,
        masking: Some(Masking {
            salt_columns: 8,
            fri_mask_columns: 8,
            log_mask_rows,
        }),
        ..SEGMENT
    }
}

/// The small format R1 passes: `h = 64` against `2(4·2 + 4·3) = 40` revealed
/// rows; every chip at 2^8 rows at least.
pub fn format() -> Format {
    small_format(ChannelKind::Poseidon2M31, 6, 4)
}

/// A proof on `MC`.
pub type Proof<MC> = SegmentProof<<MC as MerkleChannel>::H>;

/// The kernel of `io` proved masked under `format` on `MC`.
pub fn prove<MC: MerkleChannel>(
    format: &Format,
    io: [u32; 4],
    rng: MaskRng,
) -> Result<(Proof<MC>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    let mut side_note = run(io);
    let active = active(&side_note);
    prove_segment::<MC>(format, &mut side_note, active, rng)
}

/// Verifies a masked segment proof on `MC`.
pub fn verify<MC: MerkleChannel>(format: &Format, proof: &Proof<MC>) -> Result<(), Error> {
    verify_segment::<MC>(format, proof, None)
}
