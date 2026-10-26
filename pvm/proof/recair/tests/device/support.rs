//! The device kernels, the masked formats and the install, prove and
//! verify helpers the device's gates share.

use std::sync::OnceLock;

use stwo::core::channel::MerkleChannel;
use stwo::core::pcs::DeepBatching;
use stwo::prover::backend::BackendForChannel;
use stwo::prover::backend::simd::SimdBackend;
use vos_pvm_compiler::assembler::{Assembler, Reg};
use vos_pvm_final_verifier::Error;
use vos_pvm_proof::core::ecall::{ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
use vos_pvm_proof::format::{ChannelKind, Format, FormatParams, Masking, SEGMENT};
use vos_pvm_proof::poseidon2::P2MerkleChannel;
use vos_pvm_proof::side_note::SideNote;
use vos_pvm_recair::ProveError;
use vos_pvm_recair::masked::MaskRng;
use vos_pvm_recair::masked::MaskStats;
use vos_pvm_recair::masked::device::{
    DeviceProgram, DeviceProof, device_shape, install, prove_device, verify_device,
};

/// The kernel's io-hash words, φ9..12: its one public output, the same for
/// every witness.
pub const IO: [u32; 4] = [0x4433_2211, 0x0807_0605, 0x7f00_00ff, 0x1abc_def0];

/// The read-only data's first page base and the read-write data's, as the
/// standard layout places them for data under a zone.
pub const RO_BASE: u32 = 0x1_0000;
pub const RW_BASE: u32 = 0x3_0000;
/// The stack's top, φ1 at entry: the standard layout's for a stack under a
/// zone.
pub const STACK_TOP: u32 = 0xfefe_0000;
/// The heap's first page: the page after the read-write data's one.
pub const HEAP: u32 = RW_BASE + 0x1000;
/// The read-only data.
pub const RO_DATA: [u8; 16] = [
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x0f,
];
/// The read-write data.
pub const RW_DATA: [u8; 8] = [0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];

/// The device kernel, branch-free: it reads 64 bytes of witness input onto
/// its stack, hashes them with the Poseidon2 call into the 32 bytes after
/// them, reads a read-only byte and the read-write data's word, writes the
/// word to the heap, sets φ9..12 to [`IO`] and φ8 to 0, and halts. Its
/// steps and its touches' addresses are the same for every witness.
pub fn blob() -> Vec<u8> {
    let mut asm = Assembler::new();
    asm.set_ro_data(RO_DATA.to_vec())
        .set_rw_data(RW_DATA.to_vec())
        .set_heap_pages(1)
        .set_stack_pages(1);
    asm.add_imm_64(Reg::S0, Reg::SP, -128)
        .move_reg(Reg::A0, Reg::S0)
        .load_imm(Reg::A1, 64)
        .ecalli(ECALL_WITNESS_INPUT)
        .move_reg(Reg::A0, Reg::S0)
        .add_imm_64(Reg::A1, Reg::S0, 64)
        .ecalli(ECALL_POSEIDON2)
        .load_u8(Reg::T0, RO_BASE + 3)
        .load_u64(Reg::T1, RW_BASE)
        .store_u64(Reg::T1, HEAP + 8);
    io_and_halt(&mut asm);
    asm.build()
}

/// φ9..12 set to [`IO`], φ7, φ8 and the temporaries cleared, and the halt.
pub fn io_and_halt(asm: &mut Assembler) {
    for (register, word) in [Reg::A2, Reg::A3, Reg::A4, Reg::A5].into_iter().zip(IO) {
        asm.load_imm(register, word as i32);
    }
    for register in [Reg::A0, Reg::A1, Reg::T0, Reg::T1, Reg::T2, Reg::S0] {
        asm.load_imm(register, 0);
    }
    asm.jump_ind(Reg::RA, 0);
}

/// [`IO`] as the io-hash's 32 bytes, φ9..12's LE bytes, each word
/// sign-extended as `load_imm` loads it.
pub fn io_bytes() -> [u8; 32] {
    let mut io = [0u8; 32];
    for (bytes, word) in io.chunks_exact_mut(8).zip(IO) {
        bytes.copy_from_slice(&(word as i32 as i64 as u64).to_le_bytes());
    }
    io
}

/// A witness: 64 bytes, sixteen words below p from `seed`.
pub fn witness(seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..16)
        .flat_map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            ((state as u32) & 0x7fff_fffe).to_le_bytes()
        })
        .collect()
}

/// The kernel's run on `input`, traced with the Poseidon2 call served.
pub fn run(blob: &[u8], input: &[u8]) -> SideNote {
    vos_pvm_proof::kernel::trace_device_kernel(blob, input, 10_000)
        .expect("halts")
        .side_note
}

/// A masked device format of no registered number on `channel`: blowup 4,
/// `n_queries` queries, `h = 2^log_mask_rows`, 8 salts a tree and an `R` of
/// 8.
pub fn small_format(channel: ChannelKind, log_mask_rows: u32, n_queries: usize) -> Format {
    Format {
        number: 0x7e43,
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

/// The small format R1 passes: `h = 64`, every chip at 2^8 rows at least.
pub fn format() -> Format {
    small_format(ChannelKind::Poseidon2M31, 6, 4)
}

/// The kernel's program under `format` on `MC`, its shape from a reference
/// run.
pub fn program<MC: MerkleChannel>(format: &Format, blob: &[u8]) -> DeviceProgram<MC::H>
where
    SimdBackend: BackendForChannel<MC>,
{
    let mut reference = run(blob, &witness(0));
    let (active, log_sizes) = device_shape(format, blob, &mut reference).expect("a shape");
    install::<MC>(format, blob, active, &log_sizes).expect("installs")
}

/// [`blob`]'s program under [`format`] on the Poseidon2 channel, once a
/// test binary.
pub fn the_program() -> &'static DeviceProgram<<P2MerkleChannel as MerkleChannel>::H> {
    static PROGRAM: OnceLock<DeviceProgram<<P2MerkleChannel as MerkleChannel>::H>> =
        OnceLock::new();
    PROGRAM.get_or_init(|| program::<P2MerkleChannel>(&format(), &blob()))
}

/// A proof on `MC`.
pub type Proof<MC> = DeviceProof<<MC as MerkleChannel>::H>;

/// The kernel's run on `input` proved under `program`.
pub fn prove<MC: MerkleChannel>(
    format: &Format,
    program: &DeviceProgram<MC::H>,
    blob: &[u8],
    input: &[u8],
    rng: MaskRng,
) -> Result<(Proof<MC>, MaskStats), ProveError>
where
    SimdBackend: BackendForChannel<MC>,
{
    prove_device::<MC>(format, program, &mut run(blob, input), rng)
}

/// Verifies a device proof against `program`.
pub fn verify<MC: MerkleChannel>(
    format: &Format,
    program: &DeviceProgram<MC::H>,
    proof: &Proof<MC>,
) -> Result<(), Error>
where
    SimdBackend: BackendForChannel<MC>,
{
    verify_device::<MC>(format, program, proof)
}
