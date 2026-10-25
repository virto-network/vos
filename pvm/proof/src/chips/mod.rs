/// The least log size of the arithmetic chips' traces (multiplication,
/// division, comparison and the bitwise operations).
#[cfg(feature = "prover")]
const MIN_ARITHMETIC_LOG_SIZE: u32 = 5;

pub mod bitcount;
pub mod bitwise;
pub mod bitwise_and_byte;
pub mod bitwise_lookup;
pub mod blake2b;
pub mod byte_to_bits;
pub mod compare;
pub mod cpu;
pub mod divrem;
pub mod jump_table;
pub mod memory;
pub mod memory_merkle;
pub mod memory_page;
pub mod memory_root_boundary;
pub mod mul;
mod ordering;
pub mod popcount;
pub mod power_of_two;
pub mod program_boundary;
pub mod program_memory;
pub mod range_multiplicity;
pub mod register_memory;
pub mod register_memory_boundary;
pub mod register_memory_closing;
pub mod witness_input;

pub use bitcount::BitcountChip;
pub use bitwise::BitwiseChip;
pub use bitwise_and_byte::BitwiseAndByteChip;
pub use bitwise_lookup::BitwiseLookupChip;
pub use blake2b::{Blake2bBoundaryChip, Blake2bCall, Blake2bChip, blake2b_compress};
pub use byte_to_bits::ByteToBitsChip;
pub use compare::CompareChip;
pub use cpu::CpuChip;
pub use divrem::DivRemChip;
pub use jump_table::JumpTableChip;
pub use memory::MemoryChip;
pub use memory_merkle::MemoryMerkleChip;
pub use memory_page::MemoryPageChip;
pub use memory_root_boundary::MemoryRootBoundaryChip;
pub use mul::MulChip;
pub use popcount::PopcountChip;
pub use power_of_two::PowerOfTwoChip;
pub use program_boundary::ProgramBoundaryChip;
pub use program_memory::ProgramMemoryChip;
pub use range_multiplicity::RangeMultiplicity256;
pub use register_memory::RegisterMemoryChip;
pub use register_memory_boundary::RegisterMemoryBoundaryChip;
pub use register_memory_closing::RegisterMemoryClosingChip;
pub use witness_input::WitnessInputChip;

/// A fixed table's log size: its entries' `natural`, or `floor` when that
/// is larger, its rows past the entries repeating them with no
/// multiplicity, so a padded table holds the same entries.
#[cfg(feature = "prover")]
pub(crate) fn table_log_size(natural: u32, floor: u32) -> u32 {
    natural
        .max(stwo::prover::backend::simd::m31::LOG_N_LANES)
        .max(floor)
}
