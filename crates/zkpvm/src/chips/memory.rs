#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use alloc::collections::BTreeMap;
use num_traits::One;
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{
        fields::qm31::SecureField,
        ColumnVec,
    },
    prover::{
        backend::simd::{m31::LOG_N_LANES, SimdBackend},
        poly::{circle::CircleEvaluation, BitReversedOrder},
    },
};
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use crate::air_column::{AirColumn, PreprocessedAirColumn};
use crate::trace::eval::TraceEval;
#[cfg(feature = "prover")]
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};

use crate::{
    framework::{BuiltInComponent},
    lookups::{MemoryAccessLookupElements},
};
#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;

/// MemoryChip: proves read/write consistency of RAM accesses.
///
/// Each row is one memory access (Load or Store). The trace is sorted by
/// (address, timestamp). For consecutive accesses to the same address,
/// reads must return the value from the last write.
pub struct MemoryChip;

/// Byte-level memory model: each row is a single byte access.
/// Multi-byte accesses are decomposed into N byte entries.
#[derive(Debug, Copy, Clone, AirColumn)]
pub enum Column {
    /// Byte address (4 limbs, u32)
    #[size = 4]
    Address,
    /// Single byte value
    #[size = 1]
    Value,
    /// Timestamp of this access (8 limbs)
    #[size = 8]
    Timestamp,
    /// 1 = write, 0 = read
    #[size = 1]
    IsWrite,
    /// Previous byte value at same address
    #[size = 1]
    PrevValue,
    /// 1 if the next row accesses the same address
    #[size = 1]
    IsSameAddrNext,
    /// 1 if padding row
    #[size = 1]
    IsPadding,
    // (B3 audit dropped RealReadH — read-consistency now uses an
    // unconditional `(1 - is_write) · (value - prev_value) = 0`
    // constraint.  Padding rows have value=0 and prev_value=0, so the
    // stronger unconditional form holds.)
}

#[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
#[preprocessed_prefix = "mem"]
pub enum PreprocessedColumn {}

/// A single byte-level memory access entry.
#[derive(Clone, Debug)]
struct MemEntry {
    address: u32,
    value: u8,
    timestamp: u64,
    is_write: bool,
}

/// Decompose a multi-byte access into individual byte entries.
fn decompose_access(address: u32, value: u64, timestamp: u64, is_write: bool, size: u8) -> Vec<MemEntry> {
    let bytes = value.to_le_bytes();
    (0..size as usize).map(|i| MemEntry {
        address: address + i as u32,
        value: bytes[i],
        timestamp,
        is_write,
    }).collect()
}

impl BuiltInComponent for MemoryChip {
    type PreprocessedColumn = PreprocessedColumn;
    type MainColumn = Column;
    type LookupElements = MemoryAccessLookupElements;


    fn add_constraints<E: EvalAtRow>(
        &self,
        eval: &mut E,
        trace_eval: TraceEval<PreprocessedColumn, Column, E>,
        lookup_elements: &MemoryAccessLookupElements,
    ) {
        let is_pad = crate::trace::trace_eval!(trace_eval, Column::IsPadding);
        let is_real = E::F::one() - is_pad[0].clone();

        let address = crate::trace::trace_eval!(trace_eval, Column::Address);
        let value = crate::trace::trace_eval!(trace_eval, Column::Value);
        let timestamp = crate::trace::trace_eval!(trace_eval, Column::Timestamp);
        let is_write = crate::trace::trace_eval!(trace_eval, Column::IsWrite);
        let prev_value = crate::trace::trace_eval!(trace_eval, Column::PrevValue);

        // B3 audit: read consistency unconditional (was via
        // RealReadH = is_real · (1 - is_write)).  On padding rows
        // value=prev_value=0 so 1·0=0 holds.
        let is_read = E::F::one() - is_write[0].clone();
        eval.add_constraint(
            is_read * (value[0].clone() - prev_value[0].clone())
        );

        // Consumer lookup (negative multiplicity)
        // Byte-level tuple: (addr[4], value[1], timestamp[8], is_write[1])
        let mut tuple: Vec<E::F> = address.to_vec();
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&timestamp);
        tuple.push(is_write[0].clone());

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real.clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

#[cfg(feature = "prover")]
impl BuiltInProverComponent for MemoryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut(&self, side_note: &SideNote) -> FinalizedTrace {
        let mut entries: Vec<MemEntry> = Vec::new();

        // Collect step memory accesses, decomposed to individual bytes
        for step in &side_note.steps {
            if let Some(ref r) = step.mem_read {
                entries.extend(decompose_access(r.address, r.value, step.timestamp, false, r.size));
            }
            if let Some(ref w) = step.mem_write {
                entries.extend(decompose_access(w.address, w.value, step.timestamp, true, w.size));
            }
        }

        // Blake2b precompile memory ops: 64 byte reads at h_ptr + 128 byte
        // reads at m_ptr + 64 byte writes back at h_ptr, all at the ECALL
        // step's ts.  Reads are pushed before writes so the stable
        // `sort_by_key(|e| (e.address, e.timestamp))` at the end keeps the
        // (read, then write) order at the same (addr, ts) pair.
        for op in &side_note.blake2b_mem_ops {
            for (i, &b) in op.h_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.h_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.m_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.m_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.h_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: true,
                });
            }
        }

        // Step 13: Ristretto255 scalar-mult precompile memory ops.
        // 32 reads each (scalar + point) + 32 writes (output), all
        // at the ECALL ts.  Producer side comes from
        // RistrettoEcallChip.
        for op in &side_note.ristretto_mem_ops {
            for (i, &b) in op.scalar_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.scalar_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: false,
                });
            }
            for (i, &b) in op.point_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.point_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.output_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: true,
                });
            }
        }

        // Step 13: Ristretto255 point-add precompile memory ops:
        // 32 reads each (P + Q) + 32 writes (output), all at ECALL ts.
        for op in &side_note.ristretto_add_mem_ops {
            for (i, &b) in op.p_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.p_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: false,
                });
            }
            for (i, &b) in op.q_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.q_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.output_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: true,
                });
            }
        }

        // Step 18: scalar mul/add mod ℓ precompile memory ops:
        // 32 reads (a) + 32 reads (b) + 32 writes (output) per call.
        for op in &side_note.scalar_binop_mem_ops {
            for (i, &b) in op.a_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.a_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: false,
                });
            }
            for (i, &b) in op.b_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.b_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.output_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: true,
                });
            }
        }

        // Step 13: scalar_from_bytes_mod_order_wide precompile memory
        // ops: 64 reads (wide input) + 32 writes (canonical output).
        for op in &side_note.scalar_reduce_wide_mem_ops {
            for (i, &b) in op.wide_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.wide_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.output_ptr + i as u32,
                    value: b, timestamp: op.ts, is_write: true,
                });
            }
        }

        // Inject initial memory writes at timestamp 0 for byte addresses read without prior write.
        if !side_note.initial_memory.is_empty() {
            let mut first_access: BTreeMap<u32, bool> = BTreeMap::new();
            for e in &entries {
                first_access.entry(e.address).or_insert(e.is_write);
            }

            let flat_mem = &side_note.initial_memory;
            for (&addr, &first_is_write) in &first_access {
                if first_is_write { continue; }
                let a = addr as usize;
                let value = if a < flat_mem.len() { flat_mem[a] } else { 0 };
                entries.push(MemEntry {
                    address: addr,
                    value,
                    timestamp: 0,
                    is_write: true,
                });
            }
        }

        if entries.is_empty() {
            let log_size = LOG_N_LANES;
            let mut trace = TraceBuilder::<Column>::new(log_size);
            for row in 0..trace.num_rows() {
                trace.fill_columns(row, true, Column::IsPadding);
            }
            return trace.finalize_bit_reversed();
        }

        // Sort by (address, timestamp) — initial writes at ts=0 come first per address
        entries.sort_by_key(|e| (e.address, e.timestamp));

        let num_entries = entries.len();
        let log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_entries);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        for (row, entry) in entries.iter().enumerate() {
            trace.fill_columns_bytes(row, &entry.address.to_le_bytes(), Column::Address);
            trace.fill_columns(row, entry.value, Column::Value);
            trace.fill_columns(row, entry.timestamp, Column::Timestamp);
            trace.fill_columns(row, entry.is_write, Column::IsWrite);

            let prev_value: u8 = if row > 0 && entries[row - 1].address == entry.address {
                entries[row - 1].value
            } else {
                0
            };
            trace.fill_columns(row, prev_value, Column::PrevValue);

            let same_addr_next = row + 1 < num_entries && entries[row + 1].address == entry.address;
            trace.fill_columns(row, same_addr_next, Column::IsSameAddrNext);
            trace.fill_columns(row, false, Column::IsPadding);
            // Phase I-mem helper.  IsRead = 1 - IsWrite; on real rows
            // (B3 audit dropped RealReadH fill.)
        }

        for row in num_entries..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
        }

        trace.finalize_bit_reversed()
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

        let mem_lookup: &MemoryAccessLookupElements = lookup_elements.as_ref();
        let is_pad = crate::trace::original_base_column!(component_trace, Column::IsPadding);
        let address = crate::trace::original_base_column!(component_trace, Column::Address);
        let value = crate::trace::original_base_column!(component_trace, Column::Value);
        let timestamp = crate::trace::original_base_column!(component_trace, Column::Timestamp);
        let is_write = crate::trace::original_base_column!(component_trace, Column::IsWrite);

        // Byte-level tuple: (addr[4], value[1], timestamp[8], is_write[1])
        let mut tuple: Vec<_> = address.to_vec();
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&timestamp);
        tuple.push(is_write[0].clone());

        // Consumer side (negative multiplicity)
        logup.add_to_relation_with(
            mem_lookup,
            [is_pad[0].clone()],
            |[pad]| {
                use stwo::prover::backend::simd::m31::PackedBaseField;
                (-(PackedBaseField::one() - pad)).into()
            },
            &tuple,
        );

        logup.finalize()
    }
}
