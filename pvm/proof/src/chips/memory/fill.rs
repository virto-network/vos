//! The chip's trace generation, the prover's half.

use super::*;
use crate::framework::BuiltInProverComponent;
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
use crate::side_note::SideNote;
use crate::trace::{
    builder::{FinalizedTrace, TraceBuilder},
    component::ComponentTrace,
};
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
    },
};

/// The ledger's write entries for a witness-input call's bytes, one a byte
/// from its address on, at `timestamp`.
fn witness_entries(
    write: &crate::core::step::WitnessWrite,
    timestamp: u64,
) -> impl Iterator<Item = MemEntry> + '_ {
    write
        .bytes
        .iter()
        .enumerate()
        .map(move |(offset, &value)| MemEntry {
            address: write.address.wrapping_add(offset as u32),
            value,
            timestamp,
            is_write: true,
        })
}

/// The ledger's accesses, one entry per byte: every step's read, write and
/// witness input, and the Blake2b precompile's reads and writes, unsorted.
pub(crate) fn access_entries(side_note: &SideNote) -> Vec<MemEntry> {
    let mut entries: Vec<MemEntry> = Vec::new();
    for step in &side_note.steps {
        if let Some(ref r) = step.mem_read {
            entries.extend(decompose_access(
                r.address,
                r.value,
                step.timestamp,
                false,
                r.size,
            ));
        }
        if let Some(ref w) = step.mem_write {
            entries.extend(decompose_access(
                w.address,
                w.value,
                step.timestamp,
                true,
                w.size,
            ));
        }
        // A witness-input call's bytes, written at its step's ts; it
        // reads no memory. `WitnessInputChip` produces their tuples.
        if let Some(ref w) = step.witness {
            entries.extend(witness_entries(w, step.timestamp));
        }
    }

    // Blake2b precompile memory ops: 64 byte reads at h_ptr + 128 byte
    // reads at m_ptr + 64 byte writes back at h_ptr, all at the ECALL
    // step's ts.  The ledger's order puts the reads before the writes
    // at the same (addr, ts) pair, as the AIR requires.
    for op in &side_note.blake2b_mem_ops {
        for (i, &b) in op.h_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.h_ptr.wrapping_add(i as u32),
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.m_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.m_ptr.wrapping_add(i as u32),
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.out_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.h_ptr.wrapping_add(i as u32),
                value: b,
                timestamp: op.ts,
                is_write: true,
            });
        }
    }
    // Poseidon2 calls: 64 byte reads at in_ptr, 32 byte writes at out_ptr,
    // at the call step's ts; `Poseidon2Chip` produces their tuples.
    for op in &side_note.poseidon2_ops {
        for (i, &value) in op.input.iter().enumerate() {
            entries.push(MemEntry {
                address: op.in_ptr.wrapping_add(i as u32),
                value,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &value) in op.output.iter().enumerate() {
            entries.push(MemEntry {
                address: op.out_ptr.wrapping_add(i as u32),
                value,
                timestamp: op.ts,
                is_write: true,
            });
        }
    }
    entries
}

impl BuiltInProverComponent for MemoryChip {
    const IS_PRODUCER: bool = false;

    fn generate_main_trace_immut_min(
        &self,
        side_note: &SideNote,
        min_log_size: u32,
    ) -> FinalizedTrace {
        let mut entries = access_entries(side_note);

        // Inject the per-page Merkle boundary entries (design §2): for every
        // byte of every listed page, a `ts=0` boundary write carrying the
        // ENTERING image byte and a closing read carrying the EXIT image byte.
        // Read-consistency + (addr, ts) sortedness then force the closing read
        // to chain to the byte's last written value (or, for never-written
        // bytes, to the ts=0 write so `after == before`), and the
        // group-start/group-end constraints force every accessed address into a
        // listed page.  Subsumes the old read-before-write ts=0 injection
        // (MemoryBoundaryChip is deleted); the producers are MemoryPageChip.
        let closing_ts = crate::chips::register_memory_closing::closing_ts_for(side_note);
        if let Some(payload) = &side_note.memory_pages {
            for page in &payload.pages {
                let base = page.page_idx as u64 * crate::page_merkle::PAGE_SIZE as u64;
                for i in 0..crate::page_merkle::PAGE_SIZE {
                    let addr = (base + i as u64) as u32;
                    entries.push(MemEntry {
                        address: addr,
                        value: page.before[i],
                        timestamp: 0,
                        is_write: true,
                    });
                    entries.push(MemEntry {
                        address: addr,
                        value: page.after[i],
                        timestamp: closing_ts,
                        is_write: false,
                    });
                }
            }
        }

        if entries.is_empty() {
            let log_size = LOG_N_LANES.max(min_log_size);
            let mut trace = TraceBuilder::<Column>::new(log_size);
            for row in 0..trace.num_rows() {
                trace.fill_columns(row, true, Column::IsPadding);
            }
            return trace.finalize_bit_reversed();
        }

        // Sort by (address, timestamp, is_write): initial writes at ts=0
        // come first per address, and at one ts its reads precede its writes.
        entries.sort_by_key(|e| (e.address, e.timestamp, e.is_write));

        let num_entries = entries.len();
        let mut log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_entries);
        // Guarantee ≥ 1 padding row so the cyclic last→row-0 wraparound is
        // always a padding row (the sortedness gadget must not fire across it).
        if (1usize << log_size) == num_entries {
            log_size += 1;
        }
        let log_size = log_size.max(min_log_size);
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        // Pass 1: base columns; track (addr, ts, is_same_addr) per row so the
        // ordering helpers (pass 2) can read the cyclic next row.
        let mut addrs = vec![0u32; num_rows];
        let mut keys = vec![0u64; num_rows];
        let mut same_addr = vec![false; num_rows];
        let layout = side_note.layout();
        let permission_of =
            |address: u32| layout.permission(address / crate::page_merkle::PAGE_SIZE as u32);
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

            // Closing read = the per-page exit-byte read at `closing_ts` (the
            // unique max ts, one per byte).  No real step / precompile entry
            // shares it (they sit at ts ≤ last_step.ts), so ts-equality is an
            // exact closing-row marker; guard the empty-trace `closing_ts == 0`
            // collision with the ts=0 boundary writes.
            let is_closing = closing_ts != 0 && entry.timestamp == closing_ts;
            trace.fill_columns(row, is_closing, Column::IsClosing);

            // The page's permission, as MemoryPageChip proves it, held
            // along the address's group; on its start, also the tuple's.
            use crate::memory_layout::Permission;
            let permission = permission_of(entry.address);
            trace.fill_columns(row, permission >= Permission::Readable, Column::Readable);
            trace.fill_columns(row, permission == Permission::Writable, Column::Writable);
            let is_start = row == 0 || entries[row - 1].address != entry.address;
            trace.fill_columns(row, is_start, Column::IsStart);
            trace.fill_columns(
                row,
                if is_start { permission as u8 } else { 0 },
                Column::PermissionH,
            );

            addrs[row] = entry.address;
            keys[row] = 2 * entry.timestamp + u64::from(entry.is_write);
            same_addr[row] = same_addr_next;
        }
        for row in num_entries..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
        }

        // Pass 2: ordering helpers, reading the cyclic next = (row+1) % num_rows.
        //   AdvLoH / AdvHiH: which 16-bit half advances (when not same address).
        //   OrderBits: 28-bit decomposition of OrderDelta = same·key_diff +
        //   lo·(lo_diff−1) + hi·(hi_diff−1), all ≥ 0.
        for row in 0..num_rows {
            let next = (row + 1) % num_rows;
            let both_real = row < num_entries && next < num_entries;
            let hi_eq = (addrs[row] >> 16) == (addrs[next] >> 16);
            let adv_lo = both_real && !same_addr[row] && hi_eq;
            let adv_hi = both_real && !same_addr[row] && !hi_eq;
            trace.fill_columns(row, adv_lo, Column::AdvLoH);
            trace.fill_columns(row, adv_hi, Column::AdvHiH);

            // Group boundary helpers: a row ends a group iff it is real and the
            // next address differs (or next is padding); the NEXT row starts a
            // group iff it is real and the address differs from this row (or
            // this row is padding — the cyclic wrap covers natural row 0).
            let next_real = next < num_entries;
            let is_group_start = next_real && !same_addr[row];
            let is_group_end = row < num_entries && !same_addr[row];
            trace.fill_columns(row, is_group_start, Column::IsGroupStart);
            trace.fill_columns(row, is_group_end, Column::IsGroupEnd);

            let order_delta: u64 = if same_addr[row] {
                keys[next] - keys[row]
            } else if adv_lo {
                ((addrs[next] & 0xFFFF) - (addrs[row] & 0xFFFF)) as u64 - 1
            } else if adv_hi {
                ((addrs[next] >> 16) - (addrs[row] >> 16)) as u64 - 1
            } else {
                0
            };
            let bits = super::super::ordering::bits("memory", order_delta);
            trace.fill_columns_base_field(row, &bits, Column::OrderBits);
        }

        trace.finalize_bit_reversed()
    }

    fn generate_interaction_trace(
        &self,
        component_trace: &ComponentTrace,
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
        let is_closing = crate::trace::original_base_column!(component_trace, Column::IsClosing);
        let permission = crate::trace::original_base_column!(component_trace, Column::PermissionH);

        // Byte-level tuple: (addr[4], value[1], timestamp[8], is_write[1],
        // is_closing + 2·permission[1])
        let (address, value, timestamp, is_write, is_closing, permission) = (
            address.clone(),
            value.clone(),
            timestamp.clone(),
            is_write.clone(),
            is_closing.clone(),
            permission.clone(),
        );

        // Consumer side (negative multiplicity)
        logup.add_to_relation_computed(
            mem_lookup,
            [is_pad[0].clone()],
            |[pad]| {
                use stwo::prover::backend::simd::m31::PackedBaseField;
                (-(PackedBaseField::one() - pad)).into()
            },
            15,
            move |v| {
                let mut tuple = Vec::with_capacity(15);
                for limb in &address {
                    tuple.push(limb.at(v));
                }
                tuple.push(value[0].at(v));
                for limb in &timestamp {
                    tuple.push(limb.at(v));
                }
                tuple.push(is_write[0].at(v));
                tuple.push(is_closing[0].at(v) + permission[0].at(v) + permission[0].at(v));
                tuple
            },
        );

        logup.finalize()
    }
}

/// A single byte-level memory access entry.
#[derive(Clone, Debug)]
pub(crate) struct MemEntry {
    pub(crate) address: u32,
    pub(crate) value: u8,
    pub(crate) timestamp: u64,
    pub(crate) is_write: bool,
}

/// Decompose a multi-byte access into individual byte entries.
fn decompose_access(
    address: u32,
    value: u64,
    timestamp: u64,
    is_write: bool,
    size: u8,
) -> Vec<MemEntry> {
    let bytes = value.to_le_bytes();
    (0..size as usize)
        .map(|i| MemEntry {
            // PVM memory is cyclic over 32-bit addresses. A successful wide
            // access is decomposed with the same modulo-2^32 arithmetic as
            // execution rather than relying on profile-dependent overflow
            // checks or debug/release integer behavior.
            address: address.wrapping_add(i as u32),
            value: bytes[i],
            timestamp,
            is_write,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_access_decomposition_wraps_in_u32_domain() {
        let entries = decompose_access(u32::MAX - 2, 0x0807_0605_0403_0201, 7, false, 8);
        let addresses: Vec<_> = entries.iter().map(|entry| entry.address).collect();
        assert_eq!(
            addresses,
            [u32::MAX - 2, u32::MAX - 1, u32::MAX, 0, 1, 2, 3, 4]
        );
        assert_eq!(
            entries.iter().map(|entry| entry.value).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
