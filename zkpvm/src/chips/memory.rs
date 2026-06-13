use alloc::collections::BTreeMap;
#[allow(unused_imports)]
use alloc::{boxed::Box, vec, vec::Vec};
use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
#[cfg(feature = "prover")]
use stwo::{
    core::{ColumnVec, fields::qm31::SecureField},
    prover::{
        backend::simd::{SimdBackend, m31::LOG_N_LANES},
        poly::{BitReversedOrder, circle::CircleEvaluation},
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

#[cfg(feature = "prover")]
use crate::framework::BuiltInProverComponent;
#[cfg(feature = "prover")]
use crate::lookups::{AllLookupElements, LogupTraceBuilder};
#[cfg(feature = "prover")]
use crate::side_note::SideNote;
use crate::{framework::BuiltInComponent, lookups::MemoryAccessLookupElements};

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
    /// Byte address (4 limbs, u32).  `#[mask_next_row]` so the sortedness /
    /// read-consistency gadget can read the next ledger row's address.
    #[size = 4]
    #[mask_next_row]
    Address,
    /// Single byte value
    #[size = 1]
    Value,
    /// Timestamp of this access (8 limbs).  `#[mask_next_row]` for the
    /// same-address ts-monotonicity check.
    #[size = 8]
    #[mask_next_row]
    Timestamp,
    /// 1 = write, 0 = read
    #[size = 1]
    IsWrite,
    /// Previous byte value at same address.  `#[mask_next_row]` so a row can
    /// bind the *next* row's prev_value to this row's value (cross-row
    /// read-consistency).
    #[size = 1]
    #[mask_next_row]
    PrevValue,
    /// BOUND boolean: 1 iff the next ledger row is real AND accesses the same
    /// address.  No longer a free witness — pinned by the sortedness gadget
    /// and it gates the cross-row `prev_value` value binding.
    #[size = 1]
    IsSameAddrNext,
    /// 1 if padding row.  `#[mask_next_row]` so a row can tell whether its
    /// successor is real (the gadget only fires between two real rows).
    #[size = 1]
    #[mask_next_row]
    IsPadding,
    /// BOUND boolean: 1 iff this real→real transition advances the address via
    /// the LOW 16-bit half (hi halves equal, lo strictly increases).
    #[size = 1]
    AdvLoH,
    /// BOUND boolean: 1 iff this real→real transition advances the address via
    /// the HIGH 16-bit half (hi strictly increases).  Exactly one of
    /// {IsSameAddrNext, AdvLoH, AdvHiH} holds on a real→real transition.
    #[size = 1]
    AdvHiH,
    /// 24-bit little-endian decomposition of the per-transition ordering delta
    /// `OrderDelta = IsSameAddrNext·ts_diff + AdvLoH·(lo_diff−1) +
    /// AdvHiH·(hi_diff−1)`, a SELF-CONTAINED non-negativity range-check (no
    /// Range256 lookup — the consumer pass runs with an immutable `&SideNote`).
    /// 24 bits covers `ts_diff < 2^24` and the 16-bit half diffs, and `2^24 ≪ p`
    /// so a field-wrapped negative cannot alias a valid small positive.
    #[size = 24]
    OrderBits,
    /// 1 iff this is a per-page closing read (the §2 boundary injection),
    /// produced only by MemoryPageChip; 0 for every step / precompile /
    /// ts=0-write entry.  Part of the logup tuple (so producers and consumer
    /// agree) and, once MemoryPageChip lands, gates the group-end constraint.
    #[size = 1]
    IsClosing,
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
            address: address + i as u32,
            value: bytes[i],
            timestamp,
            is_write,
        })
        .collect()
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
        let is_closing = crate::trace::trace_eval!(trace_eval, Column::IsClosing);
        let prev_value = crate::trace::trace_eval!(trace_eval, Column::PrevValue);

        // IsClosing is a bound boolean (only MemoryPageChip ever sets it).
        eval.add_constraint(is_closing[0].clone() * (is_closing[0].clone() - E::F::one()));

        // B3 audit: read consistency unconditional (was via
        // RealReadH = is_real · (1 - is_write)).  On padding rows
        // value=prev_value=0 so 1·0=0 holds.
        let is_read = E::F::one() - is_write[0].clone();
        eval.add_constraint(is_read * (value[0].clone() - prev_value[0].clone()));

        // ── Cross-row read-consistency + (addr, ts) sortedness gadget ────
        // The ledger is sorted by (Address, Timestamp).  These constraints pin
        // that ordering and bind each read to the immediately-preceding
        // same-address row (closing the read-consistency soundness gap —
        // prev_value used to be a free witness).  All constraints stay ≤ degree
        // 2.  See docs/plans/ledger-read-consistency.md.
        let is_pad_next = crate::trace::trace_eval_next_row!(trace_eval, Column::IsPadding);
        let address_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Address);
        let timestamp_next = crate::trace::trace_eval_next_row!(trace_eval, Column::Timestamp);
        let prev_value_next = crate::trace::trace_eval_next_row!(trace_eval, Column::PrevValue);
        let is_same_addr = crate::trace::trace_eval!(trace_eval, Column::IsSameAddrNext);
        let adv_lo = crate::trace::trace_eval!(trace_eval, Column::AdvLoH);
        let adv_hi = crate::trace::trace_eval!(trace_eval, Column::AdvHiH);
        let order_bits = crate::trace::trace_eval!(trace_eval, Column::OrderBits);

        // 16-bit address halves (each < 2^16 < p, so the field diffs are exact —
        // a full u32 address would wrap the field).
        let b256 = E::F::from(BaseField::from(256u32));
        let a_lo = address[0].clone() + address[1].clone() * b256.clone();
        let a_hi = address[2].clone() + address[3].clone() * b256.clone();
        let a_lo_next = address_next[0].clone() + address_next[1].clone() * b256.clone();
        let a_hi_next = address_next[2].clone() + address_next[3].clone() * b256.clone();
        let lo_diff = a_lo_next - a_lo;
        let hi_diff = a_hi_next - a_hi;

        // Booleans.
        eval.add_constraint(is_same_addr[0].clone() * (is_same_addr[0].clone() - E::F::one()));
        eval.add_constraint(adv_lo[0].clone() * (adv_lo[0].clone() - E::F::one()));
        eval.add_constraint(adv_hi[0].clone() * (adv_hi[0].clone() - E::F::one()));

        // is_same_addr ⇒ both real, and addresses equal (both halves).
        eval.add_constraint(is_same_addr[0].clone() * is_pad[0].clone());
        eval.add_constraint(is_same_addr[0].clone() * is_pad_next[0].clone());
        eval.add_constraint(is_same_addr[0].clone() * hi_diff.clone());
        eval.add_constraint(is_same_addr[0].clone() * lo_diff.clone());
        // AdvLoH ⇒ hi halves equal (the advance is in the low half).
        eval.add_constraint(adv_lo[0].clone() * hi_diff.clone());
        // Exactly one of {same, lo-advance, hi-advance} on a real→real
        // transition; none on a padding boundary or the cyclic wraparound.
        let both_real = (E::F::one() - is_pad[0].clone()) * (E::F::one() - is_pad_next[0].clone());
        eval.add_constraint(
            is_same_addr[0].clone() + adv_lo[0].clone() + adv_hi[0].clone() - both_real,
        );

        // OrderDelta = same·ts_diff + lo·(lo_diff−1) + hi·(hi_diff−1), 24-bit
        // range-checked ≥ 0.  same=1 ⇒ ts non-decreasing; lo=1 ⇒ lo strictly
        // increases (hi equal) ⇒ addr↑; hi=1 ⇒ hi strictly increases ⇒ addr↑.
        // 0 on every non-real→real transition (all three coeffs are 0 there).
        let combine_ts = |bytes: &[E::F; 8]| -> E::F {
            let mut acc = E::F::zero();
            let mut pow = E::F::one();
            for b in bytes {
                acc += b.clone() * pow.clone();
                pow *= b256.clone();
            }
            acc
        };
        let ts_diff = combine_ts(&timestamp_next) - combine_ts(&timestamp);
        let order_delta = is_same_addr[0].clone() * ts_diff
            + adv_lo[0].clone() * (lo_diff - E::F::one())
            + adv_hi[0].clone() * (hi_diff - E::F::one());
        let two = E::F::from(BaseField::from(2u32));
        let mut recomposed = E::F::zero();
        let mut pow2 = E::F::one();
        for bit in &order_bits {
            eval.add_constraint(bit.clone() * (bit.clone() - E::F::one()));
            recomposed += bit.clone() * pow2.clone();
            pow2 *= two.clone();
        }
        eval.add_constraint(recomposed - order_delta);

        // Cross-row value binding: same-address ⇒ the next row's prev_value
        // equals this row's value.  Combined with read-consistency, forces every
        // read to return the most-recent same-address write / initial byte.
        eval.add_constraint(
            is_same_addr[0].clone() * (prev_value_next[0].clone() - value[0].clone()),
        );

        // Consumer lookup (negative multiplicity)
        // Byte-level tuple: (addr[4], value[1], timestamp[8], is_write[1], is_closing[1])
        let mut tuple: Vec<E::F> = address.to_vec();
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&timestamp);
        tuple.push(is_write[0].clone());
        tuple.push(is_closing[0].clone());

        eval.add_to_relation(RelationEntry::new(
            lookup_elements,
            (-is_real.clone()).into(),
            &tuple,
        ));

        eval.finalize_logup();
    }
}

/// B6 dedup-feasibility report — counts how many byte entries in the
/// (address, ts)-sorted memory ledger fall into "byte-flood" groups
/// (consecutive entries with addr[i+1] = addr[i]+1, same ts, same is_write),
/// and what the resulting `log_size` would be if every such group were
/// merged into a single multi-byte row up to a per-row cap M.  Used as a
/// feasibility check for the B6 chip-shrink (see PERF_ROADMAP §3.2).
#[derive(Debug, Default, Clone)]
pub struct MemoryDedupReport {
    /// Total byte entries in the ledger today.
    pub total_entries: usize,
    /// Number of byte entries that are part of a flood group of length ≥ 2.
    pub bytes_in_flood_groups: usize,
    /// Unbounded after-dedup ledger size (one row per flood group).
    pub after_dedup: usize,
    /// `ceil_log2_at_least_lanes(total_entries)` — what the chip uses today.
    pub current_log_size: u32,
    /// `ceil_log2_at_least_lanes(after_dedup)` — what unbounded B6 would deliver.
    pub after_dedup_log_size: u32,
    /// Histogram of flood-group lengths: `(length, count)`.
    pub flood_length_histogram: Vec<(usize, usize)>,
    /// Longest flood group encountered.  Bounds the size flag's range.
    pub longest_flood: usize,
    /// After-dedup row count under fixed per-row cap M.
    /// `cap_after_dedup[k] = (m, rows, log_size)`.
    pub cap_after_dedup: Vec<(usize, usize, u32)>,
    // ── Memory-Merkle boundary sizing (trustless-chain-verification Phase A) ──
    /// Distinct byte addresses touched in this segment.
    pub distinct_addresses: usize,
    /// Distinct addresses whose FIRST access is a read (read-before-write) —
    /// the leaves a segment must include against `initial_root`.
    pub read_before_write: usize,
    /// Distinct addresses written at least once — the leaves that change for
    /// `final_root`.
    pub written_addresses: usize,
    /// Distinct touched PAGES per granularity: `(page_size_bytes, count)`.
    /// The touched-page count drives the boundary Merkle-multiproof size.
    pub distinct_pages: Vec<(usize, usize)>,
}

/// Build the same `entries: Vec<MemEntry>` `generate_main_trace_immut` would
/// produce, then walk it (sorted by addr+ts) counting byte-flood groups.
#[cfg(feature = "prover")]
pub fn analyze_dedup(side_note: &crate::side_note::SideNote) -> MemoryDedupReport {
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
    }
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
    for op in &side_note.ristretto_mem_ops {
        for (i, &b) in op.scalar_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.scalar_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.point_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.point_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.out_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.output_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: true,
            });
        }
    }
    for op in &side_note.ristretto_add_mem_ops {
        for (i, &b) in op.p_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.p_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.q_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.q_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.out_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.output_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: true,
            });
        }
    }
    for op in &side_note.scalar_binop_mem_ops {
        for (i, &b) in op.a_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.a_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.b_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.b_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.out_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.output_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: true,
            });
        }
    }
    for op in &side_note.scalar_reduce_wide_mem_ops {
        for (i, &b) in op.wide_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.wide_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: false,
            });
        }
        for (i, &b) in op.out_bytes.iter().enumerate() {
            entries.push(MemEntry {
                address: op.output_ptr + i as u32,
                value: b,
                timestamp: op.ts,
                is_write: true,
            });
        }
    }

    if !side_note.initial_memory.is_empty() {
        let mut first_access: BTreeMap<u32, bool> = BTreeMap::new();
        for e in &entries {
            first_access.entry(e.address).or_insert(e.is_write);
        }
        let flat_mem = &side_note.initial_memory;
        for (&addr, &first_is_write) in &first_access {
            if first_is_write {
                continue;
            }
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

    let total_entries = entries.len();
    if total_entries == 0 {
        return MemoryDedupReport::default();
    }

    entries.sort_by_key(|e| (e.address, e.timestamp));

    // A "flood group" = run of consecutive entries (in sort order) where
    //   addr[i+1] == addr[i] + 1, ts[i+1] == ts[i], is_write[i+1] == is_write[i].
    // Captures the byte-flood emitted by a single multi-byte access.
    let mut after_dedup = 0usize;
    let mut histogram: std::collections::BTreeMap<usize, usize> = Default::default();
    let mut longest_flood = 0usize;
    let mut bytes_in_flood_groups = 0usize;
    let mut i = 0;
    while i < entries.len() {
        let head = &entries[i];
        let mut run_len = 1usize;
        let mut j = i + 1;
        while j < entries.len()
            && entries[j].address == entries[j - 1].address.wrapping_add(1)
            && entries[j].timestamp == head.timestamp
            && entries[j].is_write == head.is_write
        {
            run_len += 1;
            j += 1;
        }
        after_dedup += 1;
        *histogram.entry(run_len).or_default() += 1;
        if run_len > longest_flood {
            longest_flood = run_len;
        }
        if run_len >= 2 {
            bytes_in_flood_groups += run_len;
        }
        i += run_len;
    }

    // Boundary sizing: walk the (address, ts)-sorted entries grouped by
    // address. The group head is the first access (lowest ts) → classifies
    // read-before-write; any write in the group marks the address as written.
    let page_sizes = [64usize, 256, 1024, 4096];
    let mut distinct_addresses = 0usize;
    let mut read_before_write = 0usize;
    let mut written_addresses = 0usize;
    let mut page_counts = vec![0usize; page_sizes.len()];
    let mut last_page = vec![u64::MAX; page_sizes.len()];
    let mut g = 0usize;
    while g < entries.len() {
        let addr = entries[g].address;
        // Within an address group (sorted by ts asc), ts=0 entries are the
        // injected initial-memory boundary writes — skip them so we classify
        // the first REAL (ts≥1) access. (The tracer starts ts at 1.)
        let mut h = g;
        let mut first_real_is_write: Option<bool> = None;
        let mut any_real_write = false;
        while h < entries.len() && entries[h].address == addr {
            if entries[h].timestamp != 0 {
                if first_real_is_write.is_none() {
                    first_real_is_write = Some(entries[h].is_write);
                }
                any_real_write |= entries[h].is_write;
            }
            h += 1;
        }
        if let Some(first_is_write) = first_real_is_write {
            distinct_addresses += 1;
            if !first_is_write {
                read_before_write += 1;
            }
            if any_real_write {
                written_addresses += 1;
            }
            for (pi, &ps) in page_sizes.iter().enumerate() {
                let page = addr as u64 / ps as u64;
                if last_page[pi] != page {
                    page_counts[pi] += 1;
                    last_page[pi] = page;
                }
            }
        }
        g = h;
    }
    let distinct_pages: Vec<(usize, usize)> = page_sizes.iter().copied().zip(page_counts).collect();

    let current_log_size = crate::trace::utils::ceil_log2_at_least_lanes(total_entries);
    let after_dedup_log_size = crate::trace::utils::ceil_log2_at_least_lanes(after_dedup);

    let mut cap_after_dedup = Vec::new();
    for m in [1usize, 2, 4, 8, 16, 32, 64] {
        let mut rows = 0usize;
        for (&len, &count) in &histogram {
            let rows_per_run = if len == 1 { 1 } else { (len + m - 1) / m };
            rows += rows_per_run * count;
        }
        let log = crate::trace::utils::ceil_log2_at_least_lanes(rows);
        cap_after_dedup.push((m, rows, log));
    }

    MemoryDedupReport {
        total_entries,
        bytes_in_flood_groups,
        after_dedup,
        current_log_size,
        after_dedup_log_size,
        flood_length_histogram: histogram.into_iter().collect(),
        longest_flood,
        cap_after_dedup,
        distinct_addresses,
        read_before_write,
        written_addresses,
        distinct_pages,
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
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.point_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.point_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.output_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: true,
                });
            }
        }

        // Step 13: Ristretto255 point-add precompile memory ops:
        // 32 reads each (P + Q) + 32 writes (output), all at ECALL ts.
        for op in &side_note.ristretto_add_mem_ops {
            for (i, &b) in op.p_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.p_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.q_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.q_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.output_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: true,
                });
            }
        }

        // Step 18: scalar mul/add mod ℓ precompile memory ops:
        // 32 reads (a) + 32 reads (b) + 32 writes (output) per call.
        for op in &side_note.scalar_binop_mem_ops {
            for (i, &b) in op.a_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.a_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.b_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.b_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.output_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: true,
                });
            }
        }

        // Step 13: scalar_from_bytes_mod_order_wide precompile memory
        // ops: 64 reads (wide input) + 32 writes (canonical output).
        for op in &side_note.scalar_reduce_wide_mem_ops {
            for (i, &b) in op.wide_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.wide_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: false,
                });
            }
            for (i, &b) in op.out_bytes.iter().enumerate() {
                entries.push(MemEntry {
                    address: op.output_ptr + i as u32,
                    value: b,
                    timestamp: op.ts,
                    is_write: true,
                });
            }
        }

        // Inject initial memory writes at timestamp 0 for byte addresses read without prior write.
        if !side_note.initial_memory.is_empty() {
            // The boundary must reflect each address's TRUE first access (the
            // one with the lowest timestamp), not collection order. `entries`
            // is gathered steps-first then precompile mem_ops, so an address a
            // precompile READS at a low ts but a later step WRITES at a higher
            // ts would be misjudged "write-first" in collection order and
            // wrongly skip its ts=0 boundary — leaving the precompile read to
            // bottom out at prev_value 0 instead of the real initial byte.
            let mut first_access: BTreeMap<u32, (u64, bool)> = BTreeMap::new();
            for e in &entries {
                first_access
                    .entry(e.address)
                    .and_modify(|fa| {
                        if e.timestamp < fa.0 {
                            *fa = (e.timestamp, e.is_write);
                        }
                    })
                    .or_insert((e.timestamp, e.is_write));
            }

            let flat_mem = &side_note.initial_memory;
            for (&addr, &(_, first_is_write)) in &first_access {
                if first_is_write {
                    continue;
                }
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
        let mut log_size = crate::trace::utils::ceil_log2_at_least_lanes(num_entries);
        // Guarantee ≥ 1 padding row so the cyclic last→row-0 wraparound is
        // always a padding row (the sortedness gadget must not fire across it).
        if (1usize << log_size) == num_entries {
            log_size += 1;
        }
        let mut trace = TraceBuilder::<Column>::new(log_size);
        let num_rows = trace.num_rows();

        // Pass 1: base columns; track (addr, ts, is_same_addr) per row so the
        // ordering helpers (pass 2) can read the cyclic next row.
        let mut addrs = vec![0u32; num_rows];
        let mut tss = vec![0u64; num_rows];
        let mut same_addr = vec![false; num_rows];
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

            addrs[row] = entry.address;
            tss[row] = entry.timestamp;
            same_addr[row] = same_addr_next;
        }
        for row in num_entries..num_rows {
            trace.fill_columns(row, true, Column::IsPadding);
        }

        // Pass 2: ordering helpers, reading the cyclic next = (row+1) % num_rows.
        //   AdvLoH / AdvHiH: which 16-bit half advances (when not same address).
        //   OrderBits: 24-bit decomposition of OrderDelta = same·ts_diff +
        //   lo·(lo_diff−1) + hi·(hi_diff−1), all ≥ 0.
        for row in 0..num_rows {
            let next = (row + 1) % num_rows;
            let both_real = row < num_entries && next < num_entries;
            let hi_eq = (addrs[row] >> 16) == (addrs[next] >> 16);
            let adv_lo = both_real && !same_addr[row] && hi_eq;
            let adv_hi = both_real && !same_addr[row] && !hi_eq;
            trace.fill_columns(row, adv_lo, Column::AdvLoH);
            trace.fill_columns(row, adv_hi, Column::AdvHiH);

            let order_delta: u64 = if same_addr[row] {
                tss[next] - tss[row]
            } else if adv_lo {
                ((addrs[next] & 0xFFFF) - (addrs[row] & 0xFFFF)) as u64 - 1
            } else if adv_hi {
                ((addrs[next] >> 16) - (addrs[row] >> 16)) as u64 - 1
            } else {
                0
            };
            let bits: [BaseField; 24] =
                core::array::from_fn(|b| BaseField::from(((order_delta >> b) & 1) as u32));
            trace.fill_columns_base_field(row, &bits, Column::OrderBits);
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
        let is_closing = crate::trace::original_base_column!(component_trace, Column::IsClosing);

        // Byte-level tuple: (addr[4], value[1], timestamp[8], is_write[1], is_closing[1])
        let mut tuple: Vec<_> = address.to_vec();
        tuple.push(value[0].clone());
        tuple.extend_from_slice(&timestamp);
        tuple.push(is_write[0].clone());
        tuple.push(is_closing[0].clone());

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
