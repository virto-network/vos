//! Loads and stores: addresses, values, active bytes and the memory-access lookups.
use alloc::vec::Vec;

use num_traits::{One, Zero};
use stwo::core::fields::m31::BaseField;
use stwo_constraint_framework::{EvalAtRow, RelationEntry};

use super::{Lookups, Row, is_store};
use crate::core::step::WORD_SIZE;

/// Scalar-memory address validity: no access below the initialization zone, none wrapping through 2^32.
pub(in crate::chips::cpu) fn address_validity<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let f256 = E::F::from(BaseField::from(256u32));

    // ── Scalar-memory address validity ──
    //
    // A load/store must touch no address below the 64-KiB
    // initialization zone.  With scalar widths in {1,2,4,8}, this
    // is equivalent to both:
    //   1. the base high word is nonzero (`addr >= 0x1_0000`), and
    //   2. the final active byte does not wrap through 2^32.
    //
    // We prove both predicates with one nonzero product.  `last_carry`
    // is the carry into address byte 3 while adding `width - 1`; hence
    // `256 - addr[3] - last_carry` is zero exactly on top-of-u32 wrap.
    // The product is at most 65535 * 256, strictly below the M31 modulus,
    // so it cannot vanish by field reduction.
    {
        let is_memory = row.is_load[0].clone() + is_store(row);
        eval.add_constraint(row.is_standard_mem_h[0].clone() - is_memory);

        let selected_last_carry = row.is_mem_size1[0].clone() * row.mem_byte_addr_carry3[0].clone()
            + row.is_mem_size2[0].clone() * row.mem_byte_addr_carry3[1].clone()
            + row.is_mem_size4[0].clone() * row.mem_byte_addr_carry3[3].clone()
            + row.is_mem_size8[0].clone() * row.mem_byte_addr_carry3[7].clone();
        eval.add_constraint(row.mem_last_addr_carry_h[0].clone() - selected_last_carry);

        // Derive the high word from the canonical byte-0 memory-lookup
        // address, rather than the raw MemAddr limbs. Indirect-address
        // addition constrains those limbs algebraically but does not
        // range-check them individually. The byte-0 lookup contributes
        //   b2 = MemAddr[2] + carry2[0] - 256*carry3[0]
        //   b3 = MemAddr[3] + carry3[0]
        // so b2 + 256*b3 simplifies to the expression below while still
        // being authenticated by the canonical MemoryChip ledger tuple.
        let high_word = row.mem_addr[2].clone()
            + row.mem_byte_addr_carry2[0].clone()
            + f256.clone() * row.mem_addr[3].clone();
        let no_wrap_factor =
            f256.clone() - row.mem_addr[3].clone() - row.mem_last_addr_carry_h[0].clone();
        eval.add_constraint(row.mem_range_product_h[0].clone() - high_word * no_wrap_factor);
        eval.add_constraint(
            row.mem_range_times_inv_h[0].clone()
                - row.mem_range_product_h[0].clone() * row.mem_range_inv[0].clone(),
        );
        eval.add_constraint(
            row.is_standard_mem_h[0].clone() * (row.mem_range_times_inv_h[0].clone() - E::F::one()),
        );
    }
}

/// Range256 checks of the result bytes.
pub(in crate::chips::cpu) fn result_bytes<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups<'_>,
) {
    let range256_lookup = lookups.range256_lookup;
    let is_real = E::F::one() - row.is_padding[0].clone();
    // ════════════════════════════════════════════════════════════════════
    // Range256 checks for result byte limbs
    // ════════════════════════════════════════════════════════════════════
    for i in 0..WORD_SIZE {
        eval.add_to_relation(RelationEntry::new(
            range256_lookup,
            is_real.clone().into(),
            &[row.result[i].clone()],
        ));
    }
}

/// The byte-level memory-access lookups and their address carries.
pub(in crate::chips::cpu) fn memory_access<E: EvalAtRow>(
    eval: &mut E,
    row: &Row<E::F>,
    lookups: &Lookups<'_>,
) {
    let mem_lookup = lookups.mem_lookup;
    // ════════════════════════════════════════════════════════════════════
    // Memory access lookup (producer side)
    // ════════════════════════════════════════════════════════════════════
    // IsStore folded — `is_store(row)` is the sum.
    let f256 = E::F::from(BaseField::from(256));

    // Byte-level memory lookups: one per byte offset. The address is the
    // canonical little-endian decomposition of `MemAddr + byte_idx` with
    // carry propagation across address bytes (MemByteAddrCarry{1,2,3}) —
    // a misaligned multi-byte access can cross a 256/65536/16M boundary,
    // so adding the offset to the low byte alone would mismatch the
    // MemoryChip ledger's canonical address and the memory logup wouldn't
    // balance. The carries telescope (numeric address is always
    // `base + byte_idx`), and matching the canonical ledger bytes pins
    // them; the booleanity constraints below keep them in {0,1}.
    for byte_idx in 0..WORD_SIZE {
        let byte_offset = E::F::from(BaseField::from(byte_idx as u32));
        let c1 = row.mem_byte_addr_carry1[byte_idx].clone();
        let c2 = row.mem_byte_addr_carry2[byte_idx].clone();
        let c3 = row.mem_byte_addr_carry3[byte_idx].clone();
        let mut tuple: Vec<E::F> = Vec::with_capacity(15);
        // Canonical bytes of MemAddr + byte_idx, with carry.
        tuple.push(row.mem_addr[0].clone() + byte_offset - f256.clone() * c1.clone());
        tuple.push(row.mem_addr[1].clone() + c1.clone() - f256.clone() * c2.clone());
        tuple.push(row.mem_addr[2].clone() + c2.clone() - f256.clone() * c3.clone());
        tuple.push(row.mem_addr[3].clone() + c3.clone());
        // value byte
        tuple.push(row.mem_value[byte_idx].clone());
        // timestamp
        tuple.extend_from_slice(&row.timestamp);
        // is_write
        tuple.push(is_store(row));
        // is_closing = 0 (CpuChip never emits closing reads)
        tuple.push(E::F::zero());

        eval.add_to_relation(RelationEntry::new(
            mem_lookup,
            row.mem_byte_active[byte_idx].clone().into(),
            &tuple,
        ));
    }

    // Booleanity of the per-byte address carries (unconditional; the
    // carries are 0 on non-memory rows). The honest values are the true
    // carry bits; ledger-match pins them to the canonical decomposition.
    for byte_idx in 0..WORD_SIZE {
        for c in [
            row.mem_byte_addr_carry1[byte_idx].clone(),
            row.mem_byte_addr_carry2[byte_idx].clone(),
            row.mem_byte_addr_carry3[byte_idx].clone(),
        ] {
            eval.add_constraint(c.clone() * (E::F::one() - c));
        }
    }
}

/// `MemByteActive` pinned to a prefix of ones of length `MemSize`.
pub(in crate::chips::cpu) fn active_bytes<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ════════════════════════════════════════════════════════════════════
    // Pin MemByteActive to a prefix-1 pattern of length MemSize
    //
    // MemByteActive is the lookup multiplicity for byte-level memory
    // accesses.  Without shape constraints a malicious prover could set
    // it to a non-prefix pattern (e.g. [1,0,1,0,...]) or pick MemSize
    // inconsistent with the active-byte count.  These constraints force:
    //   1. each MemByteActive[i] is boolean,
    //   2. monotonic (active[i+1]=1 ⇒ active[i]=1) — prefix-1 shape,
    //   3. MemSize equals the number of active bytes,
    //   4. MemSize ∈ {0, 1, 2, 4, 8}  (the valid PVM access widths).
    //
    // Combined, these uniquely determine MemByteActive from MemSize. They
    // hold on every row: a padding row's flags are zero, so its MemSize
    // and its active bytes are too.
    {
        // Per-byte MemByteActive is boolean on every row
        // (`control::control_flow_helpers`).
        // Monotonicity.
        for i in 0..WORD_SIZE - 1 {
            eval.add_constraint(row.mem_byte_active_mono_h[i].clone());
        }
        // MemSize equals the count of active bytes.
        let mut active_sum = E::F::zero();
        for i in 0..WORD_SIZE {
            active_sum += row.mem_byte_active[i].clone();
        }
        eval.add_constraint(row.mem_size[0].clone() - active_sum);
        // Pin MemSize to opcode-canonical width via per-size flags
        // pinned by ProgramMemoryChip.  A flag-based formulation keeps
        // the degree at 1 (a direct degree-6 valid-size polynomial
        // would be too high).  Each flag IsMemSize* is bound to the
        // canonical opcode decoding via the ProgramMemory tuple, and
        // exactly one is set on a memory-op row (load OR store), all
        // zero on non-memory rows.
        let canonical_size = row.is_mem_size1[0].clone()
            + row.is_mem_size2[0].clone() * E::F::from(BaseField::from(2u32))
            + row.is_mem_size4[0].clone() * E::F::from(BaseField::from(4u32))
            + row.is_mem_size8[0].clone() * E::F::from(BaseField::from(8u32));
        eval.add_constraint(row.mem_size[0].clone() - canonical_size);
    }
}

/// Loads: the result is the memory value on active bytes.
pub(in crate::chips::cpu) fn load_result<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ════════════════════════════════════════════════════════════════════
    // Bind Result to MemValue on Load steps
    //
    // For each byte i, on a load step (is_load=1), if byte i is within
    // the load's width (mem_byte_active[i]=1), result[i] must equal
    // mem_value[i].  Without this, forging step.regs_after[dest_reg] on
    // a Load isn't caught when no later step reads the destination
    // register: the AIR links Result to the register-memory ledger and
    // MemValue to the memory ledger separately, so they must be equated
    // within the load step here.
    //
    // Inactive bytes (i >= MemSize): unsigned loads must be 0,
    // signed loads must be 0xFF · sign_bit_of_top_active_byte.
    // See the signed-load inactive-byte sign-extension block below for
    // the pinning + per-byte equality constraint.
    for i in 0..WORD_SIZE {
        eval.add_constraint(
            row.is_load[0].clone()
                * row.mem_byte_active[i].clone()
                * (row.result[i].clone() - row.mem_value[i].clone()),
        );
    }
}

/// Direct stores: the memory value is `val_b`.
pub(in crate::chips::cpu) fn direct_store_value<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ════════════════════════════════════════════════════════════════════
    // Bind MemValue ↔ val_b on Direct stores
    //
    // For StoreU8 / StoreU16 / StoreU32 / StoreU64 (the OneRegOneImm
    // category) the trace fill's default arm puts `regs[ra]` into
    // val_b — that's the source value the interpreter writes to
    // memory.  Without this binding a prover could write any byte
    // string to memory on a Store row regardless of regs[ra].
    // The active-byte equality is enough: inactive bytes (i ≥
    // MemSize) of MemValue aren't read by the memory chip
    // (mem_byte_active[i]=0 zeros their lookup multiplicity).
    //
    // Coverage note: StoreInd* / StoreImm* / StoreImmInd* leave
    // the source value in different places (regs[ra] for
    // StoreInd, imm_y for StoreImm/StoreImmInd) that aren't in
    // val_b — those are bound separately below.
    {
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.is_store_direct[0].clone()
                    * row.mem_byte_active[i].clone()
                    * (row.mem_value[i].clone() - row.val_b[i].clone()),
            );
        }
    }
}

/// Indirect register-source stores: the memory value is `RegValA`.
pub(in crate::chips::cpu) fn indirect_store_value<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ════════════════════════════════════════════════════════════════════
    // Bind MemValue ↔ RegValA on indirect register-source stores
    //
    // For StoreInd[U][8/16/32/64] (TwoRegOneImm), val_b holds
    // the *base* register `regs[rb]` — not the value being
    // stored.  The value is `regs[ra]`, which lands in the
    // RegValA column (filled in trace fill on StoreInd rows;
    // bound to the actual register snapshot via the paired
    // register-memory ledger producer in the register-memory block).
    //
    // Per-byte equality on active bytes:
    //   IsStoreInd · mem_byte_active[i] · (mem_value[i] −
    //                                      reg_val_a[i]) = 0
    {
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.is_store_ind[0].clone()
                    * row.mem_byte_active[i].clone()
                    * (row.mem_value[i].clone() - row.reg_val_a[i].clone()),
            );
        }
    }
}

/// Direct loads and stores: the address is the immediate.
pub(in crate::chips::cpu) fn direct_address<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ════════════════════════════════════════════════════════════════════
    // Bind MemAddr ↔ ImmBytes[0..4] on direct loads/stores
    //
    // For LoadU8/I8/U16/I16/U32/I32/U64 and StoreU8/16/32/64
    // (the OneRegOneImm-category direct memory ops) the runtime
    // address is just the immediate (`addr = imm` per
    // vos_pvm/src/vm.rs's RegImm-arm impls).  The interpreter uses
    // `let addr = imm as u32`, so MemAddr's 4 bytes are the low
    // 4 bytes of the canonical immediate.  ImmBytes is already
    // pinned to that immediate by the ProgramMemory tuple, so the
    // binding is a 4-byte equality.
    //
    // Without this, MemAddr would be prover-witnessed; combined with
    // the MemValue ↔ val_b binding, a malicious prover could store
    // the right value at the wrong address (or load from the wrong
    // address, returning a value that happens to be there).  This
    // covers the address half for direct ops; indirect addressing
    // (`addr = regs[r] + imm`, covers LoadInd* / StoreInd* /
    // StoreImmInd*) is bound by a separate carry-chain (below).
    {
        // This also covers StoreImm direct (TwoImm with `addr = imm_x`).
        // step.imm = imm_x for TwoImm, so ImmBytes already pins the
        // address bytes.
        let direct_mem_active = row.is_load_direct[0].clone()
            + row.is_store_direct[0].clone()
            + row.is_store_imm_direct[0].clone();
        for i in 0..4 {
            eval.add_constraint(
                direct_mem_active.clone() * (row.mem_addr[i].clone() - row.imm_bytes[i].clone()),
            );
        }
    }
}

/// StoreImm and StoreImmInd: the memory value is `imm_y`.
pub(in crate::chips::cpu) fn immediate_store_value<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ════════════════════════════════════════════════════════════════════
    // Bind MemValue ↔ ImmYBytes on StoreImm / StoreImmInd
    //
    // For all 8 immediate-source store opcodes (StoreImm[U] and
    // StoreImmInd[U] of width 1/2/4/8) the value written to
    // memory is `imm_y`.  ImmYBytes already carries the low 4
    // bytes of step.imm_y on every row (filled in trace fill,
    // pinned in ProgramMemoryChip via ImmYCanon).  Per-byte
    // equality on active bytes:
    //   IsStoreImmAny · mem_byte_active[i] · (mem_value[i] −
    //                                          imm_y_bytes[i]) = 0
    // for `i ∈ 0..4`.
    //
    // An 8-byte store's high 4 bytes are imm_y's sign extension,
    // each its byte 4, `ImmYBytes[4]`, which the prog_mem tuple
    // carries too.
    {
        for i in 0..WORD_SIZE {
            eval.add_constraint(
                row.is_store_imm_any[0].clone()
                    * row.mem_byte_active[i].clone()
                    * (row.mem_value[i].clone() - row.imm_y_bytes[i.min(4)].clone()),
            );
        }
    }
}

/// Indirect loads and stores: the address is `val_b` plus the immediate, mod 2^32.
pub(in crate::chips::cpu) fn indirect_address<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    let f256 = E::F::from(BaseField::from(256));
    // ════════════════════════════════════════════════════════════════════
    // Bind MemAddr ↔ (val_b + ImmBytes) mod 2^32 on indirect ops
    //
    // For LoadInd[U/I][8/16/32/64], StoreInd[U][8/16/32/64], and
    // StoreImmInd[U][8/16/32/64] the runtime address is
    // `regs[base] + imm` (where base = rb for the TwoRegOneImm
    // pair, ra for OneRegTwoImm).  In every case the trace fill
    // puts the base register's value into val_b — TwoRegOneImm's
    // arm gives `val_b = regs[reg_b]`, OneRegTwoImm falls
    // through to the default arm `val_b = regs[reg_a]` and
    // reg_a is decoded as the base for OneRegTwoImm — so a
    // single uniform formula works:
    //
    //   MemAddr = (val_b + ImmBytes) mod 2^32
    //
    // Encoded as a 4-byte add-with-carry chain, mirroring the
    // existing JumpIndAddr / LoadImmJumpIndAddr patterns.
    // Carry-out at byte 3 is the 32-bit overflow, discarded.
    // Per-byte carry boolean (val_b[i] + ImmBytes[i] + carry_in
    // ≤ 511 with carry_in ≤ 1, so carry_out ≤ 1).
    {
        // Per-byte mem_addr_carry is boolean on every row
        // (`row::shared_helpers`), even where the chain is dormant.
        // Add-with-carry chain (gated on is_mem_indirect).
        for i in 0..4 {
            let carry_in = if i == 0 {
                E::F::zero()
            } else {
                row.mem_addr_carry[i - 1].clone()
            };
            eval.add_constraint(
                row.is_mem_indirect[0].clone()
                    * (row.mem_addr[i].clone() + row.mem_addr_carry[i].clone() * f256.clone()
                        - row.val_b[i].clone()
                        - row.imm_bytes[i].clone()
                        - carry_in),
            );
        }
    }
}

/// Signed loads: inactive bytes extend the sign.
pub(in crate::chips::cpu) fn signed_load_extension<E: EvalAtRow>(eval: &mut E, row: &Row<E::F>) {
    // ════════════════════════════════════════════════════════════════════
    // Signed-load inactive-byte sign-extension
    //
    // For load rows, every inactive byte (mem_byte_active[i] = 0)
    // must equal 0xFF · LoadSignBit:
    //   - Unsigned loads: IsLoadI8 = IsLoadI16 = IsLoadI32 = 0 →
    //     LoadSignSrc = 0 → LoadSignBit = 0 → result[i] = 0.
    //   - Signed loads: LoadSignSrc multiplexes the highest active
    //     byte (result[0] for I8, result[1] for I16, result[3] for
    //     I32); LoadSignBit pins to its bit 7 via a nibble-AND
    //     lookup (block placed alongside the sign-bit pins).
    //     result[i] = 0xFF · LoadSignBit for all inactive bytes.
    //
    // Without this a prover could write garbage into the high bytes of
    // a load result.  The interpreter writes 0 (unsigned) / 0xFF
    // (signed-extended) per the JAVM spec.
    {
        // Boolean witnesses + at-most-one-active.
        for f in [&row.is_load_i8, &row.is_load_i16, &row.is_load_i32] {
            eval.add_constraint(f[0].clone() * (E::F::one() - f[0].clone()));
        }
        // Mutex: sum ≤ 1.  Combined with each being boolean and
        // gated to only fire on signed-load opcodes (via the
        // ProgramMemory consumer pinning the canonical decoding),
        // exactly one is 1 on a signed-load row.

        // LoadSignSrc multiplex.
        eval.add_constraint(
            row.load_sign_src[0].clone()
                - row.is_load_i8[0].clone() * row.result[0].clone()
                - row.is_load_i16[0].clone() * row.result[1].clone()
                - row.is_load_i32[0].clone() * row.result[3].clone(),
        );

        // Inactive-byte binding for all loads: result[i] = 0xFF · LoadSignBit
        // when mem_byte_active[i] = 0.  Skip i=0 (always active for any
        // non-zero MemSize, so mem_byte_active[0] = 1 ⇒ gate = 0).
        let f_ff_p20: E::F = E::F::from(BaseField::from(255));
        // 2-factor selector × linear body via helper.
        for i in 1..WORD_SIZE {
            eval.add_constraint(
                row.is_load_local_not_active_h[i].clone()
                    * (row.result[i].clone() - f_ff_p20.clone() * row.load_sign_bit[0].clone()),
            );
        }
    }
}
