//! RISC-V ELF to JAM PVM transpiler.
//!
//! Converts RISC-V rv64em ELF binaries into Gray Paper standard programs
//! (Appendix A).
//!
//! Also provides utilities to hand-assemble PVM programs directly.
//!
//! Two invariants keep translation sound:
//!
//! - **x0 is never a PVM register.** PVM register 0 holds the return
//!   address, so `TranslationContext::require_reg` refuses x0 and every
//!   translation handles an x0 source or destination itself.
//! - **A pass never clears the bitmask of an instruction start.** A PVM
//!   immediate's length follows from the instruction's length, so folding
//!   bytes into the previous instruction changes what it decodes to. A
//!   fusion writes its result where the first instruction of the pair
//!   started, with a full four-byte immediate that trailing continuation
//!   bytes cannot change.

pub mod assembler;
mod derive;
mod linker;
mod riscv;
mod spi;

use std::collections::{BTreeSet, HashSet};

use thiserror::Error;
use vos_pvm::instruction::{InstructionCategory, Opcode};

pub use derive::{DeriveError, Derived, MAX_ELF, TRANSPILER_VERSION, derive};
pub use linker::{link_elf_spi, link_elf_spi_with_symbols};

/// Parse a signed variable-length immediate from PVM bytecode.
///
/// Reads `lx` bytes starting at `code[start]`, sign-extends to i64.
/// Used by peephole passes to extract load_imm values and memory offsets.
fn parse_signed_imm(code: &[u8], start: usize, lx: usize) -> i64 {
    let mut buf = [0u8; 8];
    for k in 0..lx.min(8) {
        if start + k < code.len() {
            buf[k] = code[start + k];
        }
    }
    if lx > 0 && lx <= 8 && buf[lx.min(8) - 1] & 0x80 != 0 {
        for b in &mut buf[lx.min(8)..8] {
            *b = 0xFF;
        }
    }
    i64::from_le_bytes(buf)
}

#[derive(Error, Debug)]
pub enum TranspileError {
    #[error("ELF parse error: {0}")]
    ElfParse(String),
    #[error("unsupported RISC-V instruction at offset {offset:#x}: {detail}")]
    UnsupportedInstruction { offset: usize, detail: String },
    #[error("register mapping error: RISC-V register {0} has no PVM equivalent")]
    RegisterMapping(u8),
    #[error("invalid section: {0}")]
    InvalidSection(String),
}

/// A JAM service's metadata, which its code blob carries before its
/// program, as PolkaJam's own services do: a version (0), then its name,
/// version, license and authors.
pub struct ServiceMetadata<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub license: &'a str,
    pub authors: &'a [&'a str],
}

impl ServiceMetadata<'_> {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8];
        for text in [self.name, self.version, self.license] {
            encode_bytes(text.as_bytes(), &mut out);
        }
        vos_pvm_program::encode_nat(self.authors.len() as u64, &mut out);
        for author in self.authors {
            encode_bytes(author.as_bytes(), &mut out);
        }
        out
    }
}

/// A standard program made a JAM service's code blob, `E(↕metadata) ‖
/// program`: what `jamt create-service` takes.
pub fn service_blob(program: &[u8], metadata: &ServiceMetadata) -> Vec<u8> {
    let mut blob = Vec::with_capacity(program.len() + 64);
    encode_bytes(&metadata.encode(), &mut blob);
    blob.extend_from_slice(program);
    blob
}

/// Gray Paper bytes with their length, a natural, first.
fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    vos_pvm_program::encode_nat(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// A program's functions: each one's first PVM instruction in its code, and
/// its name (demangled), by offset.
pub type Functions = Vec<(u32, String)>;

/// Compute skip distance from bitmask: number of continuation bytes after position `pc`.
fn skip_for(bitmask: &[u8], pc: usize) -> usize {
    for j in 0..25 {
        let idx = pc + 1 + j;
        if idx >= bitmask.len() || bitmask[idx] == 1 {
            return j;
        }
    }
    0
}

/// Each instruction of PVM code, by its bitmask: where it starts, and how
/// many continuation bytes follow it.
fn instructions(bitmask: &[u8]) -> impl Iterator<Item = (usize, usize)> + '_ {
    let mut pc = 0;
    std::iter::from_fn(move || {
        while pc < bitmask.len() && bitmask[pc] != 1 {
            pc += 1;
        }
        if pc >= bitmask.len() {
            return None;
        }
        let (at, skip) = (pc, skip_for(bitmask, pc));
        pc = at + 1 + skip;
        Some((at, skip))
    })
}

/// A jump's or a branch's offset in PVM code: where its bytes lie, how
/// many there are, and its value, relative to the instruction's start.
struct Offset {
    at: usize,
    width: usize,
    value: i32,
}

/// The offset of the instruction at `pc`, `skip` continuation bytes long,
/// when it jumps or branches to a fixed target: `jump`'s four bytes, a
/// two-register branch's four after its registers, or as many as a
/// register-immediate branch or `load_imm_jump` leaves after its
/// immediate, at most four, sign-extended.
fn branch_offset(code: &[u8], pc: usize, skip: usize) -> Option<Offset> {
    let len = code.len();
    let four = |at: usize| Offset {
        at,
        width: 4,
        value: i32::from_le_bytes(code[at..at + 4].try_into().expect("four bytes")),
    };
    match Opcode::from_byte(code[pc])?.category() {
        InstructionCategory::OneOffset => (pc + 5 <= len).then(|| four(pc + 1)),
        InstructionCategory::TwoRegOneOffset => (pc + 6 <= len).then(|| four(pc + 2)),
        InstructionCategory::OneRegImmOffset if pc + 2 <= len => {
            let lx = ((code[pc + 1] as usize / 16) % 8).min(4);
            let ly = if skip > lx + 1 {
                (skip - lx - 1).min(4)
            } else {
                0
            };
            let at = pc + 2 + lx;
            if ly == 0 || at + ly > len {
                return None;
            }
            let mut buf = [0u8; 4];
            buf[..ly].copy_from_slice(&code[at..at + ly]);
            if ly < 4 && buf[ly - 1] & 0x80 != 0 {
                buf[ly..].fill(0xFF);
            }
            Some(Offset {
                at,
                width: ly,
                value: i32::from_le_bytes(buf),
            })
        }
        _ => None,
    }
}

/// Collect all branch targets and jump table entries from PVM code.
///
/// Returns a set of byte offsets that are branch/jump destinations.
/// Used by peephole passes to avoid fusing across branch boundaries.
fn collect_branch_targets(code: &[u8], bitmask: &[u8], jump_table: &[u32]) -> HashSet<usize> {
    let len = code.len();
    let mut targets = HashSet::new();
    for (pc, skip) in instructions(bitmask) {
        if let Some(offset) = branch_offset(code, pc, skip) {
            let t = (pc as i64 + offset.value as i64) as usize;
            if t < len {
                targets.insert(t);
            }
        }
    }
    targets.extend(jump_table.iter().map(|&jt| jt as usize));
    targets
}

/// Peephole pass: fuse `load_imm` + ThreeReg ALU into `TwoRegOneImm` immediate form.
///
/// Scans the PVM code for consecutive pairs where:
/// 1. First instruction is `load_imm`
/// 2. Second instruction is a ThreeReg ALU op with an immediate-form equivalent
/// 3. The load destination register equals the ALU output register (dead after ALU)
/// 4. The load value fits in i32 (4-byte immediate)
/// 5. Neither instruction is a branch target
///
/// When fusable, rewrites the pair in-place: the first instruction becomes the
/// TwoRegOneImm form with a 4-byte immediate, and all remaining bytes through
/// the end of the second instruction become bitmask=0 continuation bytes.
pub(crate) fn peephole_fuse_load_imm_alu(
    code: &mut [u8],
    bitmask: &mut [u8],
    jump_table: &[u32],
) -> usize {
    let len = code.len();
    if len < 4 {
        return 0;
    }

    let targets = collect_branch_targets(code, bitmask, jump_table);

    // ThreeReg ALU → TwoRegOneImm immediate form mapping
    let imm_opcode = |three_reg_op: Opcode| -> Option<Opcode> {
        match three_reg_op {
            Opcode::Add64 => Some(Opcode::AddImm64),
            Opcode::Mul64 => Some(Opcode::MulImm64),
            Opcode::ShloL64 => Some(Opcode::ShloLImm64),
            Opcode::ShloR64 => Some(Opcode::ShloRImm64),
            Opcode::SharR64 => Some(Opcode::SharRImm64),
            Opcode::And => Some(Opcode::AndImm),
            Opcode::Xor => Some(Opcode::XorImm),
            Opcode::Or => Some(Opcode::OrImm),
            // set_lt_u and set_lt_s are non-commutative — handled below
            _ => None,
        }
    };

    let mut fused = 0;
    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 {
            i += 1;
            continue;
        }
        let op = code[i];
        let s = skip_for(bitmask, i);
        let next_i = i + 1 + s;

        // Look for load_imm followed by a ThreeReg ALU
        if op == Opcode::LoadImm as u8
            && next_i < len
            && bitmask[next_i] == 1
            && !targets.contains(&next_i)
        {
            let alu_op = Opcode::from_byte(code[next_i]);
            let alu_s = skip_for(bitmask, next_i);
            let set_lt = matches!(alu_op, Some(Opcode::SetLtU | Opcode::SetLtS));

            // Check if the following instruction is a ThreeReg ALU we can fuse with.
            // Covers: commutative ops (add, mul, shift, logic), sub_64, set_lt.
            let is_fusable_alu =
                alu_op.and_then(imm_opcode).is_some() || alu_op == Some(Opcode::Sub64) || set_lt;

            if is_fusable_alu && i + 1 < len && next_i + 2 < len {
                // Parse load_imm: [load_imm, reg_byte, imm...] — OneRegOneImm
                let load_reg_byte = code[i + 1];
                let load_rd = load_reg_byte & 0x0F;
                let lx = s.saturating_sub(1);
                let load_val = parse_signed_imm(code, i + 2, lx);

                // Parse ThreeReg ALU: [op, ra|(rb<<4), rd]
                let alu_reg1 = code[next_i + 1];
                let alu_ra = alu_reg1 & 0x0F;
                let alu_rb = (alu_reg1 >> 4) & 0x0F;
                let alu_rd = code[next_i + 2].min(12);

                let fits_i32 = load_val >= i32::MIN as i64 && load_val <= i32::MAX as i64;
                let matches_ra = load_rd == alu_ra;
                let matches_rb = load_rd == alu_rb;
                let end_of_pair = next_i + 1 + alu_s;

                /// Write a fused TwoRegOneImm instruction in-place.
                /// `reg_byte` is `rd | (base << 4)`.
                fn emit_fused(
                    code: &mut [u8],
                    bitmask: &mut [u8],
                    i: usize,
                    end: usize,
                    fused_op: Opcode,
                    reg_byte: u8,
                    imm: i32,
                ) -> bool {
                    if end >= i + 6 {
                        code[i] = fused_op as u8;
                        code[i + 1] = reg_byte;
                        let imm_bytes = imm.to_le_bytes();
                        code[i + 2] = imm_bytes[0];
                        code[i + 3] = imm_bytes[1];
                        code[i + 4] = imm_bytes[2];
                        code[i + 5] = imm_bytes[3];
                        for k in 6..(end - i) {
                            code[i + k] = 0;
                        }
                        for b in &mut bitmask[(i + 1)..end] {
                            *b = 0;
                        }
                        true
                    } else {
                        false
                    }
                }

                // Non-commutative: set_lt_u and set_lt_s.
                // rd = ra < rb: constant as rb → set_lt_imm, constant as ra → set_gt_imm
                if set_lt && fits_i32 && load_rd == alu_rd && (matches_ra != matches_rb) {
                    let unsigned = alu_op == Some(Opcode::SetLtU);
                    let (cmp_imm_op, base) = if matches_rb {
                        let op = if unsigned {
                            Opcode::SetLtUImm
                        } else {
                            Opcode::SetLtSImm
                        };
                        (op, alu_ra)
                    } else {
                        let op = if unsigned {
                            Opcode::SetGtUImm
                        } else {
                            Opcode::SetGtSImm
                        };
                        (op, alu_rb)
                    };
                    if emit_fused(
                        code,
                        bitmask,
                        i,
                        end_of_pair,
                        cmp_imm_op,
                        alu_rd | (base << 4),
                        load_val as i32,
                    ) {
                        fused += 1;
                        i = end_of_pair;
                        continue;
                    }
                }

                // Special case: sub_64 is non-commutative.
                // load_imm rd, K; sub_64 rd, ra, rb (rd = ra - rb):
                //   rd==rb (constant subtrahend): rd = ra - K → add_imm_64(rd, ra, -K)
                //   rd==ra (constant minuend):    rd = K - rb → neg_add_imm_64(rd, rb, K)
                if alu_op == Some(Opcode::Sub64)
                    && fits_i32
                    && load_rd == alu_rd
                    && (matches_ra != matches_rb)
                {
                    let result = if matches_rb {
                        let neg_k = -(load_val as i32) as i64;
                        if neg_k >= i32::MIN as i64 && neg_k <= i32::MAX as i64 {
                            Some((Opcode::AddImm64, alu_ra, neg_k as i32))
                        } else {
                            None
                        }
                    } else {
                        Some((Opcode::NegAddImm64, alu_rb, load_val as i32))
                    };
                    if let Some((sub_imm_op, base, imm32)) = result
                        && emit_fused(
                            code,
                            bitmask,
                            i,
                            end_of_pair,
                            sub_imm_op,
                            alu_rd | (base << 4),
                            imm32,
                        )
                    {
                        fused += 1;
                        i = end_of_pair;
                        continue;
                    }
                }

                // General ALU ops with an immediate form. Beyond
                // `load_rd == alu_rd`, two correctness constraints:
                //  • the surviving operand `base` must NOT be the loaded register
                //    — folding the load away would make `op Rd, Rd, Rd` read the
                //    stale pre-load value of Rd instead of the immediate;
                //  • shifts (shl/shr/sar) are non-commutative, so the
                //    constant may only fold in as the shift *amount* (the `rb`
                //    operand), never as the value being shifted (`ra`) — otherwise
                //    `K << Rb` would be miscompiled to `Rb << K`.
                if let Some(imm_op) = alu_op.and_then(imm_opcode)
                    && fits_i32
                    && load_rd == alu_rd
                {
                    let is_shift = matches!(
                        alu_op,
                        Some(Opcode::ShloL64 | Opcode::ShloR64 | Opcode::SharR64)
                    );
                    let usable = if is_shift {
                        matches_rb
                    } else {
                        matches_ra || matches_rb
                    };
                    let base = if matches_ra { alu_rb } else { alu_ra };
                    if usable
                        && base != load_rd
                        && emit_fused(
                            code,
                            bitmask,
                            i,
                            end_of_pair,
                            imm_op,
                            alu_rd | (base << 4),
                            load_val as i32,
                        )
                    {
                        fused += 1;
                        i = end_of_pair;
                        continue;
                    }
                }
            }
        }
        i += 1 + s;
    }
    fused
}

/// Peephole pass: fuse `load_imm` + indirect memory op into direct memory op.
///
/// When `load_imm rd, K` is immediately followed by `load_ind_X dest, rd, offset`
/// or `store_ind_X [rd + offset], val`, and `K + offset` fits in i32, the pair is
/// replaced by the direct `load_X dest, K+offset` or `store_X [K+offset], val`.
/// This eliminates the intermediate address register load.
pub(crate) fn peephole_fuse_load_imm_memory(
    code: &mut [u8],
    bitmask: &mut [u8],
    jump_table: &[u32],
) -> usize {
    let len = code.len();
    if len < 4 {
        return 0;
    }

    let targets = collect_branch_targets(code, bitmask, jump_table);

    // Map indirect opcode → direct opcode
    let direct_opcode = |ind_op: Opcode| -> Option<Opcode> {
        match ind_op {
            Opcode::LoadIndU8 => Some(Opcode::LoadU8),
            Opcode::LoadIndI8 => Some(Opcode::LoadI8),
            Opcode::LoadIndU16 => Some(Opcode::LoadU16),
            Opcode::LoadIndI16 => Some(Opcode::LoadI16),
            Opcode::LoadIndU32 => Some(Opcode::LoadU32),
            Opcode::LoadIndI32 => Some(Opcode::LoadI32),
            Opcode::LoadIndU64 => Some(Opcode::LoadU64),
            Opcode::StoreIndU8 => Some(Opcode::StoreU8),
            Opcode::StoreIndU16 => Some(Opcode::StoreU16),
            Opcode::StoreIndU32 => Some(Opcode::StoreU32),
            Opcode::StoreIndU64 => Some(Opcode::StoreU64),
            _ => None,
        }
    };

    // For load_ind: rd is dest, ra is base. Fusion is safe only when the load
    // overwrites its own base, proving that the address register is dead.
    // Stores never overwrite their base, so this local pass cannot prove it is
    // dead and must retain the preceding load_imm.
    let is_load_ind = |op: Opcode| -> bool {
        matches!(
            op,
            Opcode::LoadIndU8
                | Opcode::LoadIndI8
                | Opcode::LoadIndU16
                | Opcode::LoadIndI16
                | Opcode::LoadIndU32
                | Opcode::LoadIndI32
                | Opcode::LoadIndU64
        )
    };

    let mut fused = 0;
    let mut i = 0;
    while i < len {
        if i >= bitmask.len() || bitmask[i] != 1 {
            i += 1;
            continue;
        }
        let op = code[i];
        let s = skip_for(bitmask, i);
        let next_i = i + 1 + s;

        // Look for load_imm followed by load_ind or store_ind
        if op == Opcode::LoadImm as u8
            && next_i < len
            && bitmask[next_i] == 1
            && !targets.contains(&next_i)
        {
            let mem_s = skip_for(bitmask, next_i);
            if let Some(mem_op) = Opcode::from_byte(code[next_i])
                && let Some(dir_op) = direct_opcode(mem_op)
            {
                // Parse load_imm: [load_imm, reg_byte, imm...]
                if i + 1 < len {
                    let load_rd = code[i + 1] & 0x0F;
                    let lx = s.saturating_sub(1);
                    let load_val = parse_signed_imm(code, i + 2, lx);

                    // Parse memory op: [mem_op, rd|(ra<<4), imm0-3]
                    if next_i + 2 < len {
                        let mem_reg_byte = code[next_i + 1];
                        let mem_rd = mem_reg_byte & 0x0F; // dest (load) or value (store)
                        let mem_ra = (mem_reg_byte >> 4) & 0x0F; // base address register

                        let base_matches = load_rd == mem_ra;
                        let is_load = is_load_ind(mem_op);
                        let safe = is_load && base_matches && mem_rd == load_rd;

                        // Parse memory op's offset
                        let ly = mem_s.saturating_sub(1);
                        let offset = parse_signed_imm(code, next_i + 2, ly);

                        let combined = load_val.wrapping_add(offset);
                        let fits_u32 = combined >= 0 && combined <= u32::MAX as i64;
                        let end_of_pair = next_i + 1 + mem_s;

                        if safe && fits_u32 && end_of_pair >= i + 6 {
                            // The direct form [dir_op, rd, imm0-3] replaces the
                            // pair from the load_imm's position, and the rest
                            // of the pair continues it: its full four-byte
                            // immediate decodes the same whatever follows.
                            // Folding the load_imm's bytes into the instruction
                            // before it instead would change that
                            // instruction's immediate length. Entering at the
                            // load_imm runs the fused load, which leaves the
                            // registers as the pair did.
                            let addr_bytes = (combined as u32).to_le_bytes();
                            code[i] = dir_op as u8;
                            code[i + 1] = mem_rd;
                            code[i + 2..i + 6].copy_from_slice(&addr_bytes);
                            for byte in &mut code[i + 6..end_of_pair] {
                                *byte = 0;
                            }
                            for b in &mut bitmask[(i + 1)..end_of_pair] {
                                *b = 0;
                            }

                            fused += 1;
                            i = end_of_pair;
                            continue;
                        }
                    }
                }
            }
        }
        i += 1 + s;
    }
    fused
}

/// Post-pass: ensure all PVM branch targets are basic block starts (ϖ).
///
/// Scans the PVM code for branch/jump instructions, extracts their targets,
/// and inserts `fallthrough` before any target not preceded by a
/// terminator. Adjusts all branch offsets and jump table entries to account
/// for the inserted bytes.
///
/// This guarantees the JAM spec invariant: all branch targets ∈ ϖ.
///
/// When it inserts, `remap` sees where each old offset moved, the code's
/// end included, so a caller can move what it keeps by offset alike;
/// observing it changes no byte.
pub(crate) fn ensure_branch_targets_are_block_starts(
    code: &mut Vec<u8>,
    bitmask: &mut Vec<u8>,
    jump_table: &mut [u32],
    remap: impl FnOnce(&[u32]),
) {
    // Gray Paper v0.8.0 set T. `unlikely` and `ecalli` stay inside their
    // block.
    let is_terminator = |op: u8| Opcode::from_byte(op).is_some_and(Opcode::is_terminator);

    // Pass 1: find all branch target PCs and check which need fallthrough.
    let len = code.len();
    let starts = |pc: usize| pc < len && pc < bitmask.len() && bitmask[pc] == 1;

    // The instructions a terminator precedes, and the first.
    let mut post_term = HashSet::from([0usize]);
    for (pc, skip) in instructions(bitmask) {
        if is_terminator(code[pc]) && starts(pc + 1 + skip) {
            post_term.insert(pc + 1 + skip);
        }
    }

    // The branch targets and jump table entries no terminator precedes:
    // PVM offsets to insert a fallthrough before.
    let mut insert_positions = BTreeSet::new();
    for (pc, skip) in instructions(bitmask) {
        if let Some(offset) = branch_offset(code, pc, skip) {
            let t = (pc as i64 + offset.value as i64) as usize;
            if starts(t) && !post_term.contains(&t) {
                insert_positions.insert(t);
            }
        }
    }
    insert_positions.extend(
        jump_table
            .iter()
            .map(|&entry| entry as usize)
            .filter(|&t| starts(t) && !post_term.contains(&t)),
    );

    if insert_positions.is_empty() {
        return;
    }

    // Pass 2: build new code/bitmask with fallthroughs inserted.
    // Also build an offset map: old_pc → new_pc.
    let new_len = len + insert_positions.len();
    let mut new_code = Vec::with_capacity(new_len);
    let mut new_bitmask = Vec::with_capacity(new_len);
    let mut offset_map = vec![0u32; len + 1]; // old_pc → new_pc

    let mut inserts = insert_positions.into_iter().peekable();
    for old_pc in 0..len {
        // Insert fallthrough before this PC if needed
        while inserts.next_if_eq(&old_pc).is_some() {
            new_code.push(Opcode::Fallthrough as u8);
            new_bitmask.push(1); // instruction start
        }
        offset_map[old_pc] = new_code.len() as u32;
        new_code.push(code[old_pc]);
        new_bitmask.push(bitmask[old_pc]);
    }
    offset_map[len] = new_code.len() as u32;
    remap(&offset_map);

    // Pass 3: re-point every branch offset through `offset_map`.
    for (old_pc, skip) in instructions(bitmask) {
        let Some(offset) = branch_offset(code, old_pc, skip) else {
            continue;
        };
        let old_target = (old_pc as i64 + offset.value as i64) as usize;
        if old_target <= len {
            let new_pc = offset_map[old_pc] as usize;
            let new_off = (offset_map[old_target] as i64 - new_pc as i64) as i32;
            // Written back at the same width.
            let at = new_pc + (offset.at - old_pc);
            new_code[at..at + offset.width].copy_from_slice(&new_off.to_le_bytes()[..offset.width]);
        }
    }

    // Fix jump table entries
    for entry in jump_table.iter_mut() {
        let old_pc = *entry as usize;
        if old_pc <= len {
            *entry = offset_map[old_pc];
        }
    }

    *code = new_code;
    *bitmask = new_bitmask;
}

#[cfg(test)]
mod tests {
    /// A service blob is its metadata, length-prefixed, then the program,
    /// as the probe service PolkaJam ran was built.
    #[test]
    fn a_service_blob_carries_its_metadata_first() {
        let metadata = super::ServiceMetadata {
            name: "vos-agent",
            version: "0.1.0",
            license: "AGPL-3.0-or-later",
            authors: &["VOS"],
        };
        let encoded = metadata.encode();
        assert_eq!(
            encoded,
            [
                &[0, 9][..],
                b"vos-agent",
                &[5],
                b"0.1.0",
                &[17],
                b"AGPL-3.0-or-later",
                &[1, 3],
                b"VOS"
            ]
            .concat()
        );
        let blob = super::service_blob(&[7, 8], &metadata);
        assert_eq!(
            blob,
            [&[encoded.len() as u8][..], &encoded, &[7, 8]].concat()
        );
    }

    use super::*;

    #[test]
    fn diagnostic_pc_map_tracks_insertions_without_changing_emitted_code() {
        let mut code = vec![51, 2, 42, 51, 3, 17, 0];
        let mut bitmask = vec![1, 0, 0, 1, 0, 0, 1];
        let mut jumps = vec![3];
        let (mut expected_code, mut expected_mask, mut expected_jumps) =
            (code.clone(), bitmask.clone(), jumps.clone());
        ensure_branch_targets_are_block_starts(
            &mut expected_code,
            &mut expected_mask,
            &mut expected_jumps,
            |_| {},
        );
        let mut observed = Vec::new();
        ensure_branch_targets_are_block_starts(&mut code, &mut bitmask, &mut jumps, |offsets| {
            observed.extend_from_slice(offsets);
        });
        assert_eq!(observed, vec![0, 1, 2, 4, 5, 6, 7, 8]);
        assert_eq!(jumps, vec![4]);
        assert_eq!(code[3], 1);
        assert_eq!(
            (code, bitmask, jumps),
            (expected_code, expected_mask, expected_jumps)
        );
    }

    #[test]
    fn diagnostic_pc_map_is_identity_when_no_offsets_change() {
        let mut code = vec![0];
        let mut bitmask = vec![1];
        let mut jumps = vec![0];
        ensure_branch_targets_are_block_starts(&mut code, &mut bitmask, &mut jumps, |_| {
            panic!("no relocation should be observed");
        });
        assert_eq!((code, bitmask, jumps), (vec![0], vec![1], vec![0]));
    }

    // === peephole_fuse_load_imm_alu tests ===

    #[test]
    fn test_fuse_load_imm_add64() {
        // load_imm φ[2], 42 (rd=2, imm=42)
        // add_64 φ[2] = φ[0] + φ[2] (ra=0, rb=2, rd=2)
        // → add_imm_64 φ[2] = φ[0] + 42
        let mut code = vec![
            51, 2, 42, // load_imm rd=2, imm=42 (skip=1)
            200, 0x20, 2, // add_64 ra=0, rb=2, rd=2
        ];
        let mut bitmask = vec![1, 0, 0, 1, 0, 0];

        let fused = peephole_fuse_load_imm_alu(&mut code, &mut bitmask, &[]);
        assert_eq!(fused, 1);
        assert_eq!(code[0], 149); // add_imm_64
        assert_eq!(code[1] & 0x0F, 2); // rd=2
        assert_eq!(code[1] >> 4, 0); // base=0
        assert_eq!(code[2], 42); // imm low byte
        assert_eq!(bitmask[0], 1);
        assert_eq!(bitmask[3], 0); // old ALU start cleared
    }

    #[test]
    fn test_fuse_load_imm_mul64() {
        // load_imm φ[3], 7 → mul_64 φ[3] = φ[1] * φ[3]
        // → mul_imm_64 φ[3] = φ[1] * 7
        let mut code = vec![
            51, 3, 7, // load_imm rd=3, imm=7
            202, 0x31, 3, // mul_64 ra=1, rb=3, rd=3
        ];
        let mut bitmask = vec![1, 0, 0, 1, 0, 0];

        let fused = peephole_fuse_load_imm_alu(&mut code, &mut bitmask, &[]);
        assert_eq!(fused, 1);
        assert_eq!(code[0], 150); // mul_imm_64
    }

    #[test]
    fn test_fuse_skips_branch_target() {
        // Same pattern but ALU is a branch target → should NOT fuse
        let mut code = vec![
            51, 2, 42, 200, 0x20, 2, 40, 253, 255, 255,
            255, // jump -3 (targets offset 3 = the add_64)
        ];
        let mut bitmask = vec![1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0];

        let fused = peephole_fuse_load_imm_alu(&mut code, &mut bitmask, &[]);
        assert_eq!(fused, 0, "should not fuse when ALU is a branch target");
    }

    #[test]
    fn test_fuse_no_match_different_rd() {
        // load_imm writes to rd=2 but ALU rd=3 → should NOT fuse
        let mut code = vec![
            51, 2, 42, // load_imm rd=2
            200, 0x20, 3, // add_64 rd=3 (not 2)
        ];
        let mut bitmask = vec![1, 0, 0, 1, 0, 0];

        let fused = peephole_fuse_load_imm_alu(&mut code, &mut bitmask, &[]);
        assert_eq!(fused, 0);
    }

    #[test]
    fn test_fuse_sub64_constant_subtrahend() {
        // load_imm φ[2], 5; sub_64 φ[2] = φ[0] - φ[2]
        // → add_imm_64 φ[2] = φ[0] + (-5)
        let mut code = vec![
            51, 2, 5, // load_imm rd=2, imm=5
            201, 0x20, 2, // sub_64 ra=0, rb=2, rd=2
        ];
        let mut bitmask = vec![1, 0, 0, 1, 0, 0];

        let fused = peephole_fuse_load_imm_alu(&mut code, &mut bitmask, &[]);
        assert_eq!(fused, 1);
        assert_eq!(code[0], 149); // add_imm_64
        // imm should be -5 as i32 LE
        let imm = i32::from_le_bytes([code[2], code[3], code[4], code[5]]);
        assert_eq!(imm, -5);
    }

    // === peephole_fuse_load_imm_memory tests ===

    #[test]
    fn test_fuse_load_imm_load_ind() {
        // load_imm φ[3], 0x100; load_ind_u32 φ[3], φ[3], 4
        // → load_u32 φ[3], 0x104. The load overwrites its base.
        // load_ind_u32 format: [128, rd|(ra<<4), offset_bytes]
        // rd=3 (dest), ra=3 (base). reg byte = 3 | (3<<4) = 0x33.
        let mut code = vec![
            51, 3, 0, 1, // load_imm rd=3, imm=0x100 (skip=2: reg+2 imm bytes)
            128, 0x33, 4, 0, 0, 0, // load_ind_u32 rd=3, ra=3, offset=4
        ];
        let mut bitmask = vec![1, 0, 0, 0, 1, 0, 0, 0, 0, 0];

        let fused = peephole_fuse_load_imm_memory(&mut code, &mut bitmask, &[]);
        assert_eq!(fused, 1);
        // The direct form takes the load_imm's place and the rest of the
        // pair continues it.
        assert_eq!(bitmask, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(code[0], 56, "load_ind_u32(128) → load_u32(56)");
        assert_eq!(code[1], 3, "dest register preserved");
        // Combined address: 0x100 + 4 = 0x104
        let addr = u32::from_le_bytes([code[2], code[3], code[4], code[5]]);
        assert_eq!(addr, 0x104);
    }

    #[test]
    fn test_does_not_fuse_memory_when_base_survives() {
        for (memory, what) in [(128, "load"), (123, "store")] {
            // The load writes φ[2], and the store writes memory; neither
            // overwrites φ[3]. A later memory operation may reuse that base.
            let original = vec![
                51, 3, 0, 1, // load_imm φ[3], 0x100
                memory, 0x32, 4, 0, 0, 0, // memory φ[2], [φ[3] + 4]
            ];
            let mut code = original.clone();
            let mut bitmask = vec![1, 0, 0, 0, 1, 0, 0, 0, 0, 0];

            let fused = peephole_fuse_load_imm_memory(&mut code, &mut bitmask, &[]);
            assert_eq!(fused, 0, "{what} must preserve a reusable base");
            assert_eq!(code, original);
        }
    }

    // === parse_signed_imm tests ===

    #[test]
    fn test_parse_signed_imm_positive() {
        let code = [42, 0];
        assert_eq!(parse_signed_imm(&code, 0, 2), 42);
    }

    #[test]
    fn test_parse_signed_imm_negative() {
        // -1 in 1 byte = 0xFF, sign-extended
        let code = [0xFF];
        assert_eq!(parse_signed_imm(&code, 0, 1), -1);
    }

    #[test]
    fn test_parse_signed_imm_zero_length() {
        let code = [42];
        assert_eq!(parse_signed_imm(&code, 0, 0), 0);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Generate random PVM-like bytecode: instruction starts at every 3rd byte
        /// (simulating load_imm + ALU patterns).
        fn random_pvm_program() -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
            // Generate 3-30 instructions, each 1-6 bytes
            proptest::collection::vec(
                (
                    0u8..=255u8,                                // opcode
                    proptest::collection::vec(0u8..=255, 0..5), // operand bytes
                ),
                3..30,
            )
            .prop_map(|instrs| {
                let mut code = Vec::new();
                let mut bitmask = Vec::new();
                for (opcode, operands) in &instrs {
                    code.push(*opcode);
                    bitmask.push(1u8);
                    for &b in operands {
                        code.push(b);
                        bitmask.push(0u8);
                    }
                }
                (code, bitmask)
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Peephole ALU fusion is idempotent: applying twice produces the same
            /// code as applying once.
            #[test]
            fn alu_fusion_idempotent((code, bitmask) in random_pvm_program()) {
                let mut c1 = code.clone();
                let mut b1 = bitmask.clone();
                peephole_fuse_load_imm_alu(&mut c1, &mut b1, &[]);

                let mut c2 = c1.clone();
                let mut b2 = b1.clone();
                peephole_fuse_load_imm_alu(&mut c2, &mut b2, &[]);

                prop_assert_eq!(&c1, &c2, "code should not change on second pass");
                prop_assert_eq!(&b1, &b2, "bitmask should not change on second pass");
            }

            /// Peephole memory fusion is idempotent.
            #[test]
            fn memory_fusion_idempotent((code, bitmask) in random_pvm_program()) {
                let mut c1 = code.clone();
                let mut b1 = bitmask.clone();
                peephole_fuse_load_imm_memory(&mut c1, &mut b1, &[]);

                let mut c2 = c1.clone();
                let mut b2 = b1.clone();
                peephole_fuse_load_imm_memory(&mut c2, &mut b2, &[]);

                prop_assert_eq!(&c1, &c2);
                prop_assert_eq!(&b1, &b2);
            }

            /// Full peephole pipeline is idempotent.
            #[test]
            fn full_pipeline_idempotent((code, bitmask) in random_pvm_program()) {
                let apply = |c: &mut Vec<u8>, b: &mut Vec<u8>| {
                    peephole_fuse_load_imm_alu(c, b, &[]);
                    peephole_fuse_load_imm_memory(c, b, &[]);
                };

                let mut c1 = code.clone();
                let mut b1 = bitmask.clone();
                apply(&mut c1, &mut b1);

                let mut c2 = c1.clone();
                let mut b2 = b1.clone();
                apply(&mut c2, &mut b2);

                prop_assert_eq!(&c1, &c2, "full pipeline should be idempotent");
                prop_assert_eq!(&b1, &b2);
            }

            /// Peephole passes never increase code/bitmask length.
            #[test]
            fn passes_never_grow((code, bitmask) in random_pvm_program()) {
                let orig_len = code.len();
                let mut c = code;
                let mut b = bitmask;
                peephole_fuse_load_imm_alu(&mut c, &mut b, &[]);
                peephole_fuse_load_imm_memory(&mut c, &mut b, &[]);
                prop_assert_eq!(c.len(), orig_len, "code length should not change");
                prop_assert_eq!(b.len(), orig_len, "bitmask length should not change");
            }
        }
    }
}
