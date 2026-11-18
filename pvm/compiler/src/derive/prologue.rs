//! A kernel's instruction-0 prologue.

use super::*;

/// The prologue at a kernel's instruction 0, as an attestable program's
/// `_start`, and where in it its call to the entry lies and the entry
/// returns to. It keeps the halt address; reads the input through the
/// witness input into the argument pages at `arguments` until a call
/// returns 0, at most [`Input::chunk`] bytes a call where that bounds it,
/// and traps if it filled them; calls the entry on the bytes read, with 32
/// bytes of its stack for the io-hash; then returns to the halt address
/// with the entry's output in φ7 and φ8 and the io-hash in φ9 to φ12, eight
/// little-endian bytes a register.
pub(super) struct Prologue {
    pub(super) code: Vec<u8>,
    pub(super) call_at: u64,
    pub(super) return_at: u64,
}

impl Prologue {
    pub(super) fn new(arguments: u64, input: Input) -> Self {
        const RA: u32 = 1;
        const SP: u32 = 2;
        const T0: u32 = 5;
        const T1: u32 = 6;
        const T2: u32 = 7;
        const S0: u32 = 8;
        const S1: u32 = 9;
        const A0: u32 = 10;
        const A1: u32 = 11;
        const A2: u32 = 12;
        const A3: u32 = 13;
        const BEQ: u32 = 0;
        const BLTU: u32 = 6;
        const BGEU: u32 = 7;
        // `lui` and `addi`: a value below 2^31, its low twelve bits signed.
        let load = |rd: u32, value: u64| {
            let upper = ((value + 0x800) >> 12) as u32;
            let lower = (value as i32) - ((upper << 12) as i32);
            [lui(rd, upper), addi(rd, rd, lower)]
        };
        // The offset in bytes from instruction `from` to instruction `to`.
        let offset = |from: usize, to: usize| 4 * (to as i32 - from as i32);
        const MARK: u32 = 0x801 << 20 | 1 << 12 | op::SYSTEM;
        const ECALL: u32 = op::SYSTEM;
        const UNIMP: u32 = 0xc000_1073;

        // The halt address, the argument pages, the bytes read, their room,
        // and the most a call asks for.
        let mut code = vec![addi(S0, RA, 0)];
        code.extend(load(S1, arguments));
        code.push(addi(T1, 0, 0));
        code.extend(load(T2, input.most() + 1));
        if let Some(chunk) = input.chunk() {
            code.extend(load(A3, chunk));
        }
        // The next read's destination and capacity, bounded by the chunk.
        let next = code.len();
        code.push(add(A0, S1, T1));
        code.push(sub(A1, T2, T1));
        if input.chunk().is_some() {
            code.push(b_type(BLTU, A1, A3, 8));
            code.push(addi(A1, A3, 0));
        }
        code.push(addi(T0, 0, vos_pvm::precompile::WITNESS_INPUT as i32));
        code.push(MARK);
        code.push(ECALL);
        // 0, the end of input: on to the length's check.
        let ended = code.len();
        code.push(0);
        code.push(add(T1, T1, A0));
        let back = code.len();
        code.push(jal(0, offset(back, next)));
        code[ended] = b_type(BEQ, A0, 0, offset(ended, code.len()));
        // Room filled: too long, to the trap.
        let filled = code.len();
        code.push(0);
        code.push(addi(A0, S1, 0)); // the arguments
        code.push(addi(A1, T1, 0)); // their length
        code.push(addi(SP, SP, -32)); // the io-hash's place
        code.push(addi(A2, SP, 0));
        let call_at = code.len();
        code.push(auipc(RA, 0)); // the call to the entry
        code.push(jalr(RA, RA));
        let return_at = code.len();
        code.push(ld(A2, SP, 0)); // the io-hash, φ9 to φ12
        code.push(ld(A2 + 1, SP, 8));
        code.push(ld(A2 + 2, SP, 16));
        code.push(ld(A2 + 3, SP, 24));
        code.push(addi(SP, SP, 32));
        code.push(addi(RA, S0, 0));
        code.push(jalr(0, RA)); // to the halt address
        code[filled] = b_type(BGEU, T1, T2, offset(filled, code.len()));
        code.push(UNIMP);
        Self {
            code: code.into_iter().flat_map(u32::to_le_bytes).collect(),
            call_at: 4 * call_at as u64,
            return_at: 4 * return_at as u64,
        }
    }
}
