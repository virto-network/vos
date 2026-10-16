//! VOS precompiles: deterministic memory transforms a guest invokes with
//! `ecalli` and the node serves natively.
//!
//! Precompile ids live in `0x400..=0x4ff`, outside every id JAM assigns
//! (the Gray Paper host calls and JIP-1 `log` at 100). A JAM node answers an
//! unknown id with `WHAT` in φ\[7\] and continues, so a guest that falls back
//! to software on `WHAT` computes identical results everywhere. A precompile
//! leaves every register unchanged; φ\[7\] holds an input pointer, never
//! `WHAT`, so the guest can tell the two apart.
//!
//! The refine host serves the outer machine's precompiles in place, inside
//! the current machine slice, and reports each call so a proof tracer can
//! attach the matching chip rows. An inner machine's precompile call exits
//! to the outer machine as a host call, on every host: the agent serves it
//! at the same price, natively through its own call here or in software on
//! JAM, and writes its output through the agent's tracked writes.

/// One BLAKE2b compression: φ\[7\] = h pointer (64 bytes, read and written),
/// φ\[8\] = m pointer (128 bytes, read), φ\[9\] = counter low 64 bits,
/// φ\[10\] = finalize flag (non-zero = last block).
pub const BLAKE2B_COMPRESS: u64 = 0x400;

/// Gas for one BLAKE2b compression, on top of its `ecalli`'s block gas.
///
/// Serving one natively takes about 520 time-stamp-counter cycles on the
/// reference machine (`precompile native` in `pvm/bench`), and the 0.8.0
/// block-gas model counts cycles; the price rounds that up. Computing the
/// same hash in software inside the guest costs about 15,900 gas.
pub const BLAKE2B_COMPRESS_GAS: crate::Gas = 600;

/// Whether `id` names a precompile the refine host serves in place for the
/// outer machine.
pub const fn is_precompile(id: u64) -> bool {
    id == BLAKE2B_COMPRESS
}

/// The gas a call to precompile `id` costs, or `None` if `id` names none.
pub const fn price(id: u64) -> Option<crate::Gas> {
    match id {
        BLAKE2B_COMPRESS => Some(BLAKE2B_COMPRESS_GAS),
        _ => None,
    }
}

/// A kernel's witness input: φ\[7\] the destination, φ\[8\] the capacity. It
/// writes the next `min(capacity, remaining)` bytes of the run's input at
/// the destination and returns their count in φ\[7\]; 0 means the end of
/// input. Only the agent serves it, to the kernels it runs, from the input
/// it records with their attest; a node's refine host serves it to no
/// machine of its own.
pub const WITNESS_INPUT: u64 = 0x401;

/// Gas for one witness-input call, before its bytes: the agent's copy into
/// the kernel, the work of an actor's `input` (`vos_wire::abi::price::INPUT`).
pub const WITNESS_INPUT_GAS: crate::Gas = 2_500;

/// Gas for each byte a witness-input call writes, an actor's per-byte price
/// (`vos_wire::abi::price::PER_BYTE`).
pub const WITNESS_INPUT_BYTE_GAS: crate::Gas = 24;

/// The most bytes a kernel's whole witness input holds, a work result's cap
/// (`vos_wire::abi::cap::WORK_RESULT`): the attest that records it fits one.
pub const WITNESS_INPUT_MAX: usize = 4 << 20;

/// Whether `id` names a call a kernel may make: a precompile, or its
/// witness input.
pub const fn is_kernel_call(id: u64) -> bool {
    is_precompile(id) || id == WITNESS_INPUT
}

/// A kernel's witness input as one run reads it, call by call: its bytes,
/// borrowed or held, and how many the calls have read.
#[derive(Clone, Debug)]
pub struct WitnessInput<B> {
    bytes: B,
    cursor: usize,
}

/// One served witness-input call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WitnessRead {
    /// φ\[7\] as the call found it.
    pub destination: u64,
    /// φ\[8\] as the call found it.
    pub capacity: u64,
    /// The input's bytes read before the call.
    pub cursor: usize,
    /// The bytes it wrote, now in φ\[7\].
    pub count: usize,
}

/// Why a witness-input call was not served.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessFault {
    /// The machine could not pay: its gas is now empty.
    OutOfGas,
    /// The destination is not writable for the count.
    Unwritable,
}

impl<B: AsRef<[u8]>> WitnessInput<B> {
    /// The input `bytes`, or `None` past [`WITNESS_INPUT_MAX`].
    pub fn new(bytes: B) -> Option<Self> {
        (bytes.as_ref().len() <= WITNESS_INPUT_MAX).then_some(Self { bytes, cursor: 0 })
    }

    /// The bytes read so far.
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The bytes read so far, in call order.
    pub fn read(&self) -> &[u8] {
        &self.bytes.as_ref()[..self.cursor]
    }

    /// The bytes left to read.
    pub fn remaining(&self) -> usize {
        self.bytes.as_ref().len() - self.cursor
    }

    /// The bytes the next call with capacity `capacity` writes.
    pub fn count(&self, capacity: u64) -> usize {
        let remaining = self.remaining();
        usize::try_from(capacity).map_or(remaining, |capacity| capacity.min(remaining))
    }

    /// Serve a call: its price from `gas`, [`WITNESS_INPUT_GAS`] then
    /// [`WITNESS_INPUT_BYTE_GAS`] for each byte it writes, then the bytes
    /// at φ\[7\] and their count in φ\[7\]. A refused call writes nothing,
    /// leaves the registers and the cursor as they were, and an unpaid one
    /// empties `gas`.
    pub fn serve(
        &mut self,
        registers: &mut [u64; crate::PVM_REGISTER_COUNT],
        memory: &mut crate::interpreter::Memory,
        gas: &mut crate::Gas,
    ) -> Result<WitnessRead, WitnessFault> {
        let (destination, capacity) = (registers[7], registers[8]);
        let count = self.count(capacity);
        let price = WITNESS_INPUT_GAS.saturating_add(WITNESS_INPUT_BYTE_GAS * count as u64);
        if *gas < price {
            *gas = 0;
            return Err(WitnessFault::OutOfGas);
        }
        *gas -= price;
        let bytes = &self.bytes.as_ref()[self.cursor..self.cursor + count];
        if count > 0 {
            let fits = destination
                .checked_add(count as u64)
                .is_some_and(|end| end <= 1 << 32);
            if !fits || !memory.write_bytes_checked(destination as u32, bytes) {
                return Err(WitnessFault::Unwritable);
            }
        }
        let read = WitnessRead {
            destination,
            capacity,
            cursor: self.cursor,
            count,
        };
        self.cursor += count;
        registers[7] = count as u64;
        Ok(read)
    }
}

/// Charge precompile `id`'s price from `gas` before serving it. When the
/// price cannot be paid, `gas` is emptied and the call is not served: the
/// machine stops out of gas on the call's own counter, as for any host call.
pub fn charge(id: u64, gas: &mut crate::Gas) -> bool {
    let price = price(id).unwrap_or(0);
    if *gas < price {
        *gas = 0;
        false
    } else {
        *gas -= price;
        true
    }
}

/// BLAKE2b-256 of `data`, unkeyed: the hash JAM names code by. A guest
/// computes the same with `vos_pvm_precompiles::blake2b_256`, through the
/// BLAKE2b precompile.
pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut h = IV;
    // Parameter block: 32-byte digest, no key, fanout and depth 1.
    h[0] ^= 0x0101_0000 ^ 32;
    let mut counter = 0u128;
    let mut rest = data;
    loop {
        let last = rest.len() <= 128;
        let take = rest.len().min(128);
        let mut block = [0u8; 128];
        block[..take].copy_from_slice(&rest[..take]);
        counter += take as u128;
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        }
        h = compress(&h, &m, counter, last);
        rest = &rest[take..];
        if last {
            break;
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h[..4].iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// The inputs and output of one served precompile call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrecompileCall {
    Blake2bCompress {
        h_ptr: u32,
        m_ptr: u32,
        h: [u64; 8],
        m: [u64; 16],
        t: u128,
        f: bool,
        h_bytes: [u8; 64],
        m_bytes: [u8; 128],
        out_bytes: [u8; 64],
    },
}

/// Serve precompile `id` against `memory` with `registers` as its
/// arguments. `None` means an argument range was not accessible; the
/// caller turns that into a guest panic, as for any host call.
pub fn execute(
    id: u64,
    registers: &[u64; crate::PVM_REGISTER_COUNT],
    memory: &mut crate::interpreter::Memory,
) -> Option<PrecompileCall> {
    match id {
        BLAKE2B_COMPRESS => blake2b_compress(registers, memory),
        _ => None,
    }
}

fn blake2b_compress(
    registers: &[u64; crate::PVM_REGISTER_COUNT],
    memory: &mut crate::interpreter::Memory,
) -> Option<PrecompileCall> {
    let h_ptr = u32::try_from(registers[7]).ok()?;
    let m_ptr = u32::try_from(registers[8]).ok()?;
    let t = u128::from(registers[9]);
    let f = registers[10] != 0;
    let mut h_bytes = [0u8; 64];
    let mut m_bytes = [0u8; 128];
    if !memory.read_bytes_checked(h_ptr, &mut h_bytes)
        || !memory.read_bytes_checked(m_ptr, &mut m_bytes)
    {
        return None;
    }
    let mut h = [0u64; 8];
    let mut m = [0u64; 16];
    for (i, word) in h.iter_mut().enumerate() {
        *word = u64::from_le_bytes(h_bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    for (i, word) in m.iter_mut().enumerate() {
        *word = u64::from_le_bytes(m_bytes[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let result = compress(&h, &m, t, f);
    let mut out_bytes = [0u8; 64];
    for (i, word) in result.iter().enumerate() {
        out_bytes[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
    }
    if !memory.write_bytes_checked(h_ptr, &out_bytes) {
        return None;
    }
    Some(PrecompileCall::Blake2bCompress {
        h_ptr,
        m_ptr,
        h,
        m,
        t,
        f,
        h_bytes,
        m_bytes,
        out_bytes,
    })
}

const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// The BLAKE2b compression function F (RFC 7693, section 3.2).
pub fn compress(h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if f {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    let mut out = [0u64; 8];
    for i in 0..8 {
        out[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    out
}

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod hash_tests {
    #[test]
    fn blake2b_256_matches_reference_digests() {
        let hex = |digest: [u8; 32]| {
            digest
                .iter()
                .map(|byte| alloc::format!("{byte:02x}"))
                .collect::<alloc::string::String>()
        };
        assert_eq!(
            hex(super::blake2b_256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        assert_eq!(
            hex(super::blake2b_256(b"abc")),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
        // Exactly one block, and one block plus one byte.
        assert_ne!(super::blake2b_256(&[7; 128]), super::blake2b_256(&[7; 129]));
    }
}

#[cfg(test)]
mod witness_tests {
    use super::*;
    use crate::interpreter::{Memory, PERM_NONE, PERM_RO, PERM_RW};

    /// Pages 1 and 2 writable, page 3 read-only.
    fn memory() -> Memory {
        let mut memory = Memory::sparse(1 << 32);
        let pages = memory.pages();
        assert!(memory.set_page_range(0, pages, PERM_NONE));
        assert!(memory.set_page_range(1, 2, PERM_RW));
        assert!(memory.set_page_range(3, 1, PERM_RO));
        memory
    }

    fn call(
        input: &mut WitnessInput<&[u8]>,
        memory: &mut Memory,
        gas: &mut crate::Gas,
        destination: u64,
        capacity: u64,
    ) -> (Result<WitnessRead, WitnessFault>, u64) {
        let mut registers = [0; crate::PVM_REGISTER_COUNT];
        registers[7] = destination;
        registers[8] = capacity;
        let served = input.serve(&mut registers, memory, gas);
        (served, registers[7])
    }

    /// Each call writes the next `min(capacity, remaining)` bytes and
    /// returns their count; a short read returns the rest, a read at the
    /// end 0, and a call of no capacity 0 anywhere. Each pays a call's
    /// price and its bytes'.
    #[test]
    fn reads_return_their_count_short_at_the_tail_and_zero_at_the_end() {
        let bytes: Vec<u8> = (1..=10).collect();
        let mut input = WitnessInput::new(&bytes[..]).unwrap();
        let mut memory = memory();
        let mut gas = 1_000_000;
        let mut calls = Vec::new();
        for (destination, capacity) in [
            (0x1000, 3),
            (0x1100, 0),
            (0x1ffe, 4),
            (0x1200, 8),
            (0x1300, 5),
        ] {
            let before = gas;
            let (served, returned) = call(&mut input, &mut memory, &mut gas, destination, capacity);
            let read = served.unwrap();
            assert_eq!(returned, read.count as u64);
            assert_eq!(
                before - gas,
                WITNESS_INPUT_GAS + WITNESS_INPUT_BYTE_GAS * read.count as u64
            );
            calls.push((read.cursor, read.count));
        }
        assert_eq!(calls, [(0, 3), (3, 0), (3, 4), (7, 3), (10, 0)]);
        assert_eq!((input.cursor(), input.read()), (10, &bytes[..]));
        let mut written = [0u8; 4];
        assert!(memory.read_bytes_checked(0x1ffe, &mut written));
        assert_eq!(written, [4, 5, 6, 7], "across a page");
        let mut tail = [0u8; 4];
        assert!(memory.read_bytes_checked(0x1200, &mut tail));
        assert_eq!(tail, [8, 9, 10, 0]);
    }

    /// A call that cannot write its bytes, into read-only or unmapped
    /// memory or past the address space, or cannot pay for them, is
    /// refused: nothing written, the cursor and φ7 as they were, and an
    /// unpaid call empties the gas.
    #[test]
    fn a_refused_call_writes_nothing_and_reads_nothing() {
        let bytes = [7u8; 8];
        let mut input = WitnessInput::new(&bytes[..]).unwrap();
        let mut memory = memory();
        for destination in [0x3000, 0x2ffe, 0x8000, (1 << 32) - 2, u64::MAX] {
            let mut gas = 1_000_000;
            let (served, returned) = call(&mut input, &mut memory, &mut gas, destination, 4);
            assert_eq!(served, Err(WitnessFault::Unwritable), "{destination:#x}");
            assert_eq!((returned, input.cursor()), (destination, 0));
        }
        let mut gas = WITNESS_INPUT_GAS + WITNESS_INPUT_BYTE_GAS * 4 - 1;
        let (served, _) = call(&mut input, &mut memory, &mut gas, 0x1000, 4);
        assert_eq!(
            (served, gas, input.cursor()),
            (Err(WitnessFault::OutOfGas), 0, 0)
        );
        let mut first = [0u8; 4];
        assert!(memory.read_bytes_checked(0x1000, &mut first));
        assert_eq!(first, [0; 4]);
        // A call that writes nothing touches no memory, wherever it points.
        let mut gas = 1_000_000;
        let (served, returned) = call(&mut input, &mut memory, &mut gas, u64::MAX, 0);
        assert_eq!((served.map(|read| read.count), returned), (Ok(0), 0));
    }

    /// An input past a work result's cap is refused before any call.
    #[test]
    fn an_oversize_input_is_refused() {
        let bytes = vec![0u8; WITNESS_INPUT_MAX + 1];
        assert!(WitnessInput::new(&bytes[..WITNESS_INPUT_MAX]).is_some());
        assert!(WitnessInput::new(&bytes[..]).is_none());
        assert!(is_kernel_call(WITNESS_INPUT) && is_kernel_call(BLAKE2B_COMPRESS));
        assert!(!is_precompile(WITNESS_INPUT) && price(WITNESS_INPUT).is_none());
    }
}
