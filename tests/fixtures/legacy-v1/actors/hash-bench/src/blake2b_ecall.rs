//! Blake2b precompile benchmark — uses ECALL to invoke blake2b_compress.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

const ECALL_BLAKE2B: u32 = 100;

/// Blake2b IV
static IV: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

/// Call blake2b_compress via ecall precompile.
/// h_ptr: pointer to 64 bytes (8 × u64 LE) — state, overwritten with result
/// m_ptr: pointer to 128 bytes (16 × u64 LE) — message block
/// t: counter (low 64 bits)
/// f: finalization flag (0 or 1)
#[inline(never)]
fn blake2b_compress(h_ptr: *mut u64, m_ptr: *const u64, t: u64, f: u64) {
    unsafe {
        // Convention: φ[10]=h_ptr, φ[11]=m_ptr, φ[12]=t, φ[7]=f
        core::arch::asm!(
            "ecalli {ecall_id}",
            ecall_id = const ECALL_BLAKE2B,
            in("x10") h_ptr,
            in("x11") m_ptr,
            in("x12") t,
            in("x7") f,
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut h = IV;
    let m = [0u64; 16];

    // Hash empty message (1 compression)
    blake2b_compress(h.as_mut_ptr(), m.as_ptr(), 0, 1);

    // Use result to prevent optimization
    core::hint::black_box(h);

    unsafe { core::arch::asm!("unimp") }
    loop {}
}
