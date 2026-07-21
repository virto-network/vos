//! Diverse workload — tests various operations to find prover-trusted gaps.

#![no_std]
#![no_main]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

#[inline(never)]
fn compute(input: &[i64; 16]) -> i64 {
    let mut acc: i64 = 0;
    let mut min: i64 = i64::MAX;
    let mut max: i64 = i64::MIN;
    let mut i = 0;
    while i < 16 {
        let x = input[i];
        if x < 0 { acc -= x; } else { acc += x; }  // abs sum
        if x < min { min = x; }
        if x > max { max = x; }
        // count set bits
        let mut bits = 0u32;
        let mut y = x as u64;
        while y != 0 {
            bits += (y & 1) as u32;
            y >>= 1;
        }
        acc = acc.wrapping_add(bits as i64);
        i += 1;
    }
    acc.wrapping_add(max).wrapping_sub(min)
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut input: [i64; 16] = [0; 16];
    // Prevent const folding
    let mut i = 0i64;
    while i < 16 {
        input[i as usize] = (i * 7 - 40).wrapping_mul(core::hint::black_box(1));
        i += 1;
    }
    let result = compute(&input);
    core::hint::black_box(result);
    unsafe { core::arch::asm!("unimp") }
    loop {}
}
