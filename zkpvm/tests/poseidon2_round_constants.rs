//! Vetted width-16 M31 Poseidon2 round constants.
//!
//! Generates the round constants for the Poseidon2-M31 permutation
//! (`zkpvm::poseidon2`) via the **canonical Grain LFSR** specified in the
//! POSEIDON paper (eprint 2019/458 §4.1) and reused by Poseidon2 (eprint
//! 2023/323), seeded with our exact parameters. Two upstream references pin the
//! algorithm and the Poseidon2-specific layout:
//!   - daira/pasta-hadeshash `code/generate_parameters_grain.sage` — the Grain
//!     bit generator (80-bit seed, 160-bit warm-up, self-shrinking output,
//!     taps {62,51,38,23,13,0}, n-bit MSB-first with rejection >= p).
//!   - HorizenLabs/poseidon2 `poseidon2_rust_params.sage` — Poseidon2 consumes
//!     `(R_F * t) + R_P` field elements: `R_F` full-round blocks of `t` each
//!     plus ONE per internal round.
//!
//! This is the reference the baked `EXTERNAL_ROUND_CONSTS` /
//! `INTERNAL_ROUND_CONSTS` in `src/poseidon2/mod.rs` are pinned to. Run with
//! `--nocapture` to dump the constants for (re-)baking; the
//! `round_constants_match_baked` test then asserts the module's baked arrays
//! equal the freshly-generated ones (the constants-vector test).
//!
//! Run: `cargo test -p zkpvm --test poseidon2_round_constants -- --nocapture`

use stwo::core::fields::m31::BaseField;
use zkpvm::poseidon2::{FULL_ROUNDS, N_HALF_FULL_ROUNDS, N_PARTIAL_ROUNDS, N_STATE};

const M31_PRIME: u32 = (1 << 31) - 1; // 2^31 - 1 = 2147483647
const FIELD_SIZE_BITS: usize = 31; // ceil(log2(p)) for M31

/// The canonical Grain LFSR round-constant generator for our width-16 M31
/// Poseidon2 parameters (R_F = 8 full, R_P = 14 partial, t = 16, S-box x^5).
/// Returns `(external[8][16], internal[14])` in application order.
fn grain_round_constants() -> ([[u32; N_STATE]; FULL_ROUNDS], [u32; N_PARTIAL_ROUNDS]) {
    // 80-bit Grain seed (MSB-first within each field):
    //   field=1 (2b) | sbox=0 / x^alpha (4b) | n=31 (12b) | t=16 (12b)
    //   | R_F=8 (10b) | R_P=14 (10b) | thirty 1-bits.
    let mut bits: Vec<u8> = Vec::with_capacity(80);
    let mut push = |value: u32, width: usize| {
        for k in (0..width).rev() {
            bits.push(((value >> k) & 1) as u8);
        }
    };
    push(1, 2); // field = 1 (prime field GF(p))
    push(0, 4); // sbox = 0 (x^alpha exponentiation)
    push(FIELD_SIZE_BITS as u32, 12); // n = 31
    push(N_STATE as u32, 12); // t = 16
    push(FULL_ROUNDS as u32, 10); // R_F = 8
    push(N_PARTIAL_ROUNDS as u32, 10); // R_P = 14
    bits.extend([1u8; 30]);
    assert_eq!(bits.len(), 80, "Grain seed must be exactly 80 bits");

    // One LFSR step: feedback = XOR of taps {62,51,38,23,13,0}; shift in.
    fn update(bits: &mut Vec<u8>) -> u8 {
        let new = bits[62] ^ bits[51] ^ bits[38] ^ bits[23] ^ bits[13] ^ bits[0];
        bits.remove(0);
        bits.push(new);
        new
    }

    // Warm-up: discard 160 updates.
    for _ in 0..160 {
        update(&mut bits);
    }

    // Self-shrinking output: read a selector bit; while it is 0, discard a pair
    // (the paired output + the next selector); when the selector is 1, the next
    // update is the output bit.
    fn next_bit(bits: &mut Vec<u8>) -> u8 {
        let mut selector = update(bits);
        while selector == 0 {
            update(bits); // discarded output of the (selector = 0) pair
            selector = update(bits); // next selector
        }
        update(bits) // output paired with selector = 1
    }

    // One field element: `n` bits MSB-first, rejection-sampled to < p.
    fn next_elem(bits: &mut Vec<u8>) -> u32 {
        loop {
            let mut v: u64 = 0;
            for _ in 0..FIELD_SIZE_BITS {
                v = (v << 1) | next_bit(bits) as u64;
            }
            if (v as u32) < M31_PRIME {
                return v as u32;
            }
        }
    }

    // Poseidon2 consumption order: R_F/2 beginning full rounds (t each), then
    // R_P internal rounds (1 each), then R_F/2 ending full rounds (t each).
    let mut external = [[0u32; N_STATE]; FULL_ROUNDS];
    let mut internal = [0u32; N_PARTIAL_ROUNDS];
    for round in external.iter_mut().take(N_HALF_FULL_ROUNDS) {
        for cell in round.iter_mut() {
            *cell = next_elem(&mut bits);
        }
    }
    for cell in internal.iter_mut() {
        *cell = next_elem(&mut bits);
    }
    for round in external.iter_mut().skip(N_HALF_FULL_ROUNDS) {
        for cell in round.iter_mut() {
            *cell = next_elem(&mut bits);
        }
    }
    (external, internal)
}

#[test]
fn dump_round_constants() {
    let (external, internal) = grain_round_constants();
    println!("// === width-16 M31 Poseidon2 round constants (Grain LFSR) ===");
    println!("pub const EXTERNAL_ROUND_CONSTS: [[BaseField; N_STATE]; FULL_ROUNDS] = [");
    for round in &external {
        print!("    [");
        for (i, c) in round.iter().enumerate() {
            if i > 0 {
                print!(", ");
            }
            print!("BaseField::from_u32_unchecked({c})");
        }
        println!("],");
    }
    println!("];");
    println!("pub const INTERNAL_ROUND_CONSTS: [BaseField; N_PARTIAL_ROUNDS] = [");
    print!("    ");
    for c in &internal {
        print!("BaseField::from_u32_unchecked({c}), ");
    }
    println!();
    println!("];");
}

#[test]
fn grain_is_deterministic_and_well_formed() {
    let (e1, i1) = grain_round_constants();
    let (e2, i2) = grain_round_constants();
    assert_eq!(e1, e2, "generator must be deterministic (external)");
    assert_eq!(i1, i2, "generator must be deterministic (internal)");

    // Every constant is a canonical M31 (< p).
    let all: Vec<u32> = e1.iter().flatten().copied().chain(i1).collect();
    assert_eq!(all.len(), FULL_ROUNDS * N_STATE + N_PARTIAL_ROUNDS); // 142
    for &c in &all {
        assert!(c < M31_PRIME, "constant {c} not a canonical M31");
    }

    // Non-degenerate: the placeholder `1234` set was all-equal; real constants
    // must be (overwhelmingly) distinct and not the placeholder.
    let mut sorted = all.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert!(
        sorted.len() >= all.len() - 1,
        "round constants must be essentially all-distinct (got {} unique of {})",
        sorted.len(),
        all.len()
    );
    assert!(
        all.iter().any(|&c| c != 1234),
        "round constants must not be the placeholder 1234"
    );
}

#[test]
fn round_constants_match_baked() {
    // Constants-vector test: the module's baked arrays MUST equal the canonical
    // Grain output. If this fails, either the module drifted or the generator
    // changed — re-run `dump_round_constants` and re-bake (and remember the
    // {C_0,C_1} allowlist is a function of these, so a change forces a re-bake).
    let (external, internal) = grain_round_constants();
    let baked_external = zkpvm::poseidon2::EXTERNAL_ROUND_CONSTS;
    let baked_internal = zkpvm::poseidon2::INTERNAL_ROUND_CONSTS;
    for (r, round) in external.iter().enumerate() {
        for (i, &c) in round.iter().enumerate() {
            assert_eq!(
                baked_external[r][i],
                BaseField::from_u32_unchecked(c),
                "EXTERNAL_ROUND_CONSTS[{r}][{i}] drifted from the Grain reference"
            );
        }
    }
    for (r, &c) in internal.iter().enumerate() {
        assert_eq!(
            baked_internal[r],
            BaseField::from_u32_unchecked(c),
            "INTERNAL_ROUND_CONSTS[{r}] drifted from the Grain reference"
        );
    }
}
