//! Attestable methods whose kernels reach what a derivation must follow:
//! a precompile and the constants of its software fallback, a match lowered
//! to a jump table of relative entries (`R_RISCV_ADD32` and `_SUB32` pairs),
//! and calls through a vtable, each run as a kernel derived from this
//! actor's ELF.

#![no_std]

extern crate alloc;

use alloc::boxed::Box;

use vos_sdk::prelude::*;

#[actor]
pub struct Kernels {
    checks: u64,
}

/// A shape, called through its vtable.
trait Shape {
    fn area(&self, scale: u64) -> u64;
}

struct Square(u64);
struct Line(u64);
struct Ring(u64, u64);

impl Shape for Square {
    fn area(&self, scale: u64) -> u64 {
        self.0.wrapping_mul(self.0).wrapping_mul(scale)
    }
}

impl Shape for Line {
    fn area(&self, scale: u64) -> u64 {
        self.0.wrapping_mul(scale).wrapping_add(1)
    }
}

impl Shape for Ring {
    fn area(&self, scale: u64) -> u64 {
        self.0.wrapping_sub(self.1).wrapping_mul(scale) ^ 0x5a
    }
}

/// A match's arms, each a call of its own, so the match lowers to a jump
/// table: `arm(k)` mixes `x` with the `k`th constant.
macro_rules! arms {
    ($($name:ident = $constant:literal, $factor:literal;)*) => {
        $(
            #[inline(never)]
            fn $name(x: u64) -> u64 {
                (x ^ $constant).wrapping_mul($factor)
            }
        )*
    };
}

arms! {
    arm0 = 0x1111, 3;
    arm1 = 0x2345, 5;
    arm2 = 0x3579, 7;
    arm3 = 0x4bcd, 9;
    arm4 = 0x5e0f, 11;
    arm5 = 0x6a1b, 13;
    arm6 = 0x7c2d, 15;
    arm7 = 0x8e3f, 17;
    arm8 = 0x9041, 19;
    arm9 = 0xa253, 21;
    arm10 = 0xb465, 23;
    arm11 = 0xc677, 25;
}

/// A shape for `side`, chosen by it.
#[inline(never)]
fn shape(side: u64) -> Box<dyn Shape> {
    match side % 3 {
        0 => Box::new(Square(side)),
        1 => Box::new(Line(side)),
        _ => Box::new(Ring(side, side / 2)),
    }
}

#[messages]
impl Kernels {
    pub fn new() -> Self {
        Self { checks: 0 }
    }

    /// Attest each kernel on `values`: their outputs.
    #[msg]
    pub async fn check(
        &mut self,
        ctx: &mut Command<Self>,
        values: Vec<u64>,
    ) -> (Vec<u8>, u64, u64) {
        let digest = ctx
            .attest(kernels::Digest {
                values: values.clone(),
            })
            .await
            .unwrap_or_default();
        let named = ctx
            .attest(kernels::Named {
                index: values.len() as u32,
            })
            .await
            .unwrap_or(0);
        let areas = ctx
            .attest(kernels::Areas { sides: values })
            .await
            .unwrap_or(0);
        self.checks += 1;
        (digest, named, areas)
    }

    /// BLAKE2b-256 of the values, by the precompile.
    #[attestable]
    pub fn digest(values: Vec<u64>) -> Vec<u8> {
        let bytes: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        vos_pvm_precompiles::blake2b_hash::<32>(b"kernels", &[&bytes]).to_vec()
    }

    /// A word a match of calls computes, which a jump table lowers.
    #[attestable]
    pub fn named(index: u32) -> u64 {
        let x = u64::from(index);
        match core::hint::black_box(index) % 12 {
            0 => arm0(x),
            1 => arm1(x),
            2 => arm2(x),
            3 => arm3(x),
            4 => arm4(x),
            5 => arm5(x),
            6 => arm6(x),
            7 => arm7(x),
            8 => arm8(x),
            9 => arm9(x),
            10 => arm10(x),
            _ => arm11(x),
        }
    }

    /// The areas of a shape per side, each through its vtable, added up.
    #[attestable]
    pub fn areas(sides: Vec<u64>) -> u64 {
        sides
            .iter()
            .map(|&side| shape(side).area(side + 1))
            .fold(0u64, u64::wrapping_add)
    }
}
