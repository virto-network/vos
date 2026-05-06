//! Regression actor for the JAVM ScaledAdd self-aliasing bug.
//!
//! Pre-fix, `Vec::push` on the no-grow path wrote the previous
//! call's value: the recompiler peephole that fused
//! `slli a1,s0,2; add a0,a0,a1; sw a1,0(a0)` into a scaled-index
//! store re-applied the stride at emit time when the `add`'s
//! destination aliased its base operand. See the matching fix in
//! `jar/grey/crates/javm/src/recompiler/codegen.rs::update_reg_defs`
//! and the test `pushy_vec_push_grows_correctly` in
//! `crates/vos/tests/elf_integration.rs`.

#![cfg_attr(any(target_arch = "riscv64", target_arch = "wasm32"), no_std)]

use vos::prelude::*;

#[actor]
pub struct Pushy {
    items: Vec<u32>,
}

#[messages]
impl Pushy {
    fn new() -> Self {
        Pushy { items: Vec::new() }
    }

    /// Pushes three values in a single handler call. The second
    /// and third pushes hit the no-grow path that triggered the
    /// scaled-add aliasing bug. With the fix, items ends as
    /// `[11, 22, 33]`; without it, `[11, 0, 22]`.
    #[msg]
    async fn prove_grow(&mut self) {
        self.items.push(11);
        self.items.push(22);
        self.items.push(33);
    }

    /// Pushes a single value. Used to drive two sequential
    /// invokes (each of which warm-restarts and re-deserializes
    /// the actor) and observe whether the post-restart push
    /// still sees the bug.
    #[msg]
    async fn push(&mut self, val: u32) {
        self.items.push(val);
    }

    #[msg]
    async fn get(&self) -> Vec<u32> {
        self.items.clone()
    }
}
