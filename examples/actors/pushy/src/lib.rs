// Regression actor for the JAVM ScaledAdd self-aliasing bug.
//
// Pre-fix, `Vec::push` on the no-grow path wrote the previous
// call's value: the recompiler peephole that fused
// `slli a1,s0,2; add a0,a0,a1; sw a1,0(a0)` into a scaled-index
// store re-applied the stride at emit time when the `add`'s
// destination aliased its base operand. Driven by
// `pushy_vec_push_grows_correctly` in
// `crates/vos/tests/elf_integration.rs`; fix lives in
// `jar/grey/crates/javm/src/recompiler/codegen.rs::update_reg_defs`.
//
// `no_std` is injected via `-Zcrate-attr` in `.cargo/config.toml`
// for the riscv64em-javm and wasm32 targets, so we don't repeat
// it here. Inner attributes (`#![...]`) and inner doc comments
// (`//!`) are also avoided so `src/main.rs` can `include!` this
// file without rustc complaining about attribute positions.

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

    #[msg]
    async fn prove_grow(&mut self) {
        self.items.push(11);
        self.items.push(22);
        self.items.push(33);
    }

    #[msg]
    async fn push(&mut self, val: u32) {
        self.items.push(val);
    }

    #[msg]
    async fn get(&self) -> Vec<u32> {
        self.items.clone()
    }
}
