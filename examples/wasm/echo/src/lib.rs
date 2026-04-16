//! Echo WASM actor — same DSL as PVM/worker, compiled to wasm32.
//!
//! Build:
//!   cargo build -p echo-wasm --target wasm32-unknown-unknown --release
//!
//! Output: target/wasm32-unknown-unknown/release/echo_wasm.wasm

#![no_std]

#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

use vos::{actor, messages};

#[actor]
struct EchoWasm {
    prefix: alloc::string::String,
    count: u32,
}

#[messages]
impl EchoWasm {
    fn new(prefix: String) -> Self {
        EchoWasm { prefix, count: 0 }
    }

    #[msg]
    async fn echo(&mut self, text: String, _ctx: &mut Context<Self>) -> String {
        self.count += 1;
        format!("[{}] echo #{}: {text}", self.prefix, self.count)
    }

    #[msg]
    async fn count(&self, _ctx: &mut Context<Self>) -> u32 {
        self.count
    }
}

// Provide a panic handler for no_std WASM.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}
