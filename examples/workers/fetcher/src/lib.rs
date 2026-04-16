//! Fetcher worker — demonstrates ctx.fetch() for HTTP requests.
//!
//! Same source compiles as a native worker (.so) AND a WASM module.
//! The fetch effect is handled by the host: ureq for native, the
//! browser's fetch() for WASM.

#![cfg_attr(target_arch = "wasm32", no_std)]

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

use vos::{actor, messages, effects::FetchRequest};

#[actor]
struct Fetcher;

#[messages]
impl Fetcher {
    fn new() -> Self {
        Fetcher
    }

    /// Fetch a URL and return the response body as a string.
    /// Returns the body text on 2xx, "ERROR: <status>" otherwise.
    #[msg]
    async fn get(&mut self, url: String, ctx: &mut Context<Self>) -> String {
        let resp = ctx.fetch(FetchRequest::get(url)).await;
        if resp.ok() {
            resp.text().unwrap_or("(non-utf8 body)").into()
        } else {
            format!("ERROR {}: {}", resp.status, resp.text().unwrap_or(""))
        }
    }

    /// Fetch a URL and return the HTTP status code.
    #[msg]
    async fn status(&mut self, url: String, ctx: &mut Context<Self>) -> u32 {
        let resp = ctx.fetch(FetchRequest::get(url)).await;
        resp.status as u32
    }
}
