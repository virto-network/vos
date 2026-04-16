//! Fetcher worker — demonstrates ctx.fetch() for HTTP requests.
//!
//! Same source compiles as a native worker (.so) AND a WASM module.
//! The fetch effect is handled by the host: ureq for native, the
//! browser's fetch() for WASM. WASM bootstrap (allocator + panic
//! handler) lives in vos behind the `wasm-bootstrap` feature.

#![cfg_attr(target_arch = "wasm32", no_std)]

use vos::{actor, messages};

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
        let resp = ctx.fetch(url).await;
        if resp.ok() {
            resp.text().unwrap_or("(non-utf8 body)").into()
        } else {
            format!("ERROR {}: {}", resp.status, resp.text().unwrap_or(""))
        }
    }

    /// Fetch a URL and return the HTTP status code.
    #[msg]
    async fn status(&mut self, url: String, ctx: &mut Context<Self>) -> u32 {
        let resp = ctx.fetch(url).await;
        resp.status as u32
    }

    /// POST a JSON body to a URL with an Authorization header.
    /// Demonstrates the builder chain.
    #[msg]
    async fn post_json(
        &mut self,
        url: String,
        token: String,
        body: String,
        ctx: &mut Context<Self>,
    ) -> String {
        let resp = ctx.fetch(url)
            .post()
            .header("Authorization", format!("Bearer {token}"))
            .json(body)
            .await;
        format!("{}: {}", resp.status, resp.text().unwrap_or(""))
    }
}
