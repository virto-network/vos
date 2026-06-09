//! byte-echo — a minimal byte-stream extension example.
//!
//! A native extension that drives raw TCP through the host reactor
//! (`ctx.listen` / `accept` / `read` / `write` / `close`). The `serve`
//! handler binds an address, accepts ONE connection, echoes a single read
//! back, and closes it — exercising the full byte-stream effect round-trip
//! on the host's `smol::Async` reactor from a single actor-mode task.
//!
//! Concurrency across many connections is the host's concern (it owns the
//! accept loop + a spawned task per connection); this example exercises the
//! effect plumbing + reactor, not interleaving.

use vos::prelude::*;

#[actor]
struct ByteEcho {}

#[messages]
impl ByteEcho {
    fn new() -> Self {
        ByteEcho {}
    }

    /// Bind `addr` (e.g. `"127.0.0.1:8080"`), accept one connection, echo a
    /// single read back to the peer, then close. Returns the number of bytes
    /// echoed (0 on any error).
    #[msg]
    async fn serve(&mut self, addr: String, ctx: &mut Context<Self>) -> u32 {
        let Some(lid) = ctx.listen(&addr).await else {
            log::error!("byte-echo: listen {addr} failed");
            return 0;
        };
        let Some(cid) = ctx.accept(lid).await else {
            log::error!("byte-echo: accept failed");
            return 0;
        };
        let Some(data) = ctx.read(cid, 1024).await else {
            log::error!("byte-echo: read failed");
            return 0;
        };
        log::info!("byte-echo: echoing {} bytes", data.len());
        let n = ctx.write(cid, &data).await.unwrap_or(0);
        ctx.close(cid).await;
        n as u32
    }

    /// Same as [`serve`], but over a host-terminated TLS listener
    /// (`ctx.listen_tls`). The handler still sees plaintext — TLS is
    /// transparent. Requires the host to have a cert configured for this
    /// extension (`ExtensionConfig::tls_pem`).
    #[msg]
    async fn serve_tls(&mut self, addr: String, ctx: &mut Context<Self>) -> u32 {
        let Some(lid) = ctx.listen_tls(&addr).await else {
            log::error!("byte-echo: listen_tls {addr} failed");
            return 0;
        };
        let Some(cid) = ctx.accept(lid).await else {
            log::error!("byte-echo: accept (tls) failed");
            return 0;
        };
        let Some(data) = ctx.read(cid, 1024).await else {
            log::error!("byte-echo: read (tls) failed");
            return 0;
        };
        log::info!("byte-echo: echoing {} bytes over TLS", data.len());
        let n = ctx.write(cid, &data).await.unwrap_or(0);
        ctx.close(cid).await;
        n as u32
    }
}
