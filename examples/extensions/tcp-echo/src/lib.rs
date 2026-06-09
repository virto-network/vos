//! tcp-echo — a transport-mode (concurrency) guard.
//!
//! A **transport-mode** extension: instead of `#[msg]` handlers driven N=1,
//! it declares a single `handle_connection(&self, ctx, conn_id)`. The HOST
//! owns the listener + accept loop (bound from `ExtensionConfig::serves`) and
//! spawns one connection task per accept on a single cooperative executor
//! thread — so many connections interleave, all sharing `&self` (immutable;
//! interior mutability via `RefCell`/`Cell` if needed, never `Mutex`/`Arc`).
//!
//! This handler is a true streaming echo: it loops `read → write` until the
//! peer hits EOF, then closes. Because the receiver is `&self` (shared), N of
//! these run concurrently without aliasing — the soundness invariant the host
//! upholds: a transport extension has NO `&mut self` handler; the macro
//! rejects `#[msg]` when `handle_connection` is present.

use vos::prelude::*;

#[actor(kind = "transport")]
struct TcpEcho {}

#[messages]
impl TcpEcho {
    fn new() -> Self {
        TcpEcho {}
    }

    /// Echo every byte read on `conn_id` back to the peer until EOF, then
    /// close. `&self` (shared) — the host runs one of these per connection,
    /// concurrently, all sharing this actor.
    async fn handle_connection(&self, ctx: &mut Context<Self>, conn_id: u64) {
        loop {
            match ctx.read(conn_id, 4096).await {
                // `Some(empty)` is EOF (peer closed); `None` is an error.
                Some(data) if !data.is_empty() => {
                    if ctx.write(conn_id, &data).await.is_none() {
                        break; // write error → give up on this conn
                    }
                }
                _ => break,
            }
        }
        ctx.close(conn_id).await;
    }
}
