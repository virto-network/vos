//! Kitchen-sink test fixture for the http-gateway dispatch tests.
//!
//! Covers the type matrix the gateway needs to round-trip:
//! - String / u32 / bool / Vec<u32> / Vec<String> / unit-reply
//! - One handler that always panics, for the upstream-error path
//! - One handler that takes no args, for the no-args path
//!
//! All handlers are intentionally simple — verify dispatch +
//! arg/reply codec, not any business logic. State on `&mut self`
//! handlers is observable through query-style getters so tests can
//! confirm the mutating dispatch actually reached the actor.

use vos::prelude::*;

#[actor]
#[derive(Default)]
pub struct KitchenSink {
    /// Last value `echo` saw — proves the String arg arrived.
    last_text: String,
    /// Last sum `add` produced — proves typed args arrived.
    last_sum: u32,
    /// `flip` bumps this each call — proves the Bool arg arrived.
    flip_count: u32,
}

#[messages]
impl KitchenSink {
    fn new() -> Self {
        Self::default()
    }

    // ── String round-trip ───────────────────────────────────────

    /// Echo the `text` arg. Reachable via GET (`?text=hi`) — query
    /// values arrive as Str, which matches the `String` handler arg.
    #[msg]
    async fn echo(&mut self, text: String, _ctx: &mut Context<Self>) -> String {
        self.last_text = text.clone();
        text
    }

    /// Read the last text echo recorded. Query handler.
    #[msg]
    async fn last_text(&self, _ctx: &mut Context<Self>) -> String {
        self.last_text.clone()
    }

    // ── Typed-arg paths (POST/PUT/PATCH only — JSON preserves type) ─

    /// Add two u32s. GET cannot drive this: query args are Str, and
    /// the macro's `from_msg` returns None when types don't match,
    /// dropping the message. POST `{"a":2,"b":3}` works.
    #[msg]
    async fn add(&mut self, a: u32, b: u32, _ctx: &mut Context<Self>) -> u32 {
        let sum = a + b;
        self.last_sum = sum;
        sum
    }

    /// Read the last sum. Query handler.
    #[msg]
    async fn last_sum(&self, _ctx: &mut Context<Self>) -> u32 {
        self.last_sum
    }

    /// Bool round-trip. POST `{"b":true}` returns `false`.
    #[msg]
    async fn flip(&mut self, b: bool, _ctx: &mut Context<Self>) -> bool {
        self.flip_count += 1;
        !b
    }

    /// Total times `flip` was called. Query handler.
    #[msg]
    async fn flip_count(&self, _ctx: &mut Context<Self>) -> u32 {
        self.flip_count
    }

    // ── Collection types ────────────────────────────────────────

    /// `Vec<u32>` arg, `u32` reply. POST `{"xs":[1,2,3]}` → 6.
    #[msg]
    async fn sum_list(&self, xs: Vec<u32>, _ctx: &mut Context<Self>) -> u32 {
        xs.iter().sum()
    }

    /// `Vec<String>` arg, `String` reply. POST
    /// `{"parts":["a","b","c"]}` → "a,b,c".
    #[msg]
    async fn concat(&self, parts: Vec<String>, _ctx: &mut Context<Self>) -> String {
        parts.join(",")
    }

    /// `u32` arg, `Vec<u32>` reply. POST `{"n":3}` → [0,1,2].
    #[msg]
    async fn range(&self, n: u32, _ctx: &mut Context<Self>) -> Vec<u32> {
        (0..n).collect()
    }

    /// `String` arg, `Vec<String>` reply. GET `/kitchen/split?s=a,b,c`
    /// → ["a","b","c"]. Reachable via GET because the arg is String.
    #[msg]
    async fn split(&self, s: String, _ctx: &mut Context<Self>) -> Vec<String> {
        s.split(',').map(String::from).collect()
    }

    // ── Edge cases ──────────────────────────────────────────────

    /// No-arg, no-reply (Unit). JSON should render as `null`.
    #[msg]
    async fn ping(&self, _ctx: &mut Context<Self>) {}

    /// Always panics. Exercises the upstream-error path: dispatch
    /// runs, handler panics, host catches and replies empty bytes,
    /// gateway maps to 502.
    #[msg]
    async fn boom(&self, _ctx: &mut Context<Self>) -> u32 {
        panic!("kitchen-sink boom! intentional test panic");
    }
}
