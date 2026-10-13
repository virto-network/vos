//! Three nodes on a hub, each serving its ingress over HTTP: requests
//! applied exactly once through failures, and the calls and queries a
//! follower forwards, holds back or reads.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod exactly_once;
mod forwarding;
mod harness;
