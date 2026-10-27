//! VOS's HTTP front: a small HTTP/1.1 server on any runtime
//! ([`server`]), its public TLS ([`tls`]), and the route table
//! ([`routes`]) that translates today's HTTP routes onto the node API,
//! which the node's own HTTP and the gateway share.

pub mod routes;
pub mod server;
pub mod tls;

pub use server::{
    Admit, BoxFuture, CREDENTIALED_LARGE, Handler, Head, LARGE, Limits, Listener, MAX_HEAD,
    Request, Response, Serve, Spawn, Spawned, content_length, serve,
};
