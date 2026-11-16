//! VOS's HTTP front: a request and its answer ([`request`]), the route
//! table ([`routes`]) that translates VOS's HTTP routes onto the node API
//! and back, and public TLS ([`tls`]), which the node API's client reads;
//! and with the `server` feature, the gateway's, a small HTTP/1.1 server on
//! tokio (`server`).

pub mod request;
pub mod routes;
#[cfg(feature = "server")]
pub mod server;
pub mod tls;

pub use request::{Large, MAX_HEAD, Request, Response, content_length};
#[cfg(feature = "server")]
pub use server::{
    Admit, BoxFuture, CREDENTIALED_LARGE, Handler, Head, LARGE, Limits, Serve, serve,
};
