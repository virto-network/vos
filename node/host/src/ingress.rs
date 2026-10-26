//! The node's own HTTP: today's routes translated onto the node API by
//! `vos-http`'s table, the gateway's. An operator route carries a signed
//! envelope in its header, as through the gateway, or the node's bearer
//! token.

use std::sync::Arc;
use std::time::Duration;

use subtle::ConstantTimeEq;
use vos_api::{ENVELOPE, Operated};
use vos_http::routes::{self, Authorization, Routed};
use vos_http::{Handler, Limits, Serve, Spawned};
use vos_wire::Encode;
use vos_wire::abi::cap;
use vos_wire::ingress::{Rejection, Response};

use crate::api::{Api, Via};

/// The most an install's body may hold: a package's ELF, at the most a
/// derivation reads, and its envelope.
const MAX_INSTALL: usize = cap::MAX_ELF + ENVELOPE;

/// A connection's task on the node's runtime.
struct Task(smol::Task<()>);

impl Spawned for Task {
    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    fn cancel(self: Box<Self>) -> vos_http::BoxFuture<()> {
        Box::pin(async move {
            self.0.cancel().await;
        })
    }
}

/// Serve the HTTP ingress on `listener` until `stop` resolves, then end
/// every connection.
pub(crate) async fn serve(
    api: Arc<Api>,
    token: [u8; 32],
    listener: smol::net::TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    stop: smol::channel::Receiver<()>,
) {
    let runtime = Arc::clone(&api.inner.runtime);
    let limits = Limits {
        body: cap::REQUEST + ENVELOPE,
        install: MAX_INSTALL,
        idle: Duration::from_secs(30),
        connections: api.inner.settings.ingress_connections,
    };
    let handler: Handler = Arc::new(move |request| {
        let api = Arc::clone(&api);
        Box::pin(async move { handle(&api, &token, request).await })
    });
    let serve = Serve {
        tls,
        handler,
        limits,
        spawn: Arc::new(move |connection| Box::new(Task(runtime.spawn(connection)))),
        admit: None,
    };
    vos_http::serve(listener, serve, async {
        let _ = stop.recv().await;
    })
    .await;
}

async fn handle(api: &Api, token: &[u8; 32], request: vos_http::Request) -> vos_http::Response {
    let (kind, body, via) = match routes::route(&request) {
        Routed::Answer(answer) => return answer,
        Routed::Request { kind, body } => (kind, body, Via::Http),
        Routed::Operator {
            authorization,
            kind,
            inner,
        } => {
            let unauthorized = || routes::respond(&Response::Rejected(Rejection::Unauthorized));
            let via = match &authorization {
                Authorization::Operated(_) => Via::Http,
                bearer if admitted(bearer, token) => Via::Token,
                _ => return unauthorized(),
            };
            let inner = match inner {
                Ok(inner) => inner,
                Err(answer) => return answer,
            };
            let body = match authorization {
                Authorization::Operated(credentials) => {
                    Operated::with_credentials(&credentials, inner).encode()
                }
                _ => inner,
            };
            (kind, body, via)
        }
    };
    let answer = api.handle(kind, body, via).await;
    routes::answer(kind as u16, &answer)
}

/// Whether the request carries the operator's token.
fn admitted(authorization: &Authorization, token: &[u8; 32]) -> bool {
    let Authorization::Bearer(given) = authorization else {
        return false;
    };
    std::str::from_utf8(given)
        .ok()
        .and_then(|given| crate::hex32(given.trim()))
        .is_some_and(|given| bool::from(given.ct_eq(token)))
}
