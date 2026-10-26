//! Today's HTTP routes, byte for byte, translated onto the node API by the
//! route table the node's own HTTP runs. An operator route carries the
//! operator's signed envelope in its `Authorization` header: the gateway
//! holds no token and no key that could act for anyone.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};
use vos_api::{ENVELOPE, Operated};
use vos_http::routes::{self, Authorization, Routed};
use vos_http::{Handler, Head, Limits as HttpLimits, Serve, Spawned};
use vos_wire::Encode;
use vos_wire::abi::cap;
use vos_wire::ingress::{OperatorRefusal, Rejection, Response};

use crate::limits::Limits;
use crate::routing::Gateway;

/// A TCP listener on tokio, its streams as futures-io's.
pub struct TokioListener(pub tokio::net::TcpListener);

impl vos_http::Listener for TokioListener {
    type Stream = Compat<tokio::net::TcpStream>;

    async fn accept(&mut self) -> std::io::Result<(Self::Stream, SocketAddr)> {
        let (stream, peer) = self.0.accept().await?;
        let _ = stream.set_nodelay(true);
        Ok((stream.compat(), peer))
    }
}

/// A connection's task on tokio, ended when cancelled.
struct Task(tokio::task::JoinHandle<()>);

impl Spawned for Task {
    fn is_finished(&self) -> bool {
        self.0.is_finished()
    }

    fn cancel(self: Box<Self>) -> vos_http::BoxFuture<()> {
        self.0.abort();
        Box::pin(async move {
            let _ = self.0.await;
        })
    }
}

/// How the gateway serves HTTP.
pub struct Http {
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// The most connections at once, from every address.
    pub connections: usize,
}

/// Serve HTTP on `listener` in front of `gateway` until `stop` resolves.
/// Requests are refused from their heads where they can be (see
/// [`head`]), and at most [`vos_http::LARGE`] install-size bodies are
/// held at once: past them, 503 before the body is read.
pub async fn serve(
    gateway: Arc<Gateway>,
    limits: Arc<Limits>,
    listener: tokio::net::TcpListener,
    http: Http,
    stop: impl Future<Output = ()>,
) {
    let handler: Handler = {
        let gateway = Arc::clone(&gateway);
        Arc::new(move |request| {
            let gateway = Arc::clone(&gateway);
            Box::pin(async move { handle(&gateway, request).await })
        })
    };
    let head: Head = {
        let limits = Arc::clone(&limits);
        Arc::new(move |request| head(&gateway, &limits, request))
    };
    let serve = Serve {
        tls: http.tls,
        handler,
        limits: HttpLimits {
            body: cap::REQUEST + ENVELOPE,
            install: cap::MAX_ELF + ENVELOPE,
            idle: Duration::from_secs(30),
            connections: http.connections,
            large: vos_http::LARGE,
        },
        spawn: Arc::new(|connection| Box::new(Task(tokio::spawn(connection)))),
        admit: Some(Arc::new(move |peer: SocketAddr| {
            limits
                .connect(peer.ip())
                .map(|place| Box::new(place) as Box<dyn Send>)
        })),
        head: Some(head),
    };
    vos_http::serve(TokioListener(listener), serve, stop).await;
}

/// A request's answer from its head, before its body is read: past its
/// address's rate, 429; an operator's route with no envelope, 401, or
/// with one signed for a node behind no upstream, 421. Each is the answer
/// the whole request would get, as none depends on the body.
pub fn head(
    gateway: &Gateway,
    limits: &Limits,
    request: &vos_http::Request,
) -> Option<vos_http::Response> {
    if let Some(peer) = request.peer
        && !limits.request(peer.ip())
    {
        return Some(vos_http::Response::new(429, Vec::new()));
    }
    match routes::route(request) {
        Routed::Operator {
            authorization: Authorization::Operated(credentials),
            inner: Ok(_),
            ..
        } => {
            let node: [u8; 32] = credentials[..32].try_into().expect("32 bytes");
            (!gateway.serves(&node)).then(|| {
                routes::respond(&Response::Rejected(Rejection::Operator(
                    OperatorRefusal::OtherNode,
                )))
            })
        }
        Routed::Operator {
            authorization: Authorization::Operated(_),
            ..
        } => None,
        Routed::Operator { .. } => Some(unauthorized()),
        _ => None,
    }
}

/// An operator's route without an envelope: the gateway takes no token.
fn unauthorized() -> vos_http::Response {
    routes::respond(&Response::Rejected(Rejection::Unauthorized))
}

/// A request's answer: its route's, through a node where it needs one.
pub async fn handle(gateway: &Gateway, request: vos_http::Request) -> vos_http::Response {
    let (kind, body) = match routes::route(&request) {
        Routed::Answer(answer) => return answer,
        Routed::Request { kind, body } => (kind, body),
        Routed::Operator {
            authorization: Authorization::Operated(credentials),
            kind,
            inner,
        } => match inner {
            Ok(inner) => (
                kind,
                Operated::with_credentials(&credentials, inner).encode(),
            ),
            Err(answer) => return answer,
        },
        Routed::Operator { .. } => return unauthorized(),
    };
    let (answered, bytes) = gateway.relay(kind, &body).await;
    routes::answer(answered, &bytes)
}
