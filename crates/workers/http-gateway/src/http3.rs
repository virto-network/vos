//! HTTP/3 server (gated on `feature = "http3"`).
//!
//! Mirrors the hyper-side flow: each h3 request stream becomes our
//! internal `Request`, runs the admin shortcut or pushes a `Job` into
//! the same mpsc the hyper side feeds, and writes the `Response` back
//! across the QUIC bidi stream.
//!
//! Cert handling: today we only auto-generate a self-signed cert via
//! `rcgen` for `localhost`. A future iteration will accept PEM paths
//! (or ACME) once we have an operator story.

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::sync::{Semaphore, oneshot};
use vos::log;

use crate::HttpGateway;
use crate::config;
use crate::limits::{MAX_BODY_BYTES, MAX_CONCURRENT_CONNS, MAX_REQUEST_HEADERS};
use crate::routing::handle_admin;
use crate::runtime::{self, serve_with};
use crate::state::Inner;
use crate::types::{IoResult, Job, Request, Response};

/// Actor-side entry for `serve_h3` when the feature is on.
pub(crate) async fn serve_h3_impl(
    port: u16,
    ctx: &mut vos::Context<HttpGateway>,
) -> String {
    serve_with(port, "udp/h3", spawn, ctx).await
}

fn spawn(
    port: u16,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) -> IoResult<()> {
    let addr = SocketAddr::new(config::bind_ip(), port);
    runtime::spawn_on_thread(format!("http-gateway-h3:{port}"), move |ready_tx| async move {
        let endpoint = match build_endpoint(addr) {
            Ok(ep) => ep,
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        let _ = ready_tx.send(Ok(()));
        accept_loop(endpoint, job_tx, inner).await;
    })
}

/// Build a QUIC endpoint listening on `addr` with a freshly-minted
/// self-signed cert for `localhost`. ALPN advertises `h3`.
fn build_endpoint(addr: SocketAddr) -> IoResult<quinn::Endpoint> {
    // rustls 0.23 with the ring provider needs the global crypto
    // provider installed before any cert work. Idempotent — safe to
    // call repeatedly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| format!("rcgen self-signed cert: {e}"))?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
    );

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("rustls config: {e}"))?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| format!("quinn rustls config: {e}"))?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    quinn::Endpoint::server(server_config, addr)
        .map_err(|e| format!("quinn endpoint bind {addr}: {e}"))
}

async fn accept_loop(
    endpoint: quinn::Endpoint,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) {
    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));

    while !inner.stop.load(Ordering::Relaxed) {
        let accept = tokio::time::timeout(Duration::from_millis(200), endpoint.accept()).await;
        let incoming = match accept {
            Ok(Some(i)) => i,
            Ok(None) => break, // endpoint closed
            Err(_) => continue, // timeout — re-check stop
        };
        let permit = match conn_sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                log::warn!("http-gateway: h3 conn limit ({MAX_CONCURRENT_CONNS}) hit; refusing");
                incoming.refuse();
                continue;
            }
        };
        let job_tx = job_tx.clone();
        let inner = inner.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match incoming.await {
                Ok(conn) => handle_connection(conn, job_tx, inner).await,
                Err(e) => log::debug!("http-gateway: h3 handshake: {e}"),
            }
        });
    }
    endpoint.close(0u32.into(), b"gateway-stop");
}

async fn handle_connection(
    quinn_conn: quinn::Connection,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) {
    let mut h3_conn =
        match h3::server::Connection::new(h3_quinn::Connection::new(quinn_conn)).await {
            Ok(c) => c,
            Err(e) => {
                log::debug!("http-gateway: h3 init: {e}");
                return;
            }
        };
    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let job_tx = job_tx.clone();
                let inner = inner.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_request(resolver, job_tx, inner).await {
                        log::debug!("http-gateway: h3 stream: {e}");
                    }
                });
            }
            // ConnectionError variants include peer-initiated graceful
            // shutdown — debug logging only.
            Ok(None) => break,
            Err(e) => {
                log::debug!("http-gateway: h3 accept: {e}");
                break;
            }
        }
    }
}

async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let (req, mut stream) = resolver.resolve_request().await?;

    // Drain the body chunk-by-chunk, refusing once the running total
    // crosses the cap. Mirrors the hyper-side `Limited` posture.
    let mut body = Vec::new();
    let mut over_limit = false;
    while let Some(mut chunk) = stream.recv_data().await? {
        if over_limit {
            continue; // drain remaining chunks so the peer's flow-control unblocks
        }
        if body.len().saturating_add(chunk.remaining()) > MAX_BODY_BYTES {
            over_limit = true;
            continue;
        }
        let mut buf = vec![0u8; chunk.remaining()];
        chunk.copy_to_slice(&mut buf);
        body.extend_from_slice(&buf);
    }

    let response = if over_limit {
        Response::text(413, format!("body exceeds {MAX_BODY_BYTES} bytes"))
    } else {
        let headers: Vec<(String, String)> = req
            .headers()
            .iter()
            .take(MAX_REQUEST_HEADERS)
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|v| (name.as_str().to_ascii_lowercase(), v.to_string()))
            })
            .collect();
        let our_req = Request {
            method: req.method().as_str().to_string(),
            path: req.uri().path().to_string(),
            query: req.uri().query().unwrap_or("").to_string(),
            headers,
            body,
        };

        if let Some(r) = handle_admin(&our_req, &inner) {
            r
        } else {
            let (resp_tx, resp_rx) = oneshot::channel::<Response>();
            match job_tx.try_send(Job { request: our_req, resp_tx }) {
                Ok(()) => resp_rx
                    .await
                    .unwrap_or_else(|_| Response::text(500, "no response from actor")),
                Err(mpsc::TrySendError::Full(_)) => {
                    Response::text(503, "gateway saturated; retry")
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    Response::text(503, "gateway stopped")
                }
            }
        }
    };

    let h3_resp = http::Response::builder()
        .status(response.status)
        .header("content-type", response.content_type)
        .body(())?;
    stream.send_response(h3_resp).await?;
    if !response.body.is_empty() {
        stream.send_data(Bytes::from(response.body)).await?;
    }
    stream.finish().await?;
    Ok(())
}
