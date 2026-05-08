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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::sync::oneshot;
use vos::log;

use crate::{handle_admin, IoResult, Inner, Job, Request, Response};

/// Build a QUIC endpoint listening on `addr` with a freshly-minted
/// self-signed cert for `localhost`. ALPN advertises `h3`.
pub(crate) fn build_endpoint(addr: SocketAddr) -> IoResult<quinn::Endpoint> {
    // rustls 0.23 with the ring provider needs the global crypto
    // provider installed before any cert work. Idempotent — safe
    // to call repeatedly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| format!("rcgen self-signed cert: {e}"))?;
    let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(
            cert.key_pair.serialize_der(),
        ),
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

/// Accept loop. Runs inside the gateway's tokio runtime; one tokio
/// task per QUIC connection, one task per request stream.
pub(crate) async fn accept_loop(
    endpoint: quinn::Endpoint,
    job_tx: mpsc::Sender<Job>,
    inner: Arc<Inner>,
) {
    loop {
        if inner.stop.load(Ordering::Relaxed) {
            endpoint.close(0u32.into(), b"gateway-stop");
            return;
        }
        let accept =
            tokio::time::timeout(Duration::from_millis(200), endpoint.accept()).await;
        let incoming = match accept {
            Ok(Some(i)) => i,
            Ok(None) => return, // endpoint closed
            Err(_) => continue, // timeout — re-check stop
        };
        let job_tx = job_tx.clone();
        let inner = inner.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(c) => c,
                Err(e) => {
                    log::debug!("http-gateway: h3 handshake: {e}");
                    return;
                }
            };
            handle_connection(conn, job_tx, inner).await;
        });
    }
}

async fn handle_connection(
    quinn_conn: quinn::Connection,
    job_tx: mpsc::Sender<Job>,
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
            Ok(None) => break,
            Err(e) => {
                // ConnectionError flavors include peer-initiated graceful
                // shutdown — debug-only logging.
                log::debug!("http-gateway: h3 accept: {e}");
                break;
            }
        }
    }
}

async fn handle_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    job_tx: mpsc::Sender<Job>,
    inner: Arc<Inner>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (req, mut stream) = resolver.resolve_request().await?;

    // Drain the request body. h3 hands us `impl Buf` chunks, which we
    // copy into a Vec<u8>. Bounded only by client behavior — same
    // posture as the hyper side.
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        let mut buf = vec![0u8; remaining];
        chunk.copy_to_slice(&mut buf);
        body.extend_from_slice(&buf);
    }

    let our_req = Request {
        method: req.method().as_str().to_string(),
        path: req.uri().path().to_string(),
        query: req.uri().query().unwrap_or("").to_string(),
        body,
    };

    let response = if let Some(r) = handle_admin(&our_req, &inner) {
        r
    } else {
        let (resp_tx, resp_rx) = oneshot::channel::<Response>();
        if job_tx.send(Job { request: our_req, resp_tx }).is_err() {
            Response::text(503, "gateway stopped")
        } else {
            resp_rx
                .await
                .unwrap_or_else(|_| Response::text(500, "no response from actor"))
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
