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
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use bytes::{Buf, Bytes};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::Semaphore;
use vos::log;

use crate::config;
use crate::limits::{
    H3_BODY_CHUNK_TIMEOUT, MAX_BODY_BYTES, MAX_CONCURRENT_CONNS, MAX_REQUEST_HEADERS,
    MAX_STREAMS_PER_CONN,
};
use crate::routing::{Policy, dispatch_request};
use crate::runtime::{self, InFlightGuard, drain_in_flight};
use crate::state::Inner;
use crate::types::{IoResult, Job, Request, Response};

/// Spawn the h3 protocol thread. Used by the gateway's `run` body
/// (Phase 4 follow-up) when built with `feature = "http3"` — feeds
/// the same Job mpsc the hyper (h1+h2c) thread feeds, so the drain
/// loop on the gateway's run thread services both protocols off a
/// single queue.
pub(crate) fn spawn(
    port: u16,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) -> IoResult<thread::JoinHandle<()>> {
    let addr = SocketAddr::new(config::bind_ip(), port);
    runtime::spawn_on_thread(
        format!("http-gateway-h3:{port}"),
        move |ready_tx| async move {
            let endpoint = match build_endpoint(addr) {
                Ok(ep) => ep,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(()));
            accept_loop(endpoint, job_tx, inner).await;
        },
    )
}

/// Build a QUIC endpoint listening on `addr`. Uses the operator-
/// supplied cert/key when `HTTP_GATEWAY_TLS_CERT` and
/// `HTTP_GATEWAY_TLS_KEY` are both set; otherwise falls back to a
/// freshly-minted self-signed cert for `localhost` and logs a WARN
/// (dev only). ALPN advertises `h3`.
fn build_endpoint(addr: SocketAddr) -> IoResult<quinn::Endpoint> {
    // rustls 0.23 with the ring provider needs the global crypto
    // provider installed before any cert work. Idempotent — safe to
    // call repeatedly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (cert_chain, key_der) = match config::tls_paths() {
        Some((cert_path, key_path)) => load_pem(cert_path, key_path)?,
        None => {
            log::warn!(
                "http-gateway: no HTTP_GATEWAY_TLS_CERT/KEY — using self-signed `localhost` cert (dev only)"
            );
            self_signed()?
        }
    };

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
        .map_err(|e| format!("rustls config: {e}"))?;
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
        .map_err(|e| format!("quinn rustls config: {e}"))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(MAX_STREAMS_PER_CONN.into());
    server_config.transport_config(Arc::new(transport));

    quinn::Endpoint::server(server_config, addr)
        .map_err(|e| format!("quinn endpoint bind {addr}: {e}"))
}

fn self_signed() -> IoResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| format!("rcgen self-signed cert: {e}"))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        cert.key_pair.serialize_der(),
    ));
    Ok((vec![cert_der], key_der))
}

fn load_pem(
    cert_path: &str,
    key_path: &str,
) -> IoResult<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file = File::open(cert_path).map_err(|e| format!("open cert {cert_path}: {e}"))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<core::result::Result<_, _>>()
        .map_err(|e| format!("parse cert {cert_path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certs in {cert_path}"));
    }

    let key_file = File::open(key_path).map_err(|e| format!("open key {key_path}: {e}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|e| format!("parse key {key_path}: {e}"))?
        .ok_or_else(|| format!("no private key in {key_path}"))?;

    log::info!(
        "http-gateway: loaded TLS cert chain ({} certs) from {cert_path}",
        certs.len()
    );
    Ok((certs, key))
}

async fn accept_loop(endpoint: quinn::Endpoint, job_tx: mpsc::SyncSender<Job>, inner: Arc<Inner>) {
    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNS));

    while !inner.stop.load(Ordering::Relaxed) {
        let accept = tokio::time::timeout(Duration::from_millis(200), endpoint.accept()).await;
        let incoming = match accept {
            Ok(Some(i)) => i,
            Ok(None) => break,  // endpoint closed
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
        inner.in_flight.fetch_add(1, Ordering::Relaxed);
        let job_tx = job_tx.clone();
        let inner_for_task = inner.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = InFlightGuard::new(inner_for_task.clone());
            match incoming.await {
                Ok(conn) => handle_connection(conn, job_tx, inner_for_task).await,
                Err(e) => log::debug!("http-gateway: h3 handshake: {e}"),
            }
        });
    }

    // Stop signaled — wait for live connections to drain before
    // closing the endpoint, so in-flight requests get to finish.
    drain_in_flight(&inner).await;
    endpoint.close(0u32.into(), b"gateway-stop");
}

async fn handle_connection(
    quinn_conn: quinn::Connection,
    job_tx: mpsc::SyncSender<Job>,
    inner: Arc<Inner>,
) {
    let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(quinn_conn)).await
    {
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
    // Each chunk read is bounded by `H3_BODY_CHUNK_TIMEOUT` so a
    // peer that opens the stream and stalls can't hold a slot
    // indefinitely.
    let mut body = Vec::new();
    let mut over_limit = false;
    let mut timed_out = false;
    loop {
        let chunk = match tokio::time::timeout(H3_BODY_CHUNK_TIMEOUT, stream.recv_data()).await {
            Ok(Ok(Some(c))) => c,
            Ok(Ok(None)) => break, // end of body
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                timed_out = true;
                break;
            }
        };
        let mut chunk = chunk;
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

    let response = if timed_out {
        Response::text(408, "body read timed out")
    } else if over_limit {
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
        let policy = Policy {
            admin_token: config::admin_token(),
            auth_token: config::auth_token(),
        };
        dispatch_request(our_req, &job_tx, &inner, policy).await
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
