use std::convert::Infallible;
use std::io;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

use super::limits::{MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_HEADERS};
use super::state::Inner;
use super::{HttpIngressContext, decode_access_token};
use crate::node::{IngressAuthenticationError, IngressHandle};

fn default_max_connections() -> usize {
    1024
}

const MAX_BLOCKING_REQUESTS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpTlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpIngressConfig {
    pub name: String,
    pub listen: SocketAddr,
    #[serde(default)]
    pub tls: Option<HttpTlsConfig>,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
}

#[derive(Debug)]
pub enum HttpIngressError {
    InvalidConfig(&'static str),
    Io(io::Error),
    Tls(String),
}

impl std::fmt::Display for HttpIngressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(message) => f.write_str(message),
            Self::Io(error) => write!(f, "{error}"),
            Self::Tls(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for HttpIngressError {}

impl From<io::Error> for HttpIngressError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub(crate) fn start(
    config: HttpIngressConfig,
    handle: IngressHandle,
) -> Result<thread::JoinHandle<()>, HttpIngressError> {
    if config.name.trim().is_empty() {
        return Err(HttpIngressError::InvalidConfig(
            "HTTP ingress name is empty",
        ));
    }
    if config.max_connections == 0 {
        return Err(HttpIngressError::InvalidConfig(
            "HTTP ingress max_connections must be nonzero",
        ));
    }
    let tls = config.tls.as_ref().map(load_tls).transpose()?;
    let listener = StdTcpListener::bind(config.listen)?;
    listener.set_nonblocking(true)?;
    let name = config.name.clone();
    Ok(thread::Builder::new()
        .name(format!("vos-http-{name}"))
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(2)
                .thread_name(format!("vos-http-{name}-io"))
                .build()
                .expect("HTTP ingress Tokio runtime");
            runtime.block_on(serve(listener, config, handle, tls));
        })?)
}

async fn serve(
    listener: StdTcpListener,
    config: HttpIngressConfig,
    handle: IngressHandle,
    tls: Option<TlsAcceptor>,
) {
    let listener = match TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(error) => {
            crate::log::error!("HTTP ingress {} failed: {error}", config.name);
            return;
        }
    };
    let port = listener.local_addr().map_or(0, |address| address.port());
    let inner = Arc::new(Inner::new(port));
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let blocking = Arc::new(Semaphore::new(MAX_BLOCKING_REQUESTS));
    while !handle.is_shutting_down() {
        let accepted = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
        let Ok(Ok((stream, _))) = accepted else {
            continue;
        };
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        let handle = handle.clone();
        let inner = inner.clone();
        let blocking = blocking.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(tls) = tls {
                match tokio::time::timeout(Duration::from_secs(10), tls.accept(stream)).await {
                    Ok(Ok(stream)) => serve_connection(stream, handle, inner, blocking).await,
                    Ok(Err(error)) => {
                        crate::log::debug!("HTTP TLS handshake rejected: {error}")
                    }
                    Err(_) => crate::log::debug!("HTTP TLS handshake timed out"),
                }
            } else {
                serve_connection(stream, handle, inner, blocking).await;
            }
        });
    }
}

async fn serve_connection<T>(
    stream: T,
    handle: IngressHandle,
    inner: Arc<Inner>,
    blocking: Arc<Semaphore>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        handle_request(request, handle.clone(), inner.clone(), blocking.clone())
    });
    let mut builder = http1::Builder::new();
    builder
        .keep_alive(true)
        .max_headers(MAX_HEADERS)
        .max_buf_size(MAX_HEADER_BYTES)
        .header_read_timeout(Duration::from_secs(10))
        .timer(TokioTimer::new());
    if let Err(error) = builder
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        crate::log::debug!("HTTP connection closed: {error}");
    }
}

async fn handle_request(
    request: Request<Incoming>,
    handle: IngressHandle,
    inner: Arc<Inner>,
    blocking: Arc<Semaphore>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let path = request.uri().path().to_string();
    let (parts, body) = request.into_parts();
    let body = match tokio::time::timeout(
        Duration::from_secs(30),
        Limited::new(body, MAX_BODY_BYTES).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes().to_vec(),
        Ok(Err(_)) => {
            inner.metrics.record_response(413);
            return Ok(simple(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large",
            ));
        }
        Err(_) => {
            inner.metrics.record_response(408);
            return Ok(simple(
                StatusCode::REQUEST_TIMEOUT,
                "request body timed out",
            ));
        }
    };
    let request = http::Request::from_parts(parts, body);
    let response = if path == "/__status" {
        let mut context = HttpIngressContext::new(handle, None);
        super::routing::dispatch(&request, &inner, &mut context)
    } else {
        let Ok(permit) = blocking.try_acquire_owned() else {
            let response = simple(StatusCode::SERVICE_UNAVAILABLE, "HTTP worker pool is busy");
            inner.metrics.record_response(response.status().as_u16());
            return Ok(response);
        };
        let work_inner = inner.clone();
        match tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let access = match authenticate(&request, &handle) {
                Ok(access) => access,
                Err((status, message)) => return simple_bytes(status, message),
            };
            let mut context = HttpIngressContext::new(handle, Some(access));
            super::routing::dispatch(&request, &work_inner, &mut context)
        })
        .await
        {
            Ok(response) => response,
            Err(_) => super::types::text(500, "HTTP worker failed"),
        }
    };
    inner.metrics.record_response(response.status().as_u16());
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(parts, Full::new(Bytes::from(body))))
}

fn authenticate<B>(
    request: &Request<B>,
    handle: &IngressHandle,
) -> Result<crate::IngressAccessStatus, (StatusCode, &'static str)> {
    let token = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .and_then(decode_access_token)
        .ok_or((StatusCode::UNAUTHORIZED, "invalid access token"))?;
    let credential_id = crate::ingress_credential_id(&token);
    let access = match handle.authenticate_credential(credential_id) {
        Ok(access) => access,
        Err(IngressAuthenticationError::Invalid) => {
            return Err((StatusCode::UNAUTHORIZED, "invalid access token"));
        }
        Err(IngressAuthenticationError::AuthorityUnavailable) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "space authority unavailable",
            ));
        }
    };
    if access.expires_at <= super::state::now_unix() {
        return Err((StatusCode::UNAUTHORIZED, "access token expired"));
    }
    Ok(access)
}

fn simple_bytes(status: StatusCode, message: &'static str) -> super::types::Response {
    super::types::text(status.as_u16(), message)
}

fn simple(status: StatusCode, message: &'static str) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from_static(message.as_bytes())));
    *response.status_mut() = status;
    response
}

fn load_tls(config: &HttpTlsConfig) -> Result<TlsAcceptor, HttpIngressError> {
    let mut cert = std::io::BufReader::new(std::fs::File::open(&config.cert)?);
    let certificates = rustls_pemfile::certs(&mut cert)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| HttpIngressError::Tls(error.to_string()))?;
    if certificates.is_empty() {
        return Err(HttpIngressError::Tls(
            "TLS certificate chain is empty".into(),
        ));
    }
    let mut key = std::io::BufReader::new(std::fs::File::open(&config.key)?);
    let key = rustls_pemfile::private_key(&mut key)
        .map_err(|error| HttpIngressError::Tls(error.to_string()))?
        .ok_or_else(|| HttpIngressError::Tls("TLS private key is missing".into()))?;
    let server = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| HttpIngressError::Tls(error.to_string()))?;
    Ok(TlsAcceptor::from(Arc::new(server)))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;
    use crate::node::VosNode;

    fn request(port: u16, path: &str) -> String {
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn status_is_anonymous_but_application_routes_require_access() {
        let probe = StdTcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let mut node = VosNode::new();
        node.add_http_ingress(HttpIngressConfig {
            name: "test".into(),
            listen: ([127, 0, 0, 1], port).into(),
            tls: None,
            max_connections: 4,
        })
        .unwrap();

        let status = request(port, "/__status");
        assert!(status.starts_with("HTTP/1.1 200"), "{status}");
        assert!(status.contains("\"status\":\"ok\""), "{status}");

        let protected = request(port, "/openapi.json");
        assert!(protected.starts_with("HTTP/1.1 401"), "{protected}");

        let results = node.collect();
        assert!(results.is_empty());
    }
}
