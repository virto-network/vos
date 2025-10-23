//! # Simple Serve - Light HTTP Server for Embedded Systems
//!
//! A lightweight, no_std HTTP server implementation built on top of the edge-net stack,
//! designed specifically for embedded systems and resource-constrained environments.
//!
//! ## Features
//!
//! - **No-std compatible**: Works in embedded environments without heap allocation requirements
//! - **Async/await support**: Built with async Rust for efficient resource usage
//! - **Memory efficient**: Minimal allocations with lazy parsing
//! - **Flexible handlers**: Support for both generic HTTP and structured RPC patterns
//!
//! ## Examples
//!
//! ### Basic HTTP Server
//!
//! ```rust,ignore
//! use simple_serve::{serve, Method, HttpError};
//!
//! let handler = |_ctx, method, path, _query, _headers, body| async move {
//!     match (method, path) {
//!         (Method::Get, "/hello") => Ok("Hello, World!".as_bytes()),
//!         (Method::Post, "/echo") => {
//!             let body_data = read_body(body).await?;
//!             Ok(body_data.as_slice())
//!         }
//!         _ => Err(HttpError::NotFound),
//!     }
//! };
//!
//! serve(&tcp_stack, 8080, (), handler).await?;
//! ```
//!
#![no_std]
#![feature(type_alias_impl_trait)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use core::{
    cell::RefCell,
    fmt,
    marker::PhantomData,
    mem,
    net::Ipv4Addr,
    ops::{AsyncFn, DerefMut},
};
use edge_http::io::{
    Body,
    server::{self, Connection, DefaultServer},
};
pub use edge_http::{Headers, Method};
use edge_nal::{TcpAccept, TcpBind, TcpSplit};
use embedded_io_async::{BufRead, Read, Write};
pub use form_urlencoded::parse as parse_urlencoded;

type SocketFor<'stack, S> = <<S as TcpBind>::Accept<'stack> as TcpAccept>::Socket<'stack>;
pub type MaybeBody<'conn, 'stack, 'buf, S> = Option<&'conn mut Body<'buf, SocketFor<'stack, S>>>;
pub type Path<'h> = &'h str;
pub type Query<'h> = form_urlencoded::Parse<'h>;

/// Creates and runs a simple HTTP server based on the no_std edge-net stack.
///
/// This function binds to the specified port and handles incoming HTTP requests using
/// the provided handler function. The server supports standard HTTP methods and
/// automatically parses request components like path, query parameters, and headers.
///
/// # Parameters
///
/// * `stack` - The TCP stack implementation used for network operations
/// * `port` - The port number to bind the server to (e.g., 8080)
/// * `cx` - A context object that will be passed to each request handler
/// * `handler` - An async function that processes HTTP requests and returns responses
///
/// The handler function receives:
/// - `&mut Cx` - Mutable reference to the context
/// - `Method` - HTTP method (GET, POST, etc.)
/// - `Path` - The request path as a string slice
/// - `Query` - Parsed query parameters as form-urlencoded pairs
/// - `&Headers` - HTTP headers from the request
/// - `MaybeBody` - Optional request body (present for POST/PUT requests)
///
/// # Returns
///
/// Returns `Ok(())` when the server shuts down gracefully, or an `Error` if
/// binding fails or other network errors occur.
///
/// # Example
///
/// ```rust,ignore
/// use simple_serve::{serve, Method, HttpError};
///
/// let handler = |ctx, method, path, query, headers, body| async move {
///     match (method, path) {
///         (Method::Get, "/hello") => Ok("Hello, World!".as_bytes()),
///         (Method::Post, "/echo") => {
///             // Echo the request body back
///             let body_data = read_body(body).await?;
///             Ok(body_data.as_slice())
///         }
///         _ => Err(HttpError::NotFound),
///     }
/// };
///
/// serve(&tcp_stack, 8080, (), handler).await?;
/// ```
pub async fn serve<Cx, H, S, Res>(
    stack: &S,
    port: u16,
    cx: Cx,
    handler: H,
) -> Result<(), Error<S::Error>>
where
    for<'c> H: AsyncFn(
        &mut Cx,
        Method,
        Path<'c>,
        Query<'c>,
        &'c Headers,
        MaybeBody<'c, '_, '_, S>,
    ) -> Result<Res, HttpError>,
    S: TcpBind,
    Res: BufRead + fmt::Debug,
{
    let socket = stack
        .bind((Ipv4Addr::new(0, 0, 0, 0), port).into())
        .await
        .map_err(Error::Io)?;

    let mut server = DefaultServer::new();
    server
        .run(None, socket, Handler {
            handler: RefCell::new(handler),
            cx: RefCell::new(cx),
            types: PhantomData,
        })
        .await?;

    log::debug!("server closed");
    Ok(())
}

/// A simple RPC system for "commands" and "queries"
/// expects a URL path /{module_name}/{command|query}
/// POST is used for commands, GET is used for queries
pub async fn rpc<S, Cx, H, Res>(port: u16, cx: Cx, handler: H) -> Result<(), Error<S::Error>>
where
    for<'a> H: AsyncFn(&'a str, Action<'a>) -> Result<Res, HttpError>,
    S: TcpBind + Default,
    Res: BufRead + fmt::Debug,
{
    serve(
        &S::default(),
        port,
        cx,
        async |_cx, method, path, query, _h, body| {
            if !matches!(method, Method::Get | Method::Post) {
                return Err(HttpError::MethodNotAllowed);
            }
            let (module, action) = path
                .trim_matches('/')
                .split_once('/')
                .ok_or_else(|| HttpError::NotFound)?;

            match method {
                Method::Get => handler(module, Action::Query(action, query)).await,
                Method::Post => {
                    let body = read_to_vec(body.expect("POST with body"))
                        .await
                        .map_err(|_| HttpError::BadRequest)?;
                    handler(module, Action::Command(action, body)).await
                }
                _ => unreachable!(),
            }
        },
    )
    .await
}

pub enum Action<'a> {
    Query(&'a str, Query<'a>),
    Command(&'a str, Vec<u8>),
}

impl<'a> Action<'a> {
    pub fn name(&self) -> &'a str {
        match self {
            Action::Query(name, _) => name,
            Action::Command(name, _) => name,
        }
    }

    pub fn data(&self) -> impl Iterator<Item = (String, String)> {
        match self {
            Action::Query(_, query) => query.into_owned(),
            Action::Command(_, body) => parse_urlencoded(body).into_owned(),
        }
    }

    /// Get a specific parameter value from the action data
    pub fn get_param(&self, key: &str) -> Option<String> {
        self.data().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

#[derive(Debug)]
pub enum Error<E> {
    BadRequest,
    ConnectionClosed,
    Io(E),
}
impl<E> From<edge_http::io::Error<E>> for Error<E> {
    fn from(value: edge_http::io::Error<E>) -> Self {
        match value {
            edge_http::io::Error::ConnectionClosed => Self::ConnectionClosed,
            edge_http::io::Error::Io(e) => Self::Io(e),
            _ => Self::BadRequest,
        }
    }
}

pub enum HttpError {
    BadRequest,
    Forbidden,
    Internal,
    MethodNotAllowed,
    NotFound,
    Timeout,
    Unauthorized,
    UnsupportedType,
}

struct Handler<H, Cx, S, Res> {
    handler: RefCell<H>,
    cx: RefCell<Cx>,
    types: PhantomData<(S, Res)>,
}

impl<H, Cx, S, Res> server::Handler for Handler<H, Cx, S, Res>
where
    for<'c> H: AsyncFn(
        &mut Cx,
        Method,
        Path<'c>,
        Query<'c>,
        &'c Headers,
        MaybeBody<'c, '_, '_, S>,
    ) -> Result<Res, HttpError>,
    S: TcpBind,
    Res: BufRead + fmt::Debug,
{
    type Error<E>
        = Error<E>
    where
        E: fmt::Debug;

    async fn handle<T, const N: usize>(
        &self,
        task_id: impl fmt::Display,
        conn: &mut Connection<'_, T, N>,
    ) -> Result<(), Self::Error<T::Error>>
    where
        T: Read + Write + TcpSplit,
    {
        log::trace!("received request({task_id})");
        let (h, body) = conn.split();
        let body = match h.method {
            Method::Get | Method::Delete | Method::Head | Method::Options => None,
            Method::Post | Method::Put => Some(body),
            _ => {
                conn.initiate_response(405, None, &[]).await?;
                conn.complete().await?;
                return Ok(());
            }
        };

        let headers: &Headers = unsafe { mem::transmute(&h.headers) };
        let body: MaybeBody<S> = unsafe { mem::transmute(body) };

        let (path, query) = h.path.split_once('?').unwrap_or_else(|| (h.path, ""));
        let query = parse_urlencoded(query.as_bytes());
        log::trace!("Parsed headers and query for {} {}", h.method, path);
        let mut res = {
            let mut cx = self.cx.borrow_mut();
            match self.handler.borrow_mut()(cx.deref_mut(), h.method, path, query, headers, body)
                .await
            {
                Ok(res) => res,
                Err(e) => {
                    let (status, message) = match e {
                        HttpError::BadRequest => (400, "Bad Request"),
                        HttpError::Unauthorized => (401, "Unauthorized"),
                        HttpError::Forbidden => (403, "Forbidden"),
                        HttpError::NotFound => (404, "Not Found"),
                        HttpError::MethodNotAllowed => (405, "Method Not Allowed"),
                        HttpError::Timeout => (408, "Request Timeout"),
                        HttpError::UnsupportedType => (415, "Unsupported Media Type"),
                        HttpError::Internal => (500, "Internal Server Error"),
                    };

                    log::debug!("{} {} {}", &status, h.method, h.path);
                    conn.initiate_response(status, Some(message), &[]).await?;
                    conn.complete().await?;
                    return Ok(());
                }
            }
        };
        log::trace!("Initiating successful response {:?}", &res);
        conn.initiate_response(200, None, &[]).await?;
        while let Ok(buf) = res.fill_buf().await {
            if buf.is_empty() {
                break;
            }
            let len = buf.len();
            conn.write_all(buf).await?;
            res.consume(len);
        }
        conn.complete().await?;
        log::debug!("Response Ok ({task_id}");
        Ok(())
    }
}

/// Helper function to read entire content from a Read implementation into a Vec<u8>
async fn read_to_vec<R: Read>(mut reader: R) -> Result<Vec<u8>, R::Error> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break, // End of stream
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(e),
        }
    }

    Ok(buffer)
}
