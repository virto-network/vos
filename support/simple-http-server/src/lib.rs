#![feature(type_alias_impl_trait)]

pub use edge_http::Headers;
use edge_http::{
    Method,
    io::{
        Body,
        server::{self, Connection, DefaultServer},
    },
};
use edge_nal::{TcpAccept, TcpBind, TcpSplit};
use embedded_io_async::{BufRead, Read, Write};
pub use form_urlencoded::parse as parse_urlencoded;
use std::{cell::RefCell, fmt, marker::PhantomData, mem, net::Ipv4Addr, ops::DerefMut};

type SocketFor<'stack, S> = <<S as TcpBind>::Accept<'stack> as TcpAccept>::Socket<'stack>;
pub type MaybeBody<'conn, 'stack, 'buf, S> = Option<&'conn mut Body<'buf, SocketFor<'stack, S>>>;
pub type Path<'h> = &'h str;
pub type Query<'h> = form_urlencoded::Parse<'h>;

/// Lightweight handler for GET and POST requests
pub async fn simple_serve<Cx, H, S, Res>(
    stack: &S,
    port: u16,
    cx: Cx,
    handler: H,
) -> Result<(), Error<S::Error>>
where
    for<'c> H: AsyncFn(
        &mut Cx,
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

    println!("[server] starting server");
    let mut server = DefaultServer::new();
    server
        .run(None, socket, Handler {
            handler: RefCell::new(handler),
            cx: RefCell::new(cx),
            types: PhantomData,
        })
        .await?;

    println!("[server] closing server");
    Ok(())
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
    Unauthorized,
    Forbidden,
    NotFound,
    Timeout,
    UnsupportedType,
    Internal,
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
        _task_id: impl fmt::Display,
        conn: &mut Connection<'_, T, N>,
    ) -> Result<(), Self::Error<T::Error>>
    where
        T: Read + Write + TcpSplit,
    {
        println!("starting handler");
        let (h, body) = conn.split();
        let body = match h.method {
            Method::Get => None,
            Method::Post => Some(body),
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
        println!("[http] req {} {}", h.method, path);
        let mut res = {
            let mut cx = self.cx.borrow_mut();
            match self.handler.borrow_mut()(cx.deref_mut(), path, query, headers, body).await {
                Ok(res) => res,
                Err(e) => {
                    let status = match e {
                        HttpError::BadRequest => 400,
                        HttpError::Unauthorized => 401,
                        HttpError::Forbidden => 403,
                        HttpError::NotFound => 404,
                        HttpError::Timeout => 408,
                        HttpError::UnsupportedType => 415,
                        HttpError::Internal => 500,
                    };
                    println!("[http] init err response {}", &status);
                    conn.initiate_response(status, None, &[]).await?;
                    conn.complete_err("").await?;
                    println!("[http] complete err response");
                    return Ok(());
                }
            }
        };
        println!("[http] response {:?}", &res);
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
        Ok(())
    }
}
