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
use std::{cell::RefCell, fmt, marker::PhantomData, mem, net::Ipv4Addr};

pub type MaybeBody<'s, 'b, S> = Option<&'b mut Body<'b, SocketFor<'s, S>>>;
type SocketFor<'s, S> = <<S as TcpBind>::Accept<'s> as TcpAccept>::Socket<'s>;
type Path<'a> = &'a str;
type Query<'a> = form_urlencoded::Parse<'a>;

pub async fn simple_serve<H, S, F, Res>(stack: S, port: u16, handler: H) -> Result<(), Error>
where
    H: FnMut(Path, Query, &Headers, MaybeBody<S>) -> F,
    S: TcpBind,
    F: Future<Output = Result<Res, HttpError>>,
    Res: BufRead,
{
    let socket = stack
        .bind((Ipv4Addr::new(0, 0, 0, 0), port).into())
        .await
        .map_err(|_| Error::Io)?;

    let mut server = DefaultServer::new();
    server
        .run(None, socket, Handler(RefCell::new(handler), PhantomData))
        .await?;
    Ok(())
}

#[derive(Debug)]
pub enum Error {
    BadRequest,
    ConnectionClosed,
    Io,
}
impl<E> From<edge_http::io::Error<E>> for Error {
    fn from(value: edge_http::io::Error<E>) -> Self {
        match value {
            edge_http::io::Error::ConnectionClosed => Self::ConnectionClosed,
            edge_http::io::Error::Io(_) => Self::Io,
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

struct Handler<H, S, F, Res>(RefCell<H>, PhantomData<(S, F, Res)>);

impl<H, S, F, Res> server::Handler for Handler<H, S, F, Res>
where
    H: FnMut(Path, Query, &Headers, MaybeBody<S>) -> F,
    S: TcpBind,
    F: Future<Output = Result<Res, HttpError>>,
    Res: BufRead,
{
    type Error<E>
        = Error
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

        let mut res = match self.0.borrow_mut()(path, query, headers, body).await {
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
                conn.initiate_response(status, None, &[]).await?;
                conn.complete().await?;
                return Ok(());
            }
        };
        conn.initiate_response(200, None, &[]).await?;
        while let Ok(buf) = res.fill_buf().await {
            conn.write_all(buf).await?;
        }
        conn.complete().await?;
        Ok(())
    }
}
