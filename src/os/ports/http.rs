use super::{PortError, SystemPort};
use crate::os::net::{self, http, nal::WithTimeout};
use core::fmt;
use edge_net::nal::TcpSplit;
use embedded_io_async::{Read, Write};
use serde::Deserialize;

pub struct Port {
    port: net::TcpConnection,
    srv: http::io::server::Server,
}

impl SystemPort for Port {
    type Cfg = Config;
    type Error = PortError;

    async fn configure(cfg: Option<Self::Cfg>) -> Self {
        let cfg = cfg.unwrap_or_default();
        let port = net::bind(cfg.port).await.expect("bind http port");
        Self {
            srv: Default::default(),
            port,
        }
    }

    async fn accept_connection(&mut self) -> Result<(), Self::Error> {
        const TIMEOUT: u32 = 2 * 1_000;
        self.srv
            .run(None, &self.port, WithTimeout::new(TIMEOUT, HttpTerm))
            .await?;
        Ok(())
    }
}

struct HttpTerm;

impl http::io::server::Handler for HttpTerm {
    type Error<E>
        = PortError
    where
        E: fmt::Debug;

    async fn handle<T: Read + Write + TcpSplit, const N: usize>(
        &self,
        _task_id: impl fmt::Display + Copy,
        conn: &mut http::io::server::Connection<'_, T, N>,
    ) -> Result<(), Self::Error<T::Error>> {
        let h = conn.headers()?;
        let (status, headers, body) = match (h.method, h.path) {
            (http::Method::Get, "/_health") => (200, None, Some("OK")),
            // shorthand for issuing the `open` command to get the contents of a file
            (http::Method::Get, file) => {
                log::trace!("GET {file}");
                (404, None, None)
            }
            // request body is the script passed to the shell interpreter
            (http::Method::Post, uri) => {
                log::trace!("POST {uri}");
                (200, None, None)
            }
            (_, _) => (405, None, None),
        };
        conn.initiate_response(status, None, headers.unwrap_or(&[]))
            .await?;
        if let Some(body) = body {
            conn.write_all(body.as_bytes()).await?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
pub struct Config {
    port: u16,
}
impl Default for Config {
    fn default() -> Self {
        Self { port: 8888 }
    }
}

impl<E: fmt::Debug> From<http::io::Error<E>> for PortError {
    fn from(err: http::io::Error<E>) -> Self {
        log::trace!("http error: {err:?}");
        PortError
    }
}
