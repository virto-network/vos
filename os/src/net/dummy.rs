use core::{convert::Infallible, net::SocketAddr};

use embedded_io_async::{ErrorType, Read, Write};

pub(crate) struct Stack;
impl Stack {
    pub const fn new() -> Self {
        Stack
    }
}
impl super::TcpBind for Stack {
    type Error = Infallible;
    type Accept<'a> = Accept;
    async fn bind(&self, _local: core::net::SocketAddr) -> Result<Self::Accept<'_>, Self::Error> {
        Ok(Accept)
    }
}

pub(crate) struct Accept;
impl super::TcpAccept for Accept {
    type Error = Infallible;
    type Socket<'a> = Socket;

    async fn accept(&self) -> Result<(core::net::SocketAddr, Self::Socket<'_>), Self::Error> {
        Ok((SocketAddr::new([255, 255, 255, 255].into(), 0), Socket))
    }
}

pub(crate) struct Socket;
impl super::nal::Readable for Socket {
    async fn readable(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
impl super::nal::TcpShutdown for Socket {
    async fn close(&mut self, _what: edge_net::nal::Close) -> Result<(), Self::Error> {
        unimplemented!()
    }

    async fn abort(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
impl super::nal::TcpSplit for Socket {
    type Read<'a> = Self;
    type Write<'a> = Self;
    fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>) {
        unimplemented!()
    }
}
impl Read for Socket {
    async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        unimplemented!()
    }
}
impl Write for Socket {
    async fn write(&mut self, _buf: &[u8]) -> Result<usize, Self::Error> {
        unimplemented!()
    }
}

impl ErrorType for Socket {
    type Error = Infallible;
}
