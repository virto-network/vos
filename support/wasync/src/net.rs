use crate::io::{ErrorType, Read, Write};
use crate::wait_pollable;
pub use edge_nal::{Readable, TcpAccept, TcpBind, TcpShutdown, TcpSplit};
use std::{
    cell::OnceCell,
    io::{self, ErrorKind},
    net::{SocketAddr, SocketAddrV4},
};
use wasi::{
    io::streams::StreamError,
    sockets::{
        instance_network::instance_network,
        network::{ErrorCode, IpAddressFamily, IpSocketAddress, Ipv4SocketAddress},
        tcp::{self, InputStream, OutputStream, Pollable},
        tcp_create_socket::create_tcp_socket,
    },
};

pub struct Stack;
impl Stack {
    pub const fn new() -> Self {
        Self
    }
}

impl TcpBind for Stack {
    type Error = io::Error;
    type Accept<'a> = Acceptor;

    async fn bind(&self, local: SocketAddr) -> Result<Self::Accept<'_>, Self::Error> {
        let family = match local {
            SocketAddr::V4(_) => IpAddressFamily::Ipv4,
            SocketAddr::V6(_) => IpAddressFamily::Ipv6,
        };
        let socket = create_tcp_socket(family).map_err(to_io_err)?;
        let network = instance_network();

        let addr = match local {
            SocketAddr::V4(addr) => {
                let ip = addr.ip().octets();
                IpSocketAddress::Ipv4(Ipv4SocketAddress {
                    port: addr.port(),
                    address: (ip[0], ip[1], ip[2], ip[3]),
                })
            }
            SocketAddr::V6(_addr) => unimplemented!(),
        };

        socket.start_bind(&network, addr).map_err(to_io_err)?;
        let poll = socket.subscribe();
        wait_pollable(&poll).await;
        socket.finish_bind().map_err(to_io_err)?;

        socket.start_listen().map_err(to_io_err)?;
        wait_pollable(&poll).await;
        socket.finish_listen().map_err(to_io_err)?;

        Ok(Acceptor { socket, poll })
    }
}

pub struct Acceptor {
    socket: tcp::TcpSocket,
    poll: Pollable,
}
impl TcpAccept for Acceptor {
    type Error = io::Error;

    type Socket<'a>
        = TcpSocket
    where
        Self: 'a;

    async fn accept(&self) -> Result<(SocketAddr, Self::Socket<'_>), Self::Error> {
        println!("accepting");
        wait_pollable(&self.poll).await;
        println!("accept pollable");
        let (socket, input, output) = match self.socket.accept().map_err(to_io_err) {
            Ok(accepted) => accepted,
            Err(e) => return Err(e),
        };
        let IpSocketAddress::Ipv4(addr) = socket.remote_address().map_err(to_io_err)? else {
            return Err(ErrorKind::Unsupported.into());
        };
        let ip = addr.address;
        let address = SocketAddrV4::new([ip.0, ip.1, ip.2, ip.3].into(), addr.port).into();
        Ok((address, TcpSocket {
            socket,
            reader: TcpReader::new(input),
            writer: TcpWriter::new(output),
        }))
    }
}

pub struct TcpSocket {
    socket: tcp::TcpSocket,
    reader: TcpReader,
    writer: TcpWriter,
}

impl Readable for TcpSocket {
    async fn readable(&mut self) -> Result<(), Self::Error> {
        self.reader.readable().await
    }
}
impl Read for TcpSocket {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.reader.read(buf).await
    }
}
impl Write for TcpSocket {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        self.writer.write(buf).await
    }
}
impl TcpShutdown for TcpSocket {
    async fn close(&mut self, what: edge_nal::Close) -> Result<(), Self::Error> {
        let what = match what {
            edge_nal::Close::Read => tcp::ShutdownType::Receive,
            edge_nal::Close::Write => tcp::ShutdownType::Send,
            edge_nal::Close::Both => tcp::ShutdownType::Both,
        };
        println!("[net] closing socket");
        self.socket.shutdown(what).map_err(to_io_err)
    }

    async fn abort(&mut self) -> Result<(), Self::Error> {
        println!("[net] aborting socket");
        Ok(())
    }
}
impl ErrorType for TcpSocket {
    type Error = io::Error;
}
impl Drop for TcpSocket {
    fn drop(&mut self) {
        println!("droping socket {}", self.socket.is_listening());
        let _ = self.close(edge_nal::Close::Both);
    }
}

impl TcpSplit for TcpSocket {
    type Read<'a>
        = &'a mut TcpReader
    where
        Self: 'a;

    type Write<'a>
        = &'a mut TcpWriter
    where
        Self: 'a;

    fn split(&mut self) -> (Self::Read<'_>, Self::Write<'_>) {
        (&mut self.reader, &mut self.writer)
    }
}

pub struct TcpReader {
    input: InputStream,
    subscription: OnceCell<Pollable>,
}
impl TcpReader {
    fn new(input: InputStream) -> Self {
        Self {
            input,
            subscription: OnceCell::new(),
        }
    }
}
impl Readable for TcpReader {
    async fn readable(&mut self) -> Result<(), Self::Error> {
        println!("readable");
        let subscription = self.subscription.get_or_init(|| self.input.subscribe());
        wait_pollable(subscription).await;
        Ok(())
    }
}
impl Read for TcpReader {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        println!("reading");
        let read = loop {
            self.readable().await?;
            match self.input.read(buf.len() as u64) {
                Ok(r) if r.is_empty() => continue,
                Ok(r) => break r,
                Err(StreamError::Closed) => return Ok(0),
                Err(StreamError::LastOperationFailed(err)) => {
                    return Err(io::Error::other(err.to_debug_string()));
                }
            }
        };
        let len = read.len();
        buf[0..len].copy_from_slice(&read);
        Ok(len)
    }
}
impl ErrorType for TcpReader {
    type Error = io::Error;
}

pub struct TcpWriter {
    output: OutputStream,
    subscription: OnceCell<Pollable>,
}
impl TcpWriter {
    fn new(output: OutputStream) -> Self {
        Self {
            output,
            subscription: OnceCell::new(),
        }
    }
}
impl TcpWriter {
    async fn writable(&self) {
        let subscription = self.subscription.get_or_init(|| self.output.subscribe());
        wait_pollable(subscription).await;
    }
}
impl Write for TcpWriter {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        loop {
            match self.output.check_write() {
                Ok(0) => {
                    self.writable().await;
                    continue;
                }
                Ok(some) => {
                    let writable = some.try_into().unwrap_or(usize::MAX).min(buf.len());
                    match self.output.write(&buf[0..writable]) {
                        Ok(()) => return Ok(writable),
                        Err(StreamError::Closed) => {
                            return Err(io::ErrorKind::ConnectionReset.into());
                        }
                        Err(StreamError::LastOperationFailed(err)) => {
                            return Err(io::Error::other(err.to_debug_string()));
                        }
                    }
                }
                Err(StreamError::Closed) => return Err(io::ErrorKind::ConnectionReset.into()),
                Err(StreamError::LastOperationFailed(err)) => {
                    return Err(io::Error::other(err.to_debug_string()));
                }
            }
        }
    }
}
impl ErrorType for TcpWriter {
    type Error = io::Error;
}

fn to_io_err(err: ErrorCode) -> io::Error {
    match err {
        ErrorCode::Unknown => ErrorKind::Other.into(),
        ErrorCode::AccessDenied => ErrorKind::PermissionDenied.into(),
        ErrorCode::NotSupported => ErrorKind::Unsupported.into(),
        ErrorCode::InvalidArgument => ErrorKind::InvalidInput.into(),
        ErrorCode::OutOfMemory => ErrorKind::OutOfMemory.into(),
        ErrorCode::Timeout => ErrorKind::TimedOut.into(),
        ErrorCode::WouldBlock => ErrorKind::WouldBlock.into(),
        ErrorCode::InvalidState => ErrorKind::InvalidData.into(),
        ErrorCode::AddressInUse => ErrorKind::AddrInUse.into(),
        ErrorCode::ConnectionRefused => ErrorKind::ConnectionRefused.into(),
        ErrorCode::ConnectionReset => ErrorKind::ConnectionReset.into(),
        ErrorCode::ConnectionAborted => ErrorKind::ConnectionAborted.into(),
        ErrorCode::ConcurrencyConflict => ErrorKind::AlreadyExists.into(),
        _ => ErrorKind::Other.into(),
    }
}
