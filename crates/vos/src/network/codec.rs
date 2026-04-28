//! libp2p `request_response` codec for [`Frame`].
//!
//! Each direction (request, response) carries one Frame, length-
//! prefixed on the wire as `[len: u32 LE][bytes]`. The framework
//! gives us a fresh stream per round-trip and closes it after the
//! codec returns, so we only need to read/write the bytes — no
//! delimiter handling.
//!
//! Why `#[async_trait]`: the libp2p `Codec` trait is declared with
//! native `async fn` in 2021 edition, but vos lives in 2024 edition
//! where `async fn` desugars with precise lifetime captures. The
//! two desugarings don't textually match, so a direct `async fn`
//! impl trips E0195. `async_trait` boxes the futures (one
//! allocation per round-trip — negligible) which side-steps the
//! mismatch. libp2p's own `cbor::Codec` uses the same trick.

use async_trait::async_trait;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use libp2p::StreamProtocol;
use std::io;

use super::wire::{Frame, MAX_FRAME_BYTES};

#[derive(Clone, Default)]
pub(super) struct VosCodec;

#[async_trait]
impl Codec for VosCodec {
    type Protocol = StreamProtocol;
    type Request = Frame;
    type Response = Frame;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Frame>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Frame>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Frame,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        resp: Frame,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &resp).await
    }
}

async fn write_frame<W>(io: &mut W, frame: &Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let bytes = frame.encode();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    io.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    io.write_all(&bytes).await?;
    io.flush().await?;
    Ok(())
}

async fn read_frame<R>(io: &mut R) -> io::Result<Frame>
where
    R: AsyncRead + Unpin + Send,
{
    let mut len_bytes = [0u8; 4];
    io.read_exact(&mut len_bytes).await?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame length {len} exceeds cap"),
        ));
    }
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    Frame::decode(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

pub(super) const PROTOCOL: StreamProtocol = StreamProtocol::new("/vos/0.1.0");
