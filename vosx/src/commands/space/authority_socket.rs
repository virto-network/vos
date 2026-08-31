//! Bounded generation-2 transport for the local Agent authority.
//!
//! Each connection carries exactly one length-delimited request and one
//! length-delimited response. The request includes the startup-pinned policy
//! ID, and the response repeats both that policy and a commitment to the
//! complete request. Reads, writes, and connect all consume one absolute
//! deadline rather than renewing a timeout after every byte.

use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(unix)]
use std::time::Instant;

use vos::service::Hash;

pub(super) const REQUEST_MAGIC: [u8; 4] = *b"VAA2";
pub(super) const RESPONSE_MAGIC: [u8; 4] = *b"VAR2";
pub(super) const REQUEST_HASH_DOMAIN: &[u8] = b"vos/agent-authority-socket/request/v2";

/// One operation may carry one complete 8-MiB package or catalog preimage,
/// plus its bounded Agent configuration or system-genesis proposal.
pub(super) const MAX_SOCKET_PAYLOAD_BYTES: usize = 9 * 1024 * 1024;
const REQUEST_HEADER_BYTES: usize = 4 + 32 + 1 + 4;
const RESPONSE_HEADER_BYTES: usize = 4 + 32 + 32 + 1 + 4;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SocketExchangeError {
    /// Connect, read, write, platform support, and deadline failures are all
    /// availability failures. Callers must not reinterpret them as denial.
    Unavailable,
    /// A frame was oversized, truncated, noncanonical, or not bound to the
    /// exact request sent on this connection.
    Corrupt,
    /// A valid response came from a different policy than the one sampled at
    /// startup. This remains an availability failure to provider callers.
    PolicyChanged,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SocketResponse {
    pub(super) policy: Hash,
    pub(super) status: u8,
    pub(super) payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(super) struct AuthoritySocket {
    path: PathBuf,
    policy: Hash,
}

impl AuthoritySocket {
    pub(super) fn from_sampled_policy(path: PathBuf, policy: Hash) -> Option<Self> {
        (policy != Hash::ZERO).then_some(Self { path, policy })
    }

    pub(super) const fn policy(&self) -> Hash {
        self.policy
    }

    pub(super) fn request(
        &self,
        tag: u8,
        payload: &[u8],
    ) -> Result<SocketResponse, SocketExchangeError> {
        exchange(&self.path, Some(self.policy), tag, payload)
    }
}

/// Sample the authority policy. Query requests deliberately carry a zero
/// policy because no trust anchor has been selected yet; the response must
/// supply a nonzero policy before an [`AuthoritySocket`] can be constructed.
pub(super) fn query_policy(path: &Path, tag: u8) -> Result<SocketResponse, SocketExchangeError> {
    exchange(path, None, tag, &[])
}

fn exchange(
    path: &Path,
    expected_policy: Option<Hash>,
    tag: u8,
    payload: &[u8],
) -> Result<SocketResponse, SocketExchangeError> {
    exchange_with_timeout(path, expected_policy, tag, payload, IO_TIMEOUT)
}

pub(super) fn exchange_with_timeout(
    path: &Path,
    expected_policy: Option<Hash>,
    tag: u8,
    payload: &[u8],
    timeout: Duration,
) -> Result<SocketResponse, SocketExchangeError> {
    let policy = expected_policy.unwrap_or(Hash::ZERO);
    let request = encode_request(policy, tag, payload)?;
    let response = exchange_frame(path, &request, timeout)?;
    if response.policy == Hash::ZERO {
        return Err(SocketExchangeError::Corrupt);
    }
    if expected_policy.is_some_and(|expected| response.policy != expected) {
        return Err(SocketExchangeError::PolicyChanged);
    }
    Ok(response)
}

pub(super) fn encode_request(
    policy: Hash,
    tag: u8,
    payload: &[u8],
) -> Result<Vec<u8>, SocketExchangeError> {
    if payload.len() > MAX_SOCKET_PAYLOAD_BYTES {
        return Err(SocketExchangeError::Corrupt);
    }
    let payload_len = u32::try_from(payload.len()).map_err(|_| SocketExchangeError::Corrupt)?;
    let mut request = Vec::with_capacity(REQUEST_HEADER_BYTES + payload.len());
    request.extend_from_slice(&REQUEST_MAGIC);
    request.extend_from_slice(&policy.0);
    request.push(tag);
    request.extend_from_slice(&payload_len.to_le_bytes());
    request.extend_from_slice(payload);
    Ok(request)
}

pub(super) fn request_hash(request: &[u8]) -> Hash {
    Hash::digest(REQUEST_HASH_DOMAIN, &[request])
}

#[cfg(unix)]
fn exchange_frame(
    path: &Path,
    request: &[u8],
    timeout: Duration,
) -> Result<SocketResponse, SocketExchangeError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(SocketExchangeError::Corrupt)?;
    let expected_request = request_hash(request);
    let mut stream = connect_until(path, deadline).map_err(|_| SocketExchangeError::Unavailable)?;
    let request_len = u32::try_from(request.len()).map_err(|_| SocketExchangeError::Corrupt)?;
    write_all_until(&mut stream, &request_len.to_le_bytes(), deadline)
        .and_then(|()| write_all_until(&mut stream, request, deadline))
        .map_err(|_| SocketExchangeError::Unavailable)?;

    let mut response_len = [0u8; 4];
    read_exact_until(&mut stream, &mut response_len, deadline)
        .map_err(|_| SocketExchangeError::Unavailable)?;
    let response_len = u32::from_le_bytes(response_len) as usize;
    if !(RESPONSE_HEADER_BYTES..=RESPONSE_HEADER_BYTES + MAX_SOCKET_PAYLOAD_BYTES)
        .contains(&response_len)
    {
        return Err(SocketExchangeError::Corrupt);
    }
    let mut response = vec![0; response_len];
    read_exact_until(&mut stream, &mut response, deadline)
        .map_err(|_| SocketExchangeError::Unavailable)?;
    decode_response(&response, expected_request)
}

#[cfg(unix)]
fn connect_until(path: &Path, deadline: Instant) -> std::io::Result<UnixStream> {
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    let address = socket2::SockAddr::unix(path)?;
    socket.connect_timeout(&address, remaining(deadline)?)?;
    ensure_before_deadline(deadline)?;
    Ok(socket.into())
}

#[cfg(unix)]
fn remaining(deadline: Instant) -> std::io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Agent authority deadline elapsed",
        ))
    } else {
        Ok(remaining)
    }
}

#[cfg(unix)]
fn ensure_before_deadline(deadline: Instant) -> std::io::Result<()> {
    remaining(deadline).map(|_| ())
}

#[cfg(unix)]
fn write_all_until(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "Agent authority accepted no request bytes",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_exact_until(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "Agent authority closed before its response completed",
                ));
            }
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn exchange_frame(
    _path: &Path,
    _request: &[u8],
    _timeout: Duration,
) -> Result<SocketResponse, SocketExchangeError> {
    Err(SocketExchangeError::Unavailable)
}

fn decode_response(
    bytes: &[u8],
    expected_request: Hash,
) -> Result<SocketResponse, SocketExchangeError> {
    if bytes.len() < RESPONSE_HEADER_BYTES
        || bytes.get(..4) != Some(RESPONSE_MAGIC.as_slice())
        || bytes.get(4..36) != Some(expected_request.0.as_slice())
    {
        return Err(SocketExchangeError::Corrupt);
    }
    let policy = Hash(
        bytes[36..68]
            .try_into()
            .map_err(|_| SocketExchangeError::Corrupt)?,
    );
    let status = bytes[68];
    let payload_len = u32::from_le_bytes(
        bytes[69..73]
            .try_into()
            .map_err(|_| SocketExchangeError::Corrupt)?,
    ) as usize;
    if payload_len > MAX_SOCKET_PAYLOAD_BYTES
        || RESPONSE_HEADER_BYTES.checked_add(payload_len) != Some(bytes.len())
    {
        return Err(SocketExchangeError::Corrupt);
    }
    Ok(SocketResponse {
        policy,
        status,
        payload: bytes[RESPONSE_HEADER_BYTES..].to_vec(),
    })
}
