//! Fail-closed bridge from the space daemon to a local production authority.
//!
//! The authority process owns the JAM/consensus view. `vosx` owns only a
//! Unix-domain client capability selected explicitly by the operator. Every
//! response repeats both the exact request commitment and the authority's
//! stable policy ID, so reconnecting to a different process cannot silently
//! change the verifier set of an already-open service.

use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::net::UnixStream;

use vos::v2::{
    ActorUpgradeV2, Hash, ProductionTrustDecisionV2, ProductionTrustV2, ProofVerificationRequestV2,
    ReceiptVerificationRequestV2, RoleCredentialVerificationRequestV2, ServiceGenesisV2, V2Wire,
};

const REQUEST_MAGIC: [u8; 4] = *b"VTA1";
const RESPONSE_MAGIC: [u8; 4] = *b"VTR1";
const PROTOCOL_VERSION: u16 = 1;
const MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

const QUERY_POLICY: u8 = 0;
const CURRENT_TIMESLOT: u8 = 1;
const VERIFY_TIMESLOT: u8 = 2;
const VERIFY_PROOF: u8 = 3;
const VERIFY_INSTALL: u8 = 4;
const VERIFY_UPGRADE: u8 = 5;
const VERIFY_ROLE: u8 = 6;
const VERIFY_RECEIPT: u8 = 7;

const AUTHORIZED: u8 = 0;
const DENIED: u8 = 1;
const UNAVAILABLE: u8 = 2;
const NO_TIMESLOT: u8 = 3;
const TIMESLOT: u8 = 4;
const POLICY: u8 = 5;

#[derive(Debug)]
pub(super) enum ProductionTrustSocketError {
    Connect(std::io::Error),
    Io(std::io::Error),
    InvalidResponse,
    InvalidPolicy,
    #[cfg(not(unix))]
    Unsupported,
}

impl core::fmt::Display for ProductionTrustSocketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connect(error) => write!(f, "connect to production trust sidecar: {error}"),
            Self::Io(error) => write!(f, "production trust sidecar I/O: {error}"),
            Self::InvalidResponse => f.write_str("invalid production trust sidecar response"),
            Self::InvalidPolicy => f.write_str("production trust sidecar returned a zero policy"),
            #[cfg(not(unix))]
            Self::Unsupported => {
                f.write_str("production trust sidecars require Unix-domain sockets")
            }
        }
    }
}

impl std::error::Error for ProductionTrustSocketError {}

/// Production trust capability backed by a local Unix-domain authority.
///
/// One connection carries exactly one request and response. This prevents a
/// timed-out request from being confused with a later decision and makes
/// authority restarts ordinary availability failures. The sampled policy ID
/// is immutable for this value and is checked on every subsequent response.
#[derive(Debug, Clone)]
pub(super) struct SocketProductionTrustV2 {
    path: PathBuf,
    policy: Hash,
}

#[derive(Debug, Clone, Copy)]
struct TrustResponse {
    policy: Hash,
    result: u8,
    timeslot: Option<u64>,
}

impl SocketProductionTrustV2 {
    pub(super) fn open(path: impl AsRef<Path>) -> Result<Self, ProductionTrustSocketError> {
        let path = path.as_ref().to_path_buf();
        let request = encode_request(QUERY_POLICY, &[])?;
        let response = exchange(&path, &request)?;
        if response.result != POLICY || response.policy == Hash::ZERO {
            return Err(ProductionTrustSocketError::InvalidPolicy);
        }
        Ok(Self {
            path,
            policy: response.policy,
        })
    }

    fn request(&self, tag: u8, payload: &[u8]) -> Option<TrustResponse> {
        let request = encode_request(tag, payload).ok()?;
        let response = exchange(&self.path, &request).ok()?;
        (response.policy == self.policy).then_some(response)
    }

    fn decision(&self, tag: u8, payload: &[u8]) -> ProductionTrustDecisionV2 {
        match self.request(tag, payload).map(|response| response.result) {
            Some(AUTHORIZED) => ProductionTrustDecisionV2::Authorized,
            Some(DENIED) => ProductionTrustDecisionV2::Denied,
            Some(UNAVAILABLE) | None => ProductionTrustDecisionV2::Unavailable,
            Some(_) => ProductionTrustDecisionV2::Unavailable,
        }
    }
}

impl ProductionTrustV2 for SocketProductionTrustV2 {
    fn policy_id(&self) -> Hash {
        self.policy
    }

    fn logical_timeslot(&self) -> Option<u64> {
        let response = self.request(CURRENT_TIMESLOT, &[])?;
        (response.result == TIMESLOT)
            .then_some(response.timeslot)
            .flatten()
    }

    fn verify_logical_timeslot(&self, logical_timeslot: u64) -> ProductionTrustDecisionV2 {
        self.decision(VERIFY_TIMESLOT, &logical_timeslot.to_le_bytes())
    }

    fn verify_proof(
        &self,
        request: &ProofVerificationRequestV2,
        proof: &[u8],
    ) -> ProductionTrustDecisionV2 {
        let request = request.encode();
        let Some(payload) = encode_pair(&request, proof) else {
            return ProductionTrustDecisionV2::Unavailable;
        };
        self.decision(VERIFY_PROOF, &payload)
    }

    fn verify_install(&self, genesis: &ServiceGenesisV2) -> ProductionTrustDecisionV2 {
        self.decision(VERIFY_INSTALL, &genesis.encode())
    }

    fn verify_upgrade(&self, upgrade: &ActorUpgradeV2) -> ProductionTrustDecisionV2 {
        self.decision(VERIFY_UPGRADE, &upgrade.encode())
    }

    fn verify_role_credential(
        &self,
        request: &RoleCredentialVerificationRequestV2,
    ) -> ProductionTrustDecisionV2 {
        self.decision(VERIFY_ROLE, &request.encode())
    }

    fn verify_receipt(&self, request: &ReceiptVerificationRequestV2) -> ProductionTrustDecisionV2 {
        self.decision(VERIFY_RECEIPT, &request.encode())
    }
}

fn encode_request(tag: u8, payload: &[u8]) -> Result<Vec<u8>, ProductionTrustSocketError> {
    if payload.len() > MAX_FRAME_BYTES.saturating_sub(11) {
        return Err(ProductionTrustSocketError::InvalidResponse);
    }
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| ProductionTrustSocketError::InvalidResponse)?;
    let mut request = Vec::with_capacity(11 + payload.len());
    request.extend_from_slice(&REQUEST_MAGIC);
    request.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
    request.push(tag);
    request.extend_from_slice(&payload_len.to_le_bytes());
    request.extend_from_slice(payload);
    Ok(request)
}

fn encode_pair(left: &[u8], right: &[u8]) -> Option<Vec<u8>> {
    let left_len = u32::try_from(left.len()).ok()?;
    let right_len = u32::try_from(right.len()).ok()?;
    let total = 8usize.checked_add(left.len())?.checked_add(right.len())?;
    if total > MAX_FRAME_BYTES.saturating_sub(11) {
        return None;
    }
    let mut payload = Vec::with_capacity(total);
    payload.extend_from_slice(&left_len.to_le_bytes());
    payload.extend_from_slice(left);
    payload.extend_from_slice(&right_len.to_le_bytes());
    payload.extend_from_slice(right);
    Some(payload)
}

#[cfg(unix)]
fn exchange(path: &Path, request: &[u8]) -> Result<TrustResponse, ProductionTrustSocketError> {
    let request_hash = Hash::digest(b"vos/production-trust-socket/request/v1", &[request]);
    let mut stream = UnixStream::connect(path).map_err(ProductionTrustSocketError::Connect)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(ProductionTrustSocketError::Io)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(ProductionTrustSocketError::Io)?;
    let request_len =
        u32::try_from(request.len()).map_err(|_| ProductionTrustSocketError::InvalidResponse)?;
    stream
        .write_all(&request_len.to_le_bytes())
        .and_then(|()| stream.write_all(request))
        .map_err(ProductionTrustSocketError::Io)?;

    let mut len = [0u8; 4];
    stream
        .read_exact(&mut len)
        .map_err(ProductionTrustSocketError::Io)?;
    let len = u32::from_le_bytes(len) as usize;
    if len < 71 || len > 79 {
        return Err(ProductionTrustSocketError::InvalidResponse);
    }
    let mut response = vec![0; len];
    stream
        .read_exact(&mut response)
        .map_err(ProductionTrustSocketError::Io)?;
    decode_response(&response, request_hash)
}

#[cfg(not(unix))]
fn exchange(_path: &Path, _request: &[u8]) -> Result<TrustResponse, ProductionTrustSocketError> {
    Err(ProductionTrustSocketError::Unsupported)
}

fn decode_response(
    bytes: &[u8],
    expected_request: Hash,
) -> Result<TrustResponse, ProductionTrustSocketError> {
    if bytes.get(..4) != Some(&RESPONSE_MAGIC)
        || bytes.get(4..6) != Some(PROTOCOL_VERSION.to_le_bytes().as_slice())
        || bytes.get(6..38) != Some(expected_request.0.as_slice())
    {
        return Err(ProductionTrustSocketError::InvalidResponse);
    }
    let policy = Hash(
        bytes
            .get(38..70)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(ProductionTrustSocketError::InvalidResponse)?,
    );
    let result = *bytes
        .get(70)
        .ok_or(ProductionTrustSocketError::InvalidResponse)?;
    let timeslot = match result {
        AUTHORIZED | DENIED | UNAVAILABLE | NO_TIMESLOT | POLICY if bytes.len() == 71 => None,
        TIMESLOT if bytes.len() == 79 => Some(u64::from_le_bytes(
            bytes[71..79]
                .try_into()
                .map_err(|_| ProductionTrustSocketError::InvalidResponse)?,
        )),
        _ => return Err(ProductionTrustSocketError::InvalidResponse),
    };
    Ok(TrustResponse {
        policy,
        result,
        timeslot,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    fn temp_socket(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "vos-production-trust-{label}-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ))
    }

    fn respond_once(
        path: PathBuf,
        policy: Hash,
        result: u8,
        timeslot: Option<u64>,
        corrupt_request: bool,
    ) -> thread::JoinHandle<()> {
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).unwrap();
            let mut request = vec![0; u32::from_le_bytes(len) as usize];
            stream.read_exact(&mut request).unwrap();
            let mut request_hash =
                Hash::digest(b"vos/production-trust-socket/request/v1", &[&request]);
            if corrupt_request {
                request_hash.0[0] ^= 1;
            }
            let mut response = Vec::new();
            response.extend_from_slice(&RESPONSE_MAGIC);
            response.extend_from_slice(&PROTOCOL_VERSION.to_le_bytes());
            response.extend_from_slice(&request_hash.0);
            response.extend_from_slice(&policy.0);
            response.push(result);
            if let Some(timeslot) = timeslot {
                response.extend_from_slice(&timeslot.to_le_bytes());
            }
            let len = u32::try_from(response.len()).unwrap();
            stream.write_all(&len.to_le_bytes()).unwrap();
            stream.write_all(&response).unwrap();
        })
    }

    #[test]
    fn policy_handshake_is_exact_and_nonzero() {
        let path = temp_socket("handshake");
        let policy = Hash([7; 32]);
        let server = respond_once(path.clone(), policy, POLICY, None, false);
        let trust = SocketProductionTrustV2::open(&path).unwrap();
        assert_eq!(trust.policy_id(), policy);
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reconnect_policy_change_fails_closed() {
        let path = temp_socket("policy-change");
        let server = respond_once(path.clone(), Hash([8; 32]), POLICY, None, false);
        let trust = SocketProductionTrustV2::open(&path).unwrap();
        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();

        let server = respond_once(path.clone(), Hash([9; 32]), AUTHORIZED, None, false);
        assert_eq!(
            trust.verify_logical_timeslot(4),
            ProductionTrustDecisionV2::Unavailable,
        );
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn current_slot_and_request_commitment_are_checked() {
        let path = temp_socket("slot");
        let policy = Hash([10; 32]);
        let server = respond_once(path.clone(), policy, POLICY, None, false);
        let trust = SocketProductionTrustV2::open(&path).unwrap();
        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();

        let server = respond_once(path.clone(), policy, TIMESLOT, Some(77), false);
        assert_eq!(trust.logical_timeslot(), Some(77));
        server.join().unwrap();
        std::fs::remove_file(&path).unwrap();

        let server = respond_once(path.clone(), policy, AUTHORIZED, None, true);
        assert_eq!(
            trust.verify_logical_timeslot(77),
            ProductionTrustDecisionV2::Unavailable,
        );
        server.join().unwrap();
        let _ = std::fs::remove_file(path);
    }
}
