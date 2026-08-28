//! Kreivo-first Substrate light-client extension for VOS.
//!
//! The public wire surface stays `no_std`: actor crates can depend on this
//! crate with `default-features = false` and use [`SubstrateExtensionRef`]
//! without linking smoldot. The default host build adds the native light
//! client and exports a loadable VOS extension.

#![cfg_attr(any(target_arch = "riscv64", target_arch = "wasm32"), no_std)]

use vos::prelude::*;

/// Maximum encoded success payload returned by this extension. The VOS invoke
/// envelope has additional framing, so this remains below its 8 KiB buffer.
pub const MAX_REPLY_BYTES: usize = 7 * 1024;
/// Maximum map rows per request.
pub const MAX_MAP_PAGE: u32 = 32;
/// Maximum live snapshot cursors retained for one caller.
pub const MAX_MAP_SNAPSHOTS: usize = 16;
/// Map snapshot cursors expire after four minutes of inactivity.
pub const MAP_SNAPSHOT_TTL_SECS: u64 = 240;
/// Maximum outstanding external-signature requests for one caller.
pub const MAX_PENDING_TRANSACTIONS: usize = 32;
/// External signing requests expire after four minutes.
pub const SIGNING_REQUEST_TTL_SECS: u64 = 240;

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum ErrorCode {
    BadRequest = 1,
    Unsupported = 2,
    Unavailable = 3,
    Busy = 4,
    NotFound = 5,
    Expired = 6,
    Chain = 7,
    Encoding = 8,
    InvalidSignature = 9,
    Stale = 10,
    ReplyTooLarge = 11,
    Forbidden = 12,
    /// A prior automatic-nonce submission may still finalize. Callers must
    /// wait for finalized nonce advancement or provide an explicit nonce.
    NonceUncertain = 13,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ExtensionError {
    pub code: ErrorCode,
    pub message: String,
}

impl ExtensionError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        const MAX_ERROR_LEN: usize = 384;
        if message.len() > MAX_ERROR_LEN {
            let mut boundary = MAX_ERROR_LEN;
            while !message.is_char_boundary(boundary) {
                boundary -= 1;
            }
            message.truncate(boundary);
        }
        Self { code, message }
    }
}

/// Application-level result. Transport failures still use the outer
/// `ClientError` returned by generated Ref methods.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub enum SubstrateResult<T> {
    Ok(T),
    Err(ExtensionError),
}

impl<T> SubstrateResult<T> {
    fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Err(ExtensionError::new(code, message))
    }
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum SignatureScheme {
    Sr25519 = 0,
    Ed25519 = 1,
    Ecdsa = 2,
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum Inclusion {
    BestBlock = 0,
    Finalized = 1,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct BlockRef {
    pub number: u64,
    pub hash: [u8; 32],
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ChainStatus {
    pub network: String,
    pub genesis_hash: [u8; 32],
    pub finalized: BlockRef,
    pub ss58_format: Option<u16>,
    pub token_symbols: Vec<String>,
    pub token_decimals: Vec<u32>,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct QueryResult {
    pub at: BlockRef,
    /// Metadata-rendered SCALE value. `None` means the storage key is absent.
    pub value: Option<String>,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct MapEntry {
    pub keys: Vec<String>,
    pub value: Option<String>,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct MapPage {
    pub at: BlockRef,
    pub entries: Vec<MapEntry>,
    /// Opaque, path-bound cursor. Empty means the scan is complete.
    pub next_cursor: Vec<u8>,
}

/// Metadata-driven V4 call to prepare for an external signer.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct TransactionRequest {
    /// `pallet/call` path, for example `balances/transfer_keep_alive`.
    pub call_path: String,
    /// Call fields in Sube/scales text syntax.
    pub call_body: String,
    pub signing_account: Vec<u8>,
    pub nonce_account: Vec<u8>,
    pub scheme: SignatureScheme,
    /// `None` performs one on-chain nonce lookup. Only one such pending
    /// request per nonce account is allowed at a time.
    pub nonce: Option<u64>,
    pub tip: u64,
    /// `0` means immortal; otherwise this is the mortal era period.
    pub mortality_period: u64,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct SigningExtension {
    pub identifier: String,
    pub extra_hex: String,
    pub additional_signed_hex: String,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct SigningPayload {
    pub request_id: u64,
    /// Exact bytes to sign. Payloads over 256 bytes have already been
    /// Blake2-256 hashed according to Substrate's signing rule.
    pub payload: Vec<u8>,
    pub encoded_call: Vec<u8>,
    pub signing_account: Vec<u8>,
    pub nonce_account: Vec<u8>,
    pub scheme: SignatureScheme,
    pub nonce: u64,
    pub genesis_hash: [u8; 32],
    pub checkpoint: BlockRef,
    pub expires_at: Option<u64>,
    pub spec_version: u32,
    pub transaction_version: u32,
    pub extensions: Vec<SigningExtension>,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct TransactionEvent {
    pub pallet: String,
    pub variant: String,
    pub decoded: Option<String>,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct TransactionResult {
    /// Blake2b-256 hash of the exact submitted extrinsic bytes.
    pub extrinsic_hash: [u8; 32],
    /// Exact submitted bytes when they fit the bounded reply. The hash is
    /// always present when this optional audit field is omitted.
    pub extrinsic_hex: Option<String>,
    pub best_block_hash: Option<String>,
    pub finalized_block_hash: Option<String>,
    pub extrinsic_index: Option<u32>,
    pub dispatch_outcome: String,
    pub events: Vec<TransactionEvent>,
    pub events_truncated: bool,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct Config {
    network: String,
    chain_spec_path: String,
    relay_spec_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: "kreivo-kusama".into(),
            chain_spec_path: String::new(),
            relay_spec_path: String::new(),
        }
    }
}

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
enum NonceReservationState {
    AwaitingSignature = 0,
    SubmissionUnknown = 1,
}

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct NonceReservation {
    request_id: u64,
    owner: [u8; 32],
    nonce_account: Vec<u8>,
    nonce: u64,
    state: NonceReservationState,
}

#[cfg(feature = "native")]
#[derive(Default)]
struct NativeRuntime {
    // Declared first: dropping the actor stops and joins smoldot before the
    // pending request records are released or the cdylib can be unmapped.
    client: Option<sube::Sube>,
    pending: Vec<PendingTransaction>,
    map_snapshots: Vec<MapSnapshot>,
    next_snapshot_id: u64,
}

#[cfg(not(feature = "native"))]
#[derive(Default)]
struct NativeRuntime;

/// Trusted host adapter for bounded Substrate queries and externally-signed
/// V4 transactions. It never accepts or stores signing keys.
#[actor]
pub struct SubstrateExtension {
    config: Config,
    next_request_id: u64,
    // Automatic-nonce uncertainty crosses light-client reconnects and actor
    // reloads. Awaiting reservations can be cancelled; once submission starts
    // only finalized nonce advancement can retire the reservation.
    nonce_reservations: Vec<NonceReservation>,
    #[rkyv(with = vos::rkyv::with::Skip)]
    runtime: NativeRuntime,
}

#[messages]
impl SubstrateExtension {
    /// Optional init keys: `network`, `chain_spec_path`, `relay_spec_path`.
    /// Empty paths select the pinned bundled Kreivo/Kusama specifications.
    pub fn new(raw_args: &[u8]) -> Self {
        let args = vos::value::Args::try_decode(raw_args).unwrap_or_default();
        let mut config = Config::default();
        if let Some(value) = args.get_str("network") {
            config.network = bounded_config_value(value);
        }
        if let Some(value) = args.get_str("chain_spec_path") {
            config.chain_spec_path = bounded_config_value(value);
        }
        if let Some(value) = args.get_str("relay_spec_path") {
            config.relay_spec_path = bounded_config_value(value);
        }
        Self {
            config,
            next_request_id: 1,
            nonce_reservations: Vec::new(),
            runtime: NativeRuntime::default(),
        }
    }

    /// Connect lazily and report finalized light-client state.
    #[msg(timeout_ms = 120000)]
    async fn status(&mut self, _ctx: &mut Context<Self>) -> SubstrateResult<ChainStatus> {
        #[cfg(feature = "native")]
        return self.native_status_with_deadline().await;
        #[cfg(not(feature = "native"))]
        SubstrateResult::error(ErrorCode::Unsupported, "native backend is disabled")
    }

    /// Query one constant or fully-keyed storage item. `at = None` captures
    /// the current finalized block. Reusing a returned `BlockRef` queries that
    /// exact authenticated hash without requiring an archive node.
    #[msg(timeout_ms = 120000)]
    async fn query(
        &mut self,
        path: String,
        at: Option<BlockRef>,
        _ctx: &mut Context<Self>,
    ) -> SubstrateResult<QueryResult> {
        #[cfg(feature = "native")]
        return self.native_query_with_deadline(path, at).await;
        #[cfg(not(feature = "native"))]
        {
            let _ = (path, at);
            SubstrateResult::error(ErrorCode::Unsupported, "native backend is disabled")
        }
    }

    /// Query at most 32 rows from a partially-keyed storage map. Continue by
    /// passing the opaque cursor returned by the previous page. A bounded
    /// proof page may contain fewer rows while still returning a cursor.
    #[msg(timeout_ms = 120000)]
    async fn query_map(
        &mut self,
        path: String,
        limit: u32,
        cursor: Vec<u8>,
        ctx: &mut Context<Self>,
    ) -> SubstrateResult<MapPage> {
        #[cfg(feature = "native")]
        {
            let owner = native::CallerKey::from_caller(ctx.caller());
            let invocation = ctx.invocation_id();
            return self
                .native_query_map_with_deadline(path, limit, cursor, owner, invocation)
                .await;
        }
        #[cfg(not(feature = "native"))]
        {
            let _ = (path, limit, cursor);
            SubstrateResult::error(ErrorCode::Unsupported, "native backend is disabled")
        }
    }

    /// Prepare an exact V4 payload for an external signer. No transaction is
    /// submitted and no private key material enters this extension.
    #[msg(timeout_ms = 120000)]
    async fn prepare_transaction(
        &mut self,
        request: TransactionRequest,
        ctx: &mut Context<Self>,
    ) -> SubstrateResult<SigningPayload> {
        #[cfg(feature = "native")]
        {
            let owner = native::CallerKey::from_caller(ctx.caller());
            if !owner.is_authenticated() {
                return SubstrateResult::error(
                    ErrorCode::Forbidden,
                    "transaction preparation requires an authenticated caller",
                );
            }
            let invocation = ctx.invocation_id();
            return self
                .native_prepare_transaction_with_deadline(request, owner, invocation)
                .await;
        }
        #[cfg(not(feature = "native"))]
        {
            let _ = request;
            SubstrateResult::error(ErrorCode::Unsupported, "native backend is disabled")
        }
    }

    /// Finish and synchronously submit a prepared request, waiting for best
    /// inclusion or finalization. A valid request is consumed immediately
    /// before network submission.
    #[msg(timeout_ms = 240000)]
    async fn submit_transaction(
        &mut self,
        request_id: u64,
        signature: Vec<u8>,
        wait_for: Inclusion,
        ctx: &mut Context<Self>,
    ) -> SubstrateResult<TransactionResult> {
        #[cfg(feature = "native")]
        {
            let owner = native::CallerKey::from_caller(ctx.caller());
            if !owner.is_authenticated() {
                return SubstrateResult::error(
                    ErrorCode::Forbidden,
                    "transaction submission requires an authenticated caller",
                );
            }
            return self
                .native_submit_transaction_with_deadline(request_id, signature, wait_for, owner)
                .await;
        }
        #[cfg(not(feature = "native"))]
        {
            let _ = (request_id, signature, wait_for);
            SubstrateResult::error(ErrorCode::Unsupported, "native backend is disabled")
        }
    }

    /// Release a prepared request without submitting it.
    #[msg]
    async fn cancel_transaction(
        &mut self,
        request_id: u64,
        ctx: &mut Context<Self>,
    ) -> SubstrateResult<bool> {
        #[cfg(feature = "native")]
        {
            let owner = native::CallerKey::from_caller(ctx.caller());
            if !owner.is_authenticated() {
                return SubstrateResult::error(
                    ErrorCode::Forbidden,
                    "transaction cancellation requires an authenticated caller",
                );
            }
            return SubstrateResult::Ok(self.native_cancel_transaction(request_id, &owner));
        }
        #[cfg(not(feature = "native"))]
        {
            let _ = request_id;
            SubstrateResult::error(ErrorCode::Unsupported, "native backend is disabled")
        }
    }
}

fn bounded_config_value(mut value: String) -> String {
    const MAX_CONFIG_LEN: usize = 4096;
    if value.len() > MAX_CONFIG_LEN {
        let mut boundary = MAX_CONFIG_LEN;
        while !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value.truncate(boundary);
    }
    value
}

#[cfg(any(feature = "native", test))]
const CURSOR_VERSION: u8 = 1;

#[cfg(any(feature = "native", test))]
fn encode_cursor(path: &str, snapshot_id: u64, at: &BlockRef, start_key: &[u8]) -> Option<Vec<u8>> {
    let path_len = u16::try_from(path.len()).ok()?;
    let key_len = u16::try_from(start_key.len()).ok()?;
    let mut cursor = Vec::with_capacity(1 + 8 + 8 + 32 + 2 + path.len() + 2 + start_key.len());
    cursor.push(CURSOR_VERSION);
    cursor.extend_from_slice(&snapshot_id.to_le_bytes());
    cursor.extend_from_slice(&at.number.to_le_bytes());
    cursor.extend_from_slice(&at.hash);
    cursor.extend_from_slice(&path_len.to_le_bytes());
    cursor.extend_from_slice(path.as_bytes());
    cursor.extend_from_slice(&key_len.to_le_bytes());
    cursor.extend_from_slice(start_key);
    Some(cursor)
}

#[cfg(any(feature = "native", test))]
fn decode_cursor(
    path: &str,
    cursor: &[u8],
) -> core::result::Result<(u64, u64, [u8; 32], Vec<u8>), ExtensionError> {
    if cursor.len() < 53 || cursor[0] != CURSOR_VERSION {
        return Err(ExtensionError::new(
            ErrorCode::BadRequest,
            "invalid map cursor",
        ));
    }
    let snapshot_id = u64::from_le_bytes(cursor[1..9].try_into().unwrap());
    let number = u64::from_le_bytes(cursor[9..17].try_into().unwrap());
    let hash: [u8; 32] = cursor[17..49].try_into().unwrap();
    let path_len = u16::from_le_bytes(cursor[49..51].try_into().unwrap()) as usize;
    let path_end = 51usize
        .checked_add(path_len)
        .ok_or_else(|| ExtensionError::new(ErrorCode::BadRequest, "invalid map cursor"))?;
    let key_len_end = path_end
        .checked_add(2)
        .ok_or_else(|| ExtensionError::new(ErrorCode::BadRequest, "invalid map cursor"))?;
    let encoded_path = cursor
        .get(51..path_end)
        .ok_or_else(|| ExtensionError::new(ErrorCode::BadRequest, "invalid map cursor"))?;
    if encoded_path != path.as_bytes() {
        return Err(ExtensionError::new(
            ErrorCode::BadRequest,
            "map cursor belongs to a different path",
        ));
    }
    let key_len_bytes: [u8; 2] = cursor
        .get(path_end..key_len_end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| ExtensionError::new(ErrorCode::BadRequest, "invalid map cursor"))?;
    let key_len = u16::from_le_bytes(key_len_bytes) as usize;
    let key_end = key_len_end
        .checked_add(key_len)
        .ok_or_else(|| ExtensionError::new(ErrorCode::BadRequest, "invalid map cursor"))?;
    if key_end != cursor.len() {
        return Err(ExtensionError::new(
            ErrorCode::BadRequest,
            "invalid map cursor length",
        ));
    }
    Ok((
        snapshot_id,
        number,
        hash,
        cursor[key_len_end..key_end].to_vec(),
    ))
}

#[cfg(feature = "native")]
mod native {
    use super::*;
    use core::time::Duration;
    use std::{fs, io::Read, time::Instant};

    use sube::{Backend as _, DispatchOutcome, Response, TransactionOptions};

    const MAX_PATH_LEN: usize = 256;
    const MAX_CALL_BODY_LEN: usize = 2048;
    const MAX_CHAIN_SPEC_BYTES: u64 = 16 * 1024 * 1024;
    const MAX_RECEIPT_EVENTS: usize = 16;
    const MAX_TOTAL_MAP_SNAPSHOTS: usize = 64;
    const MAX_TOTAL_PENDING_TRANSACTIONS: usize = 128;
    const MAX_TOTAL_NONCE_RESERVATIONS: usize = 128;
    const LIGHT_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(90);
    pub(super) const STANDARD_DEADLINE: Duration = Duration::from_secs(105);
    pub(super) const SUBMISSION_DEADLINE: Duration = Duration::from_secs(210);
    const BACKEND_CANCELLATION_DEADLINE: Duration = Duration::from_secs(10);
    const TRANSACTION_WATCH_TIMEOUT: Duration = Duration::from_secs(180);

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) enum CallerKey {
        Unauthenticated,
        System,
        Peer(Vec<u8>),
        Member([u8; 32]),
        Actor(u32),
    }

    impl CallerKey {
        pub(super) fn from_caller(caller: &vos::Caller) -> Self {
            match caller {
                vos::Caller::Unauthenticated => Self::Unauthenticated,
                vos::Caller::System => Self::System,
                vos::Caller::Peer(peer) => Self::Peer(peer.clone()),
                vos::Caller::Member(subject) => Self::Member(subject.0),
                vos::Caller::Actor(service) => Self::Actor(service.0),
            }
        }

        pub(super) fn is_authenticated(&self) -> bool {
            !matches!(self, Self::Unauthenticated)
        }

        fn encoded(&self) -> Vec<u8> {
            match self {
                Self::Unauthenticated => vec![0],
                Self::System => vec![1],
                Self::Peer(peer) => [&[2][..], peer.as_slice()].concat(),
                Self::Member(subject) => [&[3][..], subject.as_slice()].concat(),
                Self::Actor(service) => [&[4][..], &service.to_le_bytes()].concat(),
            }
        }

        fn reservation_owner(&self) -> [u8; 32] {
            let encoded = self.encoded();
            vos::crypto::blake2b_hash::<32>(b"vos/substrate/nonce-owner", &[&encoded])
        }
    }

    pub(super) fn capability_id(
        domain: &[u8],
        owner: &CallerKey,
        invocation: InvocationId,
        counter: u64,
    ) -> u64 {
        let counter = counter.to_le_bytes();
        let owner = owner.encoded();
        let digest = vos::crypto::blake2b_hash::<32>(
            domain,
            &[invocation.as_bytes(), &counter, owner.as_slice()],
        );
        u64::from_le_bytes(
            digest[..8]
                .try_into()
                .expect("eight-byte capability prefix"),
        )
        .max(1)
    }

    pub(super) struct PendingTransaction {
        id: u64,
        owner: CallerKey,
        created: Instant,
        automatic_nonce: bool,
        metadata: sube::Rc<sube::Metadata>,
        request: sube::ExternalSigningRequest,
    }

    #[derive(Clone)]
    pub(super) struct MapSnapshot {
        pub(super) id: u64,
        pub(super) owner: CallerKey,
        pub(super) last_used: Instant,
        pub(super) path: String,
        pub(super) at: BlockRef,
        pub(super) next_key: Vec<u8>,
        pub(super) started: bool,
        pub(super) active_invocation: InvocationId,
    }

    impl SubstrateExtension {
        async fn ensure_client(&mut self) -> core::result::Result<&mut sube::Sube, ExtensionError> {
            if self.runtime.client.is_none() {
                if self.config.network != "kreivo-kusama"
                    && (self.config.chain_spec_path.is_empty()
                        || self.config.relay_spec_path.is_empty())
                {
                    return Err(ExtensionError::new(
                        ErrorCode::BadRequest,
                        "custom network requires both chain_spec_path and relay_spec_path",
                    ));
                }
                let chain_spec = load_chain_spec(
                    &self.config.chain_spec_path,
                    include_bytes!("../assets/kreivo-kusama.json.zst"),
                )?;
                let relay_spec = load_chain_spec(
                    &self.config.relay_spec_path,
                    include_bytes!("../assets/kusama.json.zst"),
                )?;
                let client = sube::Sube::connect_light_para_with_timeout(
                    &chain_spec,
                    &relay_spec,
                    LIGHT_CLIENT_CONNECT_TIMEOUT,
                )
                .await
                .map_err(map_sube_error)?;
                self.runtime.client = Some(client);
            }
            self.runtime.client.as_mut().ok_or_else(|| {
                ExtensionError::new(ErrorCode::Unavailable, "light client unavailable")
            })
        }

        fn expire_pending(&mut self) {
            let ttl = Duration::from_secs(SIGNING_REQUEST_TTL_SECS);
            let expired = self
                .runtime
                .pending
                .iter()
                .filter(|pending| pending.created.elapsed() > ttl)
                .map(|pending| pending.id)
                .collect::<Vec<_>>();
            self.runtime
                .pending
                .retain(|pending| !expired.contains(&pending.id));
            self.nonce_reservations.retain(|reservation| {
                reservation.state == NonceReservationState::SubmissionUnknown
                    || !expired.contains(&reservation.request_id)
            });
        }

        fn release_nonce_reservation(&mut self, request_id: u64) {
            self.nonce_reservations
                .retain(|reservation| reservation.request_id != request_id);
        }

        fn mark_nonce_submission_unknown(&mut self, request_id: u64) -> bool {
            if let Some(reservation) = self
                .nonce_reservations
                .iter_mut()
                .find(|reservation| reservation.request_id == request_id)
            {
                reservation.state = NonceReservationState::SubmissionUnknown;
                true
            } else {
                false
            }
        }

        fn expire_map_snapshots(&mut self) {
            let ttl = Duration::from_secs(MAP_SNAPSHOT_TTL_SECS);
            let mut expired = Vec::new();
            self.runtime.map_snapshots.retain(|snapshot| {
                if snapshot.last_used.elapsed() <= ttl {
                    true
                } else {
                    expired.push(snapshot.at.hash);
                    false
                }
            });
            if let Some(client) = self.runtime.client.as_mut() {
                for hash in expired {
                    client.release_finalized_hash(hash);
                }
            }
        }

        fn allocate_snapshot_id(
            &mut self,
            owner: &CallerKey,
            invocation: InvocationId,
        ) -> Option<u64> {
            for _ in 0..=MAX_TOTAL_MAP_SNAPSHOTS {
                let counter = self.runtime.next_snapshot_id;
                self.runtime.next_snapshot_id = counter.wrapping_add(1);
                let candidate =
                    capability_id(b"vos/substrate/map-snapshot", owner, invocation, counter);
                if self
                    .runtime
                    .map_snapshots
                    .iter()
                    .all(|snapshot| snapshot.id != candidate)
                {
                    return Some(candidate);
                }
            }
            None
        }

        fn release_map_snapshot(&mut self, snapshot: MapSnapshot) {
            if let Some(client) = self.runtime.client.as_mut() {
                client.release_finalized_hash(snapshot.at.hash);
            }
        }

        pub(super) fn take_map_snapshot(
            &mut self,
            id: u64,
            owner: &CallerKey,
        ) -> Option<MapSnapshot> {
            self.runtime
                .map_snapshots
                .iter()
                .position(|snapshot| snapshot.id == id && &snapshot.owner == owner)
                .map(|position| self.runtime.map_snapshots.swap_remove(position))
        }

        async fn cancel_backend_operation(&mut self) {
            let cleanup_succeeded = if let Some(client) = self.runtime.client.as_mut() {
                matches!(
                    sube::time::timeout(
                        BACKEND_CANCELLATION_DEADLINE,
                        client.cancel_active_operation(),
                    )
                    .await,
                    Ok(Ok(()))
                )
            } else {
                true
            };
            if !cleanup_succeeded {
                // A client with unconfirmed server-side cleanup is poisoned:
                // dropping it closes every subscription and joins its owned
                // runtime. Snapshot pins belong to that session and are no
                // longer reusable.
                self.runtime.client = None;
                self.runtime.map_snapshots.clear();
            }
        }

        async fn cancel_map_invocation(&mut self, owner: &CallerKey, invocation: InvocationId) {
            self.cancel_backend_operation().await;
            let snapshots = self
                .runtime
                .map_snapshots
                .extract_if(.., |snapshot| {
                    &snapshot.owner == owner && snapshot.active_invocation == invocation
                })
                .collect::<Vec<_>>();
            for snapshot in snapshots {
                self.release_map_snapshot(snapshot);
            }
        }

        fn allocate_request_id(
            &mut self,
            owner: &CallerKey,
            invocation: InvocationId,
        ) -> Option<u64> {
            for _ in 0..=(MAX_TOTAL_PENDING_TRANSACTIONS + MAX_TOTAL_NONCE_RESERVATIONS) {
                let counter = self.next_request_id;
                self.next_request_id = counter.wrapping_add(1);
                let candidate =
                    capability_id(b"vos/substrate/signing-request", owner, invocation, counter);
                if self
                    .runtime
                    .pending
                    .iter()
                    .all(|pending| pending.id != candidate)
                    && self
                        .nonce_reservations
                        .iter()
                        .all(|reservation| reservation.request_id != candidate)
                {
                    return Some(candidate);
                }
            }
            None
        }

        pub(super) async fn native_status_with_deadline(&mut self) -> SubstrateResult<ChainStatus> {
            match sube::time::timeout(STANDARD_DEADLINE, self.native_status()).await {
                Ok(result) => {
                    if let SubstrateResult::Err(_) = &result {
                        self.cancel_backend_operation().await;
                    }
                    result
                }
                Err(_) => {
                    self.cancel_backend_operation().await;
                    SubstrateResult::error(ErrorCode::Unavailable, "operation timed out")
                }
            }
        }

        pub(super) async fn native_query_with_deadline(
            &mut self,
            path: String,
            at: Option<BlockRef>,
        ) -> SubstrateResult<QueryResult> {
            match sube::time::timeout(STANDARD_DEADLINE, self.native_query(path, at)).await {
                Ok(result) => {
                    if let SubstrateResult::Err(_) = &result {
                        self.cancel_backend_operation().await;
                    }
                    result
                }
                Err(_) => {
                    self.cancel_backend_operation().await;
                    SubstrateResult::error(ErrorCode::Unavailable, "operation timed out")
                }
            }
        }

        pub(super) async fn native_prepare_transaction_with_deadline(
            &mut self,
            request: TransactionRequest,
            owner: CallerKey,
            invocation: InvocationId,
        ) -> SubstrateResult<SigningPayload> {
            match sube::time::timeout(
                STANDARD_DEADLINE,
                self.native_prepare_transaction(request, owner, invocation),
            )
            .await
            {
                Ok(result) => {
                    if let SubstrateResult::Err(_) = &result {
                        self.cancel_backend_operation().await;
                    }
                    result
                }
                Err(_) => {
                    self.cancel_backend_operation().await;
                    SubstrateResult::error(ErrorCode::Unavailable, "operation timed out")
                }
            }
        }

        pub(super) async fn native_status(&mut self) -> SubstrateResult<ChainStatus> {
            let network = self.config.network.clone();
            let result = async {
                let client = self.ensure_client().await?;
                let genesis = client
                    .backend()
                    .block_info(Some(0))
                    .await
                    .map_err(map_sube_error)?;
                let finalized = client
                    .backend()
                    .block_info(None)
                    .await
                    .map_err(map_sube_error)?;
                let properties = client
                    .chain_properties()
                    .await
                    .map_err(map_sube_error)?
                    .clone();
                Ok(ChainStatus {
                    network,
                    genesis_hash: genesis.hash,
                    finalized: block_ref(finalized),
                    ss58_format: properties.ss58_format,
                    token_symbols: properties.token_symbols,
                    token_decimals: properties.token_decimals,
                })
            }
            .await;
            bounded_result(result)
        }

        pub(super) async fn native_query(
            &mut self,
            path: String,
            at: Option<BlockRef>,
        ) -> SubstrateResult<QueryResult> {
            if let Err(error) = validate_query_path(&path) {
                return SubstrateResult::Err(error);
            }
            let result = async {
                let client = self.ensure_client().await?;
                let block = match at {
                    Some(at) => {
                        let block = client
                            .block_info_at_hash(at.hash)
                            .await
                            .map_err(map_sube_error)?;
                        if block.number != at.number {
                            return Err(ExtensionError::new(
                                ErrorCode::BadRequest,
                                "block number does not match the supplied hash",
                            ));
                        }
                        block
                    }
                    None => client
                        .backend()
                        .block_info(None)
                        .await
                        .map_err(map_sube_error)?,
                };
                let response = client
                    .query_at_finalized_hash(&path, block.hash)
                    .await
                    .map_err(map_sube_error)?;
                let value = match response {
                    Response::Value(value, metadata) => {
                        Some(value.to_text(&metadata.registry).map_err(map_sube_error)?)
                    }
                    Response::None => None,
                    Response::ValueSet(_, _) => {
                        return Err(ExtensionError::new(
                            ErrorCode::BadRequest,
                            "partial maps must use query_map",
                        ));
                    }
                    Response::Meta(_) | Response::Void => {
                        return Err(ExtensionError::new(
                            ErrorCode::BadRequest,
                            "unsupported query response",
                        ));
                    }
                };
                Ok(QueryResult {
                    at: block_ref(block),
                    value,
                })
            }
            .await;
            bounded_result(result)
        }

        pub(super) async fn native_query_map_with_deadline(
            &mut self,
            path: String,
            limit: u32,
            cursor: Vec<u8>,
            owner: CallerKey,
            invocation: InvocationId,
        ) -> SubstrateResult<MapPage> {
            let cleanup_owner = owner.clone();
            match sube::time::timeout(
                STANDARD_DEADLINE,
                self.native_query_map(path, limit, cursor, owner, invocation),
            )
            .await
            {
                Ok(result) => {
                    if let SubstrateResult::Err(_) = &result {
                        self.cancel_map_invocation(&cleanup_owner, invocation).await;
                    }
                    result
                }
                Err(_) => {
                    self.cancel_map_invocation(&cleanup_owner, invocation).await;
                    SubstrateResult::error(ErrorCode::Unavailable, "operation timed out")
                }
            }
        }

        async fn native_query_map(
            &mut self,
            path: String,
            limit: u32,
            cursor: Vec<u8>,
            owner: CallerKey,
            invocation: InvocationId,
        ) -> SubstrateResult<MapPage> {
            if let Err(error) = validate_query_path(&path) {
                return SubstrateResult::Err(error);
            }
            if limit == 0 || limit > MAX_MAP_PAGE {
                return SubstrateResult::error(
                    ErrorCode::BadRequest,
                    "map limit must be between 1 and 32",
                );
            }
            self.expire_map_snapshots();

            let snapshot_id = if cursor.is_empty() {
                if self.runtime.map_snapshots.len() >= MAX_TOTAL_MAP_SNAPSHOTS
                    || self
                        .runtime
                        .map_snapshots
                        .iter()
                        .filter(|snapshot| snapshot.owner == owner)
                        .count()
                        >= MAX_MAP_SNAPSHOTS
                {
                    return SubstrateResult::error(
                        ErrorCode::Busy,
                        "too many active map snapshots",
                    );
                }
                let Some(id) = self.allocate_snapshot_id(&owner, invocation) else {
                    return SubstrateResult::error(
                        ErrorCode::Busy,
                        "unable to allocate map snapshot id",
                    );
                };
                let at = {
                    let client = match self.ensure_client().await {
                        Ok(client) => client,
                        Err(error) => return SubstrateResult::Err(error),
                    };
                    let at = match client.backend().block_info(None).await {
                        Ok(at) => at,
                        Err(error) => return SubstrateResult::Err(map_sube_error(error)),
                    };
                    client.retain_finalized_hash(at.hash);
                    block_ref(at)
                };
                self.runtime.map_snapshots.push(MapSnapshot {
                    id,
                    owner: owner.clone(),
                    last_used: Instant::now(),
                    path: path.clone(),
                    at,
                    next_key: Vec::new(),
                    started: false,
                    active_invocation: invocation,
                });
                id
            } else {
                let (id, number, hash, key) = match decode_cursor(&path, &cursor) {
                    Ok(cursor) => cursor,
                    Err(error) => return SubstrateResult::Err(error),
                };
                let Some(position) = self
                    .runtime
                    .map_snapshots
                    .iter()
                    .position(|snapshot| snapshot.id == id && snapshot.owner == owner)
                else {
                    return SubstrateResult::error(
                        ErrorCode::Stale,
                        "map cursor is expired, consumed, or belongs to another instance",
                    );
                };
                let snapshot = &self.runtime.map_snapshots[position];
                if snapshot.path != path
                    || snapshot.at.number != number
                    || snapshot.at.hash != hash
                    || snapshot.next_key != key
                {
                    return SubstrateResult::error(
                        ErrorCode::BadRequest,
                        "map cursor does not match its retained snapshot",
                    );
                }
                self.runtime.map_snapshots[position].active_invocation = invocation;
                id
            };

            let snapshot = self
                .runtime
                .map_snapshots
                .iter()
                .find(|snapshot| snapshot.id == snapshot_id && snapshot.owner == owner)
                .cloned()
                .expect("map snapshot was inserted or validated above");

            let result = async {
                let start_key = if !snapshot.started {
                    None
                } else {
                    Some(snapshot.next_key.clone())
                };
                let client = self.ensure_client().await?;
                let page = client
                    .query_page_at_hash(
                        &path,
                        limit as u16,
                        start_key,
                        sube::BlockInfo {
                            number: snapshot.at.number,
                            hash: snapshot.at.hash,
                            parent: [0; 32],
                        },
                    )
                    .await
                    .map_err(map_sube_error)?;
                let at = block_ref(page.at);
                if at != snapshot.at {
                    return Err(ExtensionError::new(
                        ErrorCode::Stale,
                        "map backend changed the retained snapshot",
                    ));
                }
                let mut entries = Vec::with_capacity(page.entries.len());
                for entry in page.entries {
                    let keys = entry
                        .keys
                        .iter()
                        .map(|key| key.to_text(&page.metadata.registry).map_err(map_sube_error))
                        .collect::<core::result::Result<Vec<_>, _>>()?;
                    let value = entry
                        .value
                        .as_ref()
                        .map(|value| {
                            value
                                .to_text(&page.metadata.registry)
                                .map_err(map_sube_error)
                        })
                        .transpose()?;
                    entries.push(MapEntry { keys, value });
                }
                Ok((at, entries, page.next_key))
            }
            .await;
            let (at, entries, next_key) = match result {
                Ok(result) => result,
                Err(error) => {
                    if let Some(snapshot) = self.take_map_snapshot(snapshot_id, &owner) {
                        self.release_map_snapshot(snapshot);
                    }
                    return SubstrateResult::Err(error);
                }
            };
            let next_cursor = match next_key.as_ref() {
                Some(next_key) => match encode_cursor(&path, snapshot_id, &at, next_key) {
                    Some(cursor) => cursor,
                    None => {
                        if let Some(snapshot) = self.take_map_snapshot(snapshot_id, &owner) {
                            self.release_map_snapshot(snapshot);
                        }
                        return SubstrateResult::error(
                            ErrorCode::Encoding,
                            "map cursor is too large",
                        );
                    }
                },
                None => Vec::new(),
            };
            let reply = SubstrateResult::Ok(MapPage {
                at,
                entries,
                next_cursor,
            });
            if reply.encode().len() > MAX_REPLY_BYTES {
                if let Some(snapshot) = self.take_map_snapshot(snapshot_id, &owner) {
                    self.release_map_snapshot(snapshot);
                }
                return SubstrateResult::error(
                    ErrorCode::ReplyTooLarge,
                    "response exceeds 7 KiB; request a smaller page",
                );
            }
            if matches!(reply, SubstrateResult::Ok(MapPage { ref next_cursor, .. }) if !next_cursor.is_empty())
            {
                let snapshot = self
                    .runtime
                    .map_snapshots
                    .iter_mut()
                    .find(|snapshot| snapshot.id == snapshot_id && snapshot.owner == owner)
                    .expect("active snapshot remains installed until page commit");
                snapshot.next_key = next_key.expect("non-empty cursor has a backend key");
                snapshot.started = true;
                snapshot.last_used = Instant::now();
            } else if let Some(snapshot) = self.take_map_snapshot(snapshot_id, &owner) {
                self.release_map_snapshot(snapshot);
            }
            reply
        }

        pub(super) async fn native_prepare_transaction(
            &mut self,
            request: TransactionRequest,
            owner: CallerKey,
            invocation: InvocationId,
        ) -> SubstrateResult<SigningPayload> {
            self.expire_pending();
            if self.runtime.pending.len() >= MAX_TOTAL_PENDING_TRANSACTIONS
                || self
                    .runtime
                    .pending
                    .iter()
                    .filter(|pending| pending.owner == owner)
                    .count()
                    >= MAX_PENDING_TRANSACTIONS
            {
                return SubstrateResult::error(
                    ErrorCode::Busy,
                    "too many pending signing requests",
                );
            }
            if request.call_path.is_empty()
                || request.call_path.len() > MAX_PATH_LEN
                || request.call_body.len() > MAX_CALL_BODY_LEN
                || request.signing_account.len() != 32
                || request.nonce_account.len() != 32
            {
                return SubstrateResult::error(
                    ErrorCode::BadRequest,
                    "invalid call path/body or account length",
                );
            }
            if request.mortality_period != 0 && !(4..=65_536).contains(&request.mortality_period) {
                return SubstrateResult::error(
                    ErrorCode::BadRequest,
                    "mortality period must be 0 or between 4 and 65536",
                );
            }
            let automatic_nonce = request.nonce.is_none();
            let reservation_owner = owner.reservation_owner();
            let prior_ambiguous_nonce = if automatic_nonce {
                match self
                    .nonce_reservations
                    .iter()
                    .find(|reservation| reservation.nonce_account == request.nonce_account)
                {
                    Some(NonceReservation {
                        state: NonceReservationState::AwaitingSignature,
                        ..
                    }) => {
                        return SubstrateResult::error(
                            ErrorCode::Busy,
                            "an automatic-nonce signing request already exists for this account",
                        );
                    }
                    Some(reservation) => Some(reservation.nonce),
                    None => {
                        if self.nonce_reservations.len() >= MAX_TOTAL_NONCE_RESERVATIONS
                            || self
                                .nonce_reservations
                                .iter()
                                .filter(|reservation| reservation.owner == reservation_owner)
                                .count()
                                >= MAX_PENDING_TRANSACTIONS
                        {
                            return SubstrateResult::error(
                                ErrorCode::Busy,
                                "too many unresolved automatic-nonce submissions",
                            );
                        }
                        None
                    }
                }
            } else {
                None
            };

            let result = async {
                let client = self.ensure_client().await?;
                let mut options = TransactionOptions::default().tip(request.tip);
                options = if request.mortality_period == 0 {
                    options.immortal()
                } else {
                    options.mortal(request.mortality_period)
                };
                if let Some(nonce) = request.nonce {
                    options = options.nonce(nonce);
                }
                let external = client
                    .prepare_external_call_signing(
                        &request.call_path,
                        &sube::Text(&request.call_body),
                        &request.signing_account,
                        &request.nonce_account,
                        to_sube_scheme(request.scheme),
                        options,
                    )
                    .await
                    .map_err(map_sube_error)?;
                Ok((external, client.metadata_rc()))
            }
            .await;
            let (external, metadata) = match result {
                Ok(request) => request,
                Err(error) => return SubstrateResult::Err(error),
            };
            if let Some(reserved_nonce) = prior_ambiguous_nonce {
                if external.context.account_nonce <= reserved_nonce {
                    return SubstrateResult::error(
                        ErrorCode::NonceUncertain,
                        format!(
                            "automatic nonce {reserved_nonce} may still finalize; retry after the finalized account nonce advances or provide an explicit nonce"
                        ),
                    );
                }
                self.nonce_reservations
                    .retain(|reservation| reservation.nonce_account != request.nonce_account);
            }
            // Metadata is large. Pending requests from the same runtime can
            // safely share one immutable registry while older runtime
            // versions keep their own exact signing schema.
            let metadata = self
                .runtime
                .pending
                .iter()
                .find(|pending| {
                    pending.request.context.spec_version == external.context.spec_version
                        && pending.request.context.tx_version == external.context.tx_version
                })
                .map(|pending| sube::Rc::clone(&pending.metadata))
                .unwrap_or(metadata);
            let id = match self.allocate_request_id(&owner, invocation) {
                Some(id) => id,
                None => {
                    return SubstrateResult::error(
                        ErrorCode::Busy,
                        "unable to allocate signing request id",
                    );
                }
            };
            let payload = signing_payload(id, request.scheme, &external);
            let reply = SubstrateResult::Ok(payload);
            if reply.encode().len() > MAX_REPLY_BYTES {
                return SubstrateResult::error(
                    ErrorCode::ReplyTooLarge,
                    "prepared transaction exceeds the extension reply budget",
                );
            }
            let reservation = automatic_nonce.then_some(NonceReservation {
                request_id: id,
                owner: reservation_owner,
                nonce_account: request.nonce_account,
                nonce: external.context.account_nonce,
                state: NonceReservationState::AwaitingSignature,
            });
            self.runtime.pending.push(PendingTransaction {
                id,
                owner,
                created: Instant::now(),
                automatic_nonce,
                metadata,
                request: external,
            });
            if let Some(reservation) = reservation {
                self.nonce_reservations.push(reservation);
            }
            reply
        }

        pub(super) async fn native_submit_transaction(
            &mut self,
            request_id: u64,
            signature: Vec<u8>,
            wait_for: Inclusion,
            owner: CallerKey,
        ) -> SubstrateResult<TransactionResult> {
            let Some(position) = self
                .runtime
                .pending
                .iter()
                .position(|pending| pending.id == request_id && pending.owner == owner)
            else {
                self.expire_pending();
                return SubstrateResult::error(ErrorCode::NotFound, "unknown signing request");
            };
            let expected_signature_len = self.runtime.pending[position]
                .request
                .scheme
                .signature_len();
            if signature.len() != expected_signature_len {
                return SubstrateResult::error(
                    ErrorCode::InvalidSignature,
                    format!(
                        "signature must be {expected_signature_len} bytes, got {}",
                        signature.len()
                    ),
                );
            }
            if self.runtime.pending[position].automatic_nonce
                && matches!(wait_for, Inclusion::BestBlock)
            {
                return SubstrateResult::error(
                    ErrorCode::BadRequest,
                    "automatic-nonce transactions must wait for finalization",
                );
            }
            if self.runtime.pending[position].created.elapsed()
                > Duration::from_secs(SIGNING_REQUEST_TTL_SECS)
            {
                let expired = self.runtime.pending.swap_remove(position);
                if expired.automatic_nonce {
                    self.release_nonce_reservation(expired.id);
                }
                return SubstrateResult::error(ErrorCode::Expired, "signing request expired");
            }
            let request = self.runtime.pending[position].request.clone();
            let metadata = sube::Rc::clone(&self.runtime.pending[position].metadata);
            let extrinsic =
                match sube::extrinsic::finish_external_signing(&metadata, &request, &signature) {
                    Ok(extrinsic) => extrinsic,
                    Err(error) => return SubstrateResult::Err(map_sube_error(error)),
                };
            if let Err(error) = self.ensure_client().await {
                // No submission was attempted; keep the signed request and its
                // awaiting-signature reservation retryable.
                return SubstrateResult::Err(error);
            }
            // Consume before submission. A timeout or ambiguous network result
            // must never make the same signature conveniently replayable. An
            // automatic nonce remains reserved until finalization proves that
            // the account nonce advanced.
            let consumed = self.runtime.pending.swap_remove(position);
            if consumed.automatic_nonce && !self.mark_nonce_submission_unknown(consumed.id) {
                return SubstrateResult::error(
                    ErrorCode::Unavailable,
                    "automatic nonce reservation is missing; transaction was not submitted",
                );
            }
            let submission = self
                .runtime
                .client
                .as_mut()
                .expect("client was connected immediately before submission")
                .submit_transaction_with_timeout(
                    &extrinsic,
                    match wait_for {
                        Inclusion::BestBlock => sube::WaitFor::BestBlock,
                        Inclusion::Finalized => sube::WaitFor::Finalized,
                    },
                    TRANSACTION_WATCH_TIMEOUT,
                )
                .await;
            let result = submission
                .map(|receipt| transaction_result(extrinsic, receipt))
                .map_err(map_sube_error);
            if result.is_ok() && consumed.automatic_nonce {
                self.release_nonce_reservation(consumed.id);
            }
            bounded_result(result)
        }

        pub(super) async fn native_submit_transaction_with_deadline(
            &mut self,
            request_id: u64,
            signature: Vec<u8>,
            wait_for: Inclusion,
            owner: CallerKey,
        ) -> SubstrateResult<TransactionResult> {
            match sube::time::timeout(
                SUBMISSION_DEADLINE,
                self.native_submit_transaction(request_id, signature, wait_for, owner),
            )
            .await
            {
                Ok(result) => {
                    if matches!(result, SubstrateResult::Err(_)) {
                        self.cancel_backend_operation().await;
                    }
                    result
                }
                Err(_) => {
                    self.cancel_backend_operation().await;
                    SubstrateResult::error(ErrorCode::Unavailable, "operation timed out")
                }
            }
        }

        pub(super) fn native_cancel_transaction(
            &mut self,
            request_id: u64,
            owner: &CallerKey,
        ) -> bool {
            self.expire_pending();
            let Some(position) = self
                .runtime
                .pending
                .iter()
                .position(|pending| pending.id == request_id && &pending.owner == owner)
            else {
                let reservation_owner = owner.reservation_owner();
                let Some(position) = self.nonce_reservations.iter().position(|reservation| {
                    reservation.request_id == request_id
                        && reservation.owner == reservation_owner
                        && reservation.state == NonceReservationState::AwaitingSignature
                }) else {
                    return false;
                };
                self.nonce_reservations.swap_remove(position);
                return true;
            };
            let pending = self.runtime.pending.swap_remove(position);
            if pending.automatic_nonce {
                self.release_nonce_reservation(pending.id);
            }
            true
        }

        #[cfg(test)]
        fn automatic_nonce_reservation(&self, nonce_account: &[u8]) -> Option<&NonceReservation> {
            self.nonce_reservations
                .iter()
                .find(|reservation| reservation.nonce_account == nonce_account)
        }
    }

    pub(super) fn load_chain_spec(
        path: &str,
        bundled: &[u8],
    ) -> core::result::Result<String, ExtensionError> {
        let bytes = if path.is_empty() {
            decode_zstd(bundled)?
        } else {
            let bytes = fs::read(path).map_err(|error| {
                ExtensionError::new(
                    ErrorCode::Unavailable,
                    format!("cannot read chain spec {path}: {error}"),
                )
            })?;
            if path.ends_with(".zst") {
                decode_zstd(&bytes)?
            } else if bytes.len() as u64 <= MAX_CHAIN_SPEC_BYTES {
                bytes
            } else {
                return Err(ExtensionError::new(
                    ErrorCode::BadRequest,
                    "chain spec exceeds 16 MiB",
                ));
            }
        };
        String::from_utf8(bytes)
            .map_err(|_| ExtensionError::new(ErrorCode::Encoding, "chain spec is not UTF-8 JSON"))
    }

    fn decode_zstd(bytes: &[u8]) -> core::result::Result<Vec<u8>, ExtensionError> {
        let decoder = zstd::stream::read::Decoder::new(bytes).map_err(|error| {
            ExtensionError::new(ErrorCode::Encoding, format!("bad zstd chain spec: {error}"))
        })?;
        let mut decoded = Vec::new();
        decoder
            .take(MAX_CHAIN_SPEC_BYTES + 1)
            .read_to_end(&mut decoded)
            .map_err(|error| {
                ExtensionError::new(
                    ErrorCode::Encoding,
                    format!("cannot decompress chain spec: {error}"),
                )
            })?;
        if decoded.len() as u64 > MAX_CHAIN_SPEC_BYTES {
            return Err(ExtensionError::new(
                ErrorCode::BadRequest,
                "decompressed chain spec exceeds 16 MiB",
            ));
        }
        Ok(decoded)
    }

    fn validate_query_path(path: &str) -> core::result::Result<(), ExtensionError> {
        if path.is_empty()
            || path.len() > MAX_PATH_LEN
            || path.starts_with('_')
            || path.as_bytes().contains(&0)
        {
            return Err(ExtensionError::new(
                ErrorCode::BadRequest,
                "invalid storage path",
            ));
        }
        Ok(())
    }

    fn block_ref(block: sube::BlockInfo) -> BlockRef {
        BlockRef {
            number: block.number,
            hash: block.hash,
        }
    }

    fn to_sube_scheme(scheme: SignatureScheme) -> sube::SignatureScheme {
        match scheme {
            SignatureScheme::Sr25519 => sube::SignatureScheme::Sr25519,
            SignatureScheme::Ed25519 => sube::SignatureScheme::Ed25519,
            SignatureScheme::Ecdsa => sube::SignatureScheme::Ecdsa,
        }
    }

    fn signing_payload(
        request_id: u64,
        scheme: SignatureScheme,
        request: &sube::ExternalSigningRequest,
    ) -> SigningPayload {
        SigningPayload {
            request_id,
            payload: request.signing_payload.clone(),
            encoded_call: request.call.bytes.clone(),
            signing_account: request.signing_account.clone(),
            nonce_account: request.nonce_account.clone(),
            scheme,
            nonce: request.context.account_nonce,
            genesis_hash: request.context.genesis_hash,
            checkpoint: BlockRef {
                number: request.context.checkpoint_number,
                hash: request.context.checkpoint_hash,
            },
            expires_at: match request.context.mortality {
                sube::Mortality::Immortal => None,
                sube::Mortality::Mortal { period } => {
                    let period = period
                        .checked_next_power_of_two()
                        .unwrap_or(1 << 16)
                        .clamp(4, 1 << 16);
                    Some(
                        (request.context.checkpoint_number
                            - (request.context.checkpoint_number % period))
                            .saturating_add(period),
                    )
                }
            },
            spec_version: request.context.spec_version,
            transaction_version: request.context.tx_version,
            extensions: request
                .extensions
                .iter()
                .map(|extension| SigningExtension {
                    identifier: extension.identifier.clone(),
                    extra_hex: extension.extra_hex.clone(),
                    additional_signed_hex: extension.additional_signed_hex.clone(),
                })
                .collect(),
        }
    }

    pub(super) fn transaction_result(
        extrinsic: sube::EncodedExtrinsic,
        receipt: sube::TransactionReceipt,
    ) -> TransactionResult {
        let extrinsic_hash = vos::crypto::blake2b_hash::<32>(b"", &[&extrinsic.bytes]);
        let event_count = receipt.events.len();
        let events = receipt
            .events
            .into_iter()
            .take(MAX_RECEIPT_EVENTS)
            .map(|event| TransactionEvent {
                pallet: bounded_text(event.pallet, 96),
                variant: bounded_text(event.variant, 96),
                decoded: event.decoded.map(|value| bounded_text(value, 320)),
            })
            .collect();
        let mut result = TransactionResult {
            extrinsic_hash,
            extrinsic_hex: Some(extrinsic.hex),
            best_block_hash: receipt.best_block_hash.map(|hash| bounded_text(hash, 96)),
            finalized_block_hash: receipt
                .finalized_block_hash
                .map(|hash| bounded_text(hash, 96)),
            extrinsic_index: receipt.extrinsic_index,
            dispatch_outcome: match receipt.dispatch_outcome {
                DispatchOutcome::Success => "success".into(),
                DispatchOutcome::Failed(error) => {
                    format!("failed: {}", bounded_text(error, 320))
                }
                DispatchOutcome::Unknown => "unknown".into(),
            },
            events,
            events_truncated: event_count > MAX_RECEIPT_EVENTS,
        };
        if result.encode().len() > MAX_REPLY_BYTES {
            result.extrinsic_hex = None;
        }
        while result.encode().len() > MAX_REPLY_BYTES && !result.events.is_empty() {
            result.events.pop();
            result.events_truncated = true;
        }
        debug_assert!(result.encode().len() <= MAX_REPLY_BYTES);
        result
    }

    fn bounded_text(mut value: String, limit: usize) -> String {
        if value.len() > limit {
            let mut boundary = limit;
            while !value.is_char_boundary(boundary) {
                boundary -= 1;
            }
            value.truncate(boundary);
        }
        value
    }

    pub(super) fn bounded_result<T>(
        result: core::result::Result<T, ExtensionError>,
    ) -> SubstrateResult<T>
    where
        SubstrateResult<T>: Encode,
    {
        match result {
            Ok(value) => {
                let reply = SubstrateResult::Ok(value);
                if reply.encode().len() <= MAX_REPLY_BYTES {
                    reply
                } else {
                    SubstrateResult::error(
                        ErrorCode::ReplyTooLarge,
                        "response exceeds 7 KiB; request a smaller page or value",
                    )
                }
            }
            Err(error) => SubstrateResult::Err(error),
        }
    }

    fn map_sube_error(error: sube::Error) -> ExtensionError {
        let code = match &error {
            sube::Error::BadInput
            | sube::Error::BadBlockNumber
            | sube::Error::StorageKeyNotFound
            | sube::Error::PalletNotFound(_)
            | sube::Error::CallNotFound
            | sube::Error::MissingConstantName
            | sube::Error::ConstantNotFound(_)
            | sube::Error::AccountNotFound => ErrorCode::BadRequest,
            sube::Error::ChainUnavailable
            | sube::Error::ConnectionTimeout
            | sube::Error::SubscriptionClosed
            | sube::Error::Node(_) => ErrorCode::Unavailable,
            sube::Error::Decode(_) | sube::Error::Encode(_) | sube::Error::Mapping(_) => {
                ErrorCode::Encoding
            }
            sube::Error::MissingExtensionValue(_) | sube::Error::OperationFailed(_) => {
                ErrorCode::Chain
            }
            sube::Error::Signing(_) => ErrorCode::InvalidSignature,
            sube::Error::RuntimeUpgrade { .. } | sube::Error::GenesisMismatch => ErrorCode::Stale,
            sube::Error::BadMetadata => ErrorCode::Unsupported,
        };
        ExtensionError::new(code, error.to_string())
    }

    #[cfg(test)]
    mod reservation_tests {
        use super::*;

        #[test]
        fn submitted_nonce_reservation_cannot_be_cancelled_as_unused() {
            let mut actor = SubstrateExtension::new(&[]);
            let owner = CallerKey::Actor(1);
            actor.nonce_reservations.push(NonceReservation {
                request_id: 7,
                owner: owner.reservation_owner(),
                nonce_account: vec![3; 32],
                nonce: 11,
                state: NonceReservationState::AwaitingSignature,
            });

            assert!(actor.mark_nonce_submission_unknown(7));
            let reservation = actor.automatic_nonce_reservation(&[3; 32]).unwrap();
            assert_eq!(reservation.nonce, 11);
            assert_eq!(reservation.state, NonceReservationState::SubmissionUnknown);
            assert!(!actor.native_cancel_transaction(7, &owner));
            assert!(actor.automatic_nonce_reservation(&[3; 32]).is_some());

            actor.release_nonce_reservation(7);
            assert!(actor.automatic_nonce_reservation(&[3; 32]).is_none());
        }

        #[test]
        fn restored_unused_nonce_reservation_remains_cancellable() {
            let mut actor = SubstrateExtension::new(&[]);
            let owner = CallerKey::Actor(1);
            actor.nonce_reservations.push(NonceReservation {
                request_id: 7,
                owner: owner.reservation_owner(),
                nonce_account: vec![3; 32],
                nonce: 11,
                state: NonceReservationState::AwaitingSignature,
            });

            assert!(actor.native_cancel_transaction(7, &owner));
            assert!(actor.nonce_reservations.is_empty());
        }
    }
}

#[cfg(feature = "native")]
use native::{MapSnapshot, PendingTransaction};

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "native")]
    struct TestLogger;

    #[cfg(feature = "native")]
    impl log::Log for TestLogger {
        fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
            metadata.level() <= log::Level::Info
        }

        fn log(&self, record: &log::Record<'_>) {
            if self.enabled(record.metadata()) {
                eprintln!("[{} {}] {}", record.level(), record.target(), record.args());
            }
        }

        fn flush(&self) {}
    }

    #[cfg(feature = "native")]
    static TEST_LOGGER: TestLogger = TestLogger;

    #[test]
    fn cursor_roundtrips_and_is_bound_to_path_and_snapshot() {
        let at = BlockRef {
            number: 42,
            hash: [7; 32],
        };
        let cursor = encode_cursor("system/account", 9, &at, &[1, 2, 3]).unwrap();
        let (snapshot_id, number, hash, key) = decode_cursor("system/account", &cursor).unwrap();
        assert_eq!(snapshot_id, 9);
        assert_eq!(number, 42);
        assert_eq!(hash, [7; 32]);
        assert_eq!(key, [1, 2, 3]);
        assert_eq!(
            decode_cursor("balances/account", &cursor).unwrap_err().code,
            ErrorCode::BadRequest
        );
    }

    #[test]
    fn cursor_rejects_truncation_and_trailing_bytes() {
        let at = BlockRef {
            number: 1,
            hash: [2; 32],
        };
        let cursor = encode_cursor("x/y", 4, &at, &[3]).unwrap();
        assert!(decode_cursor("x/y", &cursor[..cursor.len() - 1]).is_err());
        let mut trailing = cursor;
        trailing.push(0);
        assert!(decode_cursor("x/y", &trailing).is_err());
    }

    #[test]
    fn wire_surface_encodes_below_the_declared_error_budget() {
        let error: SubstrateResult<QueryResult> =
            SubstrateResult::error(ErrorCode::Chain, "x".repeat(10_000));
        assert!(error.encode().len() < MAX_REPLY_BYTES);
    }

    #[cfg(feature = "native")]
    #[test]
    fn embedded_specs_decompress_and_identify_kreivo_on_kusama() {
        let kreivo =
            native::load_chain_spec("", include_bytes!("../assets/kreivo-kusama.json.zst"))
                .unwrap();
        let kusama =
            native::load_chain_spec("", include_bytes!("../assets/kusama.json.zst")).unwrap();
        assert!(kreivo.contains("\"id\": \"kreivo\""));
        assert!(kreivo.contains("\"para_id\": 2281"));
        assert!(kreivo.contains("\"relay_chain\": \"ksmcc3\""));
        assert!(kusama.contains("\"id\": \"ksmcc3\""));
        assert!(kusama.contains("\"lightSyncState\""));
        assert!(kusama.contains("\"finalizedBlockHeader\""));
    }

    #[cfg(feature = "native")]
    #[test]
    fn native_runtime_is_transient_but_nonce_uncertainty_is_persisted() {
        let mut actor = SubstrateExtension::new(&[]);
        actor.config.network = "custom-network".into();
        actor.config.chain_spec_path = "/operator/para.json".into();
        actor.next_request_id = 91;
        actor.nonce_reservations.push(NonceReservation {
            request_id: 17,
            owner: [4; 32],
            nonce_account: vec![5; 32],
            nonce: 23,
            state: NonceReservationState::SubmissionUnknown,
        });

        let restored = SubstrateExtension::try_decode(&actor.encode()).unwrap();
        assert_eq!(restored.config.network, "custom-network");
        assert_eq!(restored.config.chain_spec_path, "/operator/para.json");
        assert_eq!(restored.next_request_id, 91);
        assert_eq!(restored.nonce_reservations, actor.nonce_reservations);
        assert!(restored.runtime.client.is_none());
        assert!(restored.runtime.pending.is_empty());
        assert!(restored.runtime.map_snapshots.is_empty());
    }

    #[cfg(feature = "native")]
    #[test]
    fn native_capabilities_and_snapshots_are_bound_to_the_caller() {
        let actor_owner = native::CallerKey::Actor(7);
        let other_owner = native::CallerKey::Actor(8);
        let invocation = InvocationId([9; 32]);
        let id = native::capability_id(b"vos/substrate/test", &actor_owner, invocation, 1);
        assert_ne!(
            id,
            native::capability_id(b"vos/substrate/test", &other_owner, invocation, 1,)
        );

        let mut actor = SubstrateExtension::new(&[]);
        actor.runtime.map_snapshots.push(MapSnapshot {
            id,
            owner: actor_owner.clone(),
            last_used: std::time::Instant::now(),
            path: "system/account".into(),
            at: BlockRef {
                number: 1,
                hash: [2; 32],
            },
            next_key: Vec::new(),
            started: false,
            active_invocation: invocation,
        });
        assert!(actor.take_map_snapshot(id, &other_owner).is_none());
        assert_eq!(actor.runtime.map_snapshots.len(), 1);
        assert!(actor.take_map_snapshot(id, &actor_owner).is_some());
    }

    #[cfg(feature = "native")]
    #[test]
    fn oversized_success_is_replaced_with_a_bounded_error() {
        let result = native::bounded_result(Ok(QueryResult {
            at: BlockRef {
                number: 1,
                hash: [2; 32],
            },
            value: Some("x".repeat(MAX_REPLY_BYTES)),
        }));
        assert!(matches!(
            result,
            SubstrateResult::Err(ExtensionError {
                code: ErrorCode::ReplyTooLarge,
                ..
            })
        ));
    }

    #[cfg(feature = "native")]
    #[test]
    fn transaction_receipt_keeps_its_hash_when_optional_details_do_not_fit() {
        let bytes = vec![0x2a; 4096];
        let expected_hash = vos::crypto::blake2b_hash::<32>(b"", &[&bytes]);
        let extrinsic = sube::EncodedExtrinsic {
            hex: format!("0x{}", "2a".repeat(bytes.len())),
            bytes,
            call: sube::PreparedCall {
                pallet: "Test".into(),
                call: "submit".into(),
                bytes: Vec::new(),
                hex: "0x".into(),
            },
            checkpoint_hash: [1; 32],
            checkpoint_number: 1,
            expires_at: None,
            genesis_hash: [2; 32],
            spec_version: 1,
            transaction_version: 1,
            nonce: 0,
            authorization: sube::AuthorizationSummary::default(),
            extensions: Vec::new(),
        };
        let receipt = sube::TransactionReceipt {
            best_block_hash: Some(format!("0x{}", "11".repeat(32))),
            finalized_block_hash: Some(format!("0x{}", "22".repeat(32))),
            extrinsic_index: Some(3),
            dispatch_outcome: sube::DispatchOutcome::Success,
            events: (0..32)
                .map(|_| sube::TransactionEvent {
                    pallet: "P".repeat(128),
                    variant: "V".repeat(128),
                    data: Vec::new(),
                    decoded: Some("D".repeat(1024)),
                })
                .collect(),
        };

        let result = native::transaction_result(extrinsic, receipt);
        assert_eq!(result.extrinsic_hash, expected_hash);
        assert!(result.extrinsic_hex.is_none());
        assert!(result.events_truncated);
        assert!(result.encode().len() <= MAX_REPLY_BYTES);
    }

    #[cfg(feature = "native")]
    #[test]
    #[ignore = "requires public Kreivo and Kusama peer access"]
    fn kreivo_light_client_status_smoke() {
        let _ = log::set_logger(&TEST_LOGGER);
        log::set_max_level(log::LevelFilter::Info);
        let mut actor = SubstrateExtension::new(&[]);
        let status = match smol::block_on(actor.native_status()) {
            SubstrateResult::Ok(status) => status,
            SubstrateResult::Err(error) => panic!("light-client status failed: {error:?}"),
        };
        assert_eq!(status.network, "kreivo-kusama");
        assert_ne!(status.genesis_hash, [0; 32]);
        assert!(status.finalized.number > 0);
        assert!(status.token_symbols.iter().any(|symbol| symbol == "KSM"));

        let query = match smol::block_on(actor.native_query("system/number".into(), None)) {
            SubstrateResult::Ok(query) => query,
            SubstrateResult::Err(error) => panic!("light-client query failed: {error:?}"),
        };
        assert!(query.value.is_some());

        let page = match smol::block_on(actor.native_query_map_with_deadline(
            "system/account".into(),
            1,
            Vec::new(),
            native::CallerKey::System,
            InvocationId([1; 32]),
        )) {
            SubstrateResult::Ok(page) => page,
            SubstrateResult::Err(error) => panic!("light-client map query failed: {error:?}"),
        };
        assert_eq!(page.entries.len(), 1);
        assert!(!page.next_cursor.is_empty());

        let next = match smol::block_on(actor.native_query_map_with_deadline(
            "system/account".into(),
            1,
            page.next_cursor.clone(),
            native::CallerKey::System,
            InvocationId([2; 32]),
        )) {
            SubstrateResult::Ok(page) => page,
            SubstrateResult::Err(error) => panic!("continued map query failed: {error:?}"),
        };
        assert_eq!(next.at, page.at);
        assert_eq!(next.entries.len(), 1);
        assert_ne!(next.entries[0].keys, page.entries[0].keys);
    }
}
