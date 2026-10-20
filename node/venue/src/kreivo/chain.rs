//! The client's [`Transport`] over a Kreivo node's RPC ([`ChainTransport`]):
//! subxt 0.51.1, which reads Kreivo's V16 metadata, signing with an
//! sr25519 account key.
//!
//! - **The call** goes as its pinned bytes ([`RawCall`]): subxt looks its
//!   pallet and call up by index in the live metadata, and writes the
//!   arguments verbatim.
//! - **The envelope** is the live metadata's: a v4 signed extrinsic, its
//!   extensions encoded by [`Extensions`]. The metadata's extension list
//!   must be [`EXTENSIONS`], in order, or nothing is signed: an extension
//!   this client does not know would be encoded by guess.
//!   `PassAuthenticate` is pinned to `None` by a typed extension
//!   ([`PassAuthenticate`]), never left to frame-decode's fallback for an
//!   absent optional one; the empty ones (`CheckNonZeroSender`,
//!   `CheckWeight`, `DynamicMaxBlockWeight`) encode nothing.
//! - **Inclusion** is watched to the best chain's block; the extrinsic's
//!   index found by its bytes in the block's body, its events read from
//!   `System.Events` there, delimited by the live metadata, filtered by
//!   that index.
//! - **Reads** are raw storage at the best block.

use subxt::config::transaction_extensions::{
    ChargeAssetTxPayment, ChargeAssetTxPaymentParams, CheckGenesis, CheckMortality,
    CheckMortalityParams, CheckNonce, CheckNonceParams, CheckSpecVersion, CheckTxVersion,
};
use subxt::config::{
    ClientState, Config, Header, PolkadotConfig, RpcConfigFor, TransactionExtension,
};
use subxt::events::Phase;
use subxt::ext::frame_decode::extrinsics::{
    TransactionExtension as Encodes, TransactionExtensionError,
};
use subxt::ext::scale_encode::{EncodeAsFields, FieldIter, TypeResolver};
use subxt::ext::scale_value::Value;
use subxt::rpcs::methods::legacy::{LegacyRpcMethods, TransactionStatus};
use subxt::rpcs::{Error as RpcError, RpcClient};
use subxt::tx::Payload;
use subxt::utils::{AccountId32, H256};
use subxt::{Metadata, OnlineClient};
use subxt_signer::sr25519::Keypair;

use super::calls::{AccountId, PALLET};
use super::transport::{Included, Invalid, Lost, SendError, Signed, Transport};

/// How many blocks a signed extrinsic is valid for.
const ERA: u64 = 64;
/// The most keys one read of a prefix asks for.
const PAGE: u32 = 512;

/// Kreivo's transaction extensions, in the order its runtime declares
/// them (6.0e, Kreivo 87f8728, spec 134). `ChargeAssetTxPayment` is the
/// identifier and data of the whole fee stack, `ChargeSpaceFee` keeping
/// both (`spaces-pallet.md` §7).
pub const EXTENSIONS: [&str; 10] = [
    "PassAuthenticate",
    "CheckNonZeroSender",
    "CheckSpecVersion",
    "CheckTxVersion",
    "CheckGenesis",
    "CheckMortality",
    "CheckNonce",
    "CheckWeight",
    "ChargeAssetTxPayment",
    "DynamicMaxBlockWeight",
];

/// Whether `live`, the metadata's extension identifiers in order, is
/// [`EXTENSIONS`]: the envelope this client builds.
pub fn known_extensions(live: &[&str]) -> Result<(), String> {
    if live == EXTENSIONS {
        return Ok(());
    }
    Err(format!(
        "Kreivo's transaction extensions are {live:?}, not the {EXTENSIONS:?} this client \
         encodes: nothing is signed"
    ))
}

/// Kreivo's chain configuration: Polkadot's types, Kreivo's extensions.
#[derive(Clone, Debug)]
pub struct KreivoConfig(PolkadotConfig);

impl Default for KreivoConfig {
    fn default() -> Self {
        Self(PolkadotConfig::builder().use_historic_types(false).build())
    }
}

/// The extensions this client encodes; [`EXTENSIONS`]' others encode
/// nothing.
pub type Extensions = (
    PassAuthenticate,
    CheckSpecVersion,
    CheckTxVersion,
    CheckGenesis<KreivoConfig>,
    CheckMortality<KreivoConfig>,
    CheckNonce,
    ChargeAssetTxPayment<KreivoConfig>,
);

impl Config for KreivoConfig {
    type AccountId = <PolkadotConfig as Config>::AccountId;
    type Address = <PolkadotConfig as Config>::Address;
    type Signature = <PolkadotConfig as Config>::Signature;
    type Hasher = <PolkadotConfig as Config>::Hasher;
    type Header = <PolkadotConfig as Config>::Header;
    type AssetId = <PolkadotConfig as Config>::AssetId;
    type TransactionExtensions = Extensions;

    fn genesis_hash(&self) -> Option<H256> {
        self.0.genesis_hash()
    }

    fn spec_and_transaction_version_for_block_number(&self, block: u64) -> Option<(u32, u32)> {
        self.0.spec_and_transaction_version_for_block_number(block)
    }

    fn metadata_for_spec_version(&self, spec: u32) -> Option<subxt::metadata::ArcMetadata> {
        self.0.metadata_for_spec_version(spec)
    }

    fn set_metadata_for_spec_version(&self, spec: u32, metadata: subxt::metadata::ArcMetadata) {
        self.0.set_metadata_for_spec_version(spec, metadata)
    }
}

/// `PassAuthenticate`, Kreivo's pass authentication, pinned to `None`: a
/// node signs as its own account. Its type must be an `Option`, or a
/// wrapper of one, whose `None` is variant 0.
pub struct PassAuthenticate;

impl<T: Config> TransactionExtension<T> for PassAuthenticate {
    type Decoded = Value;
    type Params = ();

    fn new(
        _: &ClientState<T>,
        _: Self::Params,
    ) -> Result<Self, subxt::error::TransactionExtensionError> {
        Ok(Self)
    }
}

/// Whether type `id` is an `Option`, or wraps one in a one-field
/// composite: its `None` variant 0, with no fields.
fn optional(types: &scale_info::PortableRegistry, id: u32) -> bool {
    use scale_info::TypeDef;
    match types.resolve(id).map(|ty| &ty.type_def) {
        Some(TypeDef::Composite(composite)) if composite.fields.len() == 1 => {
            optional(types, composite.fields[0].ty.id)
        }
        Some(TypeDef::Variant(variant)) => variant
            .variants
            .iter()
            .any(|v| v.name == "None" && v.index == 0 && v.fields.is_empty()),
        _ => false,
    }
}

impl Encodes<scale_info::PortableRegistry> for PassAuthenticate {
    const NAME: &str = "PassAuthenticate";

    fn encode_value_to(
        &self,
        id: u32,
        types: &scale_info::PortableRegistry,
        out: &mut Vec<u8>,
    ) -> Result<(), TransactionExtensionError> {
        if !optional(types, id) {
            return Err("PassAuthenticate is not an Option: its None cannot be pinned".into());
        }
        out.push(0);
        Ok(())
    }

    fn encode_implicit_to(
        &self,
        _: u32,
        _: &scale_info::PortableRegistry,
        _: &mut Vec<u8>,
    ) -> Result<(), TransactionExtensionError> {
        Ok(())
    }
}

/// A call's pinned bytes as subxt's payload: its pallet and call named
/// from the live metadata by their indices, its arguments verbatim.
pub struct RawCall {
    pallet: String,
    call: String,
    args: RawArgs,
}

pub struct RawArgs(Vec<u8>);

impl EncodeAsFields for RawArgs {
    fn encode_as_fields_to<R: TypeResolver>(
        &self,
        _: &mut dyn FieldIter<'_, R::TypeId>,
        _: &R,
        out: &mut Vec<u8>,
    ) -> Result<(), subxt::ext::scale_encode::Error> {
        out.extend_from_slice(&self.0);
        Ok(())
    }
}

impl Payload for RawCall {
    type CallData = RawArgs;

    fn pallet_name(&self) -> &str {
        &self.pallet
    }

    fn call_name(&self) -> &str {
        &self.call
    }

    fn call_data(&self) -> &RawArgs {
        &self.args
    }
}

impl RawCall {
    /// `bytes`, `[pallet, call] ++ args`, named from `metadata`.
    pub fn new(metadata: &Metadata, bytes: &[u8]) -> Result<Self, String> {
        let [pallet, call, ..] = *bytes else {
            return Err("a call is at least its two indices".into());
        };
        let pallet = metadata
            .pallet_by_call_index(pallet)
            .ok_or_else(|| format!("Kreivo has no pallet {pallet}"))?;
        let variant = pallet
            .call_variant_by_index(call)
            .ok_or_else(|| format!("{} has no call {call}", pallet.name()))?;
        Ok(Self {
            pallet: pallet.name().to_owned(),
            call: variant.name.clone(),
            args: RawArgs(bytes[2..].to_vec()),
        })
    }
}

type Rpc = LegacyRpcMethods<RpcConfigFor<KreivoConfig>>;

/// Kreivo through a node's RPC, signing as one sr25519 account.
pub struct ChainTransport {
    runtime: tokio::runtime::Runtime,
    client: OnlineClient<KreivoConfig>,
    rpc: Rpc,
    signer: Keypair,
    /// The pallet whose events an inclusion reports: the spaces pallet's.
    events_of: u8,
}

fn lost(error: impl std::fmt::Display) -> Lost {
    Lost(error.to_string())
}

/// The account of an sr25519 key whose 32-byte mini secret is `seed`.
pub fn keypair(seed: &[u8; 32]) -> Result<Keypair, String> {
    Keypair::from_secret_key(*seed).map_err(|error| error.to_string())
}

/// The key a secret URI names: a dev key (`//Alice`), a phrase with its
/// derivations, or a 32-byte mini secret in hex (`0x…`).
pub fn keypair_from_uri(uri: &str) -> Result<Keypair, String> {
    let uri: subxt_signer::SecretUri = uri.trim().parse().map_err(|error| format!("{error}"))?;
    Keypair::from_uri(&uri).map_err(|error| error.to_string())
}

/// The account a keypair signs as.
pub fn account(signer: &Keypair) -> AccountId {
    signer.public_key().0
}

impl ChainTransport {
    /// Connect to the node at `url` (`ws://` or `wss://`), signing with
    /// `signer`.
    pub fn connect(url: &str, signer: Keypair) -> Result<Self, Lost> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("kreivo-rpc")
            .enable_all()
            .build()
            .map_err(lost)?;
        let (client, rpc) = runtime.block_on(async {
            let rpc = RpcClient::from_insecure_url(url).await.map_err(lost)?;
            let client =
                OnlineClient::from_rpc_client_with_config(KreivoConfig::default(), rpc.clone())
                    .await
                    .map_err(lost)?;
            Ok::<_, Lost>((client, Rpc::new(rpc)))
        })?;
        Ok(Self {
            runtime,
            client,
            rpc,
            signer,
            events_of: PALLET,
        })
    }

    /// Report another pallet's events: a stock call's, to check the
    /// envelope on a chain without the spaces pallet.
    pub fn events_of(mut self, pallet: u8) -> Self {
        self.events_of = pallet;
        self
    }

    async fn best_hash(&self) -> Result<H256, Lost> {
        self.rpc
            .chain_get_block_hash(None)
            .await
            .map_err(lost)?
            .ok_or_else(|| lost("no best block"))
    }

    async fn sign_at_best(&self, call: &[u8], nonce: u64) -> Result<Signed, SendError> {
        let hash = self.best_hash().await?;
        let at = self.client.at_block(hash).await.map_err(lost)?;
        let metadata = at.metadata();
        let extrinsic = metadata.extrinsic();
        let live: Vec<&str> = extrinsic
            .transaction_extensions_to_use_for_encoding()
            .map(|extension| extension.identifier())
            .collect();
        known_extensions(&live).map_err(|why| SendError::Invalid(Invalid::Envelope(why)))?;
        let payload = RawCall::new(&metadata, call)
            .map_err(|why| SendError::Invalid(Invalid::Envelope(why)))?;
        let tx = at.tx();
        let built = tx.call_data(&payload).map_err(lost)?;
        if built != call {
            let why = "subxt changed the call's bytes".to_string();
            return Err(SendError::Invalid(Invalid::Envelope(why)));
        }
        let params = (
            (),
            (),
            (),
            (),
            CheckMortalityParams::mortal(ERA),
            CheckNonceParams::with_nonce(nonce),
            ChargeAssetTxPaymentParams::no_tip(),
        );
        let account: AccountId32 = self.signer.public_key().into();
        let signed = tx
            .create_v4_signable(&payload, &account, params)
            .await
            .map_err(|error| SendError::Invalid(Invalid::Envelope(error.to_string())))?
            .sign(&self.signer)
            .map_err(|error| SendError::Invalid(Invalid::Envelope(error.to_string())))?;
        Ok(Signed {
            bytes: signed.encoded().to_vec(),
            nonce,
            until: at.block_number() + ERA,
        })
    }

    async fn watch(&self, signed: &Signed) -> Result<Included, SendError> {
        let mut progress = self
            .rpc
            .author_submit_and_watch_extrinsic(&signed.bytes)
            .await
            .map_err(refused)?;
        let hash = loop {
            match progress.next().await {
                Some(Ok(TransactionStatus::InBlock(hash) | TransactionStatus::Finalized(hash))) => {
                    break hash;
                }
                Some(Ok(
                    TransactionStatus::Dropped
                    | TransactionStatus::Invalid
                    | TransactionStatus::Usurped(_),
                ))
                | None => return Err(lost("the pool let it go").into()),
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(lost(error).into()),
            }
        };
        let block = self
            .rpc
            .chain_get_block(Some(hash))
            .await
            .map_err(lost)?
            .ok_or_else(|| lost("the block went"))?;
        let index = block
            .block
            .extrinsics
            .iter()
            .position(|extrinsic| extrinsic.0 == signed.bytes)
            .ok_or_else(|| lost("the block does not hold it"))? as u32;
        let at = self.client.at_block(hash).await.map_err(lost)?;
        let raw = self
            .rpc
            .state_get_storage(&super::calls::keys::plain("System", "Events"), Some(hash))
            .await
            .map_err(lost)?
            .unwrap_or_default();
        let mut events = Vec::new();
        let mut failure = None;
        for event in at.events().from_bytes(raw).iter() {
            let event = event.map_err(lost)?;
            if !matches!(event.phase(), Phase::ApplyExtrinsic(at) if at == index) {
                continue;
            }
            if event.pallet_index() == self.events_of {
                events.push([&[event.event_index()][..], event.field_bytes()].concat());
            }
            if (event.pallet_name(), event.event_name()) == ("System", "ExtrinsicFailed") {
                failure = Some(event.field_bytes().to_vec());
            }
        }
        Ok(Included {
            block: block.block.header.number(),
            events,
            failure,
        })
    }
}

/// What the pool's refusal of an extrinsic says: `Invalid` for one that
/// will never be included as it is, `Lost` for one that may yet be (in the
/// pool already, temporarily banned) or a connection's loss.
fn refused(error: RpcError) -> SendError {
    let RpcError::User(error) = &error else {
        return lost(error).into();
    };
    let data = error
        .data
        .as_ref()
        .map(|data| data.get().to_lowercase())
        .unwrap_or_default();
    let invalid = match error.code {
        1010 if data.contains("pay") => Invalid::Payment,
        1010 if data.contains("outdated") || data.contains("stale") => Invalid::Stale,
        1010 if data.contains("future") => Invalid::Future,
        1010 if data.contains("decode") || data.contains("call") => Invalid::Call,
        1010 => Invalid::Other(format!("{}: {data}", error.message)),
        _ => return lost(format!("{} ({}): {data}", error.message, error.code)).into(),
    };
    SendError::Invalid(invalid)
}

impl Transport for ChainTransport {
    fn account(&self) -> AccountId {
        account(&self.signer)
    }

    fn genesis(&self) -> Result<[u8; 32], Lost> {
        Ok(self.client.genesis_hash().0)
    }

    fn best(&self) -> Result<u64, Lost> {
        self.runtime.block_on(async {
            let header = self
                .rpc
                .chain_get_header(None)
                .await
                .map_err(lost)?
                .ok_or_else(|| lost("no best block"))?;
            Ok(header.number())
        })
    }

    fn nonce(&self) -> Result<u64, Lost> {
        let account: AccountId32 = self.signer.public_key().into();
        self.runtime
            .block_on(self.rpc.system_account_next_index(&account))
            .map_err(lost)
    }

    fn sign(&self, call: &[u8], nonce: u64) -> Result<Signed, SendError> {
        self.runtime.block_on(self.sign_at_best(call, nonce))
    }

    fn send(&self, signed: &Signed) -> Result<Included, SendError> {
        self.runtime.block_on(self.watch(signed))
    }

    fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Lost> {
        self.runtime.block_on(async {
            let hash = self.best_hash().await?;
            self.rpc
                .state_get_storage(key, Some(hash))
                .await
                .map_err(lost)
        })
    }

    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Lost> {
        self.runtime.block_on(async {
            let hash = self.best_hash().await?;
            let mut keys: Vec<Vec<u8>> = Vec::new();
            loop {
                let start = keys.last().map(Vec::as_slice);
                let page = self
                    .rpc
                    .state_get_keys_paged(prefix, PAGE, start, Some(hash))
                    .await
                    .map_err(lost)?;
                let full = page.len() == PAGE as usize;
                keys.extend(page);
                if !full {
                    return Ok(keys);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ten extensions in order are the envelope; one missing, added
    /// or moved is refused before signing.
    #[test]
    fn only_kreivos_extensions_are_signed() {
        assert_eq!(known_extensions(&EXTENSIONS), Ok(()));
        let mut moved = EXTENSIONS;
        moved.swap(0, 1);
        assert!(known_extensions(&moved).is_err());
        assert!(known_extensions(&EXTENSIONS[..9]).is_err());
        let added: Vec<&str> = EXTENSIONS
            .iter()
            .copied()
            .chain(["CheckMetadataHash"])
            .collect();
        assert!(known_extensions(&added).is_err());
    }

    /// A dev key's account is its sr25519 public key.
    #[test]
    fn a_seed_is_an_sr25519_account() {
        let signer = keypair(&[7; 32]).unwrap();
        assert_eq!(account(&signer), signer.public_key().0);
        assert_ne!(account(&signer), account(&keypair(&[8; 32]).unwrap()));
    }
}
