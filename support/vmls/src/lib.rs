//! `vmls`: an MLS layer (RFC 9420) over mls-rs, for a group whose
//! commits are confirmed by its members before they take effect.
//!
//! - **Storage:** a group's state and its key packages' secrets as rows
//!   under a [`Namespace`]'s prefix of the caller's [`Store`], committed
//!   with the caller's rows as one set of writes.
//! - **Copy and swap:** a candidate is processed on a copy of the group
//!   state ([`Mls::process`], [`Mls::join`]), which never writes through
//!   the current one, and swapped in on confirmation ([`Mls::swap`]).
//! - **A member's own commit** is built detached and held ([`Mls::commit`]),
//!   in one commit with the state it spent a generation of; it is applied
//!   on a copy on confirmation ([`Mls::own`]) and deleted on a void
//!   ([`Mls::void`]).
//! - **The policy:** an allow-list of proposals, 64-byte credentials, and
//!   a candidate checked against the effect its caller expects
//!   ([`Expected`]).
//! - **The confirmation hash** ([`confirmation`]).
//!
//! Two limits: a member added over a year ago that has not committed since
//! bars new joins until it commits (a key package's lifetime, which a
//! joiner checks for every leaf); a member whose commits are voided more
//! than 1024 times in one epoch is refused until another member's commit
//! moves the epoch (a receiver ratchets at most 1024 generations ahead).
//!
//! The suite is 1 (X25519, AES-128-GCM, SHA-256, Ed25519), the only one
//! the provider is built with: a Welcome or a stored group of any other is
//! unsupported. Every time is in seconds since the Unix epoch, as mls-rs
//! counts.

mod candidate;
mod error;
mod held;
mod policy;
mod storage;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use mls_rs::client_builder::{
    BaseConfig, IntoConfigOutput, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::error::MlsError;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::time::MlsTime;
use mls_rs::{CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

pub use candidate::{Candidate, Kind};
pub use error::{Error, Refusal};
pub use held::Commit;
use policy::Rules;
pub use policy::{Expected, Identity, Refused};
pub use storage::{MemStore, Namespace, Store, Writes};

/// Ciphersuite 1: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
pub const SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// The highest epoch a Welcome may name: far below the last a `u64`
/// counts, which mls-rs's own epoch steps would overflow past.
const EPOCH_MAX: u64 = u64::MAX / 2;

/// How far a key package's lifetime starts before its maker's clock, the
/// skew between members this layer tolerates: an hour, so the members that
/// add it, process its add and join with it may be that far behind.
const CLOCK_MARGIN: u64 = 3600;

/// RustCrypto with suite 1 alone: a message naming any other suite is
/// unsupported before any key is used under it.
fn provider() -> RustCryptoProvider {
    RustCryptoProvider::with_enabled_cipher_suites(vec![SUITE])
}

/// The client configuration: the namespace's storage, the policy's
/// identities and rules, RustCrypto.
type Config = IntoConfigOutput<
    WithMlsRules<
        Rules,
        WithCryptoProvider<
            RustCryptoProvider,
            WithIdentityProvider<
                Identity,
                WithKeyPackageRepo<Namespace, WithGroupStateStorage<Namespace, BaseConfig>>,
            >,
        >,
    >,
>;

// A namespace's rows beside mls-rs's: the leaf's signing key and
// identity, the identity a held commit renews it to, the group's id, the
// held commit, and the id of the new group a held restart starts.
const SIGNER: &[u8] = b"signer";
const RENEWED: &[u8] = b"renewed";
const GROUP: &[u8] = b"group";
const HELD: &[u8] = b"held";
const NEXT: &[u8] = b"next";

/// The confirmation hash of an epoch: `BLAKE2b-256(domain ‖ group ‖
/// epoch ‖ epoch_authenticator)`, `group` the group's 32-byte id as the
/// caller names it, the epoch little-endian. A member that processed the
/// epoch's candidate posts it, signed; the hashes of the set of members
/// the caller requires confirm it. Neither `domain` nor the authenticator
/// is framed: the input is unambiguous only for one fixed domain, and
/// suite 1's authenticator is always 32 bytes.
pub fn confirmation(domain: &[u8], group: &[u8; 32], epoch: u64, authenticator: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(domain);
    hasher.update(group);
    hasher.update(epoch.to_le_bytes());
    hasher.update(authenticator);
    hasher.finalize().into()
}

fn credentials(group: &Group<Config>) -> Vec<Vec<u8>> {
    leaves(group)
        .into_iter()
        .map(|(_, credential)| credential)
        .collect()
}

/// A group's members' credentials, by leaf.
fn leaves(group: &Group<Config>) -> Vec<(u32, Vec<u8>)> {
    group
        .roster()
        .members_iter()
        .filter_map(|member| {
            let basic = member.signing_identity.credential.as_basic()?;
            Some((member.index, basic.identifier.clone()))
        })
        .collect()
}

/// A leaf's signing key and identity; its row is the two encoded in turn.
#[derive(Clone)]
struct Signer {
    secret: SignatureSecretKey,
    identity: SigningIdentity,
}

impl Signer {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = self
            .secret
            .mls_encode_to_vec()
            .map_err(|_| Error::Corrupt)?;
        bytes.extend(
            self.identity
                .mls_encode_to_vec()
                .map_err(|_| Error::Corrupt)?,
        );
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = bytes;
        let secret = SignatureSecretKey::mls_decode(&mut reader).map_err(|_| Error::Corrupt)?;
        let identity = SigningIdentity::mls_decode(&mut reader).map_err(|_| Error::Corrupt)?;
        Ok(Self { secret, identity })
    }
}

/// A member of one MLS group, over a namespace: its leaf's signing key and
/// identity, and its current group once it made or joined one.
pub struct Mls {
    namespace: Namespace,
    signer: Signer,
    client: Client<Config>,
    group: Option<Group<Config>>,
}

/// An mls-rs error as this layer's: `namespace`'s store read's failure if
/// one happened under it.
fn failure(namespace: &Namespace, error: MlsError) -> Error {
    namespace.take_failure().unwrap_or(Error::Mls(error))
}

/// A group's id and epoch, which a candidate made from it is bound to.
fn base(group: &Group<Config>) -> (Vec<u8>, u64) {
    (group.group_id().to_vec(), group.current_epoch())
}

fn client(
    namespace: &Namespace,
    rules: Rules,
    signer: Option<Signer>,
    identity: Identity,
) -> Client<Config> {
    let builder = Client::builder()
        .group_state_storage(namespace.clone())
        .key_package_repo(namespace.clone())
        .identity_provider(identity)
        .crypto_provider(provider())
        .mls_rules(rules);
    match signer {
        Some(Signer { secret, identity }) => {
            builder.signing_identity(identity, secret, SUITE).build()
        }
        None => builder.build(),
    }
}

/// A client signing as `signer`, under the policy's rules and identities.
fn signing(namespace: &Namespace, signer: &Signer) -> Client<Config> {
    client(
        namespace,
        Rules::default(),
        Some(signer.clone()),
        Identity::default(),
    )
}

impl Mls {
    /// The member whose leaf credential is `credential`, in `namespace`:
    /// the one it holds, whatever `credential` says, or, in a namespace
    /// holding none, a new one, its signing key drawn and written.
    /// [`Error::Credential`] for a new one whose `credential` is not 64
    /// bytes.
    pub fn open(namespace: Namespace, credential: &[u8]) -> Result<Self, Error> {
        let signer = match namespace.get(SIGNER)? {
            Some(bytes) => Signer::decode(&bytes)?,
            None if credential.len() != policy::CREDENTIAL_BYTES => {
                return Err(Error::Credential);
            }
            None => {
                let suite = provider()
                    .cipher_suite_provider(SUITE)
                    .ok_or(Error::Corrupt)?;
                let (secret, public) = suite.signature_key_generate().map_err(|error| {
                    Error::Mls(MlsError::CryptoProviderError(error.into_any_error()))
                })?;
                let credential = BasicCredential::new(credential.to_vec()).into_credential();
                let signer = Signer {
                    secret,
                    identity: SigningIdentity::new(credential, public),
                };
                namespace.put(SIGNER, Some(signer.encode()?));
                signer
            }
        };
        let mut mls = Self {
            client: signing(&namespace, &signer),
            signer,
            namespace,
            group: None,
        };
        mls.write(Writes::new())?;
        Ok(mls)
    }

    /// The member's leaf credential.
    pub fn credential(&self) -> Vec<u8> {
        let basic = self.signer.identity.credential.as_basic();
        basic.map_or_else(Vec::new, |basic| basic.identifier.clone())
    }

    /// Commit `rows` and the rows staged to the namespace's store as one
    /// set of writes; on a failure, discard what was staged and read the
    /// group back as the store holds it.
    pub fn write(&mut self, rows: Writes) -> Result<(), Error> {
        match self.namespace.commit(rows) {
            Ok(()) => self.reload(),
            Err(error) => self.discard(error),
        }
    }

    /// `error`, after discarding what was staged and reading the group
    /// back as the store holds it; the read's error if that fails too, the
    /// group in memory then being one the store may not hold.
    fn discard<T>(&mut self, error: Error) -> Result<T, Error> {
        self.namespace.unstage();
        self.reload()?;
        Err(error)
    }

    /// `operation`, which stages rows, and then the commit of them and of
    /// the `rows` its outcome gives; on a failure of either, nothing.
    fn staged<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
        rows: impl FnOnce(&T) -> Writes,
    ) -> Result<T, Error> {
        match operation(self) {
            Ok(outcome) => {
                self.write(rows(&outcome))?;
                Ok(outcome)
            }
            Err(error) => self.discard(error),
        }
    }

    /// The current group, read from the namespace's rows, and the signer
    /// as a renewal swapped in left it.
    fn reload(&mut self) -> Result<(), Error> {
        if let Some(bytes) = self.namespace.get(SIGNER)? {
            let signer = Signer::decode(&bytes)?;
            if signer.identity != self.signer.identity {
                self.client = signing(&self.namespace, &signer);
                self.signer = signer;
            }
        }
        self.group = self
            .namespace
            .get(GROUP)?
            .map(|id| {
                self.client
                    .load_group(&id)
                    .map_err(|error| failure(&self.namespace, error))
            })
            .transpose()?;
        Ok(())
    }

    fn group(&self) -> Result<&Group<Config>, Error> {
        self.group.as_ref().ok_or(Error::NoGroup)
    }

    /// A new group of this member alone at `time`.
    fn new_group(&self, time: u64) -> Result<Group<Config>, Error> {
        self.client
            .create_group(
                ExtensionList::new(),
                ExtensionList::new(),
                Some(MlsTime::from(time)),
            )
            .map_err(|error| failure(&self.namespace, error))
    }

    /// Whether the member has a group.
    pub fn grouped(&self) -> bool {
        self.group.is_some()
    }

    /// The current epoch.
    pub fn epoch(&self) -> Result<u64, Error> {
        Ok(self.group()?.current_epoch())
    }

    /// The MLS exporter's secret of the current epoch for `label` and
    /// `context`, `len` bytes.
    pub fn export(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        Ok(self.group()?.export_secret(label, context, len)?.to_vec())
    }

    /// The current members' credentials.
    pub fn credentials(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(credentials(self.group()?))
    }

    /// The persisted group state's bytes.
    pub fn state_bytes(&self) -> Result<usize, Error> {
        let id = self.namespace.get(GROUP)?.ok_or(Error::NoGroup)?;
        let state = self.namespace.get(&storage::state_row(&id))?;
        Ok(state.map_or(0, |state| state.len()))
    }

    /// A key package for a member that adds this one, made at `time` by
    /// this member's clock, its secrets written. It is valid from an hour
    /// before `time` and for 365 days from then.
    pub fn key_package(&mut self, time: u64) -> Result<Vec<u8>, Error> {
        let not_before = MlsTime::from(time.saturating_sub(CLOCK_MARGIN));
        self.staged(
            |member| {
                let message = member
                    .client
                    .generate_key_package_message(
                        ExtensionList::new(),
                        ExtensionList::new(),
                        Some(not_before),
                    )
                    .map_err(|error| failure(&member.namespace, error))?;
                Ok(message.to_bytes()?)
            },
            |_| Writes::new(),
        )
    }

    /// Make a group of this member alone at epoch 0, committed with
    /// `rows`.
    pub fn create(&mut self, time: u64, rows: Writes) -> Result<(), Error> {
        if self.group.is_some() {
            return Err(Error::Grouped);
        }
        self.staged(
            |member| {
                let mut group = member.new_group(time)?;
                group.write_to_storage()?;
                member.namespace.put(GROUP, Some(group.group_id().to_vec()));
                Ok(())
            },
            |_| rows,
        )
    }

    /// A copy of group `id`'s state under `rules` and `identity`.
    fn copy(
        &self,
        id: &[u8],
        rules: Rules,
        identity: Identity,
    ) -> Result<(Group<Config>, Namespace), Error> {
        let namespace = self.namespace.copy();
        let group = client(&namespace, rules, None, identity)
            .load_group(id)
            .map_err(|error| failure(&namespace, error))?;
        Ok((group, namespace))
    }
}
