//! `vos-mls`: VOS's one MLS layer, over mls-rs (`light-node.md` §3.4). The
//! user's device group is its first user; member messaging later.
//!
//! - **Storage** ([`storage`]): a group's state and its key packages'
//!   secrets as rows of a fjall keyspace under a namespace, every write
//!   staged and committed with the caller's rows in one synced batch.
//! - **Copy and swap:** mls-rs applies a received commit at once, and a
//!   commit's confirmation needs it processed. So a candidate is processed
//!   on a copy of the group state ([`Mls::process`], [`Mls::join`]), the
//!   current state kept, and swapped in on confirmation ([`Mls::swap`]) or
//!   dropped. A copy reads the current rows and writes to memory alone, so
//!   it never writes through the current namespace.
//! - **A device's own commit** is built detached ([`Mls::commit`]) and held:
//!   building it spends a handshake-key generation of the current state, so
//!   the current state and the held commit are one batch, written before
//!   the call that posts it returns to the caller. On confirmation the held
//!   commit is applied on a copy ([`Mls::own`]), only if the confirmed
//!   candidate's hash is the held commit's and the current epoch is the one
//!   before, mls-rs's `apply_detached_commit` checking nothing; a void
//!   deletes it ([`Mls::void`]).
//! - **Received commits** are processed at the log's batch time, so
//!   processing is deterministic (after a crash the logged candidate is
//!   processed again) and leaf and key-package lifetimes are checked. A
//!   key package is valid from an hour before its maker's clock
//!   ([`Mls::key_package`]) for 365 days; a joiner checks every leaf of
//!   the tree that still comes from a key package, so a member added over
//!   a year ago bars new joins until it commits.
//! - **Generations:** each held commit spends a handshake-key generation
//!   of its epoch, and a void does not give it back; a receiver ratchets
//!   at most 1024 generations ahead, so a member's commits voided more
//!   than 1024 times in one epoch are refused until another member's
//!   commit moves the epoch.
//! - **The policy** ([`policy`]): the device group's allow-list and its
//!   identities, a candidate checked against its logged effect.
//! - **The confirmation hash** ([`confirmation`]).
//!
//! The suite is 1 (X25519, AES-128-GCM, SHA-256, Ed25519), the only one
//! the provider is built with: a Welcome or a stored group of any other is
//! unsupported. Every time is in seconds since the Unix epoch, as mls-rs
//! counts.

pub mod policy;
pub mod storage;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use mls_rs::client_builder::{
    BaseConfig, IntoConfigOutput, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::error::MlsError;
use mls_rs::group::{CommitEffect, CommitSecrets, LeafNode, LeafNodeSource, Node, ReceivedMessage};
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs::time::MlsTime;
use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, Group, MlsMessage,
    WireFormat,
};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

pub use policy::{Expected, Identity, Refused, Rules};
pub use storage::{Namespace, Store, Writes};

/// Ciphersuite 1: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
pub const SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

/// The longest group id a Welcome may name: the suite's hash, the length
/// mls-rs draws.
const GROUP_ID_BYTES: usize = 32;

/// How far a key package's lifetime starts before its maker's clock, the
/// skew between devices this layer tolerates: an hour.
const CLOCK_MARGIN: u64 = 3600;

/// RustCrypto with suite 1 alone: a message naming any other suite is
/// unsupported before any key is used under it.
fn provider() -> RustCryptoProvider {
    RustCryptoProvider::with_enabled_cipher_suites(vec![SUITE])
}

/// The client configuration: the namespace's storage, the device group's
/// identities and rules, RustCrypto.
pub type Config = IntoConfigOutput<
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

/// A namespace's rows beside mls-rs's: the leaf's signing key and
/// identity, the identity a held commit renews it to, the group's id, the
/// held commit, and the id of the new group a held restart starts.
const SIGNER: &[u8] = b"signer";
const RENEWED: &[u8] = b"renewed";
const GROUP: &[u8] = b"group";
const HELD: &[u8] = b"held";
const NEXT: &[u8] = b"next";

/// Why an operation failed. A failed operation writes nothing: the
/// current state stays as the last batch left it. Two exceptions, both a
/// store's failure: a batch whose sync failed may be found applied after a
/// reopen ([`Store::commit`]), and an error reading the group back after
/// a written batch leaves that batch written.
#[derive(Debug)]
pub enum Error {
    Store(fjall::Error),
    /// A row the store cannot hold: an empty key, a key over 65,535 bytes
    /// or a value over 4 GiB.
    Unstorable,
    Mls(MlsError),
    /// A candidate refused: it is not a commit this group's rules and
    /// state accept. Its committer's to answer for.
    Refused(Refusal),
    /// No group yet, or none any more.
    NoGroup,
    /// A group already, where an operation makes one.
    Grouped,
    /// A commit is held already: confirm or void it first.
    Held,
    /// No commit held, or not the candidate's, or not for the epoch after
    /// the current one.
    NotHeld,
    /// A candidate swapped over a state it was not made from: another
    /// group or epoch than the current one, or, for the device's own, a
    /// commit held since.
    Stale,
    /// A namespace row that does not read.
    Corrupt,
}

impl From<fjall::Error> for Error {
    fn from(error: fjall::Error) -> Self {
        Error::Store(error)
    }
}

impl From<MlsError> for Error {
    fn from(error: MlsError) -> Self {
        Error::Mls(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Store(error) => write!(f, "the MLS store: {error}"),
            Error::Unstorable => f.write_str("a row the MLS store cannot hold"),
            Error::Mls(error) => write!(f, "MLS: {error:?}"),
            Error::Refused(refusal) => write!(f, "a candidate refused: {refusal:?}"),
            Error::NoGroup => f.write_str("no group"),
            Error::Grouped => f.write_str("a group already"),
            Error::Held => f.write_str("a commit is held already"),
            Error::NotHeld => f.write_str("not the commit held"),
            Error::Stale => f.write_str("a candidate of a state no longer current"),
            Error::Corrupt => f.write_str("an MLS row does not read"),
        }
    }
}

impl std::error::Error for Error {}

/// Why a candidate was refused.
#[derive(Debug)]
pub enum Refusal {
    /// Not an MLS message.
    Malformed,
    /// A handshake in the clear: the group's are encrypted.
    Plaintext,
    /// Not a commit.
    NotCommit,
    /// A commit whose committer kept its leaf: no path.
    NoPath,
    /// A ReInit.
    ReInit,
    /// A Welcome into a group this layer does not keep: its id longer than
    /// the suite's hash, or its epoch the last a `u64` counts.
    Group,
    /// A commit whose committer's leaf is not the one its log entry names:
    /// another credential than the expected one (the renewed one, when a
    /// renewal is expected), or another signature key.
    Leaf,
    /// mls-rs refused it: its framing, its signature, its secrets, or the
    /// group's rules.
    Rejected(MlsError),
}

/// What a candidate is to this device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Its own commit, held and applied.
    Own,
    /// Another device's commit, processed.
    Received,
    /// A Welcome: the device joins with it, leaving any group it is in.
    Joined,
    /// Its own restart: a new group it made, with the members it added.
    Started,
    /// A commit that removes this device.
    Removed,
}

/// A candidate's group state, on a copy: swapped in on confirmation
/// ([`Mls::swap`]), or dropped. It is bound to the state it was made from:
/// the current group's id and epoch then, and, for the device's own, the
/// commit held.
pub struct Candidate {
    group: Group<Config>,
    namespace: Namespace,
    kind: Kind,
    base: Option<(Vec<u8>, u64)>,
    held: Option<[u8; 32]>,
}

impl Candidate {
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The epoch it moves to; for a commit that removes this device, the
    /// current one, which mls-rs does not advance.
    pub fn epoch(&self) -> u64 {
        self.group.current_epoch()
    }

    /// Its epoch's authenticator, which the confirmation hashes; none for a
    /// commit that removes this device.
    pub fn authenticator(&self) -> Result<Option<Vec<u8>>, Error> {
        if self.kind == Kind::Removed {
            return Ok(None);
        }
        Ok(Some(self.group.epoch_authenticator()?.to_vec()))
    }

    /// Its members' credentials, by leaf; for a commit that removes this
    /// device, the current ones.
    pub fn credentials(&self) -> Vec<(u32, Vec<u8>)> {
        credentials(&self.group)
    }

    /// The MLS exporter's secret of its epoch for `label` and `context`,
    /// `len` bytes: none for a commit that removes this device.
    pub fn export(
        &self,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        if self.kind == Kind::Removed {
            return Ok(None);
        }
        Ok(Some(
            self.group.export_secret(label, context, len)?.to_vec(),
        ))
    }
}

/// A device's own commit, held until it is confirmed: its handshake, the
/// Welcome for the devices it adds, and the epoch it moves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub handshake: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub epoch: u64,
}

/// The confirmation hash of an epoch: `BLAKE2b-256(domain ‖ agent ‖
/// epoch ‖ epoch_authenticator)`, the epoch little-endian. A device posts
/// it, signed, once it processed the epoch's candidate; one hash from
/// every device of the confirming set confirms it. Neither `domain` nor
/// the authenticator is framed: the input is unambiguous only for one
/// fixed domain, and suite 1's authenticator is always 32 bytes.
pub fn confirmation(domain: &[u8], agent: &[u8; 32], epoch: u64, authenticator: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(domain);
    hasher.update(agent);
    hasher.update(epoch.to_le_bytes());
    hasher.update(authenticator);
    hasher.finalize().into()
}

/// A handshake's hash, which a held commit is matched by.
pub fn handshake_hash(handshake: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"vos/mls/handshake");
    hasher.update(handshake);
    hasher.finalize().into()
}

fn credentials(group: &Group<Config>) -> Vec<(u32, Vec<u8>)> {
    group
        .roster()
        .members_iter()
        .filter_map(|member| {
            let basic = member.signing_identity.credential.as_basic()?;
            Some((member.index, basic.identifier.clone()))
        })
        .collect()
}

fn leaf(group: &Group<Config>, index: u32) -> Option<LeafNode> {
    match group.export_tree().nodes().get(2 * index as usize) {
        Some(Some(Node::Leaf(leaf))) => Some(leaf.clone()),
        _ => None,
    }
}

fn encode_signer(
    secret: &SignatureSecretKey,
    identity: &SigningIdentity,
) -> Result<Vec<u8>, Error> {
    let mut bytes = secret.mls_encode_to_vec().map_err(|_| Error::Corrupt)?;
    bytes.extend(identity.mls_encode_to_vec().map_err(|_| Error::Corrupt)?);
    Ok(bytes)
}

fn decode_signer(bytes: &[u8]) -> Result<(SignatureSecretKey, SigningIdentity), Error> {
    let mut reader = bytes;
    let secret = SignatureSecretKey::mls_decode(&mut reader).map_err(|_| Error::Corrupt)?;
    let identity = SigningIdentity::mls_decode(&mut reader).map_err(|_| Error::Corrupt)?;
    Ok((secret, identity))
}

/// A held commit's row: its handshake's hash, its epoch little-endian and
/// its secrets.
struct Held {
    hash: [u8; 32],
    epoch: u64,
    secrets: Vec<u8>,
}

impl Held {
    fn encode(&self) -> Vec<u8> {
        [&self.hash[..], &self.epoch.to_le_bytes(), &self.secrets].concat()
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let (hash, rest) = bytes.split_first_chunk::<32>()?;
        let (epoch, secrets) = rest.split_first_chunk::<8>()?;
        Some(Self {
            hash: *hash,
            epoch: u64::from_le_bytes(*epoch),
            secrets: secrets.to_vec(),
        })
    }
}

/// A member of one MLS group, over a namespace: its leaf's signing key and
/// identity, and its current group once it made or joined one.
pub struct Mls {
    namespace: Namespace,
    signer: (SignatureSecretKey, SigningIdentity),
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
    signer: Option<(SignatureSecretKey, SigningIdentity)>,
    identity: Identity,
) -> Client<Config> {
    let builder = Client::builder()
        .group_state_storage(namespace.clone())
        .key_package_repo(namespace.clone())
        .identity_provider(identity)
        .crypto_provider(provider())
        .mls_rules(rules);
    match signer {
        Some((secret, identity)) => builder.signing_identity(identity, secret, SUITE).build(),
        None => builder.build(),
    }
}

impl Mls {
    /// The member whose leaf credential is `credential`, in `namespace`:
    /// the one it holds, or, in a namespace holding none, a new one, its
    /// signing key drawn and written in one batch with `rows`.
    pub fn open(namespace: Namespace, credential: &[u8], rows: Writes) -> Result<Self, Error> {
        let signer = match namespace.get(SIGNER)? {
            Some(bytes) => decode_signer(&bytes)?,
            None => {
                let suite = provider()
                    .cipher_suite_provider(SUITE)
                    .ok_or(Error::Corrupt)?;
                let (secret, public) = suite.signature_key_generate().map_err(|error| {
                    Error::Mls(MlsError::CryptoProviderError(error.into_any_error()))
                })?;
                let credential = BasicCredential::new(credential.to_vec()).into_credential();
                let identity = SigningIdentity::new(credential, public);
                namespace.put(SIGNER, Some(encode_signer(&secret, &identity)?));
                (secret, identity)
            }
        };
        let mut mls = Self {
            client: client(
                &namespace,
                Rules::default(),
                Some(signer.clone()),
                Identity::default(),
            ),
            signer,
            namespace,
            group: None,
        };
        mls.flush(rows)?;
        Ok(mls)
    }

    /// The member's leaf credential.
    pub fn credential(&self) -> Vec<u8> {
        let basic = self.signer.1.credential.as_basic();
        basic.map_or_else(Vec::new, |basic| basic.identifier.clone())
    }

    /// Write the staged rows and `rows` in one batch; on a failure, discard
    /// what was staged and read the group back as the store holds it.
    fn flush(&mut self, rows: Writes) -> Result<(), Error> {
        let store = self.namespace.store().clone();
        match store.commit(&self.namespace, rows) {
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

    /// `operation`, which stages rows, and then the batch of them and of
    /// the `rows` its outcome gives; on a failure of either, nothing.
    fn staged<T>(
        &mut self,
        operation: impl FnOnce(&mut Self) -> Result<T, Error>,
        rows: impl FnOnce(&T) -> Writes,
    ) -> Result<T, Error> {
        match operation(self) {
            Ok(outcome) => {
                self.flush(rows(&outcome))?;
                Ok(outcome)
            }
            Err(error) => self.discard(error),
        }
    }

    /// The current group, read from the namespace's rows, and the signer
    /// as a renewal swapped in left it.
    fn reload(&mut self) -> Result<(), Error> {
        if let Some(bytes) = self.namespace.get(SIGNER)? {
            let signer = decode_signer(&bytes)?;
            if signer.1 != self.signer.1 {
                self.client = client(
                    &self.namespace,
                    Rules::default(),
                    Some(signer.clone()),
                    Identity::default(),
                );
                self.signer = signer;
            }
        }
        self.group = match self.namespace.get(GROUP)? {
            Some(id) => Some(
                self.client
                    .load_group(&id)
                    .map_err(|error| self.failure(error))?,
            ),
            None => None,
        };
        Ok(())
    }

    /// An mls-rs error as this layer's: a store read's failure if one
    /// happened under it.
    fn failure(&self, error: MlsError) -> Error {
        failure(&self.namespace, error)
    }

    fn group(&self) -> Result<&Group<Config>, Error> {
        self.group.as_ref().ok_or(Error::NoGroup)
    }

    /// Whether the member has a group.
    pub fn grouped(&self) -> bool {
        self.group.is_some()
    }

    /// The current epoch.
    pub fn epoch(&self) -> Result<u64, Error> {
        Ok(self.group()?.current_epoch())
    }

    /// The current epoch's authenticator.
    pub fn authenticator(&self) -> Result<Vec<u8>, Error> {
        Ok(self.group()?.epoch_authenticator()?.to_vec())
    }

    /// The MLS exporter's secret of the current epoch for `label` and
    /// `context`, `len` bytes.
    pub fn export(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        Ok(self.group()?.export_secret(label, context, len)?.to_vec())
    }

    /// The current members' credentials, by leaf.
    pub fn credentials(&self) -> Result<Vec<(u32, Vec<u8>)>, Error> {
        Ok(credentials(self.group()?))
    }

    /// The persisted group state's bytes.
    pub fn state_bytes(&self) -> Result<usize, Error> {
        let id = self.namespace.get(GROUP)?.ok_or(Error::NoGroup)?;
        let state = self.namespace.get(&storage::state_row(&id))?;
        Ok(state.map_or(0, |state| state.len()))
    }

    /// A key package for a device that adds this one, made at `time` by
    /// this device's clock: its secrets written in one batch with `rows`.
    /// It is valid from an hour before `time`, so the devices
    /// that add it, process its add and join with it may be that far
    /// behind, and for 365 days from then.
    pub fn key_package(&mut self, time: u64, rows: Writes) -> Result<Vec<u8>, Error> {
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
                    .map_err(|error| member.failure(error))?;
                Ok(message.to_bytes()?)
            },
            |_| rows,
        )
    }

    /// Make a group of this member alone at epoch 0, written in one batch
    /// with `rows`.
    pub fn create(&mut self, time: u64, rows: Writes) -> Result<(), Error> {
        if self.group.is_some() {
            return Err(Error::Grouped);
        }
        self.staged(
            |member| {
                let mut group = member
                    .client
                    .create_group(
                        ExtensionList::new(),
                        ExtensionList::new(),
                        Some(MlsTime::from(time)),
                    )
                    .map_err(|error| member.failure(error))?;
                group.write_to_storage()?;
                member.namespace.put(GROUP, Some(group.group_id().to_vec()));
                Ok(())
            },
            |_| rows,
        )
    }

    /// The commit held, if one is: its handshake's hash and its epoch.
    pub fn held(&self) -> Result<Option<([u8; 32], u64)>, Error> {
        Ok(self.held_row()?.map(|held| (held.hash, held.epoch)))
    }

    fn held_row(&self) -> Result<Option<Held>, Error> {
        match self.namespace.get(HELD)? {
            Some(bytes) => Ok(Some(Held::decode(&bytes).ok_or(Error::Corrupt)?)),
            None => Ok(None),
        }
    }

    /// Commit adding the devices of `adds` (their key packages) and
    /// removing the members whose credentials are `removes`, with a path,
    /// at `time`, held: the current state, the held commit and the
    /// caller's `rows` of it in one batch, written before this returns.
    pub fn commit(
        &mut self,
        adds: &[Vec<u8>],
        removes: &[Vec<u8>],
        time: u64,
        rows: impl FnOnce(&Commit) -> Writes,
    ) -> Result<Commit, Error> {
        self.hold(|member| member.held_commit(None, adds, removes, time), rows)
    }

    /// [`Mls::commit`], the leaf's credential renewed to `credential` (its
    /// signing key kept): the member's from the commit's swap.
    pub fn renew(
        &mut self,
        credential: &[u8],
        adds: &[Vec<u8>],
        removes: &[Vec<u8>],
        time: u64,
        rows: impl FnOnce(&Commit) -> Writes,
    ) -> Result<Commit, Error> {
        self.hold(
            |member| member.held_commit(Some(credential), adds, removes, time),
            rows,
        )
    }

    /// The commit `build` makes, held: its state, the held commit and the
    /// caller's `rows` of it in one batch, written before this returns; on
    /// a failure, which may have spent a generation in memory alone, the
    /// group as the store holds it again. Refused while one is held.
    fn hold(
        &mut self,
        build: impl FnOnce(&mut Self) -> Result<Commit, Error>,
        rows: impl FnOnce(&Commit) -> Writes,
    ) -> Result<Commit, Error> {
        if self.held_row()?.is_some() {
            return Err(Error::Held);
        }
        self.staged(build, rows)
    }

    /// The commit built detached, and the current state and the held
    /// commit staged.
    fn held_commit(
        &mut self,
        renewed: Option<&[u8]>,
        adds: &[Vec<u8>],
        removes: &[Vec<u8>],
        time: u64,
    ) -> Result<Commit, Error> {
        let renewal = match renewed {
            Some(credential) => {
                let identity = SigningIdentity::new(
                    BasicCredential::new(credential.to_vec()).into_credential(),
                    self.signer.1.signature_key.clone(),
                );
                // The group as a client allowing the renewal loads it.
                let id = self.group()?.group_id().to_vec();
                let allowing = client(
                    &self.namespace,
                    Rules::default(),
                    Some(self.signer.clone()),
                    Identity::renewing(self.credential(), credential.to_vec()),
                );
                self.group = Some(
                    allowing
                        .load_group(&id)
                        .map_err(|error| self.failure(error))?,
                );
                self.namespace
                    .put(RENEWED, Some(encode_signer(&self.signer.0, &identity)?));
                Some(identity)
            }
            None => None,
        };
        let secret = self.signer.0.clone();
        let group = self.group.as_mut().ok_or(Error::NoGroup)?;
        let members = credentials(group);
        let mut builder = group.commit_builder().commit_time(MlsTime::from(time));
        if let Some(identity) = renewal {
            builder = builder.set_new_signing_identity(secret, identity);
        }
        for package in adds {
            let message = MlsMessage::from_bytes(package)?;
            builder = builder.add_member(message)?;
        }
        for credential in removes {
            let (index, _) = members
                .iter()
                .find(|(_, member)| member == credential)
                .ok_or(Error::Mls(MlsError::MemberNotFound))?;
            builder = builder.remove_member(*index)?;
        }
        let (output, secrets) = builder.build_detached()?;
        let handshake = output.commit_message.to_bytes()?;
        let welcome = match output.welcome_messages.first() {
            Some(welcome) => Some(welcome.to_bytes()?),
            None => None,
        };
        let epoch = group
            .current_epoch()
            .checked_add(1)
            .ok_or(Error::Mls(MlsError::InvalidEpoch))?;
        let held = Held {
            hash: handshake_hash(&handshake),
            epoch,
            secrets: secrets.to_bytes()?,
        };
        group.write_to_storage()?;
        self.namespace.put(HELD, Some(held.encode()));
        Ok(Commit {
            handshake,
            welcome,
            epoch,
        })
    }

    /// Restart: a new group of this member alone at `time`, its commit
    /// applied at once and held, the current group kept until the restart
    /// is swapped in. The new group's state, the held commit and the
    /// caller's `rows` of it in one batch, written before this returns.
    pub fn restart(
        &mut self,
        time: u64,
        rows: impl FnOnce(&Commit) -> Writes,
    ) -> Result<Commit, Error> {
        self.hold(|member| member.started(time), rows)
    }

    fn started(&mut self, time: u64) -> Result<Commit, Error> {
        let mut group = self
            .client
            .create_group(
                ExtensionList::new(),
                ExtensionList::new(),
                Some(MlsTime::from(time)),
            )
            .map_err(|error| self.failure(error))?;
        let output = group
            .commit_builder()
            .commit_time(MlsTime::from(time))
            .build()?;
        group.apply_pending_commit()?;
        let handshake = output.commit_message.to_bytes()?;
        let epoch = group.current_epoch();
        let held = Held {
            hash: handshake_hash(&handshake),
            epoch,
            secrets: Vec::new(),
        };
        group.write_to_storage()?;
        self.namespace.put(HELD, Some(held.encode()));
        self.namespace.put(NEXT, Some(group.group_id().to_vec()));
        Ok(Commit {
            handshake,
            welcome: None,
            epoch,
        })
    }

    /// A copy of the current group under `rules` and `identity`.
    fn copy(&self, rules: Rules, identity: Identity) -> Result<(Group<Config>, Namespace), Error> {
        let id = self.group()?.group_id().to_vec();
        let namespace = self.namespace.copy();
        let client = client(&namespace, rules, None, identity);
        let group = client
            .load_group(&id)
            .map_err(|error| failure(&namespace, error))?;
        Ok((group, namespace))
    }

    /// The held commit `handshake` applied on a copy: only if `handshake`
    /// is the held commit's and the current epoch is the one before it.
    pub fn own(&self, handshake: &[u8]) -> Result<Candidate, Error> {
        let held = self.held_row()?.ok_or(Error::NotHeld)?;
        if held.hash != handshake_hash(handshake) {
            return Err(Error::NotHeld);
        }
        let base = self.group.as_ref().map(base);
        if let Some(next) = self.namespace.get(NEXT)? {
            let namespace = self.namespace.copy();
            let group = client(&namespace, Rules::default(), None, Identity::default())
                .load_group(&next)
                .map_err(|error| failure(&namespace, error))?;
            return Ok(Candidate {
                group,
                namespace,
                kind: Kind::Started,
                base,
                held: Some(held.hash),
            });
        }
        if self.epoch()?.checked_add(1) != Some(held.epoch) {
            return Err(Error::NotHeld);
        }
        // `apply_detached_commit` validates nothing: the identities the
        // copy is loaded with are not used.
        let (mut group, namespace) = self.copy(Rules::default(), Identity::default())?;
        let secrets = CommitSecrets::from_bytes(&held.secrets).map_err(|_| Error::Corrupt)?;
        group.apply_detached_commit(secrets)?;
        Ok(Candidate {
            group,
            namespace,
            kind: Kind::Own,
            base,
            held: Some(held.hash),
        })
    }

    /// Another member's commit `handshake` processed on a copy at `time`
    /// (the log's batch time), under its logged effect `expected`: an
    /// encrypted commit with a path, by the expected committer, adding and
    /// removing exactly the expected credentials, its committer's leaf
    /// taking exactly the expected renewed credential if one is expected
    /// and keeping its credential otherwise, and keeping its signature key.
    /// A refusal is [`Error::Refused`].
    pub fn process(
        &self,
        handshake: &[u8],
        time: u64,
        expected: Expected,
    ) -> Result<Candidate, Error> {
        let refused = |refusal| Err(Error::Refused(refusal));
        let Ok(message) = MlsMessage::from_bytes(handshake) else {
            return refused(Refusal::Malformed);
        };
        if message.wire_format() != WireFormat::PrivateMessage {
            return refused(Refusal::Plaintext);
        }
        let current = self.group()?;
        let identity = match &expected.renewed {
            Some(after) => Identity::renewing(expected.committer.clone(), after.clone()),
            None => Identity::default(),
        };
        let leaf_credential = expected
            .renewed
            .clone()
            .unwrap_or_else(|| expected.committer.clone());
        let (mut group, namespace) = self.copy(Rules::expecting(expected), identity)?;
        let received = match group.process_incoming_message_with_time(message, MlsTime::from(time))
        {
            Ok(received) => received,
            Err(error) => {
                if let Some(error) = namespace.take_failure() {
                    return Err(error);
                }
                return refused(Refusal::Rejected(error));
            }
        };
        let ReceivedMessage::Commit(description) = received else {
            return refused(Refusal::NotCommit);
        };
        let kind = match description.effect {
            CommitEffect::NewEpoch(_) => Kind::Received,
            CommitEffect::Removed { .. } => Kind::Removed,
            CommitEffect::ReInit(_) => return refused(Refusal::ReInit),
        };
        if kind == Kind::Received {
            let (Some(before), Some(after)) = (
                leaf(current, description.committer),
                leaf(&group, description.committer),
            ) else {
                return refused(Refusal::NoPath);
            };
            if !matches!(after.leaf_node_source, LeafNodeSource::Commit(_))
                || after.public_key == before.public_key
            {
                return refused(Refusal::NoPath);
            }
            let credential = after.signing_identity.credential.as_basic();
            if credential.is_none_or(|basic| basic.identifier != leaf_credential)
                || after.signing_identity.signature_key != before.signing_identity.signature_key
            {
                return refused(Refusal::Leaf);
            }
        }
        Ok(Candidate {
            group,
            namespace,
            kind,
            base: Some(base(current)),
            held: None,
        })
    }

    /// Join with `welcome` on a copy at `time`, under the key package this
    /// member made: a candidate for the epoch the Welcome names, which a
    /// member of a group joins to leave it for a new one.
    pub fn join(&self, welcome: &[u8], time: u64) -> Result<Candidate, Error> {
        let Ok(message) = MlsMessage::from_bytes(welcome) else {
            return Err(Error::Refused(Refusal::Malformed));
        };
        let namespace = self.namespace.copy();
        let client = client(
            &namespace,
            Rules::default(),
            Some(self.signer.clone()),
            Identity::default(),
        );
        let group = match client.join_group(None, &message, Some(MlsTime::from(time))) {
            Ok((group, _)) => group,
            Err(error) => {
                if let Some(error) = namespace.take_failure() {
                    return Err(error);
                }
                return Err(Error::Refused(Refusal::Rejected(error)));
            }
        };
        if group.group_id().len() > GROUP_ID_BYTES || group.current_epoch() == u64::MAX {
            return Err(Error::Refused(Refusal::Group));
        }
        Ok(Candidate {
            group,
            namespace,
            kind: Kind::Joined,
            base: self.group.as_ref().map(base),
            held: None,
        })
    }

    /// Make `candidate` current, in one batch with `rows`: its state into
    /// the current namespace, any held commit deleted (its epoch is
    /// decided), with a held restart's new group unless it is the
    /// candidate's. A candidate that removes this member deletes the group;
    /// a new group's deletes the group it leaves. [`Error::Stale`] for a
    /// candidate made from another state than the current one.
    pub fn swap(&mut self, candidate: Candidate, rows: Writes) -> Result<(), Error> {
        let Candidate {
            mut group,
            namespace,
            kind,
            base: made_from,
            held,
        } = candidate;
        let current_held = self.held()?.map(|(hash, _)| hash);
        if made_from != self.group.as_ref().map(base)
            || held.is_some_and(|hash| current_held != Some(hash))
        {
            return Err(Error::Stale);
        }
        self.staged(
            |member| {
                let next = member.namespace.get(NEXT)?;
                let current = member.group.as_ref().map(|group| group.group_id().to_vec());
                let kept = (kind != Kind::Removed).then(|| group.group_id().to_vec());
                for id in [next, current].into_iter().flatten() {
                    if Some(&id) != kept.as_ref() {
                        member.namespace.put(&storage::state_row(&id), None);
                    }
                }
                match kept {
                    Some(id) => {
                        if kind == Kind::Own
                            && let Some(renewed) = member.namespace.get(RENEWED)?
                        {
                            member.namespace.put(SIGNER, Some(renewed));
                        }
                        group.write_to_storage()?;
                        member.namespace.stage(namespace.take_copy());
                        member.namespace.put(GROUP, Some(id));
                    }
                    None => member.namespace.put(GROUP, None),
                }
                member.namespace.put(HELD, None);
                member.namespace.put(NEXT, None);
                member.namespace.put(RENEWED, None);
                Ok(())
            },
            |_| rows,
        )
    }

    /// Delete the held commit, its candidate void, in one batch with
    /// `rows`: a held restart's new group with it.
    pub fn void(&mut self, rows: Writes) -> Result<(), Error> {
        if let Some(next) = self.namespace.get(NEXT)? {
            self.namespace.put(&storage::state_row(&next), None);
            self.namespace.put(NEXT, None);
        }
        self.namespace.put(HELD, None);
        self.namespace.put(RENEWED, None);
        self.flush(rows)
    }

    /// Write `rows` alone, in the namespace's store.
    pub fn write(&mut self, rows: Writes) -> Result<(), Error> {
        self.flush(rows)
    }
}
