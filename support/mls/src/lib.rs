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
//!   processed again) and leaf and key-package lifetimes are checked.
//! - **The policy** ([`policy`]): the device group's allow-list and its
//!   identities, a candidate checked against its logged effect.
//! - **The confirmation hash** ([`confirmation`]).
//!
//! The suite is 1 (X25519, AES-128-GCM, SHA-256, Ed25519). Every time is in
//! seconds since the Unix epoch, as mls-rs counts.

pub mod policy;
pub mod storage;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use mls_rs::client_builder::{
    BaseConfig, IntoConfigOutput, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::error::MlsError;
use mls_rs::group::{CommitEffect, LeafNode, LeafNodeSource, Node, ReceivedMessage};
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

use mls_rs::group::CommitSecrets;

/// Ciphersuite 1: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
pub const SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

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
/// current state stays as the last batch left it.
#[derive(Debug)]
pub enum Error {
    Store(fjall::Error),
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
    /// the current one; or a candidate swapped over another epoch.
    NotHeld,
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
            Error::Mls(error) => write!(f, "MLS: {error:?}"),
            Error::Refused(refusal) => write!(f, "a candidate refused: {refusal:?}"),
            Error::NoGroup => f.write_str("no group"),
            Error::Grouped => f.write_str("a group already"),
            Error::Held => f.write_str("a commit is held already"),
            Error::NotHeld => f.write_str("not the commit held"),
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
/// ([`Mls::swap`]), or dropped.
pub struct Candidate {
    group: Group<Config>,
    namespace: Namespace,
    kind: Kind,
}

impl Candidate {
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The epoch it moves to.
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

    /// Its members' credentials, by leaf.
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
/// every device of the confirming set confirms it.
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
    match namespace.take_failure() {
        Some(error) => Error::Store(error),
        None => Error::Mls(error),
    }
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
        .crypto_provider(RustCryptoProvider::default())
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
                let suite = RustCryptoProvider::default()
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
            Err(error) => {
                self.namespace.unstage();
                self.reload()?;
                Err(Error::Store(error))
            }
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

    /// A key package for a device that adds this one, at `time`: its
    /// secrets written in one batch with `rows`.
    pub fn key_package(&mut self, time: u64, rows: Writes) -> Result<Vec<u8>, Error> {
        let message = self
            .client
            .generate_key_package_message(
                ExtensionList::new(),
                ExtensionList::new(),
                Some(MlsTime::from(time)),
            )
            .map_err(|error| self.failure(error))?;
        let bytes = message.to_bytes()?;
        self.flush(rows)?;
        Ok(bytes)
    }

    /// Make a group of this member alone at epoch 0, written in one batch
    /// with `rows`.
    pub fn create(&mut self, time: u64, rows: Writes) -> Result<(), Error> {
        if self.group.is_some() {
            return Err(Error::Grouped);
        }
        let mut group = self
            .client
            .create_group(
                ExtensionList::new(),
                ExtensionList::new(),
                Some(MlsTime::from(time)),
            )
            .map_err(|error| self.failure(error))?;
        group.write_to_storage()?;
        self.namespace.put(GROUP, Some(group.group_id().to_vec()));
        self.flush(rows)
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
        self.commit_as(None, adds, removes, time, rows)
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
        self.commit_as(Some(credential), adds, removes, time, rows)
    }

    fn commit_as(
        &mut self,
        renewed: Option<&[u8]>,
        adds: &[Vec<u8>],
        removes: &[Vec<u8>],
        time: u64,
        rows: impl FnOnce(&Commit) -> Writes,
    ) -> Result<Commit, Error> {
        self.hold(
            |member| member.held_commit(renewed, adds, removes, time),
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
        match build(self) {
            Ok(commit) => {
                self.flush(rows(&commit))?;
                Ok(commit)
            }
            Err(error) => {
                self.namespace.unstage();
                self.reload()?;
                Err(error)
            }
        }
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
        let epoch = group.current_epoch() + 1;
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
        if let Some(next) = self.namespace.get(NEXT)? {
            if held.hash != handshake_hash(handshake) {
                return Err(Error::NotHeld);
            }
            let namespace = self.namespace.copy();
            let group = client(&namespace, Rules::default(), None, Identity::default())
                .load_group(&next)
                .map_err(|error| failure(&namespace, error))?;
            return Ok(Candidate {
                group,
                namespace,
                kind: Kind::Started,
            });
        }
        if held.hash != handshake_hash(handshake) || held.epoch != self.epoch()? + 1 {
            return Err(Error::NotHeld);
        }
        let identity = match self.namespace.get(RENEWED)? {
            Some(bytes) => {
                let (_, renewed) = decode_signer(&bytes)?;
                let after = renewed.credential.as_basic().ok_or(Error::Corrupt)?;
                Identity::renewing(self.credential(), after.identifier.clone())
            }
            None => Identity::default(),
        };
        let (mut group, namespace) = self.copy(Rules::default(), identity)?;
        let secrets = CommitSecrets::from_bytes(&held.secrets).map_err(|_| Error::Corrupt)?;
        group.apply_detached_commit(secrets)?;
        Ok(Candidate {
            group,
            namespace,
            kind: Kind::Own,
        })
    }

    /// Another member's commit `handshake` processed on a copy at `time`
    /// (the log's batch time), under its logged effect `expected`: an
    /// encrypted commit with a path, by the expected committer, adding and
    /// removing exactly the expected credentials. A refusal is
    /// [`Error::Refused`].
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
        let (mut group, namespace) = self.copy(Rules::expecting(expected), identity)?;
        let received = match group.process_incoming_message_with_time(message, MlsTime::from(time))
        {
            Ok(received) => received,
            Err(error) => {
                if let Some(error) = namespace.take_failure() {
                    return Err(Error::Store(error));
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
            let before = leaf(current, description.committer);
            let after = leaf(&group, description.committer);
            let renewed = match (before, after) {
                (Some(before), Some(after)) => {
                    matches!(after.leaf_node_source, LeafNodeSource::Commit(_))
                        && after.public_key != before.public_key
                }
                _ => false,
            };
            if !renewed {
                return refused(Refusal::NoPath);
            }
        }
        Ok(Candidate {
            group,
            namespace,
            kind,
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
                    return Err(Error::Store(error));
                }
                return Err(Error::Refused(Refusal::Rejected(error)));
            }
        };
        Ok(Candidate {
            group,
            namespace,
            kind: Kind::Joined,
        })
    }

    /// Make `candidate` current, in one batch with `rows`: its state into
    /// the current namespace, any held commit deleted (its epoch is
    /// decided). A candidate that removes this member deletes the group; a
    /// new group's deletes the group it leaves.
    pub fn swap(&mut self, candidate: Candidate, rows: Writes) -> Result<(), Error> {
        let Candidate {
            mut group,
            namespace,
            kind,
        } = candidate;
        match kind {
            Kind::Removed => {
                let id = self.group()?.group_id().to_vec();
                self.namespace.put(&storage::state_row(&id), None);
                self.namespace.put(GROUP, None);
            }
            Kind::Own | Kind::Received if group.current_epoch() != self.epoch()? + 1 => {
                return Err(Error::NotHeld);
            }
            Kind::Joined | Kind::Own | Kind::Received | Kind::Started => {
                if kind == Kind::Own
                    && let Some(renewed) = self.namespace.get(RENEWED)?
                {
                    self.namespace.put(SIGNER, Some(renewed));
                }
                if let Some(current) = &self.group
                    && current.group_id() != group.group_id()
                {
                    let id = current.group_id().to_vec();
                    self.namespace.put(&storage::state_row(&id), None);
                }
                group.write_to_storage()?;
                self.namespace.stage(namespace.take_copy());
                self.namespace.put(GROUP, Some(group.group_id().to_vec()));
            }
        }
        self.namespace.put(HELD, None);
        self.namespace.put(NEXT, None);
        self.namespace.put(RENEWED, None);
        self.flush(rows)
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
