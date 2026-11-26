//! A member's own commit, held until it is confirmed, and a restart.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use mls_rs::error::MlsError;
use mls_rs::group::CommitSecrets;
use mls_rs::identity::SigningIdentity;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::time::MlsTime;
use mls_rs::{Group, MlsMessage};

use crate::{
    Candidate, Config, Error, HELD, Identity, Kind, Mls, NEXT, Namespace, RENEWED, Rules, Signer,
    Writes, base, client, failure, leaves, storage,
};

/// A member's own commit, held until it is confirmed: its handshake, the
/// Welcome for the members it adds, and the epoch it moves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub handshake: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub epoch: u64,
}

/// A handshake's hash, which a held commit is matched by.
fn handshake_hash(handshake: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"vos/mls/handshake");
    hasher.update(handshake);
    hasher.finalize().into()
}

/// A held commit's row: its handshake's hash, its epoch little-endian and
/// its secrets.
pub(crate) struct Held {
    pub(crate) hash: [u8; 32],
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

/// `group`'s state and the commit of `handshake` to `epoch`, held, staged
/// in `namespace`: the commit as its caller posts it.
fn stage_held(
    namespace: &Namespace,
    group: &mut Group<Config>,
    handshake: Vec<u8>,
    welcome: Option<Vec<u8>>,
    epoch: u64,
    secrets: Vec<u8>,
) -> Result<Commit, Error> {
    let held = Held {
        hash: handshake_hash(&handshake),
        epoch,
        secrets,
    };
    group.write_to_storage()?;
    namespace.put(HELD, Some(held.encode()));
    Ok(Commit {
        handshake,
        welcome,
        epoch,
    })
}

impl Mls {
    /// The epoch of the commit held, if one is.
    pub fn held(&self) -> Result<Option<u64>, Error> {
        Ok(self.held_row()?.map(|held| held.epoch))
    }

    pub(crate) fn held_row(&self) -> Result<Option<Held>, Error> {
        self.namespace
            .get(HELD)?
            .map(|bytes| Held::decode(&bytes).ok_or(Error::Corrupt))
            .transpose()
    }

    /// Stage the deletes of a held commit's rows: the commit, a restart's
    /// new group's id and a renewal's signer.
    pub(crate) fn unhold(&self) {
        for row in [HELD, NEXT, RENEWED] {
            self.namespace.put(row, None);
        }
    }

    /// Commit adding the members of `adds` (their key packages) and
    /// removing the members whose credentials are `removes`, with a path,
    /// at `time`, held: the current state, the held commit and the
    /// caller's `rows` of it in one commit, written before this returns.
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
    /// caller's `rows` of it in one commit, written before this returns; on
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
                let renewal = Signer {
                    secret: self.signer.secret.clone(),
                    identity: SigningIdentity::new(
                        BasicCredential::new(credential.to_vec()).into_credential(),
                        self.signer.identity.signature_key.clone(),
                    ),
                };
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
                        .map_err(|error| failure(&self.namespace, error))?,
                );
                self.namespace.put(RENEWED, Some(renewal.encode()?));
                Some(renewal)
            }
            None => None,
        };
        let group = self.group.as_mut().ok_or(Error::NoGroup)?;
        let members = leaves(group);
        let mut builder = group.commit_builder().commit_time(MlsTime::from(time));
        if let Some(Signer { secret, identity }) = renewal {
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
        let welcome = output
            .welcome_messages
            .first()
            .map(MlsMessage::to_bytes)
            .transpose()?;
        let epoch = group
            .current_epoch()
            .checked_add(1)
            .ok_or(Error::Mls(MlsError::InvalidEpoch))?;
        let secrets = secrets.to_bytes()?;
        stage_held(&self.namespace, group, handshake, welcome, epoch, secrets)
    }

    /// Restart: a new group of this member alone at `time`, its commit
    /// applied at once and held, the current group kept until the restart
    /// is swapped in. The new group's state, the held commit and the
    /// caller's `rows` of it in one commit, written before this returns.
    pub fn restart(
        &mut self,
        time: u64,
        rows: impl FnOnce(&Commit) -> Writes,
    ) -> Result<Commit, Error> {
        self.hold(|member| member.started(time), rows)
    }

    fn started(&mut self, time: u64) -> Result<Commit, Error> {
        let mut group = self.new_group(time)?;
        let output = group
            .commit_builder()
            .commit_time(MlsTime::from(time))
            .build()?;
        group.apply_pending_commit()?;
        let handshake = output.commit_message.to_bytes()?;
        let epoch = group.current_epoch();
        let commit = stage_held(
            &self.namespace,
            &mut group,
            handshake,
            None,
            epoch,
            Vec::new(),
        )?;
        self.namespace.put(NEXT, Some(group.group_id().to_vec()));
        Ok(commit)
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
            let (group, namespace) = self.copy(&next, Rules::default(), Identity::default())?;
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
        let (mut group, namespace) = self.copy(
            self.group()?.group_id(),
            Rules::default(),
            Identity::default(),
        )?;
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

    /// Delete the held commit, its candidate void, in one commit with
    /// `rows`: a held restart's new group with it.
    pub fn void(&mut self, rows: Writes) -> Result<(), Error> {
        if let Some(next) = self.namespace.get(NEXT)? {
            self.namespace.put(&storage::state_row(&next), None);
        }
        self.unhold();
        self.write(rows)
    }
}
