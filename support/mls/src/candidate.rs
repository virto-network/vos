//! Another member's commit or a Welcome processed on a copy, and the swap
//! that makes a candidate current.

use mls_rs::error::MlsError;
use mls_rs::group::{CommitEffect, LeafNode, LeafNodeSource, Node, ReceivedMessage};
use mls_rs::time::MlsTime;
use mls_rs::{Group, MlsMessage, WireFormat};

use crate::{
    Config, EPOCH_MAX, Error, Expected, GROUP, Identity, Mls, NEXT, Namespace, RENEWED, Refusal,
    Rules, SIGNER, Writes, base, credentials, signing, storage,
};

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
    pub(crate) group: Group<Config>,
    pub(crate) namespace: Namespace,
    pub(crate) kind: Kind,
    pub(crate) base: Option<(Vec<u8>, u64)>,
    pub(crate) held: Option<[u8; 32]>,
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

    /// Its members' credentials; for a commit that removes this device,
    /// the current ones.
    pub fn credentials(&self) -> Vec<Vec<u8>> {
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

fn leaf(group: &Group<Config>, index: u32) -> Option<LeafNode> {
    match group.export_tree().nodes().get(2 * index as usize) {
        Some(Some(Node::Leaf(leaf))) => Some(leaf.clone()),
        _ => None,
    }
}

/// mls-rs's refusal of a candidate as this layer's: `namespace`'s store
/// read's failure if one happened under it.
fn rejected(namespace: &Namespace, error: MlsError) -> Error {
    namespace
        .take_failure()
        .unwrap_or(Error::Refused(Refusal::Rejected(error)))
}

impl Mls {
    /// Another member's commit `handshake` processed on a copy at `time`
    /// (the log's batch time, so processing it again gives the same
    /// candidate), under its logged effect [`Expected`]. A refusal is
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
        let leaf_credential = expected
            .renewed
            .clone()
            .unwrap_or_else(|| expected.committer.clone());
        let (mut group, namespace) =
            self.copy(current.group_id(), Rules::expecting(expected), identity)?;
        let received = group
            .process_incoming_message_with_time(message, MlsTime::from(time))
            .map_err(|error| rejected(&namespace, error))?;
        let ReceivedMessage::Commit(description) = received else {
            return refused(Refusal::NotCommit);
        };
        let kind = match description.effect {
            CommitEffect::NewEpoch(_) => Kind::Received,
            CommitEffect::Removed { .. } => Kind::Removed,
            // The policy refuses a ReInit proposal before mls-rs computes
            // a commit's effect.
            CommitEffect::ReInit(_) => return refused(Refusal::NotCommit),
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
        let (group, _) = signing(&namespace, &self.signer)
            .join_group(None, &message, Some(MlsTime::from(time)))
            .map_err(|error| rejected(&namespace, error))?;
        if group.group_id().len() > storage::HASH_BYTES || group.current_epoch() > EPOCH_MAX {
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
    /// a new group's deletes the group it leaves, and a Welcome's every key
    /// package this member made. [`Error::Stale`] for a candidate made
    /// from another state than the current one.
    pub fn swap(&mut self, candidate: Candidate, rows: Writes) -> Result<(), Error> {
        let Candidate {
            mut group,
            namespace,
            kind,
            base: made_from,
            held,
        } = candidate;
        let current_held = self.held_row()?.map(|held| held.hash);
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
                        if kind == Kind::Joined {
                            member.namespace.delete_all(storage::PACKAGES)?;
                        }
                        group.write_to_storage()?;
                        member.namespace.stage_copy(&namespace);
                        member.namespace.put(GROUP, Some(id));
                    }
                    None => member.namespace.put(GROUP, None),
                }
                member.unhold();
                Ok(())
            },
            |_| rows,
        )
    }
}
