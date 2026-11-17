//! Checkpoints (`light-node.md` §3.6): a scope's state after every envelope
//! up to a position the agent numbered, `P`, named by a hash every device
//! that read the scope to `P` computes alike, and pushed sealed into a
//! scope of its own beside the data scope's.
//!
//! - **The hash** ([`checkpoint_hash`]) is over the agent, the scope, `P`,
//!   and each position up to `P` whose envelope held a node, with that
//!   node's CID, in order: a function of the agent's order alone, so two
//!   devices that checkpoint at once hold the same (C3). A checkpoint is cut
//!   only where the scope's causal past is complete, no node held for a
//!   missing parent.
//! - **Its content** is those nodes, by position, in parts; its maker signs
//!   `made(P, hash)` under its sync key beside them.
//! - **Acknowledgements:** a device that has read the scope to `P`
//!   recomputes the hash from what it read: equal, it signs
//!   `acknowledged(P, hash)` into the checkpoints' scope; not, it raises
//!   [`Alarm::Checkpoint`] and acknowledges nothing (C4).
//! - **Which a device starts from:** a paired device, the one its pairing
//!   device named over the pairing channel; a restore's device, the latest
//!   one two devices other than its makers acknowledged, each signature
//!   checked against the device set; otherwise none, and it reads the scope
//!   from its start. The content is checked against its hash before a node
//!   of it is applied (C12).

use std::collections::BTreeMap;

use ed25519_dalek::Signer as _;
use vos_abi::ids::InstanceId;
use vos_abi::{Decode, Encode};
use vos_wire::personal::Scope;
use zeroize::Zeroizing;

use super::{AT, Link, SealedSync, SyncError, digest, raise, scope_key};
use crate::group::verifies;
use crate::group::{Alarm, Checkpoint, GroupError, Trust};
use crate::sealed::{self, MAX_BODY};
use crate::sync::{Blake2b256, scope_name};
use merkle_crdt::Hasher as _;

/// The name the checkpoints' scope of an instance's derives from, apart
/// from every instance's (four bytes) and from the archive's.
const CHECKPOINT_NAME: &[u8] = b"vos/personal/checkpoint/";

/// The checkpoints' scope's reading, in the group keyspace.
const MARKS: &[u8] = b"s/marks/";

/// What a device read of a scope: each position whose envelope held a
/// node, and the node's CID.
type Read = Vec<(u64, [u8; 32])>;

/// The checkpoints a device keeps waiting until it has read their scope to
/// their position.
const PENDING: usize = 16;

/// What a part holds beyond its bytes: the enum's tag, the position, the
/// hash, the two counts and the bytes' length prefix.
const PART_FRAMING: usize = 1 + 8 + 32 + 4 + 4 + 4;

/// The content's bytes a part holds.
const PART_BYTES: usize = MAX_BODY - PART_FRAMING;

/// What a device signs of a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
enum Said {
    /// Its maker's.
    #[codec(index = 0)]
    Made = 0,
    /// A device that recomputed it.
    #[codec(index = 1)]
    Acknowledged = 1,
}

/// An envelope of the checkpoints' scope.
#[derive(Clone, Debug, Encode, Decode)]
enum Mark {
    /// Part `part` of `parts` of the content of the checkpoint at
    /// `position` named `hash`.
    #[codec(index = 0)]
    Part {
        position: u64,
        hash: [u8; 32],
        part: u32,
        parts: u32,
        bytes: Vec<u8>,
    },
    /// A device's signed word on the checkpoint at `position` named `hash`.
    #[codec(index = 1)]
    Said {
        said: Said,
        position: u64,
        hash: [u8; 32],
        author: [u8; 32],
        signature: [u8; 64],
    },
}

/// The checkpoints' scope's reading, stored: its cursor, the checkpoints
/// made that wait for this device's reading of the data scope, and those
/// it acknowledged.
#[derive(Clone, Default, Encode, Decode)]
struct Marks {
    cursor: u64,
    pending: Vec<(u64, [u8; 32])>,
    acknowledged: Vec<(u64, [u8; 32])>,
}

/// What acknowledging a scope's checkpoints did.
#[derive(Debug, Default)]
pub struct Acknowledging {
    /// The checkpoints acknowledged, by position.
    pub acknowledged: Vec<u64>,
    /// Those whose hash is not this device's reading: [`Alarm::Checkpoint`].
    pub alarms: Vec<Alarm>,
}

/// The hash of the checkpoint of `scope` at `position`, for the agent whose
/// identity is `agent`: over each position up to it whose envelope held a
/// node, and that node's CID, in order.
pub fn checkpoint_hash(
    agent: &[u8; 32],
    scope: &Scope,
    position: u64,
    read: &[(u64, [u8; 32])],
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(16 + 8 + 40 * read.len() + 32);
    bytes.extend_from_slice(agent);
    bytes.extend_from_slice(scope);
    bytes.extend_from_slice(&position.to_le_bytes());
    for (at, cid) in read {
        bytes.extend_from_slice(&at.to_le_bytes());
        bytes.extend_from_slice(cid);
    }
    digest(b"vos/personal/checkpoint", &bytes)
}

/// What a device's sync key signs of the checkpoint of `scope` at
/// `position` named `hash`.
fn said_message(
    agent: &[u8; 32],
    scope: &Scope,
    said: Said,
    position: u64,
    hash: &[u8; 32],
) -> Vec<u8> {
    let mut message = b"vos/personal/checkpoint-said".to_vec();
    message.extend_from_slice(agent);
    message.extend_from_slice(scope);
    message.push(said as u8);
    message.extend_from_slice(&position.to_le_bytes());
    message.extend_from_slice(hash);
    message
}

/// A checkpoint as the checkpoints' scope shows it: the devices that made
/// it, and those that acknowledged it.
#[derive(Default)]
struct Shown {
    makers: Vec<[u8; 32]>,
    acknowledged: Vec<[u8; 32]>,
}

impl<L: Link> SealedSync<'_, L> {
    /// The id of `instance`'s checkpoints' scope.
    fn marks_scope(&self, instance: InstanceId) -> Scope {
        let name = [CHECKPOINT_NAME, &scope_name(instance)[..]].concat();
        self.group.archive().scope(&name)
    }

    /// What this device read of `scope` up to `position`: each position
    /// whose envelope held a node, and the node's CID.
    fn read_to(
        &self,
        instance: InstanceId,
        scope: &Scope,
        position: u64,
    ) -> Result<Read, SyncError<L::Error>> {
        let corrupt = || SyncError::Group(GroupError::Corrupt);
        let mut read = Vec::new();
        for (key, value) in self
            .light
            .store()
            .group_rows(&scope_key(AT, scope, None), None)?
        {
            let at = super::position_of(&key).ok_or_else(corrupt)?;
            if at > position {
                break;
            }
            let cid = <[u8; 32]>::try_from(&value[..]).map_err(|_| corrupt())?;
            // A node the scope refused (its chain broken, a parent refused)
            // is every device's to refuse: it is in no checkpoint.
            if self
                .light
                .node(instance, &merkle_crdt::Cid::<Blake2b256>(cid))?
                .is_some()
            {
                read.push((at, cid));
            }
        }
        Ok(read)
    }

    /// Seal `marks` in `instance`'s checkpoints' scope at the confirmed
    /// epoch and push them: the position of each.
    fn push_marks(
        &mut self,
        instance: InstanceId,
        marks: &[Mark],
    ) -> Result<Vec<u64>, SyncError<L::Error>> {
        let scope = self.marks_scope(instance);
        let epoch = self.group.confirmed();
        let key = Zeroizing::new(self.group.key(scope)?);
        let agent = self.group.agent().identity;
        let envelopes: Vec<Vec<u8>> = marks
            .iter()
            .map(|mark| {
                let body = Zeroizing::new(mark.encode());
                sealed::seal(&key, &agent, scope, epoch, &body).expect("a mark fits an envelope")
            })
            .collect();
        self.send(&envelopes)?
            .into_iter()
            .map(|answer| {
                answer
                    .map(|pushed| pushed.position)
                    .map_err(SyncError::Refused)
            })
            .collect()
    }

    /// This device's signed word on the checkpoint of `scope` at `position`
    /// named `hash`.
    fn say(&self, said: Said, scope: &Scope, position: u64, hash: [u8; 32]) -> Mark {
        let agent = self.group.agent().identity;
        let key = self.light.sync_key();
        let message = said_message(&agent, scope, said, position, &hash);
        Mark::Said {
            said,
            position,
            hash,
            author: key.verifying_key().to_bytes(),
            signature: key.sign(&message).to_bytes(),
        }
    }

    /// Make the checkpoint of `instance`'s scope at its cursor: its content
    /// and this device's `made` pushed into the checkpoints' scope. What a
    /// pairing device hands the device it pairs ([`crate::group::Pairing::trust`]).
    /// [`SyncError::Incomplete`] before the scope's first page, or while a
    /// node waits for a parent.
    pub fn checkpoint(&mut self, instance: InstanceId) -> Result<Checkpoint, SyncError<L::Error>> {
        let scope = self.light.scope_id(instance)?.0;
        let position = self
            .light
            .cursor(instance)?
            .filter(|position| *position > 0)
            .ok_or(SyncError::Incomplete)?;
        if self.light.wanted(instance)?.0 > 0 {
            return Err(SyncError::Incomplete);
        }
        let read = self.read_to(instance, &scope, position)?;
        let agent = self.group.agent().identity;
        let hash = checkpoint_hash(&agent, &scope, position, &read);
        let mut content = Vec::with_capacity(read.len());
        for (at, cid) in &read {
            let node = self
                .light
                .node(instance, &merkle_crdt::Cid::<Blake2b256>(*cid))?
                .ok_or(SyncError::Group(GroupError::Corrupt))?;
            content.push((*at, node));
        }
        let content = Zeroizing::new(content.encode());
        let pieces: Vec<&[u8]> = content.chunks(PART_BYTES).collect();
        let parts = pieces.len() as u32;
        let mut marks: Vec<Mark> = pieces
            .into_iter()
            .enumerate()
            .map(|(part, bytes)| Mark::Part {
                position,
                hash,
                part: part as u32,
                parts,
                bytes: bytes.to_vec(),
            })
            .collect();
        marks.push(self.say(Said::Made, &scope, position, hash));
        let positions = self.push_marks(instance, &marks)?;
        Ok(Checkpoint {
            scope,
            position,
            hash,
            from: positions[0] - 1,
        })
    }

    /// Read `instance`'s checkpoints' scope after `from`: each mark that
    /// opens, at its position, up to an envelope of an epoch past the
    /// confirmed one.
    fn marks(
        &mut self,
        instance: InstanceId,
        from: u64,
        mut each: impl FnMut(u64, Mark) -> bool,
    ) -> Result<u64, SyncError<L::Error>> {
        let scope = self.marks_scope(instance);
        let agent = self.group.agent().identity;
        let confirmed = self.group.confirmed();
        let mut cursor = from;
        loop {
            let page = self.since(scope, cursor)?;
            if page.is_empty() {
                return Ok(cursor);
            }
            for envelope in page {
                if envelope.position <= cursor {
                    return Err(SyncError::Disordered);
                }
                let Ok(header) = sealed::header_of(&envelope.bytes) else {
                    cursor = envelope.position;
                    continue;
                };
                if header.epoch > confirmed {
                    return Ok(cursor);
                }
                cursor = envelope.position;
                if header.scope != scope {
                    continue;
                }
                let keys = Zeroizing::new(self.keys(scope, header.epoch)?);
                let Ok((_, body)) = sealed::open(&keys, &agent, &envelope.bytes) else {
                    continue;
                };
                if let Some(mark) = Mark::decode_exact(&body)
                    && !each(envelope.position, mark)
                {
                    return Ok(cursor);
                }
            }
        }
    }

    /// Whether `author`'s signed word `said` on the checkpoint of `scope`
    /// at `position` named `hash` verifies against a device of the set.
    fn said_by(
        &self,
        author: &[u8; 32],
        signature: &[u8; 64],
        said: Said,
        scope: &Scope,
        position: u64,
        hash: &[u8; 32],
    ) -> bool {
        let agent = self.group.agent().identity;
        self.group.author(author).is_some()
            && verifies(
                author,
                &said_message(&agent, scope, said, position, hash),
                signature,
            )
    }

    /// Read `instance`'s checkpoints and acknowledge each one this device
    /// has read the data scope to and whose hash is its own reading's; one
    /// whose hash is not raises [`Alarm::Checkpoint`]. Those past this
    /// device's cursor wait.
    pub fn acknowledge(
        &mut self,
        instance: InstanceId,
    ) -> Result<Acknowledging, SyncError<L::Error>> {
        let scope = self.light.scope_id(instance)?.0;
        let row = scope_key(MARKS, &scope, None);
        let mut marks: Marks = self.row(&row)?;
        let mut made = Vec::new();
        marks.cursor = self.marks(instance, marks.cursor, |_, mark| {
            if let Mark::Said {
                said: Said::Made,
                position,
                hash,
                author,
                signature,
            } = mark
            {
                made.push((position, hash, author, signature));
            }
            true
        })?;
        let me = self.light.sync_key().verifying_key().to_bytes();
        for (position, hash, author, signature) in made {
            // A maker's word is its `made`: it acknowledges no checkpoint
            // of its own.
            if author != me
                && self.said_by(&author, &signature, Said::Made, &scope, position, &hash)
                && !marks.pending.contains(&(position, hash))
                && !marks.acknowledged.contains(&(position, hash))
            {
                marks.pending.push((position, hash));
            }
        }
        if marks.pending.len() > PENDING {
            marks.pending.drain(..marks.pending.len() - PENDING);
        }
        let cursor = self.light.cursor(instance)?.unwrap_or(0);
        let agent = self.group.agent().identity;
        let mut report = Acknowledging::default();
        let mut acks = Vec::new();
        let mut waiting = Vec::new();
        for (position, hash) in std::mem::take(&mut marks.pending) {
            if position > cursor {
                waiting.push((position, hash));
                continue;
            }
            let mine = checkpoint_hash(
                &agent,
                &scope,
                position,
                &self.read_to(instance, &scope, position)?,
            );
            if mine == hash {
                acks.push(self.say(Said::Acknowledged, &scope, position, hash));
                marks.acknowledged.push((position, hash));
                report.acknowledged.push(position);
            } else {
                raise(&mut report.alarms, Alarm::Checkpoint { scope, position });
            }
        }
        marks.pending = waiting;
        if marks.acknowledged.len() > PENDING {
            marks
                .acknowledged
                .drain(..marks.acknowledged.len() - PENDING);
        }
        self.keep_alarms(&report.alarms)?;
        if !acks.is_empty() {
            self.push_marks(instance, &acks)?;
        }
        self.store_row(&row, &marks)?;
        Ok(report)
    }

    /// The content of the checkpoint at `position` named `hash`, its parts
    /// read from `from` on, if they are all there.
    fn content(
        &mut self,
        instance: InstanceId,
        from: u64,
        position: u64,
        hash: [u8; 32],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, SyncError<L::Error>> {
        let mut parts: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        let mut count = None;
        self.marks(instance, from, |_, mark| {
            if let Mark::Part {
                position: at,
                hash: named,
                part,
                parts: of,
                bytes,
            } = mark
                && at == position
                && named == hash
                && part < of
                && count.is_none_or(|count| count == of)
            {
                count = Some(of);
                parts.insert(part, bytes);
            }
            count.is_none_or(|count| parts.len() < count as usize)
        })?;
        Ok(count
            .filter(|count| parts.len() == *count as usize)
            .map(|_| Zeroizing::new(parts.into_values().flatten().collect())))
    }

    /// Apply the checkpoint at `position` named `hash` from its `content`
    /// as `instance`'s scope's start: its nodes, by position, checked
    /// against the hash first, then applied with the cursor at `position`
    /// in one batch. Whether it was.
    fn install(
        &mut self,
        instance: InstanceId,
        scope: Scope,
        position: u64,
        hash: [u8; 32],
        content: &[u8],
    ) -> Result<bool, SyncError<L::Error>> {
        let Some(nodes) = Vec::<(u64, Vec<u8>)>::decode_exact(content) else {
            return Ok(false);
        };
        let read: Vec<(u64, [u8; 32])> = nodes
            .iter()
            .map(|(at, node)| (*at, Blake2b256::hash(node)))
            .collect();
        let ordered = read.windows(2).all(|pair| pair[0].0 < pair[1].0)
            && read.last().is_none_or(|(at, _)| *at <= position);
        let agent = self.group.agent().identity;
        if !ordered || checkpoint_hash(&agent, &scope, position, &read) != hash {
            return Ok(false);
        }
        let rows = read
            .iter()
            .map(|(at, cid)| (scope_key(AT, &scope, Some(*at)), Some(cid.to_vec())))
            .collect();
        self.light.store().write_group_rows(rows)?;
        self.light.ingest(
            instance,
            nodes.into_iter().map(|(_, node)| node),
            Some(position),
        )?;
        Ok(true)
    }

    /// Start `instance`'s scope, read for the first time, from the
    /// checkpoint this device trusts: the position it starts after, or none
    /// to read the scope from its start.
    pub(super) fn start(
        &mut self,
        instance: InstanceId,
        scope: Scope,
        alarms: &mut Vec<Alarm>,
    ) -> Result<Option<u64>, SyncError<L::Error>> {
        let trusted = match self.group.trust().clone() {
            Trust::Paired(checkpoints) => {
                let Some(checkpoint) = checkpoints.into_iter().find(|held| held.scope == scope)
                else {
                    return Ok(None);
                };
                vec![checkpoint]
            }
            Trust::Acknowledged => self.acknowledged(instance, scope)?,
        };
        for Checkpoint {
            position,
            hash,
            from,
            ..
        } in trusted
        {
            // A refusal is kept before an older checkpoint's install moves
            // the cursor, after which the scope starts no more.
            self.keep_alarms(alarms)?;
            let installed = match self.content(instance, from, position, hash)? {
                Some(content) => self.install(instance, scope, position, hash, &content)?,
                None => false,
            };
            if installed {
                return Ok(Some(position));
            }
            raise(alarms, Alarm::Checkpoint { scope, position });
        }
        Ok(None)
    }

    /// The checkpoints of `instance`'s scope that a device made and two
    /// devices that made none of it acknowledged, each signature checked
    /// against the device set: the latest first.
    fn acknowledged(
        &mut self,
        instance: InstanceId,
        scope: Scope,
    ) -> Result<Vec<Checkpoint>, SyncError<L::Error>> {
        let mut said = Vec::new();
        let mut firsts: BTreeMap<(u64, [u8; 32]), u64> = BTreeMap::new();
        self.marks(instance, 0, |at, mark| {
            match mark {
                Mark::Part { position, hash, .. } => {
                    firsts.entry((position, hash)).or_insert(at);
                }
                Mark::Said {
                    said: word,
                    position,
                    hash,
                    author,
                    signature,
                } => {
                    said.push((word, position, hash, author, signature));
                }
            }
            true
        })?;
        let mut shown: BTreeMap<(u64, [u8; 32]), Shown> = BTreeMap::new();
        for (word, position, hash, author, signature) in said {
            if !self.said_by(&author, &signature, word, &scope, position, &hash) {
                continue;
            }
            let entry = shown.entry((position, hash)).or_default();
            match word {
                Said::Made if !entry.makers.contains(&author) => entry.makers.push(author),
                Said::Made => {}
                Said::Acknowledged if !entry.acknowledged.contains(&author) => {
                    entry.acknowledged.push(author)
                }
                Said::Acknowledged => {}
            }
        }
        let mut trusted: Vec<Checkpoint> = shown
            .into_iter()
            .filter_map(|((position, hash), shown)| {
                let others = shown
                    .acknowledged
                    .iter()
                    .filter(|author| !shown.makers.contains(author))
                    .count();
                let first = firsts.get(&(position, hash))?;
                (!shown.makers.is_empty() && others >= 2).then_some(Checkpoint {
                    scope,
                    position,
                    hash,
                    from: first - 1,
                })
            })
            .collect();
        trusted.sort_by(|a, b| b.position.cmp(&a.position));
        Ok(trusted)
    }
}
