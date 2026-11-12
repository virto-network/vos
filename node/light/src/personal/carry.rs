//! Carrying a scope to an agent that lacks it (`light-node.md` §3.9): a
//! move pushes everything to its new home, and a device paired again
//! there pushes what the move did not carry; and the notice of a move a
//! device leaves at the home it left.
//!
//! - **What the agent lacks** is every node the scope holds applied that
//!   this device neither read there nor pushed there: its reading's and
//!   its own pushes' CIDs by position. A node past its author's cutoff
//!   stays behind, so a removed device's late nodes reach no new home; so
//!   does one of an author no device of the set is, past the number the
//!   keys of a device of the set with a voice name it carried to
//!   (`NewDevice::carried`), which no reader there would take; and so does
//!   every node over one left behind, whose parent no reader would hold.
//! - **In causal order,** parents first, sealed under the confirmed epoch
//!   with this device's view and `seen` positions, [`PIPELINE`] a round;
//!   each round's sealed bytes held in the store before they are sent, so
//!   a retry after a lost answer or a crash sends them as they are and the
//!   agent answers them by id. Each node taken is recorded as pushed at
//!   its position, and this device's own leave its outbox, round by round.
//!   The cursor stays: the next reading reads the carried envelopes back,
//!   so whatever another device pushed between them is read too.
//! - **The notice** of a move is signed by its maker's sync key, and read
//!   only from a device of the set that is not removed.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::Signer as _;
use vos_wire::ids::InstanceId;
use vos_wire::personal::PersonalError;
use vos_wire::{Decode, Encode};
use zeroize::Zeroizing;

use super::{AT, Link, OWN, PIPELINE, SealedSync, SyncError, scope_key};
use crate::group::{GroupError, verifies};
use crate::moving::Notice;
use crate::sealed;
use crate::sync::Blake2b256;

/// A scope's carry round sealed and not yet all taken, in the group
/// keyspace.
const CARRY: &[u8] = b"s/carry/";

/// The name the notice of a move derives its scope from, apart from every
/// instance's (four bytes).
const NOTICE_NAME: &[u8] = b"vos/personal/moved";

/// A notice as it is sealed: its maker's sync key and signature over
/// [`notice_message`].
#[derive(Encode, Decode)]
struct SignedNotice {
    notice: Notice,
    author: [u8; 32],
    signature: [u8; 64],
}

/// What a notice's maker signs: the notice at the agent whose identity is
/// `agent`.
fn notice_message(agent: &[u8; 32], notice: &Notice) -> Vec<u8> {
    let mut message = NOTICE_NAME.to_vec();
    message.extend_from_slice(agent);
    notice.encode_to(&mut message);
    message
}

/// A node sealed for a carry: its CID, its author and number, and its
/// envelope.
#[derive(Encode, Decode)]
struct Sealed {
    cid: [u8; 32],
    author: [u8; 32],
    seq: u64,
    envelope: Vec<u8>,
}

/// A carry's round in flight, sealed under `epoch`.
#[derive(Default, Encode, Decode)]
struct Round {
    epoch: u64,
    sealed: Vec<Sealed>,
}

/// What carrying a scope did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Carried {
    /// The positions the agent took the carried nodes at, in order.
    pub pushed: Vec<u64>,
    /// The nodes this device read or pushed there already.
    pub held: usize,
    /// The nodes left behind: past their author's cutoff, past what the
    /// keys of a device with a voice name of a carried author, or over one
    /// left behind.
    pub cut: usize,
    /// The carry stopped at `StaleEpoch` for this epoch: follow the log,
    /// then carry again.
    pub stale: Option<u64>,
}

type Node = ([u8; 32], merkle_crdt::Header<Blake2b256>, Vec<u8>);

/// `nodes` in causal order: each after its parents among them.
fn causal(nodes: Vec<Node>) -> Vec<Node> {
    let within: BTreeSet<[u8; 32]> = nodes.iter().map(|(cid, ..)| *cid).collect();
    let mut waits: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut children: BTreeMap<[u8; 32], Vec<[u8; 32]>> = BTreeMap::new();
    let mut ready = Vec::new();
    let mut by_cid = BTreeMap::new();
    for (cid, header, bytes) in nodes {
        let parents: Vec<[u8; 32]> = header
            .parents
            .iter()
            .map(|parent| parent.0)
            .filter(|parent| within.contains(parent))
            .collect();
        if parents.is_empty() {
            ready.push(cid);
        } else {
            waits.insert(cid, parents.len());
            for parent in parents {
                children.entry(parent).or_default().push(cid);
            }
        }
        by_cid.insert(cid, (header, bytes));
    }
    let mut ordered = Vec::with_capacity(by_cid.len());
    while let Some(cid) = ready.pop() {
        for child in children.remove(&cid).into_iter().flatten() {
            let waiting = waits.get_mut(&child).expect("a child waits");
            *waiting -= 1;
            if *waiting == 0 {
                waits.remove(&child);
                ready.push(child);
            }
        }
        let (header, bytes) = by_cid.remove(&cid).expect("each node once");
        ordered.push((cid, header, bytes));
    }
    ordered
}

impl<L: Link> SealedSync<'_, L> {
    /// The CIDs this device read in `scope` at the agent, or pushed there.
    fn known(&self, scope: &[u8; 16]) -> Result<BTreeSet<[u8; 32]>, SyncError<L::Error>> {
        let corrupt = || SyncError::Group(GroupError::Corrupt);
        let store = self.light.store();
        let mut known = BTreeSet::new();
        for (_, cid) in store.group_rows(&scope_key(AT, scope, None), None)? {
            known.insert(<[u8; 32]>::try_from(&cid[..]).map_err(|_| corrupt())?);
        }
        for (_, own) in store.group_rows(&scope_key(OWN, scope, None), None)? {
            let (_, cid) = <([u8; 32], [u8; 32])>::decode_exact(&own).ok_or_else(corrupt)?;
            known.insert(cid);
        }
        Ok(known)
    }

    /// Push every node of `instance`'s scope the agent lacks, as this
    /// device knows it, in causal order (the module's rules): what a move
    /// carries to its new home, and what a device paired again there
    /// carries after its catch-up. A round sealed under an epoch since
    /// replaced is sealed again; one the agent took meanwhile is a
    /// duplicate node at worst, which every reader skips.
    pub fn carry(&mut self, instance: InstanceId) -> Result<Carried, SyncError<L::Error>> {
        let scope = self.light.scope_id(instance)?.0;
        let corrupt = || SyncError::Group(GroupError::Corrupt);
        let known = self.known(&scope)?;
        let row = scope_key(CARRY, &scope, None);
        let confirmed = self.group.confirmed();
        let mut round: Round = self.row(&row)?;
        if round.epoch != confirmed {
            round.sealed.clear();
        }
        let mut report = Carried::default();
        let mut left = Vec::new();
        let mut behind = BTreeSet::new();
        for (cid, bytes) in self.light.nodes(instance)? {
            let cid = cid.0;
            if known.contains(&cid) {
                report.held += 1;
                continue;
            }
            if round.sealed.iter().any(|sealed| sealed.cid == cid) {
                continue;
            }
            let header = merkle_crdt::Header::<Blake2b256>::read(&bytes).ok_or_else(corrupt)?;
            if self
                .light
                .cutoff(instance, &header.author)?
                .is_some_and(|from| header.seq >= from)
            {
                report.cut += 1;
                behind.insert(cid);
                continue;
            }
            if self.group.author(&header.author.0).is_none()
                && self
                    .group
                    .carriers(&header.author.0, &scope)
                    .iter()
                    .all(|(through, removed)| removed.is_some() || header.seq > *through)
            {
                report.cut += 1;
                behind.insert(cid);
                continue;
            }
            left.push((cid, header, bytes));
        }
        // A node over one left behind stays behind too: no reader there
        // would ever hold its parent.
        let mut kept = Vec::with_capacity(left.len());
        for (cid, header, bytes) in causal(left) {
            if header
                .parents
                .iter()
                .any(|parent| behind.contains(&parent.0))
            {
                behind.insert(cid);
                report.cut += 1;
            } else {
                kept.push((cid, header, bytes));
            }
        }
        let author = self.light.author().0;
        let mut left = kept.into_iter();
        loop {
            if round.sealed.is_empty() {
                for (cid, header, bytes) in left.by_ref().take(PIPELINE) {
                    let queued = self.seal(scope, header.seq, &bytes)?;
                    round.sealed.push(Sealed {
                        cid,
                        author: header.author.0,
                        seq: header.seq,
                        envelope: queued.envelope,
                    });
                }
                if round.sealed.is_empty() {
                    break;
                }
                round.epoch = confirmed;
                self.store_row(&row, &round)?;
            }
            let envelopes: Vec<Vec<u8>> = round
                .sealed
                .iter()
                .map(|sealed| sealed.envelope.clone())
                .collect();
            let answers = self.send(&envelopes)?;
            let mut taken = Vec::new();
            let mut own = Vec::new();
            let mut stop = None;
            for (sealed, answer) in round.sealed.iter().zip(answers) {
                match answer {
                    Ok(pushed) => {
                        taken.push((pushed.position, pushed.id, sealed.cid));
                        if sealed.author == author {
                            own.push(sealed.seq);
                        }
                        report.pushed.push(pushed.position);
                    }
                    Err(error) => {
                        stop = Some(error);
                        break;
                    }
                }
            }
            self.record_own(scope, &taken, None)?;
            self.light.sent(instance, &own)?;
            round.sealed.drain(..taken.len());
            self.store_row(&row, &round)?;
            match stop {
                None => {}
                Some(PersonalError::StaleEpoch { confirmed: later }) if later > confirmed => {
                    report.stale = Some(later);
                    break;
                }
                Some(error) => return Err(SyncError::Refused(error)),
            }
        }
        Ok(report)
    }

    /// Leave `notice` at this agent, signed by this device's sync key and
    /// sealed under the confirmed epoch in a scope of its own, then push
    /// the archive, which carries that scope's key to the devices here at
    /// later epochs: they read where the space moved
    /// ([`SealedSync::announced`]), and the operators read nothing. Its
    /// position.
    pub fn announce(&mut self, notice: &Notice) -> Result<u64, SyncError<L::Error>> {
        let scope = self.group.archive().scope(NOTICE_NAME);
        let epoch = self.group.confirmed();
        let key = Zeroizing::new(self.group.key(scope)?);
        let agent = self.group.agent().identity;
        let sync = self.light.sync_key();
        let signed = SignedNotice {
            notice: notice.clone(),
            author: sync.verifying_key().to_bytes(),
            signature: sync.sign(&notice_message(&agent, notice)).to_bytes(),
        };
        let envelope = sealed::seal(&key, &agent, scope, epoch, &signed.encode())
            .expect("a notice fits an envelope");
        let position = match self.send(&[envelope])?.pop() {
            Some(answer) => answer.map(|pushed| pushed.position),
            None => return Err(SyncError::Unanswered),
        }
        .map_err(SyncError::Refused)?;
        self.archive()?;
        Ok(position)
    }

    /// The latest notice of a move at this agent that this device opens,
    /// signed by a device of the set that is not removed: none while no
    /// device moved.
    pub fn announced(&mut self) -> Result<Option<Notice>, SyncError<L::Error>> {
        let scope = self.group.archive().scope(NOTICE_NAME);
        let agent = self.group.agent().identity;
        let confirmed = self.group.confirmed();
        let mut cursor = 0;
        let mut found = None;
        loop {
            let page = self.since(scope, cursor)?;
            if page.is_empty() {
                return Ok(found);
            }
            for envelope in page {
                if envelope.position <= cursor {
                    return Err(SyncError::Disordered);
                }
                cursor = envelope.position;
                let Ok(header) = sealed::header_of(&envelope.bytes) else {
                    continue;
                };
                if header.scope != scope || header.epoch > confirmed {
                    continue;
                }
                let keys = Zeroizing::new(self.keys(scope, header.epoch)?);
                if let Ok((_, body)) = sealed::open(&keys, &agent, &envelope.bytes)
                    && let Some(signed) = SignedNotice::decode_exact(&body)
                    && matches!(self.group.author(&signed.author), Some((_, false)))
                    && verifies(
                        &signed.author,
                        &notice_message(&agent, &signed.notice),
                        &signed.signature,
                    )
                {
                    found = Some(signed.notice);
                }
            }
        }
    }
}
