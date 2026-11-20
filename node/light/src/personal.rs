//! Sealed sync with the personal agent (`light-node.md` §3.6): what a
//! device pushes to `Personal` and reads back, sealed, over a [`Link`] that
//! reaches the agent through the onion alone.
//!
//! - **Seal at push** ([`SealedSync::push`]): a scope's local nodes stay in
//!   its outbox, plain, until a push seals each under the confirmed epoch,
//!   read just before (the caller follows the log first). The sealed bytes
//!   are queued, synced, before they are sent, and sent as they are until
//!   the agent takes them, so a retry after a lost answer or a crash is a
//!   duplicate the agent answers by id; only `StaleEpoch` reseals them.
//!   Pushes pipeline, [`PIPELINE`] envelopes a round trip.
//! - **The cursor** ([`SealedSync::catch_up`]): a scope's envelopes read in
//!   the order the agent took them, `since` its stored position, each
//!   opened under the key of its epoch (the archive's candidates, the AEAD
//!   deciding) and its node applied, the page's position stored with them
//!   in one batch. Reading stops before an envelope of an epoch this
//!   device has not confirmed, or whose key it lacks; one that does not
//!   open, or is not a node of the scope, is passed over and reported.
//! - **The archive** ([`SealedSync::archive`]): read from its own scope,
//!   every archive sealed at the confirmed epoch merged, its `R` taken only
//!   when it is the one the log made the kit's; unless one there is this
//!   device's whole archive, this device's is pushed, chunked, under the
//!   epoch's archive key: the committer's push once an epoch is confirmed,
//!   and any device's that holds keys (or the kit's `R`) the agent's
//!   archives lack. So a new `R`, drawn at a removal, reaches the other
//!   devices under an epoch the removed device is not in.
//! - **Recovery envelopes** ([`SealedSync::recovery`]): whatever of the
//!   archive (the naming secrets, every scope key) the recovery scope does
//!   not hold under `R` yet, sealed under it at the confirmed epoch, so the
//!   kit's copy never lags: what a kit reads ([`open_recovery`],
//!   [`recover`]) after a restore releases `R2`. A new `R` seals the whole
//!   archive again.
//! - **Tor only** (E17): a link names its [`Route`], and every request is
//!   refused before it leaves unless the route is the onion, so the light
//!   node has no clearnet route for any kind addressed to the personal
//!   agent.
//!
//! A call `Personal` refuses with `Settling` is made again after a `wake`.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use merkle_crdt::Ingested;
use vos_abi::ids::InstanceId;
use vos_abi::{Decode, Encode};
use vos_wire::personal::{
    DeviceId, Envelope, PersonalError, Pushed, RECOVERY, RecoveryView, Scope, Woken, envelope_id,
};
use zeroize::Zeroizing;

use crate::group::{Alarm, Archive, DeviceGroup, GroupError};
use crate::kit::{self, KitSecret};
use crate::light::{Error, Ingest, Light, Queued};
use crate::route::Route;
use crate::sealed::{self, Body, MAX_BODY, OpenError, View};
use crate::sync::{Blake2b256, Held, Quarantined};
use merkle_crdt::Hasher as _;

/// The envelopes a push sends in one round trip, in flight at once.
pub const PIPELINE: usize = 16;

/// The `wake`s a call makes before it gives up on `Settling`, and a flow
/// sends until what fell due is settled.
pub(crate) const WAKES: usize = 8;

/// The name the archive's scope derives from, apart from every instance's
/// (four bytes).
pub const ARCHIVE_NAME: &[u8] = b"vos/personal/archive";

/// The rows of the archive's and the recovery scope's reading, in the
/// group keyspace: each one's cursor and the epoch read or pushed there.
const ARCHIVE_ROW: &[u8] = b"s/archive";
const RECOVERY_ROW: &[u8] = b"s/recovery";

/// The rows of a data scope's reading, in the group keyspace, by the
/// scope's id: the node's CID read at each position, this device's own
/// envelopes by position, and what the reading watches for.
const AT: &[u8] = b"s/at/";
const OWN: &[u8] = b"s/own/";
const WATCH: &[u8] = b"s/watch/";
/// A removed device's frontier, by its id, as the agent first answered it.
const FRONTIER: &[u8] = b"s/frontier/";

/// `prefix`'s row of `scope`, at `position` if given.
fn scope_key(prefix: &[u8], scope: &Scope, position: Option<u64>) -> Vec<u8> {
    let mut key = [prefix, &scope[..]].concat();
    if let Some(position) = position {
        key.extend_from_slice(&position.to_be_bytes());
    }
    key
}

/// The position a row of [`scope_key`] names.
fn position_of(key: &[u8]) -> Option<u64> {
    let tail = key.len().checked_sub(8)?;
    Some(u64::from_be_bytes(key[tail..].try_into().ok()?))
}

/// What a scope's reading watches for: the latest epoch an envelope it
/// opened there was sealed under, which the agent's order never goes back
/// on; and the highest position a writer said it had read there, with the
/// one it last raised the partition alarm at.
#[derive(Clone, Copy, Default, Encode, Decode)]
struct Watch {
    epoch: u64,
    claimed: u64,
    alarmed: u64,
}

/// Raise `alarm` once in `alarms`.
fn raise(alarms: &mut Vec<Alarm>, alarm: Alarm) {
    if !alarms.contains(&alarm) {
        alarms.push(alarm);
    }
}

/// A round trip's answer: the agent's, or the link's failure.
pub type Answer<T, E> = Result<Result<T, PersonalError>, E>;

/// A device's last position in each scope it pushed to.
pub type Frontier = Vec<(Scope, u64)>;

/// A connection to the personal agent: its calls signed by the device's
/// sync key in a session the link keeps, its reads queries under the same
/// key. Each method is one round trip, or a pipelined batch of them.
pub trait Link {
    /// Why a round trip failed: the connection's, not the agent's answer.
    type Error: core::fmt::Debug;

    /// The route its requests take.
    fn route(&self) -> Route;

    /// `push(envelope)` for each envelope, in order, pipelined as the link
    /// may: each one's answer.
    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, Self::Error>;

    /// `since(scope, position)`: the scope's envelopes after `position`, as
    /// much as one answer holds.
    fn since(
        &mut self,
        scope: Scope,
        position: u64,
    ) -> Result<Result<Vec<Envelope>, PersonalError>, Self::Error>;

    /// `wake()`: settle what fell due.
    fn wake(&mut self) -> Result<Result<Woken, PersonalError>, Self::Error>;

    /// `frontier(device)`: the device's last position in each scope it
    /// pushed to, its frontier once its removal matured.
    fn frontier(&mut self, device: DeviceId) -> Answer<Frontier, Self::Error>;
}

/// Why sealed sync stopped.
#[derive(Debug)]
pub enum SyncError<E> {
    /// The link's route is not the onion: nothing was sent.
    Clearnet,
    /// The link failed.
    Link(E),
    /// The agent refused a call or a read.
    Refused(PersonalError),
    /// The agent kept answering `Settling` after the wakes.
    Settling,
    Group(GroupError),
    Light(Error),
    /// A page's positions are not ascending past the cursor.
    Disordered,
    /// The link answered fewer pushes than it was given.
    Unanswered,
    /// A node whose envelope cannot hold it, at its sequence number: it
    /// stays local.
    TooLarge {
        seq: u64,
    },
}

impl<E> From<GroupError> for SyncError<E> {
    fn from(error: GroupError) -> Self {
        SyncError::Group(error)
    }
}

impl<E> From<Error> for SyncError<E> {
    fn from(error: Error) -> Self {
        SyncError::Light(error)
    }
}

impl<E> From<crate::store::StoreError> for SyncError<E> {
    fn from(error: crate::store::StoreError) -> Self {
        SyncError::Light(Error::Store(error))
    }
}

impl<E: core::fmt::Debug> std::fmt::Display for SyncError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::Clearnet => {
                f.write_str("the personal agent is reached through the onion alone")
            }
            SyncError::Link(error) => write!(f, "the link: {error:?}"),
            SyncError::Refused(error) => write!(f, "the agent refused: {error:?}"),
            SyncError::Settling => f.write_str("the agent is still settling"),
            SyncError::Group(error) => error.fmt(f),
            SyncError::Light(error) => error.fmt(f),
            SyncError::Disordered => f.write_str("a page out of order"),
            SyncError::Unanswered => f.write_str("a push the link did not answer"),
            SyncError::TooLarge { seq } => write!(f, "node {seq} does not fit an envelope"),
        }
    }
}

impl<E: core::fmt::Debug> std::error::Error for SyncError<E> {}

/// What a push did: the nodes the agent took, by sequence number, and, if
/// it stopped at `StaleEpoch` for an epoch this device has not confirmed,
/// that epoch: follow the log, then push again.
#[derive(Debug, Default)]
pub struct Pushing {
    pub pushed: Vec<(u64, Pushed)>,
    pub stale: Option<u64>,
}

/// Why a scope's reading stopped before its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Waiting {
    /// An envelope of an epoch past the one this device confirmed: follow
    /// the log, then read again.
    Epoch(u64),
    /// An envelope of a confirmed epoch whose key this device lacks: read
    /// the archive, then read again.
    Key(u64),
    /// The agent's page skips this position ([`Alarm::Withheld`]): read
    /// again.
    Withheld(u64),
}

/// Why an envelope read was passed over.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unusable {
    /// Its id is not its bytes' hash.
    Id,
    /// Its header names another scope.
    Scope,
    /// It does not open: forged, or garbage.
    Opened(OpenError),
    /// It opens, and holds no body of a node.
    Body,
    /// Its node's author is no device of the set, or a removed device past
    /// its frontier.
    Author,
    /// It is sealed under an epoch before one the agent took earlier in the
    /// scope.
    Stale,
}

/// An envelope passed over, at its position: the chrome names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Passed {
    pub position: u64,
    pub why: Unusable,
}

/// What an envelope's writer said of what it had seen: its view of the
/// control log and its `seen` positions, which detection checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Heard {
    pub position: u64,
    pub view: View,
    pub seen: Vec<(Scope, u64)>,
}

/// What reading a scope did.
#[derive(Debug, Default)]
pub struct Caught {
    pub ingested: Option<Ingested<Blake2b256>>,
    /// The operations the nodes read carried that were held, and those
    /// quarantined, each with its author ([`crate::sync`]).
    pub held: Vec<Held>,
    pub quarantined: Vec<Quarantined>,
    /// The envelopes read, and their bytes.
    pub envelopes: usize,
    pub bytes: usize,
    pub passed: Vec<Passed>,
    pub heard: Vec<Heard>,
    pub waiting: Option<Waiting>,
    /// What the reading detected (§8, B3, B4, B19, A7).
    pub alarms: Vec<Alarm>,
}

impl Caught {
    fn absorb(&mut self, ingest: Ingest) {
        self.held.extend(ingest.held);
        self.quarantined.extend(ingest.quarantined);
        let ingested = ingest.nodes;
        match &mut self.ingested {
            Some(report) => {
                report.applied.extend(ingested.applied);
                report.held.extend(ingested.held);
                report.refused.extend(ingested.refused);
                report.equivocations.extend(ingested.equivocations);
                report.duplicates += ingested.duplicates;
            }
            None => self.ingested = Some(ingested),
        }
    }
}

/// What a sample audit of this device's own pushes did (§8, B2).
#[derive(Debug, Default)]
pub struct Audited {
    /// The positions checked.
    pub checked: Vec<u64>,
    /// Those gone or replaced, each pushed again: [`Alarm::Deleted`].
    pub alarms: Vec<Alarm>,
    /// The push again stopped at `StaleEpoch` for this epoch: follow the
    /// log.
    pub stale: Option<u64>,
}

/// What reading and pushing the archive, or the recovery envelopes, did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    /// The archives merged, or the recovery envelopes found, at the
    /// confirmed epoch.
    pub found: usize,
    /// The envelopes this device pushed.
    pub pushed: usize,
    /// The push stopped at `StaleEpoch` for this epoch: follow the log.
    pub stale: Option<u64>,
}

/// A chunk of an archive: the hash of the archive's encoding, which part
/// of how many, and its bytes.
#[derive(Encode, Decode)]
struct Chunk {
    digest: [u8; 32],
    part: u16,
    parts: u16,
    bytes: Vec<u8>,
}

/// A chunk's encoding beyond its bytes: the digest, the two counts and the
/// bytes' length prefix, at most four.
const CHUNK_FRAMING: usize = 32 + 2 + 2 + 4;

/// The archive's bytes an envelope's chunk holds.
const CHUNK_BYTES: usize = MAX_BODY - CHUNK_FRAMING;

const _: () = assert!(CHUNK_BYTES < 1 << 30, "the length prefix stays four bytes");

/// The digest an archive's chunks name it by.
fn archive_digest(encoding: &[u8]) -> [u8; 32] {
    digest(b"vos/personal/archive-digest", encoding)
}

/// An archive's parts read so far: how many it has, those read, and the
/// position of its first part read.
type Parts = (u16, BTreeMap<u16, Zeroizing<Vec<u8>>>, u64);

/// Archives read in chunks, put back together, each one's parts by its
/// digest.
#[derive(Default)]
struct Reassembly {
    parts: BTreeMap<[u8; 32], Parts>,
}

impl Reassembly {
    /// A chunk read at `position`: the archive it completes, with its
    /// digest, if it does.
    fn add(&mut self, position: u64, body: &[u8]) -> Option<([u8; 32], Archive)> {
        let chunk = Chunk::decode_exact(body)?;
        if chunk.part >= chunk.parts {
            return None;
        }
        let (count, held, _) =
            self.parts
                .entry(chunk.digest)
                .or_insert((chunk.parts, BTreeMap::new(), position));
        if *count != chunk.parts {
            return None;
        }
        held.insert(chunk.part, Zeroizing::new(chunk.bytes));
        if held.len() < *count as usize {
            return None;
        }
        let (_, held, _) = self.parts.remove(&chunk.digest)?;
        let whole = Zeroizing::new(
            held.into_values()
                .flat_map(|part| part.to_vec())
                .collect::<Vec<u8>>(),
        );
        if archive_digest(&whole) != chunk.digest {
            return None;
        }
        Archive::decode_exact(&whole).map(|archive| (chunk.digest, archive))
    }

    /// The position before the first part of an archive not complete yet,
    /// which reading starts from again.
    fn rewind(&self) -> Option<u64> {
        self.parts.values().map(|(_, _, first)| first - 1).min()
    }
}

/// `archive` sealed in chunks under `key` for `scope` at `epoch`, with its
/// digest.
fn chunks(
    archive: &Archive,
    key: &[u8; 32],
    agent: &[u8; 32],
    scope: Scope,
    epoch: u64,
) -> ([u8; 32], Vec<Vec<u8>>) {
    let whole = Zeroizing::new(archive.encode());
    let digest = archive_digest(&whole);
    let pieces: Vec<&[u8]> = whole.chunks(CHUNK_BYTES).collect();
    let parts = u16::try_from(pieces.len()).expect("an archive under 3.6 GiB");
    let envelopes = pieces
        .into_iter()
        .enumerate()
        .map(|(part, bytes)| {
            let body = Zeroizing::new(
                Chunk {
                    digest,
                    part: part as u16,
                    parts,
                    bytes: bytes.to_vec(),
                }
                .encode(),
            );
            sealed::seal(key, agent, scope, epoch, &body).expect("a chunk fits an envelope")
        })
        .collect();
    (digest, envelopes)
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

/// The key recovery envelopes are sealed under: `R`'s, apart from every
/// other use of it.
pub fn recovery_key(r: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(digest(b"vos/personal/recovery", r))
}

/// What the recovery scope's `envelopes` of the agent whose identity is
/// `agent` hold under `R`: every complete archive in them, merged (the
/// naming secret and every scope key the devices sealed there), as a kit
/// reads it once a restore released `R2`; none if no envelope opens.
pub fn open_recovery(r: &[u8; 32], agent: &[u8; 32], envelopes: &[Envelope]) -> Option<Archive> {
    let key = recovery_key(r);
    let mut reassembly = Reassembly::default();
    let mut merged: Option<Archive> = None;
    for envelope in envelopes {
        let Ok((header, body)) = sealed::open(core::slice::from_ref(&*key), agent, &envelope.bytes)
        else {
            continue;
        };
        if header.scope != RECOVERY {
            continue;
        }
        if let Some((_, archive)) = reassembly.add(envelope.position, &body) {
            match &mut merged {
                Some(merged) => merged.merge(&archive),
                None => merged = Some(archive),
            }
        }
    }
    merged
}

/// What a kit recovers at the agent whose identity is `agent` once a
/// restore of it matured: `R1` opened from the entry of the kit's signing
/// key among those the restore replaced (`view` as the restore's device
/// reads it, `R2` released beside them), `R = R1 ⊕ R2`, and the recovery
/// scope's `envelopes` opened under it; none if the kit is not among them,
/// nothing was released, or no envelope opens.
pub fn recover(
    kit: &KitSecret,
    view: &RecoveryView,
    agent: &[u8; 32],
    envelopes: &[Envelope],
) -> Option<Archive> {
    let r2 = Zeroizing::new(view.released?);
    let signing = kit.key().signing;
    let entry = view
        .previous
        .iter()
        .find(|entry| entry.signing == signing)?;
    let r1 = kit.open_r1(entry, agent)?;
    let r = kit::join(&r1, &r2);
    open_recovery(&r, agent, envelopes)
}

/// The archive scope's reading, stored: its cursor, and the confirmed
/// epoch and the digest of the archive the agent is known to hold for it,
/// this device's own or one it read.
#[derive(Clone, Copy, Default, Encode, Decode)]
struct Reading {
    cursor: u64,
    epoch: Option<u64>,
    held: [u8; 32],
}

/// The recovery scope's reading, stored: its cursor, the `R` (by its
/// `since`) it was read under, and the scopes and keys the agent holds
/// sealed under it.
#[derive(Clone, Default, Encode, Decode)]
struct Recovering {
    cursor: u64,
    since: Option<u64>,
    held: Option<Archive>,
}

/// Sealed sync of a light node's scopes with the personal agent of its
/// device group, over `link`.
pub struct SealedSync<'a, L: Link> {
    light: &'a Light,
    group: &'a mut DeviceGroup,
    link: &'a mut L,
    /// The instances whose scopes are synced: their positions are each
    /// envelope's `seen`.
    instances: Vec<InstanceId>,
}

impl<'a, L: Link> SealedSync<'a, L> {
    /// Sync `instances` of `light` through `group`'s agent over `link`,
    /// refused unless the link reaches it through the onion.
    pub fn new(
        light: &'a Light,
        group: &'a mut DeviceGroup,
        link: &'a mut L,
        instances: Vec<InstanceId>,
    ) -> Result<Self, SyncError<L::Error>> {
        if link.route() != Route::Onion {
            return Err(SyncError::Clearnet);
        }
        Ok(Self {
            light,
            group,
            link,
            instances,
        })
    }

    pub fn group(&mut self) -> &mut DeviceGroup {
        self.group
    }

    /// The link, for a request: refused unless it still reaches the agent
    /// through the onion.
    fn link(&mut self) -> Result<&mut L, SyncError<L::Error>> {
        if self.link.route() != Route::Onion {
            return Err(SyncError::Clearnet);
        }
        Ok(self.link)
    }

    fn since(&mut self, scope: Scope, position: u64) -> Result<Vec<Envelope>, SyncError<L::Error>> {
        self.link()?
            .since(scope, position)
            .map_err(SyncError::Link)?
            .map_err(SyncError::Refused)
    }

    /// Push `envelopes`, in order: each one's answer, the agent woken and
    /// the rest pushed again while it answers `Settling`. Each push taken
    /// is a call the log counts this device seen by.
    fn send(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, SyncError<L::Error>> {
        let mut answers = Vec::with_capacity(envelopes.len());
        let mut wakes = 0;
        while answers.len() < envelopes.len() {
            let rest = &envelopes[answers.len()..];
            let mut round = self.link()?.push(rest).map_err(SyncError::Link)?;
            let settling = round
                .iter()
                .position(|answer| *answer == Err(PersonalError::Settling));
            match settling {
                Some(settling) => round.truncate(settling),
                None if round.len() != rest.len() => return Err(SyncError::Unanswered),
                None => {}
            }
            for pushed in round.iter().flatten() {
                self.group.called(pushed.at);
            }
            answers.extend(round);
            if settling.is_some() {
                wakes += 1;
                if wakes > WAKES {
                    return Err(SyncError::Settling);
                }
                if let Err(error) = self.link()?.wake().map_err(SyncError::Link)? {
                    return Err(SyncError::Refused(error));
                }
            }
        }
        Ok(answers)
    }

    /// This device's `seen` positions: each synced scope's cursor.
    fn seen(&self) -> Result<Vec<(Scope, u64)>, Error> {
        self.instances
            .iter()
            .map(|instance| {
                let scope = self.light.scope_id(*instance)?.0;
                Ok((scope, self.light.cursor(*instance)?.unwrap_or(0)))
            })
            .collect()
    }

    fn view(&self) -> View {
        let (index, chain) = self.group.view();
        View { index, chain }
    }

    /// `node`, the local node `seq` of `scope`, sealed under the confirmed
    /// epoch's key with this device's view and `seen` positions.
    fn seal(&mut self, scope: Scope, seq: u64, node: &[u8]) -> Result<Queued, SyncError<L::Error>> {
        let epoch = self.group.confirmed();
        let key = Zeroizing::new(self.group.key(scope)?);
        let body = Body {
            node: node.to_vec(),
            view: self.view(),
            seen: self.seen()?,
        }
        .sealable(&scope)
        .map_err(|_| SyncError::TooLarge { seq })?;
        let agent = self.group.agent().identity;
        let envelope = sealed::seal(&key, &agent, scope, epoch, &body)
            .map_err(|_| SyncError::TooLarge { seq })?;
        Ok(Queued { epoch, envelope })
    }

    /// Push `instance`'s local nodes: each not yet queued sealed under the
    /// confirmed epoch and queued, then the queue sent in order until the
    /// agent has taken all of it. `StaleEpoch` for the epoch this device
    /// confirmed reseals what was sealed under an earlier one; for a later
    /// epoch the push stops ([`Pushing::stale`]).
    pub fn push(&mut self, instance: InstanceId) -> Result<Pushing, SyncError<L::Error>> {
        let scope = self.light.scope_id(instance)?.0;
        let author = self.light.author();
        let nodes: BTreeMap<u64, Vec<u8>> = self
            .light
            .outbox(instance)?
            .into_iter()
            .filter(|node| node.author == author)
            .map(|node| (node.seq, node.bytes))
            .collect();
        let mut queued: BTreeMap<u64, Queued> = BTreeMap::new();
        let mut leftover = Vec::new();
        for (seq, entry) in self.light.queued(instance)? {
            if nodes.contains_key(&seq) {
                queued.insert(seq, entry);
            } else {
                leftover.push(seq);
            }
        }
        self.light.sent(instance, &leftover)?;
        // A node no envelope holds stays local, and so do the nodes after
        // it: those before it are pushed, then the error.
        let mut fresh = Vec::new();
        let mut unsealed = None;
        for (seq, node) in &nodes {
            if !queued.contains_key(seq) {
                match self.seal(scope, *seq, node) {
                    Ok(entry) => fresh.push((*seq, entry)),
                    Err(error) => {
                        unsealed = Some(error);
                        break;
                    }
                }
            }
        }
        self.light.enqueue(instance, &fresh)?;
        queued.extend(fresh);
        let order: Vec<u64> = queued.keys().copied().collect();
        let mut report = Pushing::default();
        let mut at = 0;
        while at < order.len() {
            let round = &order[at..order.len().min(at + PIPELINE)];
            let envelopes: Vec<Vec<u8>> = round
                .iter()
                .map(|seq| queued[seq].envelope.clone())
                .collect();
            let answers = self.send(&envelopes)?;
            let mut taken = Vec::new();
            let mut own = Vec::new();
            let mut stop = None;
            for (seq, answer) in round.iter().zip(answers) {
                match answer {
                    Ok(pushed) => {
                        taken.push(*seq);
                        own.push((pushed.position, pushed.id, Blake2b256::hash(&nodes[seq])));
                        report.pushed.push((*seq, pushed));
                    }
                    Err(error) => {
                        stop = Some(error);
                        break;
                    }
                }
            }
            self.record_own(scope, &own, None)?;
            self.light.sent(instance, &taken)?;
            at += taken.len();
            match stop {
                None => {}
                Some(PersonalError::StaleEpoch { confirmed })
                    if confirmed == self.group.confirmed()
                        && queued[&order[at]].epoch != confirmed =>
                {
                    let mut resealed = Vec::new();
                    for seq in &order[at..] {
                        if queued[seq].epoch != confirmed {
                            resealed.push((*seq, self.seal(scope, *seq, &nodes[seq])?));
                        }
                    }
                    self.light.enqueue(instance, &resealed)?;
                    queued.extend(resealed);
                }
                Some(PersonalError::StaleEpoch { confirmed })
                    if confirmed > self.group.confirmed() =>
                {
                    report.stale = Some(confirmed);
                    return Ok(report);
                }
                Some(error) => return Err(SyncError::Refused(error)),
            }
        }
        if let Some(error) = unsealed {
            return Err(error);
        }
        Ok(report)
    }

    /// The candidate keys of `scope` at `epoch`: the archive's, and the
    /// confirmed epoch's exported (a restore's device starts a group of its
    /// own at the epoch its old devices sealed under, whose keys its
    /// archive holds, and recovers the old group's of that number).
    fn keys(&mut self, scope: Scope, epoch: u64) -> Result<Vec<[u8; 32]>, GroupError> {
        let mut keys = self.group.archive().keys(epoch, &scope).to_vec();
        if epoch == self.group.confirmed() {
            let key = self.group.key(scope)?;
            if !keys.contains(&key) {
                keys.insert(0, key);
            }
        }
        Ok(keys)
    }

    /// Read `instance`'s scope from its cursor to the agent's end: each
    /// page's envelopes opened, their nodes applied and the page's position
    /// stored, in one batch a page. Stops before an envelope it cannot open
    /// yet ([`Caught::waiting`]).
    ///
    /// What the agent serves is checked as it is read (§8, B3, B4, B19,
    /// A7): positions are dense, so one skipped is withheld; epochs never go
    /// back along a scope, so an envelope under an earlier one is a push the
    /// agent should have refused, passed over; a node's author is a device
    /// of the set, a removed one's counted only up to its frontier and cut
    /// off past it in the light node, so its entries read filtered and its
    /// later operations met anywhere are quarantined; each
    /// writer's view of the control log is checked against this device's;
    /// and each writer's `seen` positions are kept, so that a scope served
    /// to its end short of where a writer had read it raises the partition
    /// alarm.
    pub fn catch_up(&mut self, instance: InstanceId) -> Result<Caught, SyncError<L::Error>> {
        // A full disk pauses the reading before it writes anything.
        self.light.room()?;
        let scope = self.light.scope_id(instance)?.0;
        let agent = self.group.agent().identity;
        // Tracked from now: the archive records its key at every confirmed
        // epoch.
        drop(Zeroizing::new(self.group.key(scope)?));
        let mut caught = Caught::default();
        let mut scan = Scan::new(self.tracked()?);
        loop {
            let from = self.light.cursor(instance)?.unwrap_or(0);
            let page = self.since(scope, from)?;
            if page.is_empty() {
                let watch = self.watch(&mut scan, scope)?;
                if watch.claimed > from && watch.claimed > watch.alarmed {
                    watch.alarmed = watch.claimed;
                    let position = watch.claimed;
                    raise(&mut caught.alarms, Alarm::Partition { scope, position });
                }
                self.store_watches(&scan, &caught.alarms)?;
                return Ok(caught);
            }
            let mut nodes = Vec::with_capacity(page.len());
            let mut at = Vec::with_capacity(page.len());
            let mut to = from;
            for envelope in page {
                if envelope.position <= to {
                    return Err(SyncError::Disordered);
                }
                if envelope.position != to + 1 {
                    // Read on past it and this device's reading of the
                    // scope would differ from the others' for good.
                    let position = to + 1;
                    raise(&mut caught.alarms, Alarm::Withheld { scope, position });
                    caught.waiting = Some(Waiting::Withheld(position));
                    break;
                }
                let opened = self.open(scope, &agent, &envelope)?;
                let position = envelope.position;
                match opened {
                    Opening::Node(epoch, body) => {
                        let admitted =
                            self.admit(instance, position, epoch, &body, &mut scan, &mut caught)?;
                        match admitted {
                            Ok(cid) => {
                                at.push((
                                    scope_key(AT, &scope, Some(position)),
                                    Some(cid.to_vec()),
                                ));
                                nodes.push(body.node);
                                caught.heard.push(Heard {
                                    position,
                                    view: body.view,
                                    seen: body.seen,
                                });
                            }
                            Err(why) => caught.passed.push(Passed { position, why }),
                        }
                    }
                    Opening::Passed(why) => caught.passed.push(Passed { position, why }),
                    Opening::Waiting(waiting) => {
                        caught.waiting = Some(waiting);
                        break;
                    }
                }
                caught.envelopes += 1;
                caught.bytes += envelope.bytes.len();
                to = position;
            }
            if to > from {
                // What was read at each position, and the alarms the page
                // raised, written before the page is applied: a reading
                // again after a crash writes it the same.
                at.extend(crate::group::raised_row(
                    self.light.store(),
                    &caught.alarms,
                )?);
                self.light.store().write_group_rows(at)?;
                caught.absorb(self.light.ingest(instance, nodes, Some(to))?);
            }
            self.store_watches(&scan, &caught.alarms)?;
            if caught.waiting.is_some() {
                return Ok(caught);
            }
        }
    }

    /// The scopes this sync reads: their `seen` positions are kept.
    fn tracked(&self) -> Result<Vec<Scope>, Error> {
        self.instances
            .iter()
            .map(|instance| Ok(self.light.scope_id(*instance)?.0))
            .collect()
    }

    /// `scope`'s watch, read once for `scan`.
    fn watch<'r>(
        &self,
        scan: &'r mut Scan,
        scope: Scope,
    ) -> Result<&'r mut Watch, SyncError<L::Error>> {
        Ok(match scan.watches.entry(scope) {
            Entry::Occupied(held) => held.into_mut(),
            Entry::Vacant(vacant) => vacant.insert(self.row(&scope_key(WATCH, &scope, None))?),
        })
    }

    /// `scan`'s watches written, with `alarms` kept in the same batch.
    fn store_watches(&self, scan: &Scan, alarms: &[Alarm]) -> Result<(), SyncError<L::Error>> {
        let mut rows: Vec<_> = scan
            .watches
            .iter()
            .map(|(scope, watch)| (scope_key(WATCH, scope, None), Some(watch.encode())))
            .collect();
        rows.extend(crate::group::raised_row(self.light.store(), alarms)?);
        Ok(self.light.store().write_group_rows(rows)?)
    }

    /// Keep `alarms` until the chrome acknowledges them
    /// ([`DeviceGroup::alarms`]): written before what consumed their
    /// evidence is, so a reading stopped or killed after loses none.
    pub(crate) fn keep_alarms(&self, alarms: &[Alarm]) -> Result<(), SyncError<L::Error>> {
        if let Some(row) = crate::group::raised_row(self.light.store(), alarms)? {
            self.light.store().write_group_rows(vec![row])?;
        }
        Ok(())
    }

    /// Whether the node an envelope at `instance`'s scope's `position`,
    /// sealed under `epoch`, holds is admitted: its CID, or why it is
    /// passed over, with what its writer said checked into `caught`'s
    /// alarms. A removed device's node is admitted up to its frontier, and
    /// its author cut off past it ([`SealedSync::cut_off_removed`]).
    fn admit(
        &mut self,
        instance: InstanceId,
        position: u64,
        epoch: u64,
        body: &Body,
        scan: &mut Scan,
        caught: &mut Caught,
    ) -> Result<Result<[u8; 32], Unusable>, SyncError<L::Error>> {
        let scope = self.light.scope_id(instance)?.0;
        let watch = self.watch(scan, scope)?;
        if epoch < watch.epoch {
            raise(&mut caught.alarms, Alarm::Stale { scope, position });
            return Ok(Err(Unusable::Stale));
        }
        watch.epoch = epoch;
        // Its author's signature, checked here: a header naming a device
        // over a node no device signed is refused before its author counts.
        match merkle_crdt::validate::<Blake2b256, crate::sync::Ops>(
            &merkle_crdt::Scope(scope),
            &body.node,
        ) {
            Ok(_) => {}
            Err((_, merkle_crdt::Refusal::BadSignature)) => {
                raise(&mut caught.alarms, Alarm::Author { scope, position });
                return Ok(Err(Unusable::Author));
            }
            Err(_) => return Ok(Err(Unusable::Body)),
        }
        let Some(header) = merkle_crdt::Header::<Blake2b256>::read(&body.node) else {
            return Ok(Err(Unusable::Body));
        };
        let within = match self.group.author(&header.author.0) {
            None => false,
            Some((_, false)) => true,
            Some((device, true)) => {
                let last = self.last(scan, device, scope)?;
                if !scan.cut.contains(&device) {
                    let removed = Removed {
                        author: header.author,
                        last,
                        position,
                        seq: header.seq,
                    };
                    if self.cut_off_removed(instance, scope, &removed)? {
                        scan.cut.push(device);
                    }
                }
                last.is_some_and(|last| position <= last)
            }
        };
        if !within {
            raise(&mut caught.alarms, Alarm::Author { scope, position });
            return Ok(Err(Unusable::Author));
        }
        if let Some(alarm) = self.group.check_view(body.view.index, body.view.chain)? {
            raise(&mut caught.alarms, alarm);
        }
        for (seen_scope, seen) in &body.seen {
            // A writer read its envelope's scope before the agent numbered
            // the envelope after it.
            if *seen_scope == scope && *seen >= position {
                let position = *seen;
                raise(&mut caught.alarms, Alarm::Partition { scope, position });
            }
            if scan.tracked.contains(seen_scope) {
                let watch = self.watch(scan, *seen_scope)?;
                watch.claimed = watch.claimed.max(*seen);
            }
        }
        Ok(Ok(Blake2b256::hash(&body.node)))
    }

    /// The position of `device`'s last envelope in `scope` the agent took
    /// before its removal matured, its frontier: asked once, and kept, so
    /// an answer that later names a higher one moves nothing (the removal
    /// fixed it).
    fn last(
        &mut self,
        scan: &mut Scan,
        device: DeviceId,
        scope: Scope,
    ) -> Result<Option<u64>, SyncError<L::Error>> {
        let row = [FRONTIER, &device.to_be_bytes()[..]].concat();
        let frontier = match scan.frontiers.entry(device) {
            Entry::Occupied(held) => held.into_mut(),
            Entry::Vacant(vacant) => {
                let kept = match self.light.store().group_row(&row)? {
                    Some(bytes) => Frontier::decode_exact(&bytes)
                        .ok_or(SyncError::Group(GroupError::Corrupt))?,
                    None => {
                        let asked = self
                            .link()?
                            .frontier(device)
                            .map_err(SyncError::Link)?
                            .map_err(SyncError::Refused)?;
                        self.light
                            .store()
                            .write_group_rows(vec![(row, Some(asked.encode()))])?;
                        asked
                    }
                };
                vacant.insert(kept)
            }
        };
        Ok(frontier
            .iter()
            .find(|(at, _)| *at == scope)
            .map(|(_, last)| *last))
    }

    /// Cut a removed device's author off in `instance`'s scope, one past its
    /// node at its frontier, the position of its last envelope there that
    /// the agent took: from 0 when it has none there; from the node's
    /// number plus one when `removed` is that node, or when this device
    /// read it before; from `removed`'s own number when it is past the
    /// frontier and the node there was not read, an upper bound a lower
    /// cutoff replaces. Whether it was cut off; not yet, while the
    /// frontier's node is ahead. So the
    /// frontier the agent's log gives is the one source of a removed
    /// author's cutoff, which filters its entries at read and quarantines
    /// its later operations at ingest.
    fn cut_off_removed(
        &self,
        instance: InstanceId,
        scope: Scope,
        removed: &Removed,
    ) -> Result<bool, SyncError<L::Error>> {
        let from = match removed.last {
            None => Some(0),
            Some(last) if removed.position == last => Some(removed.seq + 1),
            Some(last) => match self
                .light
                .store()
                .group_row(&scope_key(AT, &scope, Some(last)))?
            {
                Some(cid) => {
                    let cid = <[u8; 32]>::try_from(&cid[..])
                        .map_err(|_| SyncError::Group(GroupError::Corrupt))?;
                    match self
                        .light
                        .node(instance, &merkle_crdt::Cid(cid))?
                        .and_then(|node| merkle_crdt::Header::<Blake2b256>::read(&node))
                    {
                        Some(header) if header.author == removed.author => Some(header.seq + 1),
                        _ if removed.position > last => Some(removed.seq),
                        _ => None,
                    }
                }
                None if removed.position > last => Some(removed.seq),
                None => None,
            },
        };
        let Some(from) = from else {
            return Ok(false);
        };
        self.light.cut_off(instance, removed.author, from)?;
        Ok(true)
    }

    /// Record this device's envelopes the agent took in `scope`, each
    /// `(position, id, cid)`, and drop the record at `moved` if given: what
    /// the sample audit checks.
    fn record_own(
        &self,
        scope: Scope,
        own: &[(u64, [u8; 32], [u8; 32])],
        moved: Option<u64>,
    ) -> Result<(), SyncError<L::Error>> {
        let mut rows: Vec<(Vec<u8>, Option<Vec<u8>>)> = own
            .iter()
            .map(|(position, id, cid)| {
                (
                    scope_key(OWN, &scope, Some(*position)),
                    Some((*id, *cid).encode()),
                )
            })
            .collect();
        if let Some(moved) = moved {
            rows.push((scope_key(OWN, &scope, Some(moved)), None));
        }
        if rows.is_empty() {
            return Ok(());
        }
        Ok(self.light.store().write_group_rows(rows)?)
    }

    /// Audit a sample of `sample` of this device's own envelopes in
    /// `instance`'s scope (§8, B2): each fetched at its position, and one
    /// gone or replaced there pushed again, its node sealed anew under the
    /// confirmed epoch.
    pub fn audit(
        &mut self,
        instance: InstanceId,
        sample: usize,
    ) -> Result<Audited, SyncError<L::Error>> {
        let scope = self.light.scope_id(instance)?.0;
        let mut own = self
            .light
            .store()
            .group_rows(&scope_key(OWN, &scope, None), None)?;
        // A uniform sample, drawn without replacement.
        for i in 0..own.len().min(sample) {
            let mut draw = [0; 8];
            getrandom::getrandom(&mut draw).expect("the operating system's randomness");
            let j = i + (u64::from_le_bytes(draw) % (own.len() - i) as u64) as usize;
            own.swap(i, j);
        }
        own.truncate(sample);
        let mut audited = Audited::default();
        for (key, value) in own {
            let position = position_of(&key).ok_or(SyncError::Group(GroupError::Corrupt))?;
            let (id, cid) = <([u8; 32], [u8; 32])>::decode_exact(&value)
                .ok_or(SyncError::Group(GroupError::Corrupt))?;
            audited.checked.push(position);
            let page = self.since(scope, position - 1)?;
            if page.first().is_some_and(|envelope| {
                envelope.position == position && envelope_id(&envelope.bytes) == id
            }) {
                continue;
            }
            raise(&mut audited.alarms, Alarm::Deleted { scope, position });
            self.keep_alarms(&audited.alarms)?;
            let Some(node) = self
                .light
                .node(instance, &merkle_crdt::Cid::<Blake2b256>(cid))?
            else {
                continue;
            };
            let seq = merkle_crdt::Header::<Blake2b256>::read(&node).map_or(0, |header| header.seq);
            let queued = self.seal(scope, seq, &node)?;
            match self.send(&[queued.envelope])?.remove(0) {
                Ok(pushed) => {
                    self.record_own(scope, &[(pushed.position, pushed.id, cid)], Some(position))?
                }
                Err(PersonalError::StaleEpoch { confirmed })
                    if confirmed > self.group.confirmed() =>
                {
                    audited.stale = Some(confirmed);
                    return Ok(audited);
                }
                Err(error) => return Err(SyncError::Refused(error)),
            }
        }
        Ok(audited)
    }

    fn open(
        &mut self,
        scope: Scope,
        agent: &[u8; 32],
        envelope: &Envelope,
    ) -> Result<Opening, GroupError> {
        if envelope_id(&envelope.bytes) != envelope.id {
            return Ok(Opening::Passed(Unusable::Id));
        }
        let header = match sealed::header_of(&envelope.bytes) {
            Ok(header) => header,
            Err(error) => return Ok(Opening::Passed(Unusable::Opened(error))),
        };
        if header.scope != scope {
            return Ok(Opening::Passed(Unusable::Scope));
        }
        if header.epoch > self.group.confirmed() {
            return Ok(Opening::Waiting(Waiting::Epoch(header.epoch)));
        }
        let keys = Zeroizing::new(self.keys(scope, header.epoch)?);
        if keys.is_empty() {
            return Ok(Opening::Waiting(Waiting::Key(header.epoch)));
        }
        Ok(match sealed::open(&keys, agent, &envelope.bytes) {
            Ok((_, body)) => match Body::decode_exact(&body) {
                Some(body) => Opening::Node(header.epoch, body),
                None => Opening::Passed(Unusable::Body),
            },
            Err(error) => Opening::Passed(Unusable::Opened(error)),
        })
    }

    fn row<T: Decode + Default>(&self, row: &[u8]) -> Result<T, SyncError<L::Error>> {
        match self.light.store().group_row(row)? {
            Some(bytes) => T::decode_exact(&bytes).ok_or(SyncError::Group(GroupError::Corrupt)),
            None => Ok(T::default()),
        }
    }

    fn store_row(&self, row: &[u8], value: &impl Encode) -> Result<(), SyncError<L::Error>> {
        let bytes = Zeroizing::new(value.encode());
        Ok(self
            .light
            .store()
            .write_group_rows(vec![(row.to_vec(), Some(bytes.to_vec()))])?)
    }

    /// Push `envelopes` at the confirmed epoch: how many the agent took,
    /// or the later epoch it answered `StaleEpoch` for.
    fn push_kept(&mut self, envelopes: &[Vec<u8>]) -> Result<Kept, SyncError<L::Error>> {
        let mut kept = Kept::default();
        for answer in self.send(envelopes)? {
            match answer {
                Ok(_) => kept.pushed += 1,
                Err(PersonalError::StaleEpoch { confirmed })
                    if confirmed > self.group.confirmed() =>
                {
                    kept.stale = Some(confirmed);
                    return Ok(kept);
                }
                Err(error) => return Err(SyncError::Refused(error)),
            }
        }
        Ok(kept)
    }

    /// Read `scope` after `cursor`, each envelope that opens under `key`
    /// a chunk of an archive (of the confirmed epoch alone, with
    /// `epoch`): every archive completed, and the position read to, before
    /// any archive whose parts are not all in and before an envelope of an
    /// epoch past the confirmed one.
    #[allow(clippy::type_complexity)]
    fn read_archives(
        &mut self,
        scope: Scope,
        key: &[u8; 32],
        mut cursor: u64,
        epoch: Option<u64>,
    ) -> Result<(Vec<([u8; 32], Archive)>, u64), SyncError<L::Error>> {
        let agent = self.group.agent().identity;
        let confirmed = self.group.confirmed();
        let mut reassembly = Reassembly::default();
        let mut archives = Vec::new();
        'read: loop {
            let page = self.since(scope, cursor)?;
            if page.is_empty() {
                break;
            }
            for envelope in page {
                if envelope.position <= cursor {
                    return Err(SyncError::Disordered);
                }
                let header = sealed::header_of(&envelope.bytes);
                if header.is_ok_and(|header| header.epoch > confirmed) {
                    break 'read;
                }
                cursor = envelope.position;
                if !header.is_ok_and(|header| {
                    header.scope == scope && epoch.is_none_or(|epoch| header.epoch == epoch)
                }) {
                    continue;
                }
                let keys = Zeroizing::new([*key]);
                if let Ok((_, body)) = sealed::open(&*keys, &agent, &envelope.bytes)
                    && let Some(archive) = reassembly.add(envelope.position, &body)
                {
                    archives.push(archive);
                }
            }
        }
        Ok((
            archives,
            reassembly
                .rewind()
                .map_or(cursor, |first| first.min(cursor)),
        ))
    }

    /// Read the archive's scope from its cursor, merging every archive
    /// sealed at the confirmed epoch, its `R` only if the log made it the
    /// kit's; then, unless the agent holds one at this epoch that is this
    /// device's whole archive, push this device's there, chunked, `R` with
    /// it and the `R`s it drew not: the committer's push once an epoch is
    /// confirmed, and any device's that holds keys the archives there lack,
    /// are one rule. Archives of earlier epochs are passed over: their keys
    /// are this device's no longer, and a later archive holds theirs.
    pub fn archive(&mut self) -> Result<Kept, SyncError<L::Error>> {
        let scope = self.group.archive().scope(ARCHIVE_NAME);
        let agent = self.group.agent().identity;
        let epoch = self.group.confirmed();
        let key = Zeroizing::new(self.group.archive_key()?);
        let mut reading: Reading = self.row(ARCHIVE_ROW)?;
        let mut kept = Kept::default();
        let (archives, cursor) = self.read_archives(scope, &key, reading.cursor, Some(epoch))?;
        reading.cursor = cursor;
        if reading.epoch != Some(epoch) {
            reading.epoch = Some(epoch);
            reading.held = [0; 32];
        }
        let mut held = vec![reading.held];
        for (digest, archive) in archives {
            self.group.merge_read(&archive)?;
            held.push(digest);
            kept.found += 1;
        }
        // `R` travels only while this device may let it: never under an
        // epoch a device whose removal is owed is still in.
        let mine = if self.group.holds_recovery() {
            self.group.archive().shareable()
        } else {
            self.group.archive().without_recovery()
        };
        let digest = archive_digest(&mine.encode());
        if held.contains(&digest) {
            reading.held = digest;
        } else {
            let (digest, envelopes) = chunks(&mine, &key, &agent, scope, epoch);
            let pushed = self.push_kept(&envelopes)?;
            kept.pushed = pushed.pushed;
            kept.stale = pushed.stale;
            if pushed.stale.is_none() {
                reading.held = digest;
            }
        }
        self.store_row(ARCHIVE_ROW, &reading)?;
        Ok(kept)
    }

    /// Read the recovery scope from its cursor for what the agent holds
    /// sealed under `R`, and push, sealed under it at the confirmed epoch,
    /// whatever of this device's archive it lacks: the naming secrets and
    /// every scope key, so the kit's copy never lags. Nothing without `R`,
    /// and nothing while the log names an `R` this device does not hold
    /// yet: a removed device may hold the one before; a new `R` reads the
    /// scope again from its start and pushes the whole archive under it.
    pub fn recovery(&mut self) -> Result<Kept, SyncError<L::Error>> {
        if !self.group.holds_recovery() {
            return Ok(Kept::default());
        }
        let Some((since, key)) = self
            .group
            .archive()
            .recovery
            .as_ref()
            .map(|recovery| (recovery.since, recovery_key(&recovery.r)))
        else {
            return Ok(Kept::default());
        };
        let agent = self.group.agent().identity;
        let epoch = self.group.confirmed();
        let mut reading: Recovering = self.row(RECOVERY_ROW)?;
        if reading.since != Some(since) {
            reading = Recovering {
                cursor: 0,
                since: Some(since),
                held: None,
            };
        }
        let mut kept = Kept::default();
        let (archives, cursor) = self.read_archives(RECOVERY, &key, reading.cursor, None)?;
        reading.cursor = cursor;
        for (_, archive) in archives {
            kept.found += 1;
            match &mut reading.held {
                Some(held) => held.merge(&archive),
                None => reading.held = Some(archive),
            }
        }
        let mine = self.group.archive().without_recovery();
        let lacking = match &reading.held {
            Some(held) if held.naming == mine.naming => mine.beyond(held),
            _ => mine,
        };
        if !lacking.is_empty() || reading.held.is_none() {
            let (_, envelopes) = chunks(&lacking, &key, &agent, RECOVERY, epoch);
            let pushed = self.push_kept(&envelopes)?;
            kept.pushed = pushed.pushed;
            kept.stale = pushed.stale;
            if pushed.stale.is_none() {
                match &mut reading.held {
                    Some(held) => held.merge(&lacking),
                    None => reading.held = Some(lacking),
                }
            }
        }
        self.store_row(RECOVERY_ROW, &reading)?;
        Ok(kept)
    }
}

/// A scope's reading: the scopes whose `seen` positions it keeps, their
/// watches as read and updated, and the removed devices' frontiers it
/// asked for.
struct Scan {
    tracked: Vec<Scope>,
    watches: BTreeMap<Scope, Watch>,
    frontiers: BTreeMap<DeviceId, Frontier>,
    /// The removed devices whose authors it cut off.
    cut: Vec<DeviceId>,
}

impl Scan {
    fn new(tracked: Vec<Scope>) -> Self {
        Self {
            tracked,
            watches: BTreeMap::new(),
            frontiers: BTreeMap::new(),
            cut: Vec::new(),
        }
    }
}

/// A removed device's node read in a scope: its author, the device's
/// frontier there, and the node's position and number.
struct Removed {
    author: merkle_crdt::Author,
    last: Option<u64>,
    position: u64,
    seq: u64,
}

/// What opening an envelope of a data scope gave.
enum Opening {
    /// A node's body, sealed under its epoch.
    Node(u64, Body),
    Passed(Unusable),
    Waiting(Waiting),
}
