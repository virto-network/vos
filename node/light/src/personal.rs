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
//!   every archive sealed at the confirmed epoch merged; if none was, this
//!   device's is pushed, chunked, under the epoch's archive key: the
//!   committer's push once an epoch is confirmed, or any device's that
//!   finds it missing.
//! - **Recovery envelopes** ([`SealedSync::recovery`]): at each confirmed
//!   epoch, the naming secret and the epoch's scope keys sealed under `R`
//!   into the recovery scope, unless one is there already: what a kit
//!   opens ([`open_recovery`]) after a restore releases `R2`.
//! - **Tor only** [E17]: a link names its [`Route`], and every request is
//!   refused before it leaves unless the route is the onion, so the light
//!   node has no clearnet route for any kind addressed to the personal
//!   agent.
//!
//! A call `Personal` refuses with `Settling` is made again after a `wake`.

use std::collections::BTreeMap;

use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use merkle_crdt::Ingested;
use vos_wire::ids::InstanceId;
use vos_wire::personal::{Envelope, PersonalError, Pushed, RECOVERY, Scope, Woken, envelope_id};
use vos_wire::{Decode, Encode};
use zeroize::Zeroizing;

use crate::group::{Archive, DeviceGroup, GroupError};
use crate::light::{Error, Light, Queued};
use crate::sealed::{self, Body, MAX_BODY, OpenError, View};
use crate::sync::Blake2b256;

/// The envelopes a push sends in one round trip, in flight at once.
pub const PIPELINE: usize = 16;

/// The `wake`s a call makes before it gives up on `Settling`.
const WAKES: usize = 8;

/// The name the archive's scope derives from, apart from every instance's
/// (four bytes).
pub const ARCHIVE_NAME: &[u8] = b"vos/personal/archive";

/// The rows of the archive's and the recovery scope's reading, in the
/// group keyspace: each one's cursor and the epoch read or pushed there.
const ARCHIVE_ROW: &[u8] = b"s/archive";
const RECOVERY_ROW: &[u8] = b"s/recovery";

/// How the link reaches the agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Route {
    /// Through the home's onion service.
    Onion = 0,
    /// Over the clearnet: no request to the personal agent takes it.
    Clearnet = 1,
}

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
    /// The envelopes read, and their bytes.
    pub envelopes: usize,
    pub bytes: usize,
    pub passed: Vec<Passed>,
    pub heard: Vec<Heard>,
    pub waiting: Option<Waiting>,
}

impl Caught {
    fn absorb(&mut self, ingested: Ingested<Blake2b256>) {
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

/// An archive's parts read so far: how many it has, those read, and the
/// position of its first part read.
type Parts = (u16, BTreeMap<u16, Vec<u8>>, u64);

/// The chunk's bytes an envelope holds beside its framing.
const CHUNK_BYTES: usize = MAX_BODY - 64;

/// A recovery envelope's body: the naming secret and the epoch's scope
/// keys, every candidate.
#[derive(Encode, Decode)]
struct RecoveryBody {
    naming: [u8; 32],
    keys: Vec<(Scope, [u8; 32])>,
}

/// What a recovery envelope holds: its epoch, the naming secret, and the
/// epoch's scope keys.
#[derive(Clone, PartialEq, Eq)]
pub struct Recovered {
    pub epoch: u64,
    pub naming: [u8; 32],
    pub keys: Vec<(Scope, [u8; 32])>,
}

impl std::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recovered")
            .field("epoch", &self.epoch)
            .field("keys", &self.keys.len())
            .finish_non_exhaustive()
    }
}

impl Drop for Recovered {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.naming.zeroize();
        for (_, key) in &mut self.keys {
            key.zeroize();
        }
    }
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

/// Open a recovery envelope of the agent whose identity is `agent` under
/// `R`: what a kit reads once a restore released `R2`.
pub fn open_recovery(
    r: &[u8; 32],
    agent: &[u8; 32],
    envelope: &[u8],
) -> Result<Recovered, OpenError> {
    let (header, body) = sealed::open(&[*recovery_key(r)], agent, envelope)?;
    if header.scope != RECOVERY {
        return Err(OpenError::Framing);
    }
    let body = RecoveryBody::decode_exact(&body).ok_or(OpenError::Framing)?;
    Ok(Recovered {
        epoch: header.epoch,
        naming: body.naming,
        keys: body.keys,
    })
}

/// A scope's reading, stored: its cursor, and the epoch at which this
/// device read or pushed what it keeps there.
#[derive(Clone, Copy, Default, Encode, Decode)]
struct Reading {
    cursor: u64,
    epoch: Option<u64>,
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
        let mut fresh = Vec::new();
        for (seq, node) in &nodes {
            if !queued.contains_key(seq) {
                fresh.push((*seq, self.seal(scope, *seq, node)?));
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
            let mut stop = None;
            for (seq, answer) in round.iter().zip(answers) {
                match answer {
                    Ok(pushed) => {
                        taken.push(*seq);
                        report.pushed.push((*seq, pushed));
                    }
                    Err(error) => {
                        stop = Some(error);
                        break;
                    }
                }
            }
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
                Some(PersonalError::StaleEpoch { confirmed }) => {
                    report.stale = Some(confirmed);
                    return Ok(report);
                }
                Some(error) => return Err(SyncError::Refused(error)),
            }
        }
        Ok(report)
    }

    /// The candidate keys of `scope` at `epoch`: the confirmed epoch's
    /// exported, an earlier one's from the archive.
    fn keys(&mut self, scope: Scope, epoch: u64) -> Result<Vec<[u8; 32]>, GroupError> {
        if epoch == self.group.confirmed() {
            return Ok(vec![self.group.key(scope)?]);
        }
        Ok(self.group.archive().keys(epoch, &scope).to_vec())
    }

    /// Read `instance`'s scope from its cursor to the agent's end: each
    /// page's envelopes opened, their nodes applied and the page's position
    /// stored, in one batch a page. Stops before an envelope it cannot open
    /// yet ([`Caught::waiting`]).
    pub fn catch_up(&mut self, instance: InstanceId) -> Result<Caught, SyncError<L::Error>> {
        let scope = self.light.scope_id(instance)?.0;
        let agent = self.group.agent().identity;
        // Tracked from now: the archive records its key at every confirmed
        // epoch.
        self.group.key(scope)?;
        let mut caught = Caught::default();
        loop {
            let from = self.light.cursor(instance)?.unwrap_or(0);
            let page = self.since(scope, from)?;
            if page.is_empty() {
                return Ok(caught);
            }
            let mut nodes = Vec::with_capacity(page.len());
            let mut to = from;
            for envelope in page {
                if envelope.position <= to {
                    return Err(SyncError::Disordered);
                }
                let opened = self.open(scope, &agent, &envelope)?;
                match opened {
                    Opening::Node(body) => {
                        nodes.push(body.node);
                        caught.heard.push(Heard {
                            position: envelope.position,
                            view: body.view,
                            seen: body.seen,
                        });
                    }
                    Opening::Passed(why) => caught.passed.push(Passed {
                        position: envelope.position,
                        why,
                    }),
                    Opening::Waiting(waiting) => {
                        caught.waiting = Some(waiting);
                        break;
                    }
                }
                caught.envelopes += 1;
                caught.bytes += envelope.bytes.len();
                to = envelope.position;
            }
            if to > from {
                caught.absorb(self.light.ingest(instance, nodes, Some(to))?);
            }
            if caught.waiting.is_some() {
                return Ok(caught);
            }
        }
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
                Some(body) => Opening::Node(body),
                None => Opening::Passed(Unusable::Body),
            },
            Err(error) => Opening::Passed(Unusable::Opened(error)),
        })
    }

    fn reading(&self, row: &[u8]) -> Result<Reading, SyncError<L::Error>> {
        match self.light.store().group_row(row)? {
            Some(bytes) => {
                Reading::decode_exact(&bytes).ok_or(SyncError::Group(GroupError::Corrupt))
            }
            None => Ok(Reading::default()),
        }
    }

    fn store_reading(&self, row: &[u8], reading: Reading) -> Result<(), SyncError<L::Error>> {
        Ok(self
            .light
            .store()
            .write_group_rows(vec![(row.to_vec(), Some(reading.encode()))])?)
    }

    /// Push `envelopes` at the confirmed epoch: how many the agent took,
    /// or the later epoch it answered `StaleEpoch` for.
    fn push_kept(&mut self, envelopes: &[Vec<u8>]) -> Result<Kept, SyncError<L::Error>> {
        let mut kept = Kept::default();
        for answer in self.send(envelopes)? {
            match answer {
                Ok(_) => kept.pushed += 1,
                Err(PersonalError::StaleEpoch { confirmed }) => {
                    kept.stale = Some(confirmed);
                    return Ok(kept);
                }
                Err(error) => return Err(SyncError::Refused(error)),
            }
        }
        Ok(kept)
    }

    /// Read the archive's scope from its cursor, merging every archive
    /// sealed at the confirmed epoch; if none was, push this device's
    /// there, chunked. Archives of earlier epochs are passed over: their
    /// keys are this device's no longer, and a later archive holds theirs.
    pub fn archive(&mut self) -> Result<Kept, SyncError<L::Error>> {
        let scope = self.group.archive().scope(ARCHIVE_NAME);
        let agent = self.group.agent().identity;
        let epoch = self.group.confirmed();
        let key = Zeroizing::new(self.group.archive_key()?);
        let mut reading = self.reading(ARCHIVE_ROW)?;
        let mut kept = Kept::default();
        // The parts of each archive read, by its digest: how many it has,
        // its parts, and the position of its first part read.
        let mut parts: BTreeMap<[u8; 32], Parts> = BTreeMap::new();
        let mut later = false;
        while !later {
            let page = self.since(scope, reading.cursor)?;
            if page.is_empty() {
                break;
            }
            for envelope in page {
                if envelope.position <= reading.cursor {
                    return Err(SyncError::Disordered);
                }
                let header = sealed::header_of(&envelope.bytes);
                if header.is_ok_and(|header| header.epoch > epoch) {
                    later = true;
                    break;
                }
                reading.cursor = envelope.position;
                if header.is_ok_and(|header| header.epoch == epoch && header.scope == scope)
                    && let Ok((_, body)) = sealed::open(&[*key], &agent, &envelope.bytes)
                    && let Some(chunk) = Chunk::decode_exact(&body)
                    && chunk.part < chunk.parts
                {
                    let (count, held, _) = parts.entry(chunk.digest).or_insert((
                        chunk.parts,
                        BTreeMap::new(),
                        envelope.position,
                    ));
                    if *count == chunk.parts {
                        held.insert(chunk.part, chunk.bytes);
                    }
                    if held.len() == *count as usize {
                        let (_, held, _) = parts.remove(&chunk.digest).expect("held");
                        let whole =
                            Zeroizing::new(held.into_values().flatten().collect::<Vec<u8>>());
                        if digest(b"vos/personal/archive-digest", &whole) == chunk.digest
                            && let Some(archive) = Archive::decode_exact(&whole)
                        {
                            self.group.merge_archive(&archive)?;
                            kept.found += 1;
                            reading.epoch = Some(epoch);
                        }
                    }
                }
            }
        }
        // An archive whose parts are not all in yet is read again from its
        // first part.
        if let Some(first) = parts.values().map(|(_, _, first)| *first).min() {
            reading.cursor = reading.cursor.min(first - 1);
        }
        self.store_reading(ARCHIVE_ROW, reading)?;
        if reading.epoch != Some(epoch) {
            let whole = Zeroizing::new(self.group.archive().encode());
            let digest = digest(b"vos/personal/archive-digest", &whole);
            let chunks: Vec<&[u8]> = whole.chunks(CHUNK_BYTES).collect();
            let parts = u16::try_from(chunks.len()).expect("an archive under 3.6 GiB");
            let mut envelopes = Vec::with_capacity(chunks.len());
            for (part, bytes) in chunks.into_iter().enumerate() {
                let body = Zeroizing::new(
                    Chunk {
                        digest,
                        part: part as u16,
                        parts,
                        bytes: bytes.to_vec(),
                    }
                    .encode(),
                );
                envelopes.push(
                    sealed::seal(&key, &agent, scope, epoch, &body)
                        .expect("a chunk fits an envelope"),
                );
            }
            let pushed = self.push_kept(&envelopes)?;
            kept.pushed = pushed.pushed;
            kept.stale = pushed.stale;
            if pushed.stale.is_none() {
                reading.epoch = Some(epoch);
                self.store_reading(ARCHIVE_ROW, reading)?;
            }
        }
        Ok(kept)
    }

    /// Read the recovery scope from its cursor for an envelope sealed under
    /// `R` at the confirmed epoch; if none is there, push this device's:
    /// the naming secret and the epoch's scope keys. Nothing without `R`.
    pub fn recovery(&mut self) -> Result<Kept, SyncError<L::Error>> {
        let Some(recovery) = self.group.archive().recovery else {
            return Ok(Kept::default());
        };
        let key = recovery_key(&recovery.r);
        let agent = self.group.agent().identity;
        let epoch = self.group.confirmed();
        let mut reading = self.reading(RECOVERY_ROW)?;
        let mut kept = Kept::default();
        'read: loop {
            let page = self.since(RECOVERY, reading.cursor)?;
            if page.is_empty() {
                break;
            }
            for envelope in page {
                if envelope.position <= reading.cursor {
                    return Err(SyncError::Disordered);
                }
                if sealed::header_of(&envelope.bytes).is_ok_and(|header| header.epoch > epoch) {
                    break 'read;
                }
                reading.cursor = envelope.position;
                if open_recovery(&recovery.r, &agent, &envelope.bytes)
                    .is_ok_and(|recovered| recovered.epoch == epoch)
                {
                    kept.found += 1;
                    reading.epoch = Some(epoch);
                }
            }
        }
        self.store_reading(RECOVERY_ROW, reading)?;
        if reading.epoch != Some(epoch) {
            let archive = self.group.archive();
            let keys = archive
                .scopes
                .iter()
                .flat_map(|scope| {
                    archive
                        .keys(epoch, scope)
                        .iter()
                        .map(move |key| (*scope, *key))
                })
                .collect();
            let body = Zeroizing::new(
                RecoveryBody {
                    naming: archive.naming,
                    keys,
                }
                .encode(),
            );
            let envelope = sealed::seal(&key, &agent, RECOVERY, epoch, &body)
                .map_err(|_| SyncError::TooLarge { seq: epoch })?;
            let pushed = self.push_kept(&[envelope])?;
            kept.pushed = pushed.pushed;
            kept.stale = pushed.stale;
            if pushed.stale.is_none() {
                reading.epoch = Some(epoch);
                self.store_reading(RECOVERY_ROW, reading)?;
            }
        }
        Ok(kept)
    }
}

/// What opening an envelope of a data scope gave.
enum Opening {
    Node(Body),
    Passed(Unusable),
    Waiting(Waiting),
}
