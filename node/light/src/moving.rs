//! Moving home (`light-node.md` §3.9): the personal space carried to an
//! agent claimed at another home, when the home vanishes, turns hostile,
//! lets its lease lapse, or the user wants out. Devices are full replicas,
//! so nothing is lost but the agent.
//!
//! - **The claim elsewhere** ([`Move`]): a device of the group claims the
//!   agent another home's `Homes` answers `pooled` for, as a first claim
//!   does, the kit split anew there (`R1` sealed to that agent, a new
//!   `R2` in the claim). Its keys there name each device of the old set,
//!   and each author the old set's keys named, as a carried author in
//!   each scope up to the node this device holds of it ([`carried`]):
//!   readers at the new home take those nodes as the set's, on the word of
//!   the log that holds the keys, never of an archive. The claim is held
//!   in the store beside the group it leaves, so a retry after a lost
//!   answer sends the same claim, and a refused one ([`Move::abandon`])
//!   leaves the old group as it was.
//! - **Leaving, and a new group** ([`Move::claimed`]): once the new agent's
//!   log assigns it, the old group, given up by the caller, is left: its
//!   state, its MLS state and every row of its sealed sync deleted, the
//!   scopes' data kept and each scope's cursor and push queue forgotten;
//!   the archive keeps its naming secrets and keys and drops the old `R`.
//!   Then this device's group alone at the new agent, its `R` the new
//!   split's.
//! - **Push everything** ([`finish`]): the archive, then each scope's nodes
//!   the new agent lacks carried in causal order
//!   ([`SealedSync::carry`]) and read back, the archive again, then the
//!   recovery envelopes under the new `R`, last: until then the kit opens
//!   nothing at the new home.
//! - **Re-pair** ([`rejoin`]): each other device pairs again by QR from a
//!   device at the new home, the move done there. It reads the old home to
//!   its end first, then its keys name what it carries as the mover's do
//!   ([`naming`]), which the commit adding it puts in the new home's log
//!   for every device there; its key package waits beside its old group, so a
//!   pairing cut short before the handover leaves that group standing; on
//!   the handover it leaves its old group and joins the new one (a pairing
//!   of the same personal space's alone), starts its scopes from the
//!   checkpoints handed over, and carries what the new home lacks: what it
//!   and the devices still at the old home wrote there after the move
//!   ([`finish`] again). Cut short after the handover, it pairs again from
//!   a new slot with no group to give up.
//! - **The notice** ([`Notice`]): once its claim is answered, the mover
//!   leaves at the old home where the space went, signed and sealed under
//!   the old group's epoch ([`SealedSync::announce`]); a device that missed
//!   the move reads it there ([`SealedSync::announced`]), and the app asks
//!   for the re-pairing. Until then that device follows the old home with
//!   the devices still there, and what they write reaches the new home
//!   with the first of them to pair again.
//!
//! **What the old home keeps:** what it held, for as long as its operators
//! keep it: the control log, every scope's ciphertext to the move, the
//! recovery envelopes under the old `R`, and the old `R2` with the old
//! kit's entries; deletion there cannot be verified. It is let go as the
//! last device leaves it: no device re-proves its lease, which lapses 13
//! months after the last re-proof, then refuses pushes and serves reads, a
//! restore and a move for the grace (§8, B14). A kit kept across the move
//! still restores there, unanswered once no device follows it, and reads
//! the history to the move: a move from a hostile home takes a new kit.
//!
//! **An interrupted move:** before the claim's answer, the claim is held
//! and sent again; refused, it is abandoned and the old group stands; once
//! the new agent assigned it, [`Move::claimed`] again leaves the old group
//! (again, if a crash cut it short: the cursors first, then one batch of
//! the group's rows) and starts the new one, or takes the one already made.
//! After that, [`carrying`] holds until [`finish`] has pushed everything:
//! each carry round's sealed bytes are held before they are sent and sent
//! again as they are.

use vos_abi::ids::InstanceId;
use vos_abi::{Decode, Encode};
use vos_wire::personal::{Entry, NewDevice};

use crate::group::{CarriedAuthor, Course, DeviceGroup, GroupError, Pairing, same_space};
use crate::home::{Claim, ClaimError, Home};
use crate::kit::KitKey;
use crate::personal::{Carried, Caught, Kept, Link, SealedSync, SyncError};
use crate::store::{Store, StoreError};
use crate::{Call, DeviceError, Error, Light};

/// A move's row in the group keyspace, from its preparation until it
/// pushed everything.
const MOVE_ROW: &[u8] = b"c/move";

/// Where the personal space moved: the new home and its personal agent.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Notice {
    pub home: Home,
    pub agent: u32,
    pub identity: [u8; 32],
}

/// Why a move cannot go on.
#[derive(Debug)]
pub enum MoveError {
    Claim(ClaimError),
    /// The agent named is the one this group already has.
    Here,
    /// The pairing is of another personal space.
    Elsewhere,
    /// A move or a claim waits already.
    Held,
    /// The group is one this device cannot follow, or is out of.
    Course,
    /// The device carries more authors than its keys can name
    /// (`vos_wire::personal::CARRIED`).
    Carried,
    Group(GroupError),
    Light(Error),
    Store(StoreError),
}

impl From<ClaimError> for MoveError {
    fn from(error: ClaimError) -> Self {
        MoveError::Claim(error)
    }
}

impl From<GroupError> for MoveError {
    fn from(error: GroupError) -> Self {
        MoveError::Group(error)
    }
}

impl From<Error> for MoveError {
    fn from(error: Error) -> Self {
        MoveError::Light(error)
    }
}

impl From<StoreError> for MoveError {
    fn from(error: StoreError) -> Self {
        MoveError::Store(error)
    }
}

impl std::fmt::Display for MoveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MoveError::Claim(error) => error.fmt(f),
            MoveError::Here => f.write_str("the personal space is at that agent already"),
            MoveError::Elsewhere => f.write_str("the pairing is of another personal space"),
            MoveError::Held => f.write_str("a move or a claim waits already"),
            MoveError::Course => f.write_str("the device does not follow its group"),
            MoveError::Carried => f.write_str("the device carries more authors than its keys name"),
            MoveError::Group(error) => error.fmt(f),
            MoveError::Light(error) => error.fmt(f),
            MoveError::Store(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for MoveError {}

/// Whether a move is held in `store`: prepared, and not yet finished.
pub fn moving(store: &Store) -> Result<bool, StoreError> {
    Ok(store.group_row(MOVE_ROW)?.is_some())
}

/// Whether the move held in `store` waits for its claim's answer, beside
/// the group it leaves: that group's scopes are read no more
/// (`personal::Waiting::Moving`), since the claim's keys named what the
/// move carries.
pub fn claiming(store: &Store) -> Result<bool, StoreError> {
    Ok(moving(store)? && crate::home::claim_held(store)?)
}

/// Whether the move held in `store` started its new group and waits to
/// push everything ([`finish`]).
pub fn carrying(store: &Store) -> Result<bool, MoveError> {
    Ok(moving(store)? && Claim::held(store)?.is_none() && crate::group::grouped(store)?)
}

/// A move: the claim of an agent at another home, held in the store from
/// before its call until the new group starts. Its `Debug` shows no `R`.
#[derive(Debug)]
pub struct Move(Claim);

impl Move {
    /// The move of `group`'s personal space, kept in `light`, to the pooled
    /// `agent` of another home, whose identity is `identity`, for `device`
    /// (its nullifier the new home's), its keys naming what it carries
    /// ([`naming`]), with the kit of `keys`: `R` split anew, `R1` sealed to
    /// each key at that agent, held in the store before this returns.
    /// Refused while a move or a claim waits, for the agent the group has,
    /// and for a group this device cannot follow or is out of.
    pub fn prepare(
        light: &Light,
        group: &DeviceGroup,
        device: NewDevice,
        keys: Vec<KitKey>,
        agent: u32,
        identity: [u8; 32],
    ) -> Result<Self, MoveError> {
        let store = light.store();
        if moving(store)? || Claim::held(store)?.is_some() {
            return Err(MoveError::Held);
        }
        if identity == group.agent().identity {
            return Err(MoveError::Here);
        }
        if group.course() != Course::Following {
            return Err(MoveError::Course);
        }
        let device = naming(light, group, device)?;
        let claim = Claim::draw(device, keys, agent, identity)?;
        store.write_group_rows(vec![claim.row(), (MOVE_ROW.to_vec(), Some(Vec::new()))])?;
        Ok(Self(claim))
    }

    /// The move held in `store` whose claim waits, if one does: made again
    /// as it was.
    pub fn pending(store: &Store) -> Result<Option<Self>, MoveError> {
        if !moving(store)? {
            return Ok(None);
        }
        Ok(Claim::held(store)?.map(Self))
    }

    /// The agent claimed, and its identity.
    pub fn agent(&self) -> (u32, [u8; 32]) {
        self.0.agent()
    }

    /// `Homes`' claim at the new `home` ([`Claim::call`]).
    pub fn call(&self, home: &Home, expires_ms: u64) -> Result<Call, DeviceError> {
        self.0.call(home, expires_ms)
    }

    /// The notice of this move to `home`, to leave at the home it leaves.
    pub fn notice(&self, home: &Home) -> Notice {
        let (agent, identity) = self.agent();
        Notice {
            home: home.clone(),
            agent,
            identity,
        }
    }

    /// Drop the move whose claim `Homes` refused: the old group stands.
    pub fn abandon(self, store: &Store) -> Result<(), MoveError> {
        self.0.abandon(store)?;
        store.write_group_rows(vec![(MOVE_ROW.to_vec(), None)])?;
        Ok(())
    }

    /// The new agent assigned (its log `entries` from its start, `Personal`
    /// at `instance`): `group`, the store's group, given up and left
    /// ([`DeviceGroup`]'s rows, and each of `light`'s scopes' cursor and
    /// push queue), then this device's group at the new agent, its `R` the
    /// new split's; the claim's row deleted, the move's kept until
    /// [`finish`]. Again after a crash, what is left of it is done: `group`
    /// is then none, or the new one.
    pub fn claimed(
        self,
        light: &Light,
        group: Option<DeviceGroup>,
        instance: InstanceId,
        entries: &[(u64, Entry)],
        now: u64,
    ) -> Result<DeviceGroup, MoveError> {
        let store = light.store();
        self.0.assigned(entries)?;
        let group = given(store, group)?;
        if let Some(old) = group
            && old.agent().identity != self.agent().1
        {
            leave(light, old, false)?;
        }
        Ok(self.0.claimed(store, instance, entries, now)?)
    }
}

/// `group`, given up by its caller, as the store's: the caller holds no
/// handle on a group a leave deletes, which would write it again.
fn given(store: &Store, group: Option<DeviceGroup>) -> Result<Option<DeviceGroup>, MoveError> {
    if crate::group::grouped(store)? != group.is_some() {
        return Err(MoveError::Group(GroupError::Grouped));
    }
    Ok(group)
}

/// Leave `group` for good: each of `light`'s scopes' cursor and push queue
/// forgotten first, then the group's rows in one batch, so that a leave
/// cut short is made again whole.
fn leave(light: &Light, group: DeviceGroup, rejoining: bool) -> Result<(), MoveError> {
    for instance in light.instances()? {
        light.forget_feed(instance)?;
    }
    group.leave(rejoining)?;
    Ok(())
}

/// `device`, the keys a device of `group` takes to the home its personal
/// space moves to, naming what it carries there ([`carried`]): each device
/// of `group`'s set, removed ones' too, and each author their keys named
/// as carried, so a second move carries what the first did. What a mover
/// claims with ([`Move::prepare`]) and what a device pairing again there
/// says in its hello, its old group still held ([`rejoin`]). Refused past
/// `vos_wire::personal::CARRIED` of them.
pub fn naming(
    light: &Light,
    group: &DeviceGroup,
    mut device: NewDevice,
) -> Result<NewDevice, MoveError> {
    device.carried = carried(light, &group.moved_authors())?;
    if !device.bounded() {
        return Err(MoveError::Carried);
    }
    Ok(device)
}

/// What a move carries of `authors` (a group's sync keys) in `light`'s
/// scopes: each that a scope holds nodes of, up to the highest it holds
/// there short of its cutoff (`NewDevice::carried`). A restore elsewhere
/// names the old agent's device set's so in the keys it claims with.
pub fn carried(light: &Light, authors: &[[u8; 32]]) -> Result<Vec<CarriedAuthor>, MoveError> {
    let mut carried = Vec::new();
    for instance in light.instances()? {
        let scope = light.scope_id(instance)?.0;
        for (author, seq) in light.have(instance)? {
            if !authors.contains(&author.0) {
                continue;
            }
            let through = match light.cutoff(instance, &author)? {
                Some(0) => continue,
                Some(from) => seq.min(from - 1),
                None => seq,
            };
            carried.push(CarriedAuthor {
                author: author.0,
                scope,
                through,
            });
        }
    }
    Ok(carried)
}

/// A device of a group a move left, joining the moved group from the
/// `pairing` a device at the new home handed over (`me` its keys there, as
/// [`naming`] made them before its hello): `group`, the store's old group,
/// given up and left, then its group from the pairing, its archive's keys
/// kept. Refused
/// before anything is left for a pairing of another personal space, or of
/// the agent its group has. The move is held until [`finish`] carried
/// what the new home lacks. Once the old group is left, a pairing cut
/// short is started again from a new slot, `group` none.
pub fn rejoin(
    light: &Light,
    group: Option<DeviceGroup>,
    me: NewDevice,
    pairing: Pairing,
) -> Result<DeviceGroup, MoveError> {
    let store = light.store();
    if !same_space(pairing.archive(), &store.archive()?) {
        return Err(MoveError::Elsewhere);
    }
    let old = given(store, group)?;
    if old
        .as_ref()
        .is_some_and(|old| old.agent() == pairing.agent())
    {
        return Err(MoveError::Here);
    }
    store.write_group_rows(vec![(MOVE_ROW.to_vec(), Some(Vec::new()))])?;
    if let Some(old) = old {
        leave(light, old, true)?;
    }
    Ok(DeviceGroup::rejoin(store, me, pairing)?)
}

/// What pushing everything did.
#[derive(Debug, Default)]
pub struct Finished {
    /// Each scope's reading at the new agent before its carry, and the
    /// carry.
    pub scopes: Vec<(InstanceId, Caught, Carried)>,
    pub archive: Kept,
    pub recovery: Kept,
    /// Everything pushed: the move is done. Not while a reading waits (for
    /// an epoch, a key, a withheld position) or a push met a later epoch:
    /// follow the log, read the archive, and finish again.
    pub done: bool,
}

/// Push everything to the agent of `sync`'s group: the archive read and
/// pushed, each installed scope read to its end, its nodes the agent lacks carried and
/// read back; then the archive again, and once all of it went the move
/// held is done and the recovery envelopes pushed, the last push. What a
/// move does at its new home, and what a device paired again there does:
/// again after an interruption, it pushes what is left. A failed recovery
/// push after the move is done is the next sync round's, as any is.
pub fn finish<L: Link>(sync: &mut SealedSync<'_, L>) -> Result<Finished, SyncError<L::Error>> {
    let mut finished = Finished {
        archive: sync.archive()?,
        ..Finished::default()
    };
    if finished.archive.stale.is_some() {
        return Ok(finished);
    }
    for instance in sync.light().instances()? {
        let caught = sync.catch_up(instance)?;
        let mut stop = caught.waiting.is_some();
        let mut carried = Carried::default();
        if !stop {
            carried = sync.carry(instance)?;
            stop = carried.stale.is_some();
            if !stop && !carried.pushed.is_empty() {
                stop = sync.catch_up(instance)?.waiting.is_some();
            }
        }
        finished.scopes.push((instance, caught, carried));
        if stop {
            return Ok(finished);
        }
    }
    finished.archive = sync.archive()?;
    if finished.archive.stale.is_some() {
        return Ok(finished);
    }
    sync.light()
        .store()
        .write_group_rows(vec![(MOVE_ROW.to_vec(), None)])?;
    finished.done = true;
    finished.recovery = sync.recovery()?;
    Ok(finished)
}
