//! Accumulate: each item's verdict applied to the service's state, at the
//! venue's time, `genesis_ms + slot × 6 s` (every deadline between parties
//! is the venue's time, `proving.md` §7), by the venue rules
//! (`vos_anchor::venue`).
//!
//! - **A registration** refine admitted: `vos_anchor::venue::register`, the
//!   space not registered yet, ended or not; it anchors from the venue's
//!   next window, its founding keys its anchor keys.
//! - **An anchor**, by `vos_anchor::venue::anchor`, its signature verified
//!   at refine: the same root at its window again taken as a repeat;
//!   another root kept as evidence, which ends the space for good.
//! - **A control:** the signer the space's controller, its nonce the
//!   space's next; a key added (at most `MAX_FOUNDING_KEYS`, none of small
//!   order) or removed, or another controller. An ended space is
//!   controlled still.
//! - **A statement** refine accepted: every root anchored
//!   (`vos_anchor::venue::anchored`), then unseen, then recorded under the
//!   `Seen` rule. A verdict refine refused is recorded as it is, so only a
//!   code 0 is ever accepted.
//!
//! Each item's outcome is kept under its package's and its payload's
//! hashes for its submitter to read: a later package of the same payload,
//! anyone's, keeps its own. Rows age out: an anchor, a `Seen` entry and an
//! outcome are queued, by the hour they expire in, and dropped a few an
//! accumulate once that hour is past (`spaces-pallet.md` §6.5); a space and
//! its evidence never do. `MaxRootAge` is a constant here: a raise is a
//! redeploy that first prunes the anchors older than the old bound, or a
//! `Seen` entry dropped by the old bound would let its statement's replay
//! through anchors still fresh by the new one (`spaces-pallet.md` §6.5).

use alloc::vec::Vec;

use vos_statement::vos_anchor::venue::{
    self as rules, AnchorRefusal, Anchoring, Held, Roots, Status, VenueState,
};
use vos_statement::vos_anchor::{Anchor, RootKind, RootRead, SpaceId, VenueId};

use crate::config::Config;
use crate::item::Op;
use crate::refine::register_code;
use crate::state::{self, AnchorRecord, Evidence, Outcome, SpaceRecord, Storage, keys};
use crate::verdict::{AnchorCode, ControlCode, Judged, RegisterCode, Registered, Verdict};
use crate::{SLOT_MS, natural};

/// How long an item's outcome is kept for its submitter to read: a day.
/// It is also the horizon a client reading the drop queue scans, so every
/// row queued, an anchor's at `MaxRootAge` included, expires within it.
pub const OUTCOME_KEEP_MS: u64 = 86_400_000;

/// The rows queued to drop, by the hour they expire in.
pub const BUCKET_MS: u64 = 3_600_000;
/// The queued rows an accumulate drops at most: this, and two an input.
const PRUNE_BASE: u32 = 8;

/// A work item's result as accumulate takes it: its payload's hash, and
/// refine's output or the work error's code (Gray Paper 0.8.0: 1 out of
/// gas, 2 a panic, …).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    pub package_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub result: Result<Vec<u8>, u8>,
}

impl Operand {
    /// The operand an accumulate input holds (`fetch` kind 15): the kind
    /// byte 0, the package's hash, its exports' root, the authorizer, the
    /// payload's hash (32 each), the gas limit (a natural), the result
    /// (0, a natural length and the output; or the error's byte) and the
    /// authorizer's trace. None for a deferred transfer, or bytes that are
    /// not an operand.
    pub fn decode_input(bytes: &[u8]) -> Option<Self> {
        let (&0, rest) = bytes.split_first()? else {
            return None;
        };
        let package_hash = rest.get(..32)?.try_into().ok()?;
        let payload_hash = rest.get(96..128)?.try_into().ok()?;
        let (_, at) = natural(rest, 128)?;
        let (&tag, rest) = rest.get(at..)?.split_first()?;
        let result = match tag {
            0 => {
                let (len, at) = natural(rest, 0)?;
                let len = usize::try_from(len).ok()?;
                Ok(rest.get(at..at.checked_add(len)?)?.to_vec())
            }
            error => Err(error),
        };
        Some(Self {
            package_hash,
            payload_hash,
            result,
        })
    }
}

/// The venue's time at `slot`: ms since the Unix epoch.
pub fn time(config: &Config, slot: u64) -> u64 {
    config
        .genesis_ms
        .saturating_add(slot.saturating_mul(SLOT_MS))
}

/// Apply `operands` at `slot` to `storage`, as the service `venue`, then
/// drop the rows past their hour.
pub fn accumulate(
    config: &Config,
    venue: VenueId,
    slot: u64,
    operands: &[Operand],
    storage: &mut impl Storage,
) {
    let now = time(config, slot);
    for operand in operands {
        let outcome = apply(storage, venue, now, operand);
        let at = keys::outcome(&state::outcome_id(
            &operand.package_hash,
            &operand.payload_hash,
        ));
        storage.write(&at, Some(&outcome.encode()));
        enqueue(storage, now, now.saturating_add(OUTCOME_KEEP_MS), &at);
    }
    let budget = u32::try_from(operands.len())
        .unwrap_or(u32::MAX)
        .saturating_mul(2)
        .saturating_add(PRUNE_BASE);
    prune(storage, now, budget);
}

/// An operand applied: its outcome.
fn apply(storage: &mut impl Storage, venue: VenueId, now: u64, operand: &Operand) -> Outcome {
    let failed = |code: u32| Outcome {
        time: now,
        kind: u8::MAX,
        code: Outcome::FAILED.saturating_add(code),
        subject: [0; 32],
        refine_gas: 0,
    };
    let output = match &operand.result {
        Ok(output) => output,
        Err(error) => return failed(u32::from(*error)),
    };
    let decoded = Verdict::decode_prefix(output)
        .ok()
        .and_then(|(verdict, used)| {
            let gas = output.get(used..)?.try_into().ok()?;
            Some((verdict, u64::from_le_bytes(gas)))
        });
    let Some((verdict, refine_gas)) = decoded else {
        return failed(u32::from(u8::MAX));
    };
    let kind = verdict.kind().map_or(u8::MAX, |kind| kind as u8);
    let (code, subject) = match verdict {
        Verdict::Register(registered) => (register(storage, now, &registered), registered.space.0),
        Verdict::Anchor {
            space,
            window,
            kind,
            root,
            signer,
        } => {
            let anchor = Anchor {
                space,
                window,
                kind,
                root,
                signer,
                signature: [0; 64],
            };
            (self::anchor(storage, venue, now, &anchor), space.0)
        }
        Verdict::Submit(judged) => (submit(storage, venue, now, &judged), judged.id),
        Verdict::Control {
            space,
            nonce,
            op,
            controller,
        } => (control(storage, &space, nonce, op, &controller), space.0),
        Verdict::Refused { code, .. } => (code, [0; 32]),
    };
    Outcome {
        time: now,
        kind,
        code,
        subject,
        refine_gas,
    }
}

/// One space's record and one window's root as the service holds them,
/// at the venue's time: what the venue rules read of an item. Every
/// signature it is asked of was verified at refine.
struct Snapshot {
    venue: VenueId,
    now: u64,
    space: Option<SpaceRecord>,
    held: Option<AnchorRecord>,
}

impl Snapshot {
    /// `space`'s record and its root of `kind` at `window`, read.
    fn read(
        storage: &mut impl Storage,
        venue: VenueId,
        now: u64,
        space: &SpaceId,
        kind: RootKind,
        window: u64,
    ) -> Self {
        Self {
            venue,
            now,
            space: state::space(storage, space),
            held: state::anchor(storage, space, kind, window),
        }
    }
}

impl Roots for Snapshot {
    fn now(&self) -> u64 {
        self.now
    }

    fn space(&self, _: &SpaceId) -> Option<rules::Space> {
        self.space.as_ref().map(|record| rules::Space {
            clock: record.clock,
            start: record.start,
            status: if record.ended {
                Status::Ended
            } else {
                Status::Active
            },
        })
    }

    fn held(&self, _: &SpaceId, _: RootKind, _: u64) -> Option<Held> {
        self.held.map(|held| Held {
            root: held.root,
            signer: held.signer,
        })
    }
}

impl VenueState for Snapshot {
    fn venue(&self) -> VenueId {
        self.venue
    }

    fn listed(&self, _: &SpaceId, key: &[u8; 32]) -> bool {
        self.space
            .as_ref()
            .is_some_and(|record| record.keys.contains(key))
    }

    fn last(&self, _: &SpaceId, _: RootKind) -> Option<u64> {
        self.space.as_ref()?.last
    }

    /// Refine verified it, strictly.
    fn verify(&self, _: &[u8; 32], _: &[u8; 32], _: &[u8; 64]) -> bool {
        true
    }
}

fn register(storage: &mut impl Storage, now: u64, registered: &Registered) -> u32 {
    let snapshot = Snapshot {
        venue: VenueId([0; 32]),
        now,
        space: state::space(storage, &registered.space),
        held: None,
    };
    let registration = rules::Registration {
        space: registered.space,
        clock: registered.clock,
        keys: registered.keys.clone(),
    };
    let start = match rules::register(&snapshot, &registration) {
        Ok(start) => start,
        Err(refusal) => return register_code(refusal) as u32,
    };
    let record = SpaceRecord {
        clock: registered.clock,
        controller: registered.controller,
        keys: registered.keys.clone(),
        start,
        last: None,
        ended: false,
        nonce: 0,
    };
    storage.write(&keys::space(&registered.space), Some(&record.encode()));
    RegisterCode::Registered as u32
}

/// The anchor rule's answer to `anchor`, applied: a new root stored and
/// queued to drop past `MaxRootAge`; evidence kept and the space ended.
fn anchor(storage: &mut impl Storage, venue: VenueId, now: u64, anchor: &Anchor) -> u32 {
    let (space, kind, window) = (anchor.space, anchor.kind, anchor.window);
    let snapshot = Snapshot::read(storage, venue, now, &space, kind, window);
    let anchoring = match rules::anchor(&snapshot, anchor) {
        Ok(anchoring) => anchoring,
        Err(refusal) => {
            return match refusal {
                AnchorRefusal::Unregistered => AnchorCode::Unregistered,
                AnchorRefusal::Stopped => AnchorCode::Ended,
                AnchorRefusal::Key => AnchorCode::Key,
                AnchorRefusal::Signature => AnchorCode::Signature,
                AnchorRefusal::Window => AnchorCode::Window,
                AnchorRefusal::Open => AnchorCode::Open,
                AnchorRefusal::Age => AnchorCode::Age,
            } as u32;
        }
    };
    let Some(mut record) = snapshot.space else {
        return AnchorCode::Unregistered as u32;
    };
    let signed = AnchorRecord {
        root: anchor.root,
        signer: anchor.signer,
    };
    match anchoring {
        Anchoring::Again => AnchorCode::Again as u32,
        Anchoring::New => {
            record.last = Some(window);
            storage.write(&keys::space(&space), Some(&record.encode()));
            let at = keys::anchor(&space, kind, window);
            storage.write(&at, Some(&signed.encode()));
            let expiry = rules::expiry(&record.clock, window).unwrap_or(u64::MAX);
            enqueue(storage, now, expiry, &at);
            AnchorCode::New as u32
        }
        Anchoring::Evidence(held) => {
            let evidence = Evidence {
                held: AnchorRecord {
                    root: held.root,
                    signer: held.signer,
                },
                other: signed,
            };
            let at = keys::evidence(&space, kind, window);
            storage.write(&at, Some(&evidence.encode()));
            record.ended = true;
            storage.write(&keys::space(&space), Some(&record.encode()));
            AnchorCode::Equivocation as u32
        }
    }
}

/// A control: the controller's, at the space's next nonce; then its op, as
/// the model venue's `add_anchor_key` and `remove_anchor_key` apply it.
fn control(
    storage: &mut impl Storage,
    space: &SpaceId,
    nonce: u64,
    op: Op,
    controller: &[u8; 32],
) -> u32 {
    let Some(mut record) = state::space(storage, space) else {
        return ControlCode::Unregistered as u32;
    };
    if record.controller != *controller {
        return ControlCode::Controller as u32;
    }
    if nonce != record.nonce {
        return ControlCode::Nonce as u32;
    }
    match op {
        Op::AddKey(key) => {
            if rules::add_key(record.keys.len(), record.keys.contains(&key), &key).is_err() {
                return ControlCode::Key as u32;
            }
            record.keys.push(key);
        }
        Op::RemoveKey(key) => {
            if !record.keys.contains(&key) {
                return ControlCode::Key as u32;
            }
            record.keys.retain(|held| *held != key);
        }
        Op::SetController(key) => record.controller = key,
    }
    record.nonce = nonce.saturating_add(1);
    storage.write(&keys::space(space), Some(&record.encode()));
    ControlCode::Done as u32
}

/// Whether the service holds `root` anchored at the venue's time `now`
/// (`vos_anchor::venue::anchored`).
pub fn anchored(storage: &mut impl Storage, venue: VenueId, now: u64, root: &RootRead) -> bool {
    let snapshot = Snapshot::read(storage, venue, now, &root.space, root.kind, root.window);
    rules::anchored(&snapshot, root)
}

fn submit(storage: &mut impl Storage, venue: VenueId, now: u64, judged: &Judged) -> u32 {
    if judged.code != 0 {
        return judged.code;
    }
    let all = judged.roots.iter().all(|root| {
        let read = RootRead {
            kind: root.kind,
            space: judged.space,
            window: root.window,
            root: root.root,
        };
        anchored(storage, venue, now, &read)
    });
    if !all {
        return vos_statement::Refusal::Unanchored.code();
    }
    let Some(record) = state::space(storage, &judged.space) else {
        return vos_statement::Refusal::Unanchored.code();
    };
    let clock = record.clock;
    let id = vos_statement::StatementId(judged.id);
    if state::seen(storage, &id).is_some() {
        return vos_statement::Refusal::Repeated.code();
    }
    let expiry = judged.seen_expiry(&clock);
    let at = keys::seen(&id);
    storage.write(&at, Some(&expiry.to_le_bytes()));
    enqueue(storage, now, expiry, &at);
    0
}

/// The pruning's cursor: the bucket and the index it is at.
fn cursor(storage: &mut impl Storage) -> Option<(u64, u32)> {
    let bytes = storage.read(keys::CURSOR)?;
    let (bucket, index) = bytes.split_at_checked(8)?;
    Some((
        u64::from_le_bytes(bucket.try_into().ok()?),
        u32::from_le_bytes(index.try_into().ok()?),
    ))
}

fn set_cursor(storage: &mut impl Storage, bucket: u64, index: u32) {
    let bytes = [&bucket.to_le_bytes()[..], &index.to_le_bytes()].concat();
    storage.write(keys::CURSOR, Some(&bytes));
}

fn count(storage: &mut impl Storage, bucket: u64) -> u32 {
    storage
        .read(&keys::bucket(bucket))
        .and_then(|bytes| Some(u32::from_le_bytes(bytes.try_into().ok()?)))
        .unwrap_or(0)
}

/// Queue `key` to drop once `expiry`'s hour is past. The cursor starts at
/// the hour of the first row queued: every expiry is at least the time it
/// is queued at, so none is queued behind the cursor, which passes an hour
/// only once it is over.
fn enqueue(storage: &mut impl Storage, now: u64, expiry: u64, key: &[u8]) {
    if cursor(storage).is_none() {
        set_cursor(storage, now / BUCKET_MS, 0);
    }
    let bucket = expiry / BUCKET_MS;
    let index = count(storage, bucket);
    storage.write(&keys::queued(bucket, index), Some(key));
    storage.write(
        &keys::bucket(bucket),
        Some(&index.saturating_add(1).to_le_bytes()),
    );
}

/// Drop at most `budget` of the queued rows whose hour is past `now`, or
/// pass that many hours' ends.
fn prune(storage: &mut impl Storage, now: u64, budget: u32) {
    let Some((mut bucket, mut index)) = cursor(storage) else {
        return;
    };
    let moved = (bucket, index);
    for _ in 0..budget {
        let over = bucket
            .checked_add(1)
            .and_then(|next| next.checked_mul(BUCKET_MS))
            .is_some_and(|end| end <= now);
        if !over {
            break;
        }
        if index < count(storage, bucket) {
            let at = keys::queued(bucket, index);
            if let Some(key) = storage.read(&at) {
                storage.write(&key, None);
                storage.write(&at, None);
            }
            index = index.saturating_add(1);
        } else {
            storage.write(&keys::bucket(bucket), None);
            bucket = bucket.saturating_add(1);
            index = 0;
        }
    }
    if (bucket, index) != moved {
        set_cursor(storage, bucket, index);
    }
}
