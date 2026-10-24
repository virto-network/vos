//! Accumulate: each item's verdict applied to the service's state, at the
//! venue's time, `genesis_ms + slot × 6 s` (every deadline between parties
//! is the venue's time, `proving.md` §7).
//!
//! - **A registration:** the space not registered yet, its start window
//!   within `[now_w − MaxRootAge / length, now_w + 1]` by the venue's
//!   clock; its founding keys its anchor keys.
//! - **A migration:** the signer the space's controller; once, from a
//!   window past every one anchored and not before the venue's next, nor
//!   before the space's start here (`vos_venue::ModelVenue::migrate`'s).
//! - **An anchor**, the anchor rule as the model venue applies it: a
//!   registered, unsuspended space; a signer among its anchor keys; the
//!   same root at its window again taken as a repeat, another root kept as
//!   evidence, the space suspended and the window's anchor dropped, so
//!   neither root counts again, a resume restoring neither; `Last < w`, w
//!   within its range; `w < now_w`; `now − B_w ≤ MaxRootAge`.
//! - **A control:** the signer the space's controller, its nonce the
//!   space's next; a key added (at most `MAX_FOUNDING_KEYS`) or removed, a
//!   resume once neither signer of any equivocation is listed (the space
//!   anchors again from the window after its last, every disputed window
//!   unanchored for good), or another controller.
//! - **A statement** refine accepted: every root anchored (its space
//!   registered and unsuspended, the window within its range and no older
//!   than `MaxRootAge`, the root the one held), then unseen, then recorded
//!   under the `Seen` rule. A verdict refine refused is recorded as it is,
//!   so only a code 0 is ever accepted.
//!
//! Each item's outcome is kept under its package's and its payload's
//! hashes for its submitter to read: a later package of the same payload,
//! anyone's, keeps its own. Rows age out: an anchor, a rooted statement's
//! `Seen` entry and an outcome are queued, by the hour they expire in, and
//! dropped a few an accumulate once that hour is past; a rootless
//! statement's `Seen` entry is never queued, since it has no anchor to fail
//! (`spaces-pallet.md` §6.3). `MaxRootAge` is a constant here: a raise is a
//! redeploy that first prunes the anchors older than the old bound, or a
//! `Seen` entry dropped by the old bound would let its statement's replay
//! through anchors still fresh by the new one (`spaces-pallet.md` §6.5).

use alloc::vec::Vec;

use vos_statement::MAX_ROOT_AGE_MS;
use vos_statement::model::Range;
use vos_statement::vos_anchor::{MAX_FOUNDING_KEYS, SpaceId, WindowClock};

use crate::config::Config;
use crate::item::Op;
use crate::state::{self, AnchorRecord, Evidence, Outcome, SpaceRecord, Storage, keys};
use crate::verdict::{
    AnchorCode, ControlCode, Judged, MigrateCode, RegisterCode, Registered, Verdict,
};
use crate::{SLOT_MS, natural};

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

/// Apply `operands` at `slot` to `storage`, then drop the rows past their
/// hour.
pub fn accumulate(config: &Config, slot: u64, operands: &[Operand], storage: &mut impl Storage) {
    let now = time(config, slot);
    for operand in operands {
        let outcome = apply(storage, now, operand);
        let at = keys::outcome(&state::outcome_id(
            &operand.package_hash,
            &operand.payload_hash,
        ));
        storage.write(&at, Some(&outcome.encode()));
        enqueue(storage, now, now.saturating_add(MAX_ROOT_AGE_MS), &at);
    }
    let budget = u32::try_from(operands.len())
        .unwrap_or(u32::MAX)
        .saturating_mul(2)
        .saturating_add(PRUNE_BASE);
    prune(storage, now, budget);
}

/// An operand applied: its outcome.
fn apply(storage: &mut impl Storage, now: u64, operand: &Operand) -> Outcome {
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
        Verdict::Migrate {
            space,
            from_window,
            controller,
        } => (
            migrate(storage, now, &space, from_window, &controller),
            space.0,
        ),
        Verdict::Anchor {
            space,
            window,
            kind,
            root,
            signer,
        } => {
            let held = AnchorRecord { root, signer };
            (anchor(storage, now, &space, kind, window, held), space.0)
        }
        Verdict::Submit(judged) => (submit(storage, now, &judged), judged.id),
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

fn register(storage: &mut impl Storage, now: u64, registered: &Registered) -> u32 {
    if state::space(storage, &registered.space).is_some() {
        return RegisterCode::Again as u32;
    }
    let clock = registered.clock;
    let Some(now_w) = clock.window(now) else {
        return RegisterCode::Clock as u32;
    };
    let back = MAX_ROOT_AGE_MS
        .checked_div(clock.length_ms)
        .unwrap_or(u64::MAX);
    let start = registered.start_window;
    if start < now_w.saturating_sub(back) || start > now_w.saturating_add(1) {
        return RegisterCode::Start as u32;
    }
    let record = SpaceRecord {
        clock,
        controller: registered.controller,
        keys: registered.keys.clone(),
        range: Range {
            from: start,
            until: None,
        },
        last: None,
        suspended: false,
        equivocators: Vec::new(),
        nonce: 0,
    };
    storage.write(&keys::space(&registered.space), Some(&record.encode()));
    RegisterCode::Registered as u32
}

fn migrate(
    storage: &mut impl Storage,
    now: u64,
    space: &SpaceId,
    from_window: u64,
    controller: &[u8; 32],
) -> u32 {
    let Some(mut record) = state::space(storage, space) else {
        return MigrateCode::Unregistered as u32;
    };
    if record.controller != *controller {
        return MigrateCode::Controller as u32;
    }
    if record.range.until.is_some() {
        return MigrateCode::AlreadyMigrated as u32;
    }
    let next = record
        .clock
        .window(now)
        .map_or(0, |open| open.saturating_add(1));
    let anchored = record.last.is_some_and(|last| from_window <= last);
    if anchored || from_window < next || from_window < record.range.from {
        return MigrateCode::Window as u32;
    }
    record.range.until = Some(from_window);
    storage.write(&keys::space(space), Some(&record.encode()));
    MigrateCode::Migrated as u32
}

/// Whether window `window`'s root is no older than `MaxRootAge` at `now`.
fn fresh(clock: &WindowClock, window: u64, now: u64) -> bool {
    clock
        .boundary(window)
        .and_then(|boundary| boundary.checked_add(MAX_ROOT_AGE_MS))
        .is_some_and(|last| now <= last)
}

fn anchor(
    storage: &mut impl Storage,
    now: u64,
    space: &SpaceId,
    kind: vos_statement::RootKind,
    window: u64,
    signed: AnchorRecord,
) -> u32 {
    let Some(mut record) = state::space(storage, space) else {
        return AnchorCode::Unregistered as u32;
    };
    if record.suspended {
        return AnchorCode::Suspended as u32;
    }
    if !record.keys.contains(&signed.signer) {
        return AnchorCode::Key as u32;
    }
    if let Some(held) = state::anchor(storage, space, kind, window) {
        if held.root == signed.root {
            return AnchorCode::Again as u32;
        }
        let evidence = Evidence {
            held,
            other: signed,
        };
        let at = keys::evidence(space, kind, window);
        if storage.read(&at).is_none() {
            storage.write(&at, Some(&evidence.encode()));
        }
        storage.write(&keys::anchor(space, kind, window), None);
        record.suspended = true;
        for signer in [held.signer, signed.signer] {
            if !record.equivocators.contains(&signer) {
                record.equivocators.push(signer);
            }
        }
        storage.write(&keys::space(space), Some(&record.encode()));
        return AnchorCode::Equivocation as u32;
    }
    if !record.range.contains(window) || record.last.is_some_and(|last| window <= last) {
        return AnchorCode::Window as u32;
    }
    if record.clock.window(now).is_none_or(|open| window >= open) {
        return AnchorCode::Open as u32;
    }
    let Some(boundary) = record.clock.boundary(window) else {
        return AnchorCode::Age as u32;
    };
    if now.saturating_sub(boundary) > MAX_ROOT_AGE_MS {
        return AnchorCode::Age as u32;
    }
    record.last = Some(window);
    storage.write(&keys::space(space), Some(&record.encode()));
    let at = keys::anchor(space, kind, window);
    storage.write(&at, Some(&signed.encode()));
    enqueue(storage, now, boundary.saturating_add(MAX_ROOT_AGE_MS), &at);
    AnchorCode::New as u32
}

/// A control: the controller's, at the space's next nonce; then its op, as
/// the model venue's `add_anchor_key`, `remove_anchor_key` and `resume`
/// apply it, a resume only once no equivocator is listed, which clears
/// them.
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
            if record.keys.contains(&key) || record.keys.len() >= MAX_FOUNDING_KEYS {
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
        Op::Resume => {
            if record
                .equivocators
                .iter()
                .any(|signer| record.keys.contains(signer))
            {
                return ControlCode::Suspended as u32;
            }
            record.suspended = false;
            record.equivocators.clear();
        }
        Op::SetController(key) => record.controller = key,
    }
    record.nonce = nonce.saturating_add(1);
    storage.write(&keys::space(space), Some(&record.encode()));
    ControlCode::Done as u32
}

fn submit(storage: &mut impl Storage, now: u64, judged: &Judged) -> u32 {
    if judged.code != 0 {
        return judged.code;
    }
    let space = if judged.roots.is_empty() {
        None
    } else {
        state::space(storage, &judged.space)
    };
    let anchored = judged.roots.iter().all(|root| {
        space.as_ref().is_some_and(|record| {
            !record.suspended
                && record.range.contains(root.window)
                && fresh(&record.clock, root.window, now)
                && state::anchor(storage, &judged.space, root.kind, root.window)
                    .is_some_and(|held| held.root == root.root)
        })
    });
    if !anchored {
        return vos_statement::Refusal::Unanchored.code();
    }
    let id = vos_statement::StatementId(judged.id);
    if state::seen(storage, &id).is_some() {
        return vos_statement::Refusal::Repeated.code();
    }
    let expiry = space
        .as_ref()
        .map_or(u64::MAX, |record| judged.seen_expiry(&record.clock));
    let at = keys::seen(&id);
    storage.write(&at, Some(&expiry.to_le_bytes()));
    if expiry != u64::MAX {
        enqueue(storage, now, expiry, &at);
    }
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
