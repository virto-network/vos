//! [`KreivoVenue`](super::KreivoVenue)'s calls to the chain: an anchor sent
//! while the client's last read has its space active, its signer listed
//! and anchors not paused, unless the venue already holds a root at its
//! window; the pallet's answer placed by one table ([`outcome`],
//! `spaces-pallet.md` §9) and kept; and a submit checked against the
//! venue's state before it is paid for.

use std::sync::Arc;
use std::time::Duration;

use vos_anchor::venue as rules;
use vos_anchor::{Anchor, RootKind};
use vos_statement::{Refusal, Statement, StatementId};

use super::calls::{
    Active, AnchorRecord, Call, Error, Event, PAUSED_ANCHOR, PAUSED_SUBMIT, ProgramInfo, SpaceInfo,
    SpaceStatus, Spend, keys,
};
use super::transport::{Invalid, Sender, Sent, Unsent};
use super::venue::{Alert, Shared};
use crate::queue::{AnchorSend, Fate};
use crate::{AnchorOutcome, SubmitOutcome, UNJUDGED};

/// How long an anchor the pool refused waits before it goes again.
const POOL_BACKOFF: Duration = Duration::from_secs(30);

impl Shared {
    /// Send `anchor`, unless the client's last read, or the venue's record
    /// of its window read now, says not to.
    fn send_anchor(&self, anchor: &Anchor) -> Fate {
        let wait = Fate::Again(self.options.refresh);
        let Some(sender) = self.sender.get() else {
            return wait;
        };
        let Ok(now) = self.venue_now() else {
            return wait;
        };
        let info = match self.ready(anchor, now) {
            Ok(info) => info,
            Err(fate) => return fate,
        };
        let record = keys::anchors(&anchor.space.0, RootKind::Space as u8, anchor.window);
        let Ok(held) = self.read::<AnchorRecord>(&record) else {
            return wait;
        };
        if let Some(fate) = self.held_before(anchor, held.map(|record| record.root)) {
            return fate;
        }
        let sent = sender.call(&Call::anchor(anchor).bytes());
        self.place(anchor, sent, &info, now)
    }

    /// Whether `anchor` goes now, by the client's last read at the venue's
    /// time `now`: its space, or its fate. One whose space is not active,
    /// whose signer is not listed, or whose window has aged is dropped:
    /// the client answers the leader from what it read. It waits while the
    /// space is not registered, anchors are paused, or the venue's time
    /// has not passed the wait a refusal set.
    fn ready(&self, anchor: &Anchor, now: u64) -> Result<SpaceInfo, Fate> {
        let wait = Fate::Again(self.options.refresh);
        let key = (anchor.space, anchor.window);
        let mut state = self.state();
        let paused = state.paused & PAUSED_ANCHOR != 0;
        let later = state.later.get(&key).is_some_and(|at| now < *at);
        let Some(known) = state.spaces.get_mut(&anchor.space) else {
            return Err(wait);
        };
        let Some(info) = known.info else {
            return Err(wait);
        };
        if info.status != SpaceStatus::Active || !known.keys.contains(&anchor.signer) {
            return Err(Fate::Done);
        }
        if rules::aged(&info.clock(), anchor.window, now) {
            known
                .never
                .insert(anchor.window, Error::WindowTooOld as u32);
            return Err(Fate::Done);
        }
        if paused || later {
            return Err(wait);
        }
        Ok(info)
    }

    /// What the venue's record `held` of `anchor`'s window, read before
    /// sending, settles: the same root is held; another is kept for the
    /// leader to read, and sent only as the evidence it offered; none at
    /// or behind the space's last is never taken. None to send it.
    fn held_before(&self, anchor: &Anchor, held: Option<[u8; 32]>) -> Option<Fate> {
        let mut state = self.state();
        let known = state.spaces.get_mut(&anchor.space)?;
        let window = anchor.window;
        match held {
            Some(root) if root == anchor.root => {
                state.held(anchor);
                Some(Fate::Done)
            }
            Some(root) => {
                known.held.insert(window, Some(root));
                (!known.evidence.contains(&window)).then_some(Fate::Done)
            }
            None if rules::passed(known.last, window) => {
                known.held.insert(window, None);
                known.never.insert(window, Error::WindowNotAfterLast as u32);
                Some(Fate::Done)
            }
            None => None,
        }
    }

    /// The fate of `anchor`, sent at the venue's time `now` as `sent`
    /// answers: `info` its space. One that landed with its answer lost is
    /// done once the venue holds its root at its window, else it goes again
    /// a block later.
    fn place(
        &self,
        anchor: &Anchor,
        sent: Result<Sent, Unsent>,
        info: &SpaceInfo,
        now: u64,
    ) -> Fate {
        let wait = Fate::Again(self.options.refresh);
        let (space, window) = (anchor.space, anchor.window);
        let key = (space, window);
        if let Ok(Sent::Landed) = sent {
            let record = keys::anchors(&space.0, anchor.kind as u8, window);
            let held = self.read::<AnchorRecord>(&record);
            let mut state = self.state();
            if held.is_ok_and(|held| held.is_some_and(|held| held.root == anchor.root)) {
                state.held(anchor);
                return Fate::Done;
            }
            state
                .later
                .insert(key, now.saturating_add(self.options.block_ms));
            return wait;
        }
        let mut state = self.state();
        match sent {
            Ok(Sent::Included(outcome)) => {
                let anchored = outcome.events.iter().any(|event| {
                    matches!(event, Event::Anchored { space: of, window: w, root, .. }
                        if *of == space.0 && *w == window && *root == anchor.root)
                });
                let equivocated = outcome
                    .events
                    .iter()
                    .any(|event| matches!(event, Event::Equivocated { .. }));
                if anchored {
                    state.held(anchor);
                    return Fate::Done;
                }
                if equivocated {
                    state.ended(space);
                    state.alert(Alert::Equivocation { space, window });
                    return Fate::Done;
                }
                let error = outcome.failure.and_then(|failure| failure.pallet());
                state.forget(key);
                match outcome_of(error) {
                    AnchorOutcome::Taken => {
                        state.refreshed = None;
                        Fate::Done
                    }
                    AnchorOutcome::Never(code) => {
                        if let Some(known) = state.spaces.get_mut(&space) {
                            known.never.insert(window, code);
                        }
                        // A window behind the space's first or last is
                        // routine (one before its registration); an aged
                        // one is lost, and a signature or kind refused a
                        // node's fault.
                        match error {
                            Some(Error::WindowNotAfterLast) => {}
                            Some(error @ Error::WindowTooOld) => state.alert(Alert::Dead {
                                space,
                                window,
                                error,
                            }),
                            _ => {
                                let what = format!("an anchor refused: {error:?}");
                                state.alert(Alert::Configuration { space, what });
                            }
                        }
                        Fate::Done
                    }
                    AnchorOutcome::Unlisted(_) => {
                        if let Some(known) = state.spaces.get_mut(&space) {
                            known.keys.retain(|key| *key != anchor.signer);
                        }
                        state.refreshed = None;
                        let what = format!("an anchor refused: {error:?}");
                        state.alert(Alert::Configuration { space, what });
                        Fate::Done
                    }
                    AnchorOutcome::Stopped(_) => {
                        state.refreshed = None;
                        wait
                    }
                    AnchorOutcome::NotYet => match error {
                        Some(Error::WindowInFuture) => {
                            state
                                .later
                                .insert(key, now.saturating_add(self.options.block_ms));
                            wait
                        }
                        Some(Error::Paused) => {
                            state.paused |= PAUSED_ANCHOR;
                            state.refreshed = None;
                            wait
                        }
                        Some(error @ (Error::InsufficientSovereignBalance | Error::OverBudget)) => {
                            let what = format!("an anchor refused: {error:?}");
                            state.alert(Alert::Funding { space, what });
                            wait
                        }
                        _ => {
                            let what = format!(
                                "an anchor refused: {:?}; again a window later",
                                outcome.failure
                            );
                            state.alert(Alert::Configuration { space, what });
                            state.refreshed = None;
                            Fate::Again(Duration::from_millis(info.length_ms))
                        }
                    },
                }
            }
            Ok(Sent::Landed) => wait,
            Err(Unsent::Invalid(Invalid::Payment)) => {
                let what = "the venue refused an anchor's fee".to_string();
                state.alert(Alert::Funding { space, what });
                wait
            }
            Err(Unsent::Invalid(invalid)) => {
                let what = format!("the pool refused an anchor: {invalid:?}");
                state.alert(Alert::Unexpected(what));
                Fate::Again(POOL_BACKOFF)
            }
            Err(Unsent::Stopped) => wait,
        }
    }

    /// Send a submit: its outcome.
    pub(super) fn send_submit(
        &self,
        sender: &Sender,
        call: &[u8],
        id: StatementId,
    ) -> SubmitOutcome {
        let space = self.payer;
        let unjudged = |alert: Alert| {
            self.state().alert(alert);
            SubmitOutcome::Retry(UNJUDGED)
        };
        match sender.call(call) {
            Ok(Sent::Included(outcome)) => {
                if let Some(verdict) = judged(&outcome.events, id) {
                    return verdict;
                }
                let error = outcome.failure.and_then(|failure| failure.pallet());
                let what = format!("a submit refused: {error:?}");
                match error {
                    Some(Error::InsufficientSovereignBalance | Error::OverBudget) => {
                        unjudged(Alert::Funding { space, what })
                    }
                    Some(_) => unjudged(Alert::Configuration { space, what }),
                    None => {
                        let what = format!("a submit's outcome unread: {outcome:?}");
                        unjudged(Alert::Unexpected(what))
                    }
                }
            }
            Ok(Sent::Landed) => match self.read::<u64>(&keys::seen(&id.0)) {
                Ok(Some(_)) => SubmitOutcome::Accepted,
                _ => SubmitOutcome::Retry(UNJUDGED),
            },
            Err(Unsent::Invalid(Invalid::Payment)) => {
                let what = "the venue refused a submit's fee".to_string();
                unjudged(Alert::Funding { space, what })
            }
            Err(Unsent::Invalid(invalid)) => {
                let what = format!("a submit refused: {invalid:?}");
                unjudged(Alert::Configuration { space, what })
            }
            Err(Unsent::Stopped) => SubmitOutcome::Retry(UNJUDGED),
        }
    }

    /// What the venue's state says of `statement` before paying for it, in
    /// `spaces-pallet.md` §6.3's order as far as its storage tells (the pause,
    /// the format, the program, a repeat), then the paying space and its
    /// budget: a verdict, or none to send it. A read that fails says nothing.
    pub(super) fn before_paying(
        &self,
        statement: &Statement,
        id: &StatementId,
    ) -> Option<SubmitOutcome> {
        let space = self.payer;
        let configuration = |what: &str| {
            let what = what.to_string();
            self.state().alert(Alert::Configuration { space, what });
            Some(SubmitOutcome::Retry(UNJUDGED))
        };
        if self.read::<u8>(&keys::paused()).ok()?.unwrap_or(0) & PAUSED_SUBMIT != 0 {
            return configuration("submits are paused");
        }
        let now = self.venue_now().ok()?;
        let format = self.read::<Active>(&keys::formats(statement.format)).ok()?;
        if !format.is_some_and(|active| active.at(now)) {
            return Some(SubmitOutcome::judged(Refusal::Format.code()));
        }
        let program = self
            .read::<ProgramInfo>(&keys::programs(&statement.program.0))
            .ok()?;
        if !program.is_some_and(|info| info.active.at(now)) {
            return Some(SubmitOutcome::judged(Refusal::Program.code()));
        }
        if self.read::<u64>(&keys::seen(&id.0)).ok()?.is_some() {
            return Some(SubmitOutcome::Accepted);
        }
        let Some(info) = self.read::<SpaceInfo>(&keys::spaces(&space.0)).ok()? else {
            return configuration("the paying space is not registered");
        };
        if info.status != SpaceStatus::Active {
            return configuration("the paying space is not active");
        }
        let spend = self.read::<Spend>(&keys::budget(&space.0)).ok()?;
        let window = info.clock().window(now);
        let spent = spend
            .filter(|spend| Some(spend.window) == window)
            .map_or(0, |spend| spend.spent);
        if spent.saturating_add(self.options.per_submit) > info.max_spend_per_window {
            let what = format!(
                "the window's budget is spent: {spent} of {}",
                info.max_spend_per_window
            );
            self.state().alert(Alert::Funding { space, what });
            return Some(SubmitOutcome::Retry(UNJUDGED));
        }
        None
    }
}

/// The anchors' sending, as the queue's worker drives it.
pub(super) struct KreivoSend(pub(super) Arc<Shared>);

impl AnchorSend for KreivoSend {
    fn send(&self, anchor: &Anchor) -> Fate {
        self.0.send_anchor(anchor)
    }
}

/// The leader's outcome of an anchor the pallet refused with `error`
/// (`spaces-pallet.md` §9), its code kept:
/// - 14 `AlreadyAnchored`: taken, the venue holding that root;
/// - 15 `WindowNotAfterLast`, 17 `WindowTooOld`, 12 `BadAnchorSignature`
///   (signing again with the same key makes the same signature), 13 the
///   kind: never;
/// - 7 `NotAuthority`, 11 `UnknownAnchorKey`: unlisted;
/// - 19 `SpaceNotActive`: stopped;
/// - 16 `WindowInFuture`, 20 `Paused`, 21 `InsufficientSovereignBalance`,
///   27 `OverBudget`, 1 `UnknownSpace` (its registration not read yet),
///   any other, or not the pallet's: not yet.
pub(super) fn outcome_of(error: Option<Error>) -> AnchorOutcome {
    match error {
        Some(Error::AlreadyAnchored) => AnchorOutcome::Taken,
        Some(
            error @ (Error::WindowNotAfterLast
            | Error::WindowTooOld
            | Error::BadAnchorSignature
            | Error::BadKind),
        ) => AnchorOutcome::Never(error as u32),
        Some(error @ (Error::NotAuthority | Error::UnknownAnchorKey)) => {
            AnchorOutcome::Unlisted(error as u32)
        }
        Some(error @ Error::SpaceNotActive) => AnchorOutcome::Stopped(error as u32),
        _ => AnchorOutcome::NotYet,
    }
}

/// A submit's outcome from its events: `Accepted { id }` accepted,
/// `Refused { c }` as [`SubmitOutcome::judged`] takes `c` (a repeat,
/// two nodes racing, accepted); none when it was not judged.
pub(super) fn judged(events: &[Event], id: StatementId) -> Option<SubmitOutcome> {
    events.iter().find_map(|event| match event {
        Event::Accepted { id: accepted, .. } if *accepted == id.0 => Some(SubmitOutcome::Accepted),
        Event::Refused { code, .. } => Some(SubmitOutcome::judged(*code)),
        _ => None,
    })
}
