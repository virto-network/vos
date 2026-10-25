//! [`KreivoVenue`](super::KreivoVenue)'s calls to the chain: an anchor sent
//! while the client's last read has its space active and anchors not
//! paused, the pallet's answer placed as the queue's [`Fate`]
//! (`spaces-pallet.md` §9), and a submit checked against the venue's state
//! before it is paid for.

use std::sync::Arc;
use std::time::Duration;

use vos_anchor::Anchor;
use vos_statement::{Refusal, Statement, StatementId};

use super::calls::{
    Active, AnchorRecord, Call, Error, Event, PAUSED_ANCHOR, PAUSED_SUBMIT, ProgramInfo, SpaceInfo,
    SpaceStatus, Spend, keys,
};
use super::transport::{Invalid, Sender, Sent, Unsent};
use super::venue::{Alert, Shared};
use crate::queue::{AnchorSend, Fate};
use crate::{NotAccepted, Unjudged};

/// How long an anchor the pool refused waits before it goes again.
const POOL_BACKOFF: Duration = Duration::from_secs(30);

impl Shared {
    /// Send `anchor`, unless the client's last read says the venue would
    /// not take it now.
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
        let sent = sender.call(&Call::anchor(anchor).bytes());
        self.place(anchor, sent, &info, now)
    }

    /// Whether `anchor` goes now, by the client's last read at the venue's
    /// time `now`: its space, or its fate. It waits while the space is not
    /// registered or not active, anchors are paused, or the venue's time
    /// has not passed the wait a refusal set; its key no longer listed, it
    /// is handed back to be signed again.
    fn ready(&self, anchor: &Anchor, now: u64) -> Result<SpaceInfo, Fate> {
        let wait = Fate::Again(self.options.refresh);
        let (space, window) = (anchor.space, anchor.window);
        let key = (space, window);
        let mut state = self.state();
        let paused = state.paused & PAUSED_ANCHOR != 0;
        let known = state.spaces.get(&space);
        let listed = known.is_some_and(|known| known.keys.contains(&anchor.signer));
        let Some(info) = known.and_then(|known| known.info) else {
            let what = "the space is not registered".to_string();
            state.alert(Alert::Configuration { space, what });
            return Err(wait);
        };
        if !listed {
            state.forget(key);
            let what = format!("window {window}'s anchor key is not listed: to be signed again");
            state.alert(Alert::Configuration { space, what });
            return Err(Fate::Resign);
        }
        let later = state.later.get(&key).is_some_and(|at| now < *at);
        if paused || info.status != SpaceStatus::Active || later {
            return Err(wait);
        }
        Ok(info)
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
        let window_length = Duration::from_millis(info.length_ms);
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
                match answer(error) {
                    Answer::Done => {
                        state.forget(key);
                        Fate::Done
                    }
                    Answer::Later => {
                        state
                            .later
                            .insert(key, now.saturating_add(self.options.block_ms));
                        wait
                    }
                    Answer::Dead(error) => {
                        state.alert(Alert::Dead {
                            space,
                            window,
                            error,
                        });
                        Fate::Dead
                    }
                    Answer::Wait => {
                        if error == Some(Error::Paused) {
                            state.paused |= PAUSED_ANCHOR;
                        }
                        state.refreshed = None;
                        wait
                    }
                    Answer::Funding(error) => {
                        let what = format!("an anchor refused: {error:?}");
                        state.alert(Alert::Funding { space, what });
                        wait
                    }
                    Answer::Resign(error) => {
                        state.forget(key);
                        let what = format!("an anchor refused: {error:?}; to be signed again");
                        state.alert(Alert::Configuration { space, what });
                        Fate::Resign
                    }
                    Answer::Configuration => {
                        let what = format!(
                            "an anchor refused: {:?}; again a window later",
                            outcome.failure
                        );
                        state.alert(Alert::Configuration { space, what });
                        Fate::Again(window_length)
                    }
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

    /// Send a submit: its verdict.
    pub(super) fn send_submit(
        &self,
        sender: &Sender,
        call: &[u8],
        id: StatementId,
    ) -> Result<StatementId, NotAccepted> {
        let space = self.payer;
        let unjudged = |alert: Alert, why: Unjudged| {
            self.state().alert(alert);
            Err(NotAccepted::Unjudged(why))
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
                        unjudged(Alert::Funding { space, what }, Unjudged::Funding)
                    }
                    Some(_) => unjudged(
                        Alert::Configuration { space, what },
                        Unjudged::Configuration,
                    ),
                    None => {
                        let what = format!("a submit's outcome unread: {outcome:?}");
                        unjudged(Alert::Unexpected(what), Unjudged::Unknown)
                    }
                }
            }
            Ok(Sent::Landed) => match self.read::<u64>(&keys::seen(&id.0)) {
                Ok(Some(_)) => Ok(id),
                _ => Err(NotAccepted::Unjudged(Unjudged::Unknown)),
            },
            Err(Unsent::Invalid(Invalid::Payment)) => {
                let what = "the venue refused a submit's fee".to_string();
                unjudged(Alert::Funding { space, what }, Unjudged::Funding)
            }
            Err(Unsent::Invalid(invalid)) => {
                let what = format!("a submit refused: {invalid:?}");
                unjudged(
                    Alert::Configuration { space, what },
                    Unjudged::Configuration,
                )
            }
            Err(Unsent::Stopped) => Err(NotAccepted::Unjudged(Unjudged::Unknown)),
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
    ) -> Option<Result<StatementId, NotAccepted>> {
        let space = self.payer;
        let configuration = |what: &str| {
            let what = what.to_string();
            self.state().alert(Alert::Configuration { space, what });
            Some(Err(NotAccepted::Unjudged(Unjudged::Configuration)))
        };
        if self.read::<u8>(&keys::paused()).ok()?.unwrap_or(0) & PAUSED_SUBMIT != 0 {
            return configuration("submits are paused");
        }
        let now = self.venue_now().ok()?;
        let format = self.read::<Active>(&keys::formats(statement.format)).ok()?;
        if !format.is_some_and(|active| active.at(now)) {
            return Some(Err(Refusal::Format.into()));
        }
        let program = self
            .read::<ProgramInfo>(&keys::programs(&statement.program.0))
            .ok()?;
        if !program.is_some_and(|info| info.active.at(now)) {
            return Some(Err(Refusal::Program.into()));
        }
        if self.read::<u64>(&keys::seen(&id.0)).ok()?.is_some() {
            return Some(Ok(*id));
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
            return Some(Err(NotAccepted::Unjudged(Unjudged::Funding)));
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

    /// By the client's last read: the space's last anchored window at or
    /// past the anchor's, or the window past `MaxRootAge` by the venue's
    /// time (`vos_anchor::venue::{passed, aged}`).
    fn settled(&self, anchor: &Anchor) -> bool {
        let mut state = self.0.state();
        let now = state.now;
        let known = state.watch(anchor.space);
        let aged = known
            .info
            .zip(now)
            .is_some_and(|(info, now)| vos_anchor::venue::aged(&info.clock(), anchor.window, now));
        vos_anchor::venue::passed(known.last, anchor.window) || aged
    }
}

/// What an anchor the chain refused waits for (`spaces-pallet.md` §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Answer {
    /// 14 `AlreadyAnchored`, 15 `WindowNotAfterLast`: the venue holds it,
    /// or a later window.
    Done,
    /// 16 `WindowInFuture`: sent again a block of the venue's time later;
    /// never skipped.
    Later,
    /// 17 `WindowTooOld`: never taken; an alert.
    Dead(Error),
    /// 19 `SpaceNotActive`, 20 `Paused`: kept until the space is active
    /// and anchors are not paused.
    Wait,
    /// 21 `InsufficientSovereignBalance`, 27 `OverBudget`: kept; a
    /// funding alert.
    Funding(Error),
    /// 11 `UnknownAnchorKey`: dropped, an alert, handed back to be
    /// signed again with a key the space lists.
    Resign(Error),
    /// 7 `NotAuthority`, 12 `BadAnchorSignature` (signing again with the
    /// same key makes the same signature), 13 the kind, any other, or not
    /// the pallet's: kept, an alert, again a window later.
    Configuration,
}

pub(super) fn answer(error: Option<Error>) -> Answer {
    match error {
        Some(Error::AlreadyAnchored | Error::WindowNotAfterLast) => Answer::Done,
        Some(Error::WindowInFuture) => Answer::Later,
        Some(error @ Error::WindowTooOld) => Answer::Dead(error),
        Some(Error::SpaceNotActive | Error::Paused) => Answer::Wait,
        Some(error @ (Error::InsufficientSovereignBalance | Error::OverBudget)) => {
            Answer::Funding(error)
        }
        Some(error @ Error::UnknownAnchorKey) => Answer::Resign(error),
        _ => Answer::Configuration,
    }
}

/// A submit's verdict from its events: `Accepted { id }` accepted,
/// `Refused` with [`Refusal::Repeated`]'s code accepted (a repeat, two
/// nodes racing), `Refused { c }` refused; none when it was not judged.
pub(super) fn judged(
    events: &[Event],
    id: StatementId,
) -> Option<Result<StatementId, NotAccepted>> {
    events.iter().find_map(|event| match event {
        Event::Accepted { id: accepted, .. } if *accepted == id.0 => Some(Ok(id)),
        Event::Refused { code, .. } if *code == Refusal::Repeated.code() => Some(Ok(id)),
        Event::Refused { code, .. } => Some(Err(NotAccepted::Refused(*code))),
        _ => None,
    })
}
