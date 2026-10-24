//! The representative's leader's anchoring: the anchor of each closed
//! window's space root `S_w`, signed with the newest of this node's anchor
//! keys the venue lists and handed to the venue inside the batch that
//! closes it; those the venue's client hands back, or that an earlier
//! leadership left waiting, taken up and signed again.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::{Duration, Instant};

use ed25519_dalek::Signer;
use vos_venue::AnchorRefusal;
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::vos_anchor::{Anchor, RootKind, RootRead, space_root};

use super::Leader;
use super::close::Unsent;
use crate::fault::{Fault, read};
use crate::roots;
use crate::store::Snapshot;

/// How long an idle representative's leader waits before handing the
/// venue a waiting anchor again: a venue's clock a block behind takes it
/// within one.
const ANCHOR_RECHECK: Duration = Duration::from_secs(2);

/// What a leadership knows of its anchors.
#[derive(Default)]
pub(super) struct Anchoring {
    /// The windows still to close whose anchors this leadership settled.
    anchored: BTreeSet<u64>,
    /// The anchors this leadership has still to hand the venue, by window:
    /// the space's root `S_w`.
    unanchored: BTreeMap<u64, [u8; 32]>,
    /// When it last handed the venue an anchor that then waited: an idle
    /// leader tries again a recheck later.
    anchor_tried: Option<Instant>,
    /// The window whose anchor this leadership last alerted it could not
    /// sign, or the venue would not take yet for want of a key or a
    /// resumption: alerted once a window.
    alerted: Option<u64>,
    /// The windows whose anchors the venue refused for good, or that aged
    /// unsent, among those whose cut roots this replica keeps: not taken
    /// up again.
    refused: BTreeSet<u64>,
    /// The last anchor this leadership signed of each window still
    /// waiting, kept or handed back: an anchor handed back that it has
    /// since replaced is not taken up.
    signed: BTreeMap<u64, Anchor>,
    /// Anchors handed back whose root is not the space's at their window,
    /// by the cut root this replica keeps: never signed again.
    foreign: HashSet<Anchor>,
    /// When this leadership last took up the anchors left waiting by its
    /// cut roots: at its first batch, then a window length later.
    seeded: Option<Instant>,
    /// The venue's anchor key listing when it last refused this node's
    /// key, and the node's time then: the anchor goes again once the
    /// listing changes, or a window later.
    key_refused: Option<(Vec<[u8; 32]>, u64)>,
}

impl Leader {
    /// How long until an idle leader hands the venue a waiting anchor
    /// again, a recheck after the last try, or takes up anchors left
    /// waiting ([`Leader::reseed_wait`]); none while neither is due.
    pub(super) fn anchor_wait(&self) -> Option<Duration> {
        let waiting = (!self.anchoring.unanchored.is_empty()).then(|| {
            let since = self
                .anchoring
                .anchor_tried
                .map_or(ANCHOR_RECHECK, |at| at.elapsed());
            ANCHOR_RECHECK.saturating_sub(since)
        });
        waiting.into_iter().chain(self.reseed_wait()).min()
    }

    /// The anchors the venue's client handed back to be signed again
    /// ([`vos_venue::VenueClient::unsettled`]) that this node signed, of
    /// its space's root, over this venue's digest, and that this
    /// leadership has neither taken up, nor settled since (a later anchor of
    /// the window it signed settled), nor settled for good. An anchor
    /// another key signed, of another kind or space, or over another
    /// digest, is no anchor of this node's: it is never signed again.
    fn handed_back(&self) -> Vec<Anchor> {
        let Some(venue) = self.inner.venue.as_ref() else {
            return Vec::new();
        };
        let (space, _) = self.inner.space_and_clock();
        let ours = self.inner.anchor_keys.public();
        let id = venue.id();
        venue
            .unsettled(&space)
            .into_iter()
            .filter(|anchor| {
                let signed = anchor.space == space
                    && anchor.kind == RootKind::Space
                    && ours.contains(&anchor.signer)
                    && vos_venue::signed(anchor, &id);
                let window = anchor.window;
                let settled_since = self.anchoring.anchored.contains(&window)
                    && self
                        .anchoring
                        .signed
                        .get(&window)
                        .is_some_and(|last| last != anchor);
                signed
                    && !settled_since
                    && !self.anchoring.foreign.contains(anchor)
                    && !self.anchoring.unanchored.contains_key(&window)
                    && !self.anchoring.refused.contains(&window)
            })
            .collect()
    }

    /// How long until the representative's leader takes up anchors left
    /// waiting: at once for one the venue's client handed back, and its
    /// cut roots ([`Leader::seed_waiting`]) a window length after it last
    /// did; an idle leader looks for anchors handed back a recheck apart,
    /// as a client hands them back on its own thread; at once before this
    /// leadership has. None with no venue.
    fn reseed_wait(&self) -> Option<Duration> {
        self.inner.venue.as_ref()?;
        if !self.represents() {
            return None;
        }
        let Some(seeded) = self.anchoring.seeded else {
            return Some(Duration::ZERO);
        };
        if !self.handed_back().is_empty() {
            return Some(Duration::ZERO);
        }
        let (_, clock) = self.inner.space_and_clock();
        let reseed = Duration::from_millis(clock.length_ms).saturating_sub(seeded.elapsed());
        Some(reseed.min(ANCHOR_RECHECK))
    }

    /// Take up the anchors the venue's client handed back
    /// ([`Leader::handed_back`]): each root signed again, by the newest key
    /// the venue lists, whether or not this replica still keeps its cut
    /// root; where it keeps it, only a root that is the space's root over
    /// it, `S_w`, which an anchor still waiting holds already. Whether to
    /// take up the cut roots' too: at a leadership's first batch, then a
    /// window length after it last did.
    pub(super) fn take_up(&mut self, snapshot: &Snapshot) -> Result<bool, Fault> {
        if self.inner.venue.is_none() || !self.represents() {
            return Ok(false);
        }
        let (space, clock) = self.inner.space_and_clock();
        for anchor in self.handed_back() {
            let window = anchor.window;
            let cut = roots::cut_root(snapshot, self.id, window)?;
            let computed = cut.map(|(root, _)| space_root(&space, window, &root));
            if computed.is_some_and(|root| root != anchor.root) {
                self.anchoring.foreign.insert(anchor);
                self.alert(
                    window,
                    "the venue's client handed back an anchor whose root is not the space's at \
                     its window; it is not signed again",
                );
                continue;
            }
            self.anchoring.anchored.remove(&window);
            self.anchoring
                .unanchored
                .entry(window)
                .or_insert(anchor.root);
        }
        let every = Duration::from_millis(clock.length_ms);
        let due = self.anchoring.seeded.is_none_or(|at| at.elapsed() >= every);
        if due {
            self.anchoring.seeded = Some(Instant::now());
        }
        Ok(due)
    }

    /// Take up the anchors left waiting, by an earlier leadership or by
    /// the venue: every window up to the close mark whose cut root this
    /// replica still keeps (the representative's last
    /// [`defaults::CUT_KEEP`] windows) and whose root the venue does not
    /// hold anchored, whether never handed over, handed over and dropped
    /// by the venue's client to be signed again, or refused while the
    /// space was not registered there yet. Its close was sent, so no unsent
    /// close names it; the root is the representative's at its cut, the
    /// one its close carried.
    pub(super) fn seed_waiting(&mut self, snapshot: &Snapshot) -> Result<(), Fault> {
        let Some(venue) = self.inner.venue.clone() else {
            return Ok(());
        };
        if !self.represents() {
            return Ok(());
        }
        let Some((through, _)) =
            read::<(u64, Option<AgentId>)>(snapshot, self.id, &keys::close_mark())?
        else {
            return Ok(());
        };
        let (space, _) = self.inner.space_and_clock();
        let mut kept = BTreeSet::new();
        let cut_roots = roots::cut_roots(snapshot, self.id)?;
        for (&window, &(root, _)) in cut_roots.range(..=through) {
            kept.insert(window);
            if self.anchoring.refused.contains(&window) {
                continue;
            }
            let closing = roots::closing_of(snapshot, self.id, window)?;
            if closing.is_some_and(|closing| closing.root != root) {
                return Err(roots::Error::Corrupt("a close whose root is not its cut's").into());
            }
            let root = space_root(&space, window, &root);
            let held = venue.anchored(&RootRead {
                kind: RootKind::Space,
                space,
                window,
                root,
            });
            if !held {
                self.anchoring.unanchored.entry(window).or_insert(root);
            }
        }
        let handed: Vec<Anchor> = venue.unsettled(&space);
        let back: Vec<u64> = handed.iter().map(|anchor| anchor.window).collect();
        self.anchoring
            .refused
            .retain(|window| kept.contains(window) || back.contains(window));
        let waiting = |window: &u64| {
            kept.contains(window)
                || back.contains(window)
                || self.anchoring.unanchored.contains_key(window)
        };
        self.anchoring
            .foreign
            .retain(|anchor| handed.contains(anchor));
        self.anchoring.signed.retain(|window, _| waiting(window));
        Ok(())
    }

    /// Hand the venue the anchors this leadership has not settled, in
    /// window order, until one waits: a window the venue's clock has not
    /// yet closed, an anchor no key of this node's can sign, or one the
    /// venue will not take until its controller acts (a key registered, the
    /// space resumed). The next batch tries again, or an idle leader a
    /// recheck later ([`Leader::anchor_wait`]), with the later ones behind
    /// it, so none passes it. A window past `MaxRootAge` by the venue's
    /// time (this node's while the venue's client cannot say) is settled
    /// here, unsent: no venue takes it. One taken, or refused for good, is
    /// settled; the close goes on either way, and a statement over an
    /// unanchored root is refused at the venue.
    fn anchor_due(&mut self) {
        let (_, clock) = self.inner.space_and_clock();
        if self.anchoring.unanchored.is_empty() {
            return;
        }
        let now = self
            .inner
            .venue
            .as_ref()
            .and_then(|venue| venue.time())
            .unwrap_or_else(|| (self.inner.clock)());
        while let Some((&window, &root)) = self.anchoring.unanchored.first_key_value() {
            if vos_venue::aged(&clock, window, now) {
                tracing::error!(
                    window,
                    "the space's root waited past `MaxRootAge`; no venue takes it now"
                );
                self.anchoring.refused.insert(window);
            } else if !self.anchor(window, &root) {
                self.anchoring.anchor_tried = Some(Instant::now());
                return;
            }
            self.anchoring.unanchored.remove(&window);
            self.anchoring.anchored.insert(window);
        }
    }

    /// Sign the anchor of the space's root `root` of window `window` (`S_w`,
    /// over the representative's root at its cut), with the newest of this
    /// node's anchor keys the venue lists, and hand it to the venue:
    /// whether that settled it, taken or refused for good. With no key of
    /// this node's listed it signs nothing, and alerts. Synchronous, inside
    /// the batch: a venue's client queues and answers at once.
    fn anchor(&mut self, window: u64, root: &[u8; 32]) -> bool {
        let Some(venue) = self.inner.venue.clone() else {
            return true;
        };
        let (space, clock) = self.inner.space_and_clock();
        if venue.status(&space).waits() {
            self.alert(
                window,
                "the space is suspended or blocked at the venue; its anchors wait, unsent, until \
                 its controller resumes it (after removing both equivocating keys) or the venue \
                 unblocks it",
            );
            return false;
        }
        let listing = venue.anchor_keys(&space);
        let now = (self.inner.clock)();
        let refused_again = self
            .anchoring
            .key_refused
            .as_ref()
            .is_some_and(|(listed, at)| {
                *listed == listing && now.saturating_sub(*at) < clock.length_ms
            });
        if refused_again {
            return false;
        }
        let Some(key) = self.inner.anchor_keys.listed(&listing) else {
            self.alert(
                window,
                "the venue lists none of this node's anchor keys; the space's root is not signed \
                 until it lists one: replace this replica of the representative, or list one of \
                 its keys (`vos node anchor-key rotate`, then the controller's `add_authority`)",
            );
            return false;
        };
        let mut anchor = Anchor {
            space,
            window,
            kind: RootKind::Space,
            root: *root,
            signer: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = key.sign(&anchor.digest(&venue.id())).to_bytes();
        self.anchoring.signed.insert(window, anchor);
        let answer = venue.anchor(&anchor);
        self.anchoring.key_refused = None;
        match answer {
            Ok(anchored) => {
                tracing::debug!(window, ?anchored, "anchored the space's root");
                true
            }
            Err(AnchorRefusal::Open) => {
                tracing::info!(
                    window,
                    "the venue has not closed the window yet; anchoring again"
                );
                false
            }
            Err(AnchorRefusal::Key) => {
                self.anchoring.key_refused = Some((listing, now));
                self.alert(
                    window,
                    "the venue no longer lists the anchor key signed with; anchoring again once \
                     its listing changes, or a window later",
                );
                false
            }
            Err(AnchorRefusal::Suspended) => {
                self.alert(
                    window,
                    "the space is suspended at the venue, for an equivocation, until its \
                     controller removes both keys and resumes it; anchoring again",
                );
                false
            }
            Err(AnchorRefusal::Unregistered) => {
                self.alert(
                    window,
                    "the space is not registered at the venue, or its client has not read the \
                     registration yet; anchoring again",
                );
                false
            }
            Err(refusal) => {
                tracing::error!(window, ?refusal, "the venue refused the space's root");
                self.anchoring.refused.insert(window);
                true
            }
        }
    }

    /// Alert, once a window, that `window`'s anchor waits.
    fn alert(&mut self, window: u64, why: &str) {
        if self.anchoring.alerted != Some(window) {
            self.anchoring.alerted = Some(window);
            tracing::error!(window, "{why}");
        }
    }

    /// Before the closes `unsent` are proposed: the windows before the
    /// first settled, each unsent close's anchor waiting unless settled,
    /// and the venue handed those due ([`Leader::anchor_due`]).
    pub(super) fn anchor_closes(&mut self, unsent: &[Unsent]) {
        let first = unsent.first().map(|(window, _)| *window);
        self.anchoring
            .anchored
            .retain(|window| first.is_some_and(|first| *window >= first));
        let (space, _) = self.inner.space_and_clock();
        for (window, closing) in unsent {
            if !self.anchoring.anchored.contains(window) {
                let root = space_root(&space, *window, &closing.root);
                self.anchoring.unanchored.entry(*window).or_insert(root);
            }
        }
        self.anchor_due();
    }
}
