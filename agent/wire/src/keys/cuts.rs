//! The rows of a window's cut and close: the cut's version and the
//! requests read at it, the node's undo and proof rows of its build, the
//! reports to the representative, its closes and the space's roots, and
//! the attests stated there.

use alloc::vec::Vec;

use super::{Row, TreeRow, is_committed, key};
use crate::ids::{AgentId, RequestId, WorkflowId};

/// The state version of the window `window`'s cut: the version before the
/// first work result applied with a time at or past the window's boundary
/// ([`crate::WindowClock::boundary`]). Apply writes it, in an agent of a
/// space, for the window a read waits on, or for every window that
/// result's time crosses when the agent reports every one; it is
/// replicated, and never rewritten.
pub fn cut(window: u64) -> Vec<u8> {
    key(&[&Row::Cut.prefix(), &window.to_be_bytes()])
}

/// The prefix of the cuts, in window order.
pub fn cuts() -> Vec<u8> {
    Row::Cut.prefix().to_vec()
}

/// The window a [`cut`] key names; `None` for any other key.
pub fn cut_entry(key: &[u8]) -> Option<u64> {
    window_of(&Row::Cut.prefix(), key)
}

/// A pending request of the window `window` ([`crate::records::PendingRead`]):
/// replicated, written by the workflow step that asks.
pub fn request(window: u64, id: RequestId) -> Vec<u8> {
    key(&[
        &Row::Request.prefix(),
        &window.to_be_bytes(),
        &request_id(id),
    ])
}

/// The prefix of every pending request, in window order.
pub fn request_prefix() -> Vec<u8> {
    Row::Request.prefix().to_vec()
}

/// The prefix of the window `window`'s pending requests.
pub fn requests(window: u64) -> Vec<u8> {
    key(&[&Row::Request.prefix(), &window.to_be_bytes()])
}

/// The window and request a [`request`] key names; `None` for any other
/// key.
pub fn request_entry(key: &[u8]) -> Option<(u64, RequestId)> {
    let rest = key.strip_prefix(&Row::Request.prefix())?;
    let (window, id) = rest.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*window), request_of(id.try_into().ok()?)))
}

/// The value the committed row `row` held at the window `window`'s cut,
/// its stored bytes, kept by the node while that cut's build is pending
/// and a later write overwrites the row. Node-local: the node's apply
/// writes it beside the agent's writes, and the cut's build deletes it.
pub fn undo(window: u64, row: &[u8]) -> Vec<u8> {
    TreeRow::Undo.key(&[&window.to_be_bytes()[..], row].concat())
}

/// The prefix of the window `window`'s [`undo`] rows.
pub fn undos(window: u64) -> Vec<u8> {
    TreeRow::Undo.key(&window.to_be_bytes())
}

/// The prefix of every [`undo`] row.
pub fn undo_prefix() -> Vec<u8> {
    TreeRow::Undo.prefix().to_vec()
}

/// The window and committed row an [`undo`] key names; `None` for any
/// other key.
pub fn undo_entry(key: &[u8]) -> Option<(u64, &[u8])> {
    let rest = key.strip_prefix(&TreeRow::Undo.prefix())?;
    let (window, row) = rest.split_first_chunk::<8>()?;
    is_committed(row).then(|| (u64::from_be_bytes(*window), row))
}

/// The agent's root at the window `window`'s cut, and the cut's version,
/// once the cut's build is done: node-local, kept for the two latest cuts.
pub fn cut_root(window: u64) -> Vec<u8> {
    TreeRow::CutRoot.key(&window.to_be_bytes())
}

/// The prefix of every [`cut_root`] row.
pub fn cut_roots() -> Vec<u8> {
    TreeRow::CutRoot.prefix().to_vec()
}

/// The window a [`cut_root`] key names; `None` for any other key.
pub fn cut_root_entry(key: &[u8]) -> Option<u64> {
    window_of(&TreeRow::CutRoot.prefix(), key)
}

/// A pending request's rows and their proof at the cut of window `window`,
/// the one it was asked in: node-local, written in the commit that marks
/// the cut built.
pub fn cut_proof(id: RequestId, window: u64) -> Vec<u8> {
    TreeRow::CutProof.key(&[&request_id(id)[..], &window.to_be_bytes()].concat())
}

/// The prefix of the [`cut_proof`] row of request `id`.
pub fn cut_proofs_of(id: RequestId) -> Vec<u8> {
    TreeRow::CutProof.key(&request_id(id))
}

/// The prefix of every [`cut_proof`] row.
pub fn cut_proofs() -> Vec<u8> {
    TreeRow::CutProof.prefix().to_vec()
}

/// The request and window a [`cut_proof`] key names; `None` for any other
/// key.
pub fn cut_proof_entry(key: &[u8]) -> Option<(RequestId, u64)> {
    let rest = key.strip_prefix(&TreeRow::CutProof.prefix())?;
    let (id, window) = rest.split_first_chunk::<16>()?;
    Some((request_of(id), u64::from_be_bytes(window.try_into().ok()?)))
}

/// The last window whose root at its cut the agent reported to its
/// space's representative, and the representative's id
/// ([`crate::batch::Input::Report`]): replicated, written by the report's
/// step. A report of that window or an earlier one sends nothing, and a
/// `Closed` comes only from that agent.
pub fn reported() -> Vec<u8> {
    Row::Reported.prefix().to_vec()
}

/// The representative's close of the window `window` as the agent holds
/// it ([`crate::served::ClosedRow`]): the representative's root at its cut
/// of the window, and the agent's row's salt and path there. Replicated,
/// written by the step of the representative's `Closed`; a second one for
/// the window is ignored.
pub fn closed(window: u64) -> Vec<u8> {
    key(&[&Row::Closed.prefix(), &window.to_be_bytes()])
}

/// The prefix of every [`closed`] row, in window order.
pub fn closed_prefix() -> Vec<u8> {
    Row::Closed.prefix().to_vec()
}

/// The first and last of the windows the latest recording cut. Replicated,
/// written by apply with the cuts: the rows of earlier windows lie no
/// further back than `CUT_KEEP` before its first.
pub fn cut_mark() -> Vec<u8> {
    Row::CutMark.prefix().to_vec()
}

/// The latest window a read waits on: one asked in it at a cut
/// ([`crate::abi::Op::AttestAt`]), or, at the space's representative, an
/// agent's report of it. Replicated, written by those steps; apply records
/// the cut of the window the agent's batch-time mark lies in only when it
/// is this one or an earlier ([`crate::apply`]).
pub fn reading() -> Vec<u8> {
    Row::Reading.prefix().to_vec()
}

/// A row of a window's close that did not decode, moved aside by the step
/// that read it, under its own key: its bytes, the decoded value's when it
/// was stored whole, else as stored. Replicated; the step goes on as if the
/// row were absent, and the node alerts.
pub fn quarantined(row: &[u8]) -> Vec<u8> {
    key(&[&Row::Quarantined.prefix(), row])
}

/// The prefix of every [`quarantined`] row.
pub fn quarantined_prefix() -> Vec<u8> {
    Row::Quarantined.prefix().to_vec()
}

/// Present when the agent records its cut, and reports its root there, at
/// every window ([`crate::batch::Admin::ReportEveryWindow`]). Replicated.
pub fn every_window() -> Vec<u8> {
    Row::EveryWindow.prefix().to_vec()
}

/// The representative's mark of the closes it has sent
/// ([`crate::batch::Input::Close`]): the window, and the last agent sent
/// its path for it. Replicated.
pub fn close_mark() -> Vec<u8> {
    Row::CloseMark.prefix().to_vec()
}

/// The last window whose root agent `agent` reported to this agent, its
/// space's representative ([`crate::batch::Body::Report`]): replicated,
/// written by the report's step. A report of that window or an earlier
/// one stores nothing.
pub fn reports(agent: AgentId) -> Vec<u8> {
    key(&[&Row::Reports.prefix(), &agent.0.to_be_bytes()])
}

/// The final proof of the agent's statement `id` (a
/// `vos_statement::StatementId`) of an attest at window `window`'s cut, as
/// its prover recorded it ([`crate::batch::Input::Proven`]): the proof's
/// BLAKE2b-256, a blob in the prover's store. Replicated, written by the
/// step of the first `Proven` of the id; a later one is ignored. Every
/// replica learns from it that the statement is proved, so a new leader
/// proves it again only when no replica holds the proof. Keyed by window
/// first, so the rows of windows no venue anchors any more go by prefix.
pub fn proven(window: u64, id: &[u8; 32]) -> Vec<u8> {
    key(&[&Row::Proven.prefix(), &window.to_be_bytes(), id])
}

/// The representative's close of the window `window`, node-local, written
/// by the commit that finishes its cut's build when some agent's row
/// reaches it: its root there, and the path of each agent that reported
/// the window ([`crate::served::Closing`]).
pub fn closing(window: u64) -> Vec<u8> {
    TreeRow::Closing.key(&window.to_be_bytes())
}

/// The prefix of every [`closing`] row, in window order.
pub fn closings() -> Vec<u8> {
    TreeRow::Closing.prefix().to_vec()
}

/// The window a [`closing`] key names; `None` for any other key.
pub fn closing_entry(key: &[u8]) -> Option<u64> {
    window_of(&TreeRow::Closing.prefix(), key)
}

/// The space's root `S_w` of the window `window`, as the representative's
/// close of it makes it: node-local, written by the commit that finishes
/// the representative's cut build of the window when some agent reported
/// it, the same bytes on every replica, the cut fixed by the committed
/// log. Kept for `MaxRootAge`; its leader signs only these, so a window no
/// one reported is not anchored.
pub fn anchor(window: u64) -> Vec<u8> {
    TreeRow::Anchor.key(&window.to_be_bytes())
}

/// The prefix of every [`anchor`] row, in window order.
pub fn anchors() -> Vec<u8> {
    TreeRow::Anchor.prefix().to_vec()
}

/// The window an [`anchor`] key names; `None` for any other key.
pub fn anchor_entry(key: &[u8]) -> Option<u64> {
    window_of(&TreeRow::Anchor.prefix(), key)
}

/// The record of an attest at window `window`'s cut
/// ([`crate::result::Attest`]), by its digest
/// ([`crate::result::Attest::digest`]): node-local, written by the node's
/// apply of the work result that made it, kept with its witness, and
/// dropped once the window's roots age past `MaxRootAge`; the same rows on
/// every replica, so a replica that installs a snapshot holds them. The
/// prover reads its jobs from these.
pub fn attested(window: u64, digest: &[u8; 32]) -> Vec<u8> {
    TreeRow::Attested.key(&[&window.to_be_bytes()[..], digest].concat())
}

/// The key the [`attested`] rows of window `window` and later follow, in
/// window order.
pub fn attested_from(window: u64) -> Vec<u8> {
    TreeRow::Attested.key(&window.to_be_bytes())
}

/// The prefix of every [`attested`] row.
pub fn attested_prefix() -> Vec<u8> {
    TreeRow::Attested.prefix().to_vec()
}

/// The window and digest an [`attested`] key names; `None` for any other
/// key.
pub fn attested_entry(key: &[u8]) -> Option<(u64, [u8; 32])> {
    let rest = key.strip_prefix(&TreeRow::Attested.prefix())?;
    let (window, digest) = rest.split_first_chunk::<8>()?;
    Some((u64::from_be_bytes(*window), digest.try_into().ok()?))
}

/// The window a [`closed`] key names; `None` for any other key.
pub fn closed_entry(key: &[u8]) -> Option<u64> {
    window_of(&Row::Closed.prefix(), key)
}

/// The window a key of `prefix` then the window alone names; `None` for
/// any other key.
fn window_of(prefix: &[u8], key: &[u8]) -> Option<u64> {
    let rest = key.strip_prefix(prefix)?;
    Some(u64::from_be_bytes(rest.try_into().ok()?))
}

/// A request's id in a key: its workflow, then its await's counter.
fn request_id(id: RequestId) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&id.workflow.0.to_be_bytes());
    bytes[8..].copy_from_slice(&id.awaits.to_be_bytes());
    bytes
}

/// The request id [`request_id`] wrote.
fn request_of(bytes: &[u8; 16]) -> RequestId {
    let ([workflow, awaits], _) = bytes.as_chunks::<8>() else {
        unreachable!("16 bytes are two words")
    };
    RequestId {
        workflow: WorkflowId(u64::from_be_bytes(*workflow)),
        awaits: u64::from_be_bytes(*awaits),
    }
}
