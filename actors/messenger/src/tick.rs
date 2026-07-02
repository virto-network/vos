//! The poll loop: pull the channel's control chain and ciphertext
//! log forward, advancing local MLS state and the decrypted store.
//!
//! Order matters within one channel: the commit chain first (so the
//! group's epoch is as current as possible), then the message log.
//! The two replicate independently, so an envelope can still arrive
//! for an epoch ahead of the local group — the drain stops *before*
//! it (cursor untouched) and retries next tick once the chain
//! catches up.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;

use mls_rs::client_builder::MlsConfig;
use mls_rs::group::{CommitEffect, Group, ReceivedMessage};
use mls_rs::{MlsMessage, WireFormat};
use vos::prelude::*;

use crate::clients::{ctl_commits, log_history, log_stats, resolve};
use crate::store;
use crate::{ChannelEntry, Messenger, MsgrCtx, PlainMessage, ctl_agent_name, log_agent_name};

const PAGE_LIMIT: u32 = 16;

pub(crate) async fn tick_channels(m: &mut Messenger, ctx: &mut MsgrCtx) {
    for i in 0..m.channels.len() {
        let (run_ctl, run_log) =
            channel_drain_plan(m.channels[i].joined, m.channels[i].desynced);
        // Box the drain futures onto the heap: each embeds the full ctl/log
        // RPC + MLS decrypt path, so inlining both into `tick_channels`'s own
        // future would blow the small PVM stack when the future is constructed
        // (a 0xfffffff8 page fault) — even on an idle tick. Boxing keeps this
        // future pointer-small.
        if run_ctl && let Err(e) = Box::pin(drain_ctl(m, i, ctx)).await {
            log::debug!(
                "messenger: ctl drain for '{}' paused: {e}",
                m.channels[i].name
            );
        }
        if run_log && let Err(e) = Box::pin(drain_log(m, i, ctx)).await {
            log::debug!(
                "messenger: log drain for '{}' paused: {e}",
                m.channels[i].name
            );
        }
    }
}

/// Per-channel drain gating for one tick → `(run_ctl, run_log)`.
///
/// **Graceful degradation:** a *desynced* channel — a commit we cannot
/// apply (a non-member's garbage first-write, which `msg-ctl` can't reject
/// because it only ever sees ciphertext) bricked the chain at some epoch —
/// stops advancing the **ctl chain** (re-fetching that record every tick makes
/// no progress, and the first-writer-wins chain has lost that epoch for good)
/// but KEEPS draining its **message log**. The group is frozen at its last
/// good epoch, so `drain_log` decrypts everything it still holds keys for and
/// [`plan_row`] parks anything stamped at or beyond the unreachable epoch — the
/// channel degrades to READ-ONLY at the last good epoch instead of going dark.
/// (Membership changes stay refused in `commit_chain_op`; repair is re-create
/// or re-join.) The log drains only once joined; the ctl chain drains whether
/// joined (process records) or not (scan for our Welcome).
fn channel_drain_plan(joined: bool, desynced: bool) -> (bool, bool) {
    (!desynced, joined)
}

/// Advance the channel's view of the commit chain. Unjoined: scan
/// records for a Welcome addressed to one of our published
/// KeyPackages. Joined: process each record through MLS in chain
/// order. Also the catch-up path a losing committer runs before
/// re-issuing.
pub(crate) async fn drain_ctl(
    m: &mut Messenger,
    i: usize,
    ctx: &mut MsgrCtx,
) -> Result<(), String> {
    let name = m.channels[i].name.clone();
    let ctl_id = resolve(ctx, &ctl_agent_name(&name)).await?;
    loop {
        let from = m.channels[i].next_epoch;
        let rows = ctl_commits(ctx, ctl_id, from, PAGE_LIMIT).await?;
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            if m.channels[i].joined {
                if let Err(e) = process_chain_record(m, i, &row.commit_body, row.epoch) {
                    // A commit we cannot apply (malformed, or a non-member's
                    // garbage first-write the first-writer-wins chain can't
                    // reject). Mark the channel desynced and stop advancing
                    // the chain here — re-fetching this record every tick
                    // makes no progress, and the bad epoch is permanently the
                    // chain's winner. The channel is NOT frozen: `tick_channels`
                    // keeps draining the message log, so we degrade to
                    // read-only at the last good epoch (group stays at the
                    // epoch before this record) rather than going dark. Other
                    // members who CAN apply it are unaffected.
                    log::warn!(
                        "messenger: channel '{}' desynced at chain epoch {}: {e}",
                        m.channels[i].name,
                        row.epoch
                    );
                    m.channels[i].desynced = true;
                    m.channels[i].next_epoch = row.epoch + 1;
                    return Ok(());
                }
                m.channels[i].next_epoch = row.epoch + 1;
            } else if !row.welcome.is_empty() {
                // We don't yet hold this channel's group. Try to join
                // from this Welcome: MLS join succeeds only if it was
                // sealed to a KeyPackage we published, so trial-decryption
                // is how we recognise our own Welcome — there is no public
                // routing tag to match (the row's token is random).
                match join_from_welcome(m, i, &row.welcome) {
                    Ok(()) => {
                        // Joined; the join repositioned `next_epoch`. Seat
                        // the authenticated frontier on the join watermark
                        // before draining so pre-join history is skipped,
                        // not parked (see [`seat_join_frontier`]). Restart
                        // paging from the group's own epoch next turn.
                        seat_join_frontier(m, i, ctx).await?;
                        break;
                    }
                    Err(e) => {
                        // Not sealed to us (or malformed) — someone
                        // else's join. Skip it and keep scanning.
                        log::debug!(
                            "messenger: welcome at chain epoch {} not for us: {e}",
                            row.epoch
                        );
                        m.channels[i].next_epoch = row.epoch + 1;
                    }
                }
            } else {
                // Someone else's membership change from before our
                // join — history we'll never hold keys for.
                m.channels[i].next_epoch = row.epoch + 1;
            }
        }
    }
}

/// Process one commit record against the local group. Records the
/// group already incorporated (our own merged commits included —
/// applying advanced the epoch past them) are skipped. mls-rs
/// auto-applies a processed commit (no separate merge step) and
/// short-circuits re-processing our own committed epoch, so chain
/// replay is idempotent.
fn process_chain_record(
    m: &mut Messenger,
    i: usize,
    commit_body: &[u8],
    record_epoch: u64,
) -> Result<(), String> {
    let (binding, space_id) = (m.binding()?, m.space_id_array()?);
    let stores = crate::mls::open_stores(&m.mls_store);
    let client = crate::mls::build_bound_client(&binding, space_id, &m.csprng_seed, &stores)?;
    let mut group = crate::mls::load_group(&client, &m.channels[i].name)?;
    if group.current_epoch() > record_epoch {
        return Ok(());
    }
    let msg = MlsMessage::from_bytes(commit_body)
        .map_err(|e| format!("commit deserialize failed: {e:?}"))?;
    let received = group
        .process_incoming_message(msg)
        .map_err(|e| format!("commit processing failed: {e:?}"))?;
    let evicted = match received {
        // A processed commit is applied in place; inspect its effect to
        // learn whether it evicted us (mls-rs has no `is_active`).
        ReceivedMessage::Commit(desc) => matches!(desc.effect, CommitEffect::Removed { .. }),
        _ => return Err("control record did not contain a commit".into()),
    };
    if evicted {
        // This commit evicted us. PCS means our keys stop working at this
        // epoch; drop the dead group state so a re-invite's Welcome can
        // rebuild under the same group id, and park the channel (history
        // kept, decryption stops). Our key schedule was NOT advanced for
        // this commit, so nothing to persist beyond the deletion.
        stores
            .group_state
            .delete_group(&crate::mls::group_id_for(&m.channels[i].name));
        m.mls_store = store::snapshot(&stores);
        let entry = &mut m.channels[i];
        entry.joined = false;
        entry.removed = true;
        log::info!(
            "messenger: removed from channel '{}' at chain epoch {record_epoch}",
            entry.name
        );
    } else {
        group
            .write_to_storage()
            .map_err(|e| format!("persisting applied commit failed: {e:?}"))?;
        m.mls_store = store::snapshot(&stores);
    }
    Ok(())
}

/// Join the channel's group from a Welcome addressed to us. Returns
/// `Err` when the Welcome isn't sealed to a KeyPackage we hold (the
/// caller trial-decrypts every Welcome to find ours), is malformed,
/// or carries a foreign group id.
fn join_from_welcome(m: &mut Messenger, i: usize, welcome_bytes: &[u8]) -> Result<(), String> {
    let (binding, space_id) = (m.binding()?, m.space_id_array()?);
    let stores = crate::mls::open_stores(&m.mls_store);
    let client = crate::mls::build_bound_client(&binding, space_id, &m.csprng_seed, &stores)?;
    let msg = MlsMessage::from_bytes(welcome_bytes)
        .map_err(|e| format!("welcome deserialize failed: {e:?}"))?;
    if msg.wire_format() != WireFormat::Welcome {
        return Err("control record's welcome is not a Welcome message".into());
    }
    // Trial-decryption: join succeeds only if the Welcome was sealed to a
    // KeyPackage we hold. The ratchet tree rides in-band, so tree_data = None.
    let (group, _info) = client
        .join_group(None, &msg, None)
        .map_err(|e| format!("joining from welcome failed: {e:?}"))?;
    // Bind the Welcome to THIS channel: a Welcome rides channel X's ctl
    // chain but its embedded GroupId is attacker/peer-chosen. Refuse one
    // whose group isn't this channel's, so a misrouted or malicious Welcome
    // can't graft a foreign group onto the channel. We have NOT persisted the
    // group yet (no write_to_storage), so on mismatch we simply drop it.
    let expected = crate::mls::group_id_for(&m.channels[i].name);
    if group.group_id() != expected {
        return Err("welcome's group id does not match this channel — ignoring".into());
    }
    let join_epoch = group.current_epoch();
    let mut group = group;
    group
        .write_to_storage()
        .map_err(|e| format!("persisting joined group failed: {e:?}"))?;

    m.mls_store = store::snapshot(&stores);
    // This join consumed exactly one of our published KeyPackages.
    m.published_kp_count = m.published_kp_count.saturating_sub(1);
    let entry: &mut ChannelEntry = &mut m.channels[i];
    entry.joined = true;
    entry.removed = false;
    entry.desynced = false;
    entry.join_epoch = join_epoch;
    entry.next_epoch = join_epoch;
    log::info!(
        "messenger: joined channel '{}' at epoch {join_epoch}",
        entry.name
    );
    Ok(())
}

/// Seat the authenticated frontier (`max_lamport`) on the **join
/// watermark** — the log's current head lamport at the moment we join.
///
/// Every envelope already in the log when we join is pre-join history we
/// hold no keys for. The drain skips such rows by advancing the cursor past
/// them, but only when they sit *within* the frontier; a row stamped beyond
/// it [`Park`](RowPlan::Park)s, because beyond the frontier an undeliverable
/// row is indistinguishable from a cursor-poisoning envelope (see
/// [`plan_row`]). A fresh joiner's frontier is 0, so without this seat the
/// first real pre-join row (any `lamport > 0`) would park the drain and
/// wedge it before a single post-join message is delivered. Seating the
/// frontier on the head makes all current pre-join history skippable while
/// still parking anything a peer appends *beyond* the watermark afterwards.
/// A best-effort read: if `stats` is briefly unreachable the join still
/// stands and the next tick retries the drain.
async fn seat_join_frontier(m: &mut Messenger, i: usize, ctx: &mut MsgrCtx) -> Result<(), String> {
    let name = m.channels[i].name.clone();
    let log_id = resolve(ctx, &log_agent_name(&name)).await?;
    let head = log_stats(ctx, log_id).await?.max_lamport;
    let entry = &mut m.channels[i];
    if head > entry.max_lamport {
        entry.max_lamport = head;
    }
    Ok(())
}

/// Pull the ciphertext log forward from the cursor, decrypting App
/// envelopes into the channel's plaintext store.
async fn drain_log(m: &mut Messenger, i: usize, ctx: &mut MsgrCtx) -> Result<(), String> {
    let name = m.channels[i].name.clone();
    let log_id = resolve(ctx, &log_agent_name(&name)).await?;
    loop {
        let (cur_lamport, cur_id) = {
            let c = &m.channels[i];
            (c.cursor_lamport, c.cursor_id.clone())
        };
        let rows = log_history(ctx, log_id, cur_lamport, cur_id, PAGE_LIMIT).await?;
        if rows.is_empty() {
            return Ok(());
        }

        let (binding, space_id) = (m.binding()?, m.space_id_array()?);
        let stores = crate::mls::open_stores(&m.mls_store);
        let client = crate::mls::build_bound_client(&binding, space_id, &m.csprng_seed, &stores)?;
        let mut group = crate::mls::load_group(&client, &name)?;
        let mut dirty = false;
        // Set when we stop the drain mid-page — an envelope from an epoch
        // ahead of us, or one stamped beyond the authenticated frontier
        // (see [`plan_row`]). The cursor stays put; we persist any ratchet
        // advanced so far and retry next tick.
        let mut parked = false;
        for row in &rows {
            let entry = &mut m.channels[i];
            let own_pos = entry.own_ids.iter().position(|id| *id == row.id);
            match plan_row(
                own_pos.is_some(),
                row.epoch,
                row.lamport,
                entry.join_epoch,
                group.current_epoch(),
                entry.max_lamport,
            ) {
                // Nothing to deliver (our own echo, or pre-join history),
                // and skipping it strands no later message — advance past.
                RowPlan::SkipAdvance => {
                    if let Some(pos) = own_pos {
                        entry.own_ids.remove(pos);
                    }
                    advance_cursor(entry, row.lamport, row.id);
                }
                // From an epoch ahead of us, or stamped beyond the
                // authenticated frontier (cursor poisoning). Stop here
                // WITHOUT moving the cursor; reconsidered next tick.
                RowPlan::Park => {
                    parked = true;
                    break;
                }
                RowPlan::Decrypt => match decrypt_app(&mut group, &row.body) {
                    Ok((sender, text)) => {
                        dirty = true;
                        let entry = &mut m.channels[i];
                        entry.messages.push(PlainMessage {
                            lamport: row.lamport,
                            ts_ms: row.ts_ms,
                            sender,
                            text,
                        });
                        advance_cursor(entry, row.lamport, row.id);
                        // Only an MLS-authenticated message may raise our
                        // send clock / frontier.
                        if row.lamport > entry.max_lamport {
                            entry.max_lamport = row.lamport;
                        }
                    }
                    Err(e) => {
                        // Garbage, replay, or a non-member's injection: MLS
                        // already refused it. Skip past it only when it sits
                        // within the authenticated frontier (advancing the
                        // cursor strands nothing then); one stamped beyond
                        // the frontier parks the drain — the same poisoning
                        // guard [`plan_row`] applies to undeliverable rows.
                        // The send clock never moves for an undecryptable
                        // envelope.
                        log::warn!(
                            "messenger: dropping undecryptable envelope in '{name}': {e}"
                        );
                        if row.lamport > m.channels[i].max_lamport {
                            parked = true;
                            break;
                        }
                        advance_cursor(&mut m.channels[i], row.lamport, row.id);
                    }
                },
            }
        }
        if dirty {
            group
                .write_to_storage()
                .map_err(|e| format!("persisting decrypt ratchet failed: {e:?}"))?;
            m.mls_store = store::snapshot(&stores);
        }
        if parked {
            return Ok(());
        }
    }
}

/// Advance the pagination cursor only. The send clock
/// (`max_lamport`) is bumped separately, and exclusively from
/// MLS-authenticated messages, so untrusted envelopes can't drive
/// it (see the decrypt loop above).
fn advance_cursor(entry: &mut ChannelEntry, lamport: u64, id: [u8; 32]) {
    entry.cursor_lamport = lamport;
    entry.cursor_id = id.to_vec();
}

/// What [`drain_log`] should do with a fetched log row, decided from the
/// channel's position *before* any decryption.
#[derive(Debug, PartialEq, Eq)]
enum RowPlan {
    /// Skip this row and advance the read cursor past it: it carries
    /// nothing we will deliver (our own echo, or pre-join history) and is
    /// within the authenticated frontier, so skipping strands no later
    /// message.
    SkipAdvance,
    /// Attempt to decrypt-and-deliver this row.
    Decrypt,
    /// Stop the drain here WITHOUT advancing the cursor: the row is from an
    /// epoch we have not reached, or is stamped beyond the authenticated
    /// frontier — a cursor-poisoning attempt. Reconsidered next tick.
    Park,
}

/// The log-drain disposition + **cursor-poisoning guard**, factored out as
/// a pure function so it is unit-tested in isolation.
///
/// `max_lamport` is this member's *authenticated frontier* — only an
/// MLS-decryptable message ever raises it (enforced by [`drain_log`]).
/// Envelopes carry a sender-chosen, unbounded `lamport` (the convergent
/// CRDT sort key — `msg-log` cannot bound it without breaking replica
/// convergence). So any space member can append a validly-framed but
/// undecryptable envelope stamped `lamport = u64::MAX`. If the drain
/// advanced the read cursor onto such a row, every later message — which
/// sorts *before* it — would never be fetched again, silently suppressing
/// the channel for the whole membership. The guard: a row we will not
/// deliver may advance the cursor only when its lamport is within the
/// frontier; one stamped beyond it [`Park`](RowPlan::Park)s instead,
/// leaving the cursor at the frontier. A poison envelope is then revisited
/// for free only if real traffic ever advances the frontier past it (it
/// never can for `u64::MAX`), and real messages keep flowing because they
/// sort below it and are processed before the park. The send clock carries
/// the matching guard in `lib.rs::send`.
fn plan_row(
    is_own: bool,
    row_epoch: u64,
    row_lamport: u64,
    join_epoch: u64,
    current_epoch: u64,
    max_lamport: u64,
) -> RowPlan {
    // Our own echo: we set the frontier to its lamport at send time, so it
    // is never ahead of the frontier — always safe to skip past.
    if is_own {
        return RowPlan::SkipAdvance;
    }
    let ahead_of_frontier = row_lamport > max_lamport;
    // Pre-join history: we never held those epochs' keys, so there is
    // nothing to deliver — but it must still not poison the cursor.
    if row_epoch < join_epoch {
        return if ahead_of_frontier {
            RowPlan::Park
        } else {
            RowPlan::SkipAdvance
        };
    }
    // From an epoch ahead of our group: wait for the commit chain.
    if row_epoch > current_epoch {
        return RowPlan::Park;
    }
    RowPlan::Decrypt
}

/// Decrypt one ciphertext envelope to `(sender_nickname, text)`. The group's
/// sender ratchet advances in place (the caller persists it); a commit or any
/// non-application message is rejected.
pub(crate) fn decrypt_app<C: MlsConfig>(
    group: &mut Group<C>,
    body: &[u8],
) -> Result<(String, String), String> {
    let msg = MlsMessage::from_bytes(body).map_err(|e| format!("deserialize: {e:?}"))?;
    let received = group
        .process_incoming_message(msg)
        .map_err(|e| format!("process: {e:?}"))?;
    match received {
        ReceivedMessage::ApplicationMessage(app) => {
            // Display name only (non-authoritative — the cryptographic identity
            // is the credential's PeerId, validated by the identity provider).
            // Read it from the VOS credential, falling back to a bare
            // BasicCredential identifier for any non-bound leaf.
            let sender = group
                .member_at_index(app.sender_index)
                .and_then(|m| {
                    crate::identity::member_binding(&m.signing_identity)
                        .map(|d| d.display_name)
                        .or_else(|| {
                            m.signing_identity
                                .credential
                                .as_basic()
                                .map(|b| String::from_utf8_lossy(b.identifier()).into_owned())
                        })
                })
                .unwrap_or_default();
            let text = String::from_utf8_lossy(app.data()).into_owned();
            Ok((sender, text))
        }
        _ => Err("envelope decrypted to a non-application message".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{RowPlan, channel_drain_plan, plan_row};

    #[test]
    fn desynced_channel_degrades_to_read_only() {
        // Healthy joined channel: both chains drain.
        assert_eq!(channel_drain_plan(true, false), (true, true));
        // Desynced joined channel: the ctl chain stops advancing, but
        // the message log KEEPS draining — read-only at the last good epoch,
        // not frozen. This is the graceful-degradation invariant.
        assert_eq!(channel_drain_plan(true, true), (false, true));
        // Unjoined healthy: only the ctl drain (scanning for our Welcome).
        assert_eq!(channel_drain_plan(false, false), (true, false));
        // Unjoined + desynced (not a reachable state, but fail safe): idle.
        assert_eq!(channel_drain_plan(false, true), (false, false));
    }

    // Channel position used by most cases: joined at epoch 2, group is at
    // epoch 5, authenticated frontier (max_lamport) at 100.
    const JOIN: u64 = 2;
    const CUR: u64 = 5;
    const FRONTIER: u64 = 100;

    fn plan(is_own: bool, epoch: u64, lamport: u64) -> RowPlan {
        plan_row(is_own, epoch, lamport, JOIN, CUR, FRONTIER)
    }

    #[test]
    fn own_echo_always_skips_even_at_max_lamport() {
        // Our own echo never poisons the cursor — we own its lamport.
        assert_eq!(plan(true, CUR, u64::MAX), RowPlan::SkipAdvance);
        assert_eq!(plan(true, 0, 1), RowPlan::SkipAdvance);
    }

    #[test]
    fn in_frontier_rows_decrypt_or_skip() {
        // A current-epoch row within the frontier is decrypted.
        assert_eq!(plan(false, CUR, FRONTIER), RowPlan::Decrypt);
        assert_eq!(plan(false, JOIN, 50), RowPlan::Decrypt);
        // Pre-join history within the frontier is skipped (cursor advances).
        assert_eq!(plan(false, JOIN - 1, 50), RowPlan::SkipAdvance);
    }

    #[test]
    fn future_epoch_parks() {
        // An epoch ahead of our group parks regardless of lamport.
        assert_eq!(plan(false, CUR + 1, 1), RowPlan::Park);
        assert_eq!(plan(false, CUR + 1, FRONTIER), RowPlan::Park);
    }

    #[test]
    fn poison_beyond_frontier_parks_not_advances() {
        // The core fix: an UNDELIVERABLE row (pre-join history here) stamped
        // beyond the authenticated frontier must PARK, never advance the
        // cursor onto it — otherwise it would strand every later message.
        assert_eq!(plan(false, JOIN - 1, FRONTIER + 1), RowPlan::Park);
        assert_eq!(plan(false, 0, u64::MAX), RowPlan::Park);
        // Exactly at the frontier is still within it (not "ahead").
        assert_eq!(plan(false, JOIN - 1, FRONTIER), RowPlan::SkipAdvance);
        assert_eq!(plan(false, JOIN - 1, FRONTIER + 1), RowPlan::Park);
    }

    #[test]
    fn current_epoch_poison_routes_to_decrypt_then_caller_guards() {
        // A current-epoch row beyond the frontier is handed to Decrypt; the
        // drain's decrypt-failure arm re-applies the same frontier guard, so
        // an undecryptable one parks rather than poisoning the cursor. (A
        // *decryptable* current-epoch message legitimately raises the
        // frontier, so routing it to Decrypt is correct.)
        assert_eq!(plan(false, CUR, u64::MAX), RowPlan::Decrypt);
        assert_eq!(plan(false, JOIN, FRONTIER + 1), RowPlan::Decrypt);
    }
}
