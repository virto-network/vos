//! The poll loop: pull the channel's control chain and ciphertext
//! log forward, advancing local MLS state and the decrypted store.
//!
//! Order matters within one channel: the commit chain first (so the
//! group's epoch is as current as possible), then the message log.
//! The two replicate independently, so an envelope can still arrive
//! for an epoch ahead of the local group — the drain stops *before*
//! it (cursor untouched) and retries next tick once the chain
//! catches up.

use openmls::prelude::tls_codec::Deserialize as TlsDeserialize;
use openmls::prelude::*;
use vos::prelude::*;

use crate::clients::{ctl_commits, log_history, resolve};
use crate::mls::{join_config, snapshot_provider};
use crate::{ChannelEntry, Messenger, MsgrCtx, PlainMessage, ctl_agent_name, log_agent_name};

const PAGE_LIMIT: u32 = 16;

pub(crate) async fn tick_channels(m: &mut Messenger, ctx: &mut MsgrCtx) {
    for i in 0..m.channels.len() {
        // A frozen channel makes no progress until repaired; don't
        // spend ticks re-fetching its chain or parking its log.
        if m.channels[i].desynced {
            continue;
        }
        if let Err(e) = drain_ctl(m, i, ctx).await {
            log::debug!(
                "messenger: ctl drain for '{}' paused: {e}",
                m.channels[i].name
            );
        }
        if m.channels[i].joined
            && !m.channels[i].desynced
            && let Err(e) = drain_log(m, i, ctx).await
        {
            log::debug!(
                "messenger: log drain for '{}' paused: {e}",
                m.channels[i].name
            );
        }
    }
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
                    // A commit we cannot apply (malformed, or we are
                    // already behind). Freeze the channel pending
                    // repair instead of re-fetching this record every
                    // tick and wedging the drain forever. Other
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
                // from this Welcome: MLS staging succeeds only if it was
                // sealed to a KeyPackage we published, so trial-decryption
                // is how we recognise our own Welcome — there is no public
                // routing tag to match (the row's token is random).
                match join_from_welcome(m, i, &row.welcome) {
                    Ok(()) => {
                        // Joined; the join repositioned `next_epoch`.
                        // Restart paging from the group's own epoch on
                        // the next loop turn.
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
/// merging advanced the epoch past them) are skipped.
fn process_chain_record(
    m: &mut Messenger,
    i: usize,
    commit_body: &[u8],
    record_epoch: u64,
) -> Result<(), String> {
    let provider = m.open_mls();
    let mut group = m.load_group(&provider, &m.channels[i].name)?;
    if group.epoch().as_u64() > record_epoch {
        return Ok(());
    }
    let mls_msg = MlsMessageIn::tls_deserialize(&mut &commit_body[..])
        .map_err(|e| format!("commit deserialize failed: {e}"))?;
    let protocol = mls_msg
        .try_into_protocol_message()
        .map_err(|e| format!("commit is not a protocol message: {e}"))?;
    let processed = group
        .process_message(&provider, protocol)
        .map_err(|e| format!("commit processing failed: {e}"))?;
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => {
            group
                .merge_staged_commit(&provider, *staged)
                .map_err(|e| format!("commit merge failed: {e}"))?;
        }
        _ => return Err("control record did not contain a commit".into()),
    }
    if !group.is_active() {
        // This commit evicted us. PCS means our keys stop working
        // at this epoch; drop the dead group state so a re-invite's
        // Welcome can rebuild under the same group id, and park the
        // channel (history kept, decryption stops).
        let _ = group.delete(provider.storage());
        let entry = &mut m.channels[i];
        entry.joined = false;
        entry.removed = true;
        log::info!(
            "messenger: removed from channel '{}' at chain epoch {record_epoch}",
            entry.name
        );
    }
    m.mls_store = snapshot_provider(&provider);
    Ok(())
}

/// Join the channel's group from a Welcome addressed to us. Returns
/// `Err` when the Welcome isn't sealed to a KeyPackage we hold (the
/// caller trial-decrypts every Welcome to find ours), is malformed,
/// or carries a foreign group id.
fn join_from_welcome(m: &mut Messenger, i: usize, welcome_bytes: &[u8]) -> Result<(), String> {
    let provider = m.open_mls();
    let mls_msg = MlsMessageIn::tls_deserialize(&mut &welcome_bytes[..])
        .map_err(|e| format!("welcome deserialize failed: {e}"))?;
    let MlsMessageBodyIn::Welcome(welcome) = mls_msg.extract() else {
        return Err("control record's welcome is not a Welcome message".into());
    };
    let staged = StagedWelcome::new_from_welcome(&provider, &join_config(), welcome, None)
        .map_err(|e| format!("welcome staging failed: {e}"))?;
    let mut group = staged
        .into_group(&provider)
        .map_err(|e| format!("joining from welcome failed: {e}"))?;
    // Bind the Welcome to THIS channel: a Welcome rides channel X's
    // ctl chain but its embedded GroupId is attacker/peer-chosen.
    // Refuse one whose group isn't this channel's, so a misrouted or
    // malicious Welcome can't graft a foreign group onto the channel.
    let expected = crate::mls::group_id_for(&m.channels[i].name);
    if group.group_id().as_slice() != expected {
        let _ = group.delete(provider.storage());
        return Err("welcome's group id does not match this channel — ignoring".into());
    }
    let join_epoch = group.epoch().as_u64();

    m.mls_store = snapshot_provider(&provider);
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

        let provider = m.open_mls();
        let mut group = m.load_group(&provider, &name)?;
        let mut dirty = false;
        for row in &rows {
            let entry = &mut m.channels[i];
            // Our own envelope echoing back — already displayed at
            // send time, and MLS can't decrypt to self anyway.
            if let Some(pos) = entry.own_ids.iter().position(|id| *id == row.id) {
                entry.own_ids.remove(pos);
                advance_cursor(entry, row.lamport, row.id);
                continue;
            }
            // Pre-join history: we never held those epochs' keys.
            if row.epoch < entry.join_epoch {
                advance_cursor(entry, row.lamport, row.id);
                continue;
            }
            // From an epoch ahead of us: park until the commit
            // chain catches up. Cursor stays put.
            if row.epoch > group.epoch().as_u64() {
                if dirty {
                    m.mls_store = snapshot_provider(&provider);
                }
                return Ok(());
            }
            match decrypt_app(&provider, &mut group, &row.body) {
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
                    // send clock. Undecryptable envelopes (garbage,
                    // replay, injection) must not — otherwise one
                    // envelope with lamport u64::MAX would poison every
                    // member's `send`. See lib.rs send saturating add.
                    if row.lamport > entry.max_lamport {
                        entry.max_lamport = row.lamport;
                    }
                }
                Err(e) => {
                    // Garbage, replay, or a non-member's injection:
                    // skip permanently — MLS already refused it. The
                    // cursor advances (so we don't re-fetch it) but the
                    // send clock does NOT move.
                    log::warn!("messenger: dropping undecryptable envelope in '{name}': {e}");
                    advance_cursor(&mut m.channels[i], row.lamport, row.id);
                }
            }
        }
        if dirty {
            m.mls_store = snapshot_provider(&provider);
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

pub(crate) fn decrypt_app(
    provider: &crate::host_rand::VosProvider,
    group: &mut MlsGroup,
    body: &[u8],
) -> Result<(String, String), String> {
    let mls_msg =
        MlsMessageIn::tls_deserialize(&mut &body[..]).map_err(|e| format!("deserialize: {e}"))?;
    let protocol = mls_msg
        .try_into_protocol_message()
        .map_err(|e| format!("not a protocol message: {e}"))?;
    let processed = group
        .process_message(provider, protocol)
        .map_err(|e| format!("process: {e}"))?;
    let sender = String::from_utf8_lossy(processed.credential().serialized_content()).into_owned();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            let text = String::from_utf8_lossy(&app.into_bytes()).into_owned();
            Ok((sender, text))
        }
        _ => Err("envelope decrypted to a non-application message".into()),
    }
}
