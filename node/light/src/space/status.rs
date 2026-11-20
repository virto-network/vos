//! What the personal space is, read without a request: the UI's one read
//! ([`Personal::status`]), so a screen branches on the state rather than
//! on a flow failing.

use super::{Held, Host, Kept, Personal, failed, store_failed};
use crate::group::Course;
use crate::memberships;

/// Where the device's personal space is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// None: a claim, a pairing or a restore makes one.
    None,
    /// A claim under way: claiming at its home again finishes it.
    Claiming,
    /// Paired, and not yet added by the opener's confirmed commit.
    Joining,
    /// The device holds the group and follows it.
    Held,
    /// A restore opened: it matures at `matures` (0 before the agent's log
    /// showed it), then `restored`.
    Restoring { matures: u64 },
    /// The device is out of its group: it pairs again, or claims.
    Removed,
    /// The device cannot follow its group: it pairs again, or regroups.
    Stuck,
}

/// The personal space's state, as the device holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub phase: Phase,
    /// The home the device's agent is at.
    pub home: Option<Kept>,
    /// The agent there, and its identity.
    pub agent: Option<(u32, [u8; 32])>,
    /// The device's id in the set, once added.
    pub device: Option<u32>,
    /// The memberships owed on this device: enrollments, confirmations.
    pub owed: u32,
}

impl<H: Host> Personal<H> {
    /// The personal space's state, from what the device holds alone; while
    /// the follows a flow left for after it run and the space is held, the
    /// state that flow left (a follow that finds the device removed shows
    /// at the next read after it).
    pub fn status(&self) -> Result<Status, super::Error> {
        let held = match self.held.try_lock() {
            Ok(held) => held,
            Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                let last = self.last.lock().unwrap_or_else(|e| e.into_inner()).clone();
                match last {
                    Some(last) if self.behind() => return Ok(last),
                    _ => self.held(),
                }
            }
        };
        let status = read(&held)?;
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some(status.clone());
        Ok(status)
    }
}

pub(super) fn read(held: &Held) -> Result<Status, super::Error> {
    let phase = phase(held)?;
    let store = held.light.store();
    let owed = memberships::enrollments(store).map_err(store_failed)?.len()
        + memberships::confirmations(store)
            .map_err(store_failed)?
            .len();
    Ok(Status {
        phase,
        home: held.state.home.clone(),
        agent: held.state.agent,
        device: held.group.as_ref().and_then(|group| group.id()),
        owed: owed as u32,
    })
}

fn phase(held: &Held) -> Result<Phase, super::Error> {
    // A restore stands until `restored` clears it, its group made or not.
    if let Some(restoring) = &held.state.restoring {
        return Ok(Phase::Restoring {
            matures: restoring.matures,
        });
    }
    if let Some(group) = &held.group {
        return Ok(match group.course() {
            Course::Out => Phase::Removed,
            Course::Stuck { .. } => Phase::Stuck,
            Course::Following if group.id().is_none() || held.state.acked.is_some() => {
                Phase::Joining
            }
            Course::Following => Phase::Held,
        });
    }
    if crate::home::Claim::pending(held.light.store())
        .map_err(failed)?
        .is_some()
    {
        return Ok(Phase::Claiming);
    }
    Ok(Phase::None)
}
