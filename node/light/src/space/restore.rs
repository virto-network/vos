//! A fresh device's restore from the kit: opened at the agent the kit's
//! index names, signed by the kit, maturing after the kit's delay unless a
//! device of the set answers `alive`; then the archive recovered and the
//! group started from what the agent holds.

use ed25519_dalek::Signer as _;
use vos_abi::Encode;
use vos_wire::homes;
use vos_wire::personal::{
    Attached, Body, DeviceView, Entry, KitKind, NewDevice, OpState, Overview, RECOVERY, Recorded,
    RecoveryView, method,
};

use super::link::{Key, Signer, answer};
use super::set::evidence;
use super::{
    Claim, Claimed, Error, Held, Host, PERSONAL, Personal, Posted, Prompts, Restoring, answered,
    entered_kit, failed, link, logged, new_kit, secret, unreached,
};
use crate::group::{Agent as GroupAgent, DeviceGroup, Restored};
use crate::personal::{Link as _, recover};
use crate::route::Purpose;

impl<H: Host> Personal<H> {
    /// A fresh device's restore from the kit of `old` at the request's
    /// home (a device out of its group leaves it first, as a fresh install): the agent the kit's index names, a new kit split for it, the
    /// restore signed by the kit. It matures after the kit's delay unless a
    /// device of the set answers `alive`; then [`Personal::restored`]. What
    /// the restore makes is kept before its call: called again with the
    /// kit, a restore cut short is resumed, its call sent if the agent
    /// never took it and its evidence posted, no new kit shown.
    pub fn restore(
        &self,
        prompts: &dyn Prompts,
        request: Claim,
        old: KitKind,
    ) -> Result<Posted, Error> {
        let mut held = self.held();
        // A device out of its group (its removal read through) restores as
        // a fresh install, as it pairs again: what it kept is left once the
        // kit is entered.
        let out = held
            .group
            .as_ref()
            .map(|group| group.course() == crate::group::Course::Out);
        if out == Some(false) {
            return Err(Error::AlreadyHeld);
        }
        let kept = request.home.clone();
        self.pin(&kept);
        let home = kept.home.clone();
        let kit = entered_kit(prompts, old)?;
        if out == Some(true) {
            self.leave(&mut held)?;
        }
        let signing = kit.signing();
        let mut session = Signer::new(signing.verifying_key().to_bytes());
        let mut resumed = match (&held.state.restoring, &held.state.home, held.state.agent) {
            (Some(_), Some(at), Some(agent)) if at.home.handle == home.handle => Some(agent),
            _ => None,
        };
        // A restore kept from before is resumed while the agent holds it
        // open; one cancelled since (an `alive`, a veto, no evidence) is
        // dropped, and a new one opened.
        let mut entries = Vec::new();
        if let Some(agent) = resumed
            && let Some(restoring) = held.state.restoring.clone()
            && restoring.signed.is_some()
        {
            let mut link = link(
                &self.host,
                &kept,
                Purpose::Personal,
                agent,
                &signing,
                &mut session,
            );
            entries = logged(&mut link, 0)?;
            if restore_cancelled(&entries, &restoring.arguments) {
                held.state.restoring = None;
                held.state.home = None;
                held.state.agent = None;
                self.keep(&held.light, &held.state)?;
                resumed = None;
                entries.clear();
            }
        }
        let agent = match resumed {
            Some(agent) => agent,
            None => {
                // A claim under way holds the home and agent it claims.
                if crate::home::Claim::pending(held.light.store())
                    .map_err(failed)?
                    .is_some()
                {
                    let home = held
                        .state
                        .home
                        .as_ref()
                        .map_or([0; 32], |at| at.home.handle);
                    return Err(Error::ClaimElsewhere { home });
                }
                let found: Option<u32> = self.home_query(
                    &home,
                    Purpose::Personal,
                    home.homes.0,
                    homes::method::FIND,
                    kit.index().encode(),
                )?;
                let agent = found.ok_or(Error::NoAgentForKit)?;
                let agent = (agent, self.identity(&home, agent)?);
                // Every prompt that can refuse before the new kit is shown.
                let source = self.source(prompts, &mut held)?;
                let secret = secret(prompts, &source, &home.handle)?;
                let device = self.device(&mut held, prompts, &home, &secret, &request.label)?;
                let kit = new_kit(prompts, request.kit, &kept)?;
                // The home, the agent and the restore are the device's in
                // the split's batch.
                let mut next = held.state.clone();
                next.home = Some(kept.clone());
                next.agent = Some(agent);
                next.label = request.label;
                crate::group::restoring(
                    held.light.store(),
                    &[kit.key()],
                    &GroupAgent {
                        identity: agent.1,
                        instance: PERSONAL,
                    },
                    |split| {
                        next.restoring =
                            Some(Restoring::new(&device, &split.kit, kit.key(), *split.r2()));
                        next.rows()
                    },
                )
                .map_err(failed)?;
                self.adopt(&mut held, next);
                agent
            }
        };
        let mut link = link(
            &self.host,
            &kept,
            Purpose::Personal,
            agent,
            &signing,
            &mut session,
        );
        let restoring = held.state.restoring.clone().ok_or(Error::NoSpace)?;
        if entries.is_empty() && restoring.signed.is_some() {
            entries = logged(&mut link, 0)?;
        }
        let taken = entries.iter().find_map(|(index, entry)| match &entry.body {
            Body::Operation { call, matures, .. }
                if call.method == method::RESTORE.0 && call.arguments == restoring.arguments =>
            {
                Some((
                    Posted {
                        index: *index,
                        at: entry.at,
                    },
                    *matures,
                ))
            }
            _ => None,
        });
        let matures = taken.as_ref().map(|(_, matures)| *matures);
        let taken = taken.map(|(posted, _)| posted);
        let (posted, message, signature) = match (taken, &restoring.signed) {
            (Some(posted), Some((message, signature))) => (posted, message.clone(), *signature),
            _ => {
                let sign = |message: &[u8]| Ok(signing.sign(message).to_bytes());
                let mut kit_signer = Signer::new(signing.verifying_key().to_bytes());
                // The call as signed is kept before it leaves, so a
                // restart finds it in the log and posts its evidence.
                let mut hold = |message: &[u8], signature: &[u8; 64]| {
                    if let Some(restoring) = held.state.restoring.as_mut() {
                        restoring.signed = Some((message.to_vec(), *signature));
                    }
                    self.keep(&held.light, &held.state)
                        .map_err(|error| error.to_string())
                };
                let called = link
                    .settled(
                        &mut Key::Lent(&mut kit_signer, &sign),
                        method::RESTORE,
                        restoring.arguments.clone(),
                        &mut hold,
                    )
                    .map_err(unreached)?;
                let recorded = answer::<Recorded>(&called.outcome)
                    .map_err(failed)?
                    .map_err(Error::AgentRefused)?;
                let posted = Posted {
                    index: recorded.index,
                    at: recorded.at,
                };
                (posted, called.message, called.signature)
            }
        };
        let evidenced = entries.iter().any(|(_, entry)| {
            matches!(&entry.body, Body::Evidence { index, .. } if *index == posted.index)
        });
        if let (false, Some(r2)) = (evidenced, restoring.r2) {
            evidence(
                &mut link,
                posted.index,
                (&message, &signature),
                Attached {
                    welcome: None,
                    r2: Some(r2),
                },
            )?;
        }
        // When it matures, as the log took it.
        let matures = match matures {
            Some(matures) => matures,
            None => logged(&mut link, posted.index)?
                .iter()
                .find_map(|(index, entry)| match &entry.body {
                    Body::Operation { matures, .. } if *index == posted.index => Some(*matures),
                    _ => None,
                })
                .unwrap_or(0),
        };
        if let Some(restoring) = held.state.restoring.as_mut() {
            restoring.r2 = None;
            restoring.matures = matures;
        }
        self.keep(&held.light, &held.state)?;
        Ok(posted)
    }

    /// The restore matured: the kit entered again opens `R1`, the archive
    /// recovered from the recovery scope, the device's group started from
    /// what the agent holds, the personal space read back. Called again
    /// after a process killed between its writes, it finishes from the
    /// group already made.
    pub fn restored(&self, prompts: &dyn Prompts, kind: KitKind) -> Result<Claimed, Error> {
        let mut held = self.held();
        let (kept, agent) = (
            held.state.home.clone().ok_or(Error::NoSpace)?,
            held.state.agent.ok_or(Error::NoSpace)?,
        );
        let (next, r_hash) = held
            .state
            .restoring
            .as_ref()
            .map(|restoring| (restoring.next, restoring.r_hash))
            .ok_or(Error::NoRestore)?;
        let kit = entered_kit(prompts, kind)?;
        let signing = kit.signing();
        let mut kit_signer = Signer::new(signing.verifying_key().to_bytes());
        {
            let mut link = link(
                &self.host,
                &kept,
                Purpose::Personal,
                agent,
                &signing,
                &mut kit_signer,
            );
            answered(link.wake())?;
        }
        let key = held.light.sync_key().clone();
        let (view, envelopes, overview, devices, policy) = {
            // The sync key's own session: a read that fails keeps what the
            // wakes before it used.
            let mut link = link(
                &self.host,
                &kept,
                Purpose::Personal,
                agent,
                &key,
                &mut held.sync,
            );
            answered(link.settle())?;
            let view: RecoveryView = answered(link.query(method::RECOVERY, ()))?;
            let mut envelopes = Vec::new();
            loop {
                let after = envelopes
                    .last()
                    .map_or(0, |envelope: &vos_wire::personal::Envelope| {
                        envelope.position
                    });
                let page: Vec<vos_wire::personal::Envelope> =
                    answered(link.query(method::SINCE, (RECOVERY, after)))?;
                if page.is_empty() {
                    break;
                }
                envelopes.extend(page);
            }
            let overview: Overview = answered(link.query(method::OVERVIEW, ()))?;
            let devices: Vec<DeviceView> = answered(link.query(method::DEVICES, ()))?;
            // The log's policy, as every device of the set follows it.
            let entries = logged(&mut link, 0)?;
            let read: Vec<_> = entries
                .into_iter()
                .filter(|(index, _)| *index < overview.next)
                .collect();
            // The log as the agent's head names it, so the policy is the
            // head's log's.
            let chain = read.iter().fold([0; 32], |chain, (index, entry)| {
                vos_wire::personal::chain(&chain, *index, entry.at, &entry.body)
            });
            if read.len() as u64 != overview.next || chain != overview.chain {
                return Err(failed("the log read is not the one the agent's head names"));
            }
            let policy = crate::group::configured(&read);
            (view, envelopes, overview, devices, policy)
        };
        let archive = recover(&kit, &view, &agent.1, &envelopes).ok_or(Error::WrongKit)?;
        let device = device_of(&held, &devices)?;
        // The agent's batch time, not this device's clock: no entry after
        // goes back on it.
        let read = Restored {
            next: overview.next,
            chain: overview.chain,
            time: overview.at,
            confirmed: overview.confirmed,
            policy,
            kit: vec![next],
            r_hash,
            devices,
        };
        // A restore cut short after its group was made resumes with it:
        // the archive merged again, the restore's row cleared.
        let mut group = match held.group.take() {
            Some(group) if group.agent().identity == agent.1 => group,
            Some(other) => {
                held.group = Some(other);
                return Err(Error::AlreadyHeld);
            }
            None => DeviceGroup::restore(
                held.light.store(),
                GroupAgent {
                    identity: agent.1,
                    instance: PERSONAL,
                },
                device,
                read,
            )
            .map_err(failed)?,
        };
        group.inherit(&archive).map_err(failed)?;
        let id = group.id().unwrap_or(0);
        held.group = Some(group);
        held.state.restoring = None;
        self.keep(&held.light, &held.state)?;
        self.follow(&mut held)?;
        drop(held);
        // Its first commit re-seals the kit under a new `R`.
        self.update(prompts)?;
        Ok(Claimed {
            agent: agent.0,
            device: id,
        })
    }
}

/// This device's keys as the agent's set holds them.
fn device_of(held: &Held, devices: &[DeviceView]) -> Result<NewDevice, Error> {
    let sync = held.light.sync_key().verifying_key().to_bytes();
    devices
        .iter()
        .find(|view| view.device.keys.sync == sync)
        .map(|view| view.device.keys.clone())
        .ok_or(Error::NotInAgentSet)
}

/// Whether the restore whose arguments are `arguments` was cancelled, as
/// the log `entries` show it.
fn restore_cancelled(entries: &[(u64, Entry)], arguments: &[u8]) -> bool {
    let Some(at) = entries.iter().find_map(|(index, entry)| match &entry.body {
        Body::Operation { call, .. }
            if call.method == method::RESTORE.0 && call.arguments == arguments =>
        {
            Some(*index)
        }
        _ => None,
    }) else {
        return false;
    };
    entries.iter().any(|(_, entry)| {
        matches!(
            &entry.body,
            Body::Settled { op, state: OpState::Cancelled { .. } } if *op == at
        )
    })
}
