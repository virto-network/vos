//! A fresh device's restore from the kit: opened at the agent the kit's
//! index names, signed by the kit, maturing after the kit's delay unless a
//! device of the set answers `alive`; then the archive recovered and the
//! group started from what the agent holds.

use ed25519_dalek::Signer as _;
use vos_abi::Encode;
use vos_wire::homes;
use vos_wire::personal::{
    Attached, Body, DeviceView, Entry, KitKind, NewDevice, OpState, Overview, PersonalError,
    RECOVERY, Recorded, RecoveryView, method,
};

use super::link::{Signer, answer};
use super::set::evidence;
use super::{
    Claim, Claimed, Error, Held, Host, PERSONAL, Personal, Posted, Prompts, Restoring, WAKES,
    entered_kit, failed, link, new_kit, secret, unreached,
};
use crate::group::{Agent as GroupAgent, DeviceGroup, Restored};
use crate::personal::{Link as _, recover};
use crate::route::Purpose;

fn agent_refused(error: PersonalError) -> Error {
    Error::AgentRefused(error)
}

impl<H: Host> Personal<H> {
    /// A fresh device's restore from the kit of `old` at the request's
    /// home: the agent the kit's index names, a new kit split for it, the
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
        if held.group.is_some() {
            return Err(Error::AlreadyHeld);
        }
        let kept = request.home.clone();
        self.pin(&kept);
        let home = kept.home.clone();
        let kit = entered_kit(prompts, old)?;
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
            entries = link.log_all(0).map_err(unreached)?.map_err(agent_refused)?;
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
                crate::group::restoring_with(
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
                held.state = next;
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
            entries = link.log_all(0).map_err(unreached)?.map_err(agent_refused)?;
        }
        let taken = entries.iter().find_map(|(index, entry)| match &entry.body {
            Body::Operation { call, .. }
                if call.method == method::RESTORE.0 && call.arguments == restoring.arguments =>
            {
                Some(Posted {
                    index: *index,
                    at: entry.at,
                })
            }
            _ => None,
        });
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
                    .settled_held(
                        &mut kit_signer,
                        &sign,
                        method::RESTORE,
                        restoring.arguments.clone(),
                        &mut hold,
                    )
                    .map_err(unreached)?;
                let recorded = answer::<Recorded>(&called.outcome)
                    .map_err(failed)?
                    .map_err(agent_refused)?;
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
        if let Some(restoring) = held.state.restoring.as_mut() {
            restoring.r2 = None;
        }
        self.keep(&held.light, &held.state)?;
        Ok(posted)
    }

    /// The restore matured: the kit entered again opens `R1`, the archive
    /// recovered from the recovery scope, the device's group started from
    /// what the agent holds, the personal space read back.
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
            link.wake().map_err(unreached)?.map_err(agent_refused)?;
        }
        let key = held.light.sync_key().clone();
        let mut sync = held.sync;
        let (view, envelopes, overview, devices) = {
            let mut link = link(&self.host, &kept, Purpose::Personal, agent, &key, &mut sync);
            for _ in 0..WAKES {
                let woken = link.wake().map_err(unreached)?.map_err(agent_refused)?;
                if woken.settled {
                    break;
                }
            }
            let view: RecoveryView = link
                .query(method::RECOVERY, ())
                .map_err(unreached)?
                .map_err(agent_refused)?;
            let mut envelopes = Vec::new();
            loop {
                let after = envelopes
                    .last()
                    .map_or(0, |envelope: &vos_wire::personal::Envelope| {
                        envelope.position
                    });
                let page: Vec<vos_wire::personal::Envelope> = link
                    .query(method::SINCE, (RECOVERY, after))
                    .map_err(unreached)?
                    .map_err(agent_refused)?;
                if page.is_empty() {
                    break;
                }
                envelopes.extend(page);
            }
            let overview: Overview = link
                .query(method::OVERVIEW, ())
                .map_err(unreached)?
                .map_err(agent_refused)?;
            let devices: Vec<DeviceView> = link
                .query(method::DEVICES, ())
                .map_err(unreached)?
                .map_err(agent_refused)?;
            (view, envelopes, overview, devices)
        };
        held.sync = sync;
        let archive = recover(&kit, &view, &agent.1, &envelopes).ok_or(Error::WrongKit)?;
        let device = device_of(&held, &devices)?;
        let read = Restored {
            next: overview.next,
            chain: overview.chain,
            time: self.host.now(),
            confirmed: overview.confirmed,
            policy: vos_wire::personal::Policy::DEFAULT,
            kit: vec![next],
            r_hash,
            devices,
        };
        let mut group = DeviceGroup::restore(
            held.light.store(),
            GroupAgent {
                identity: agent.1,
                instance: PERSONAL,
            },
            device,
            read,
        )
        .map_err(failed)?;
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
