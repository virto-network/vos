// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A matured regroup's handover (`light-node.md` §3.5): every device the
//! regroup keeps hands the regrouper its key package for the new group,
//! as a pairing's joiner hands its own, and the regrouper starts the new
//! group with them all; the kept devices join it by its Welcome, the
//! devices the regroup named are out.
//!
//! - **The handover is an inbox item for the devices** ([`Handover`]),
//!   signed by the kept device's sync key: the agent's word on an item's
//!   author is the operators', so the regrouper takes a key package only
//!   under the signature of the sync key its own log knows for that
//!   device. It is not sealed: a key package is public, and the regrouper
//!   may not follow the epoch the others seal under.
//! - **The kept device** puts it from its pass, under the sync key and
//!   with no prompt, the same package each time (kept in the state) until
//!   the new group is confirmed, its expiry moved on before it lapses.
//! - **The regrouper** starts the new group only with a handover from
//!   every device the regroup keeps, waiting [`WAIT`] for them; otherwise
//!   it holds nothing and names the devices missing.

use std::time::{Duration, Instant};

use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use vos_light::group::{Course, DeviceGroup};
use vos_wire::personal::{InboxItem, Recipient};
use vos_wire::{Decode, Encode};

use super::super::link::AgentLink;
use super::{Held, Refusal, Refused, Space, State, agent_refused, no_space, refused, unreached};
use crate::job::now_ms;

/// How long the regrouper waits for the kept devices' handovers.
const WAIT: Duration = Duration::from_secs(10);
/// The wait between two reads of the inbox.
const POLL: Duration = Duration::from_millis(500);
/// The signed message's domain, and the item id's.
const DOMAIN: &[u8] = b"vos/personal/regroup/handover";
const ITEM: &[u8] = b"vos/personal/regroup/item";

/// A kept device's key package for the new group of `regrouper`'s
/// matured regroup, the one after the confirmed epoch `epoch` (so a
/// handover to an earlier regroup is never taken for a later one), signed
/// by the device's sync key over [`Handover::message`].
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(in crate::personal) struct Handover {
    device: u32,
    regrouper: u32,
    epoch: u64,
    package: Vec<u8>,
    signature: [u8; 64],
}

/// A handover put in the inbox, and the expiry it was put with.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub(in crate::personal) struct Handed {
    handover: Handover,
    expires: u64,
}

impl Handover {
    /// What the sync key signs: the domain, the personal agent's identity,
    /// the regrouper, the epoch, the device, then its key package.
    fn message(&self, identity: &[u8; 32]) -> Vec<u8> {
        [
            DOMAIN,
            identity,
            &self.regrouper.to_be_bytes(),
            &self.epoch.to_be_bytes(),
            &self.device.to_be_bytes(),
            &self.package,
        ]
        .concat()
    }

    fn signed(
        sync: &SigningKey,
        identity: &[u8; 32],
        (regrouper, epoch): (u32, u64),
        device: u32,
        package: Vec<u8>,
    ) -> Self {
        let mut handover = Self {
            device,
            regrouper,
            epoch,
            package,
            signature: [0; 64],
        };
        handover.signature = sync.sign(&handover.message(identity)).to_bytes();
        handover
    }

    /// Whether `sync`, the set's sync key of [`Handover::device`], signed
    /// it for the agent `identity`.
    fn verifies(&self, identity: &[u8; 32], sync: &[u8; 32]) -> bool {
        ed25519_dalek::VerifyingKey::from_bytes(sync).is_ok_and(|key| {
            key.verify_strict(
                &self.message(identity),
                &ed25519_dalek::Signature::from_bytes(&self.signature),
            )
            .is_ok()
        })
    }

    /// Its inbox id: the first 16 bytes of `SHA-256(ITEM ‖ device ‖
    /// regrouper ‖ epoch ‖ package)`.
    fn id(&self) -> [u8; 16] {
        let hash = Sha256::new()
            .chain_update(ITEM)
            .chain_update(self.device.to_be_bytes())
            .chain_update(self.regrouper.to_be_bytes())
            .chain_update(self.epoch.to_be_bytes())
            .chain_update(&self.package)
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&hash[..16]);
        id
    }
}

/// The devices `group`'s matured regroup keeps besides this one: every
/// device of the set no removal took, as the new group must hold them.
fn kept(group: &DeviceGroup) -> Vec<(u32, [u8; 32])> {
    group
        .sync_keys()
        .into_iter()
        .filter(|(id, sync)| {
            Some(*id) != group.id() && group.author(sync).is_some_and(|(_, removed)| !removed)
        })
        .collect()
}

/// This device's handover while another device's matured regroup waits
/// for its new group, put in the inbox under the sync key: the package
/// drawn once and kept in `state`, put again each time (the agent stores
/// the same item once) with its expiry moved on in the last quarter of
/// the inbox's life; the caller keeps `state` when it changed. Answers
/// whether it handed over: a device out of the set or that cannot follow,
/// the regrouper, or one no regroup waits on, hands nothing over.
pub(in crate::personal) fn hand_over(
    link: &mut AgentLink<'_>,
    group: &mut DeviceGroup,
    state: &mut State,
    sync: &SigningKey,
) -> Result<bool, String> {
    let me = group.id();
    // A device that cannot follow takes no other device's new group, so it
    // hands nothing over and the regrouper names it missing.
    let standing = group.course() == Course::Following
        && group
            .author(&sync.verifying_key().to_bytes())
            .is_some_and(|(id, removed)| Some(id) == me && !removed);
    let (Some(regrouper), Some(me), true) = (group.regrouper(), me, standing) else {
        state.handover = None;
        return Ok(false);
    };
    if regrouper == me {
        state.handover = None;
        return Ok(false);
    }
    let regroup = (regrouper, group.confirmed());
    let identity = group.agent().identity;
    let now = link.now()?;
    let life = group.policy().inbox_ttl_ms;
    let handed = match state.handover.take() {
        Some(handed) if (handed.handover.regrouper, handed.handover.epoch) == regroup => {
            if handed.expires <= now.saturating_add(life / 4) {
                Handed {
                    expires: now.saturating_add(life / 4 * 3),
                    ..handed
                }
            } else {
                handed
            }
        }
        _ => {
            let package = group
                .regroup_package(now_ms())
                .map_err(|error| error.to_string())?;
            Handed {
                handover: Handover::signed(sync, &identity, regroup, me, package),
                expires: now.saturating_add(life / 4 * 3),
            }
        }
    };
    let arguments = (
        (Recipient::Devices, handed.handover.id()),
        (handed.expires, handed.handover.encode()),
    )
        .encode();
    state.handover = Some(handed);
    link.call::<u64>("put", arguments)?
        .map_err(|error| format!("the personal agent refused the handover: {error:?}"))?;
    Ok(true)
}

/// The handovers to `regroup` (its regrouper and the confirmed epoch it
/// starts after) in `items` that verify, the newest a device's kept, by
/// device.
fn handovers(
    items: &[InboxItem],
    identity: &[u8; 32],
    regroup: (u32, u64),
    kept: &[(u32, [u8; 32])],
) -> Vec<(u32, u64, Vec<u8>)> {
    let mut found: Vec<(u32, u64, Vec<u8>)> = Vec::new();
    for item in items {
        if item.item.to != Recipient::Devices {
            continue;
        }
        let Some(handover) = Handover::decode_exact(&item.item.bytes) else {
            continue;
        };
        let Some((_, sync)) = kept.iter().find(|(id, _)| *id == handover.device) else {
            continue;
        };
        if (handover.regrouper, handover.epoch) != regroup || !handover.verifies(identity, sync) {
            continue;
        }
        match found.iter_mut().find(|(id, ..)| *id == handover.device) {
            Some(newest) if newest.1 >= item.expires => {}
            Some(newest) => *newest = (handover.device, item.expires, handover.package),
            None => found.push((handover.device, item.expires, handover.package)),
        }
    }
    found
}

impl Space {
    /// The inbox's unexpired items, every page, read before `until`: the
    /// pages must move on in key order and hold no more than the policy's
    /// items, so a node serving anything else is refused, not followed.
    fn inbox(&self, held: &mut Held, until: Instant) -> Result<Vec<InboxItem>, Refusal> {
        let bound = held
            .group
            .as_ref()
            .ok_or_else(no_space)?
            .policy()
            .inbox_items as usize;
        let stray = || unreached("the personal agent's inbox pages do not follow its order");
        self.with_link(held, vos_light::route::Purpose::Personal, |link, _| {
            let mut items: Vec<InboxItem> = Vec::new();
            loop {
                if Instant::now() > until {
                    return Err(unreached("the personal agent's inbox was not read in time"));
                }
                let after = items.last().map(|item| (item.expires, item.id));
                let page: Vec<InboxItem> = link
                    .query("inbox", after)
                    .map_err(unreached)?
                    .map_err(agent_refused)?;
                if page.is_empty() {
                    return Ok(items);
                }
                let mut last = after;
                for item in &page {
                    let key = Some((item.expires, item.id));
                    if key <= last {
                        return Err(stray());
                    }
                    last = key;
                }
                items.extend(page);
                if items.len() > bound {
                    return Err(stray());
                }
            }
        })
    }

    /// This device's matured regroup: the key packages of every device it
    /// keeps, from their handovers, read until all are there or [`WAIT`]
    /// passed; refused then, naming the devices whose handover is missing.
    pub(super) fn handed_over(&self, held: &mut Held) -> Result<Vec<Vec<u8>>, Refusal> {
        let group = held.group.as_ref().ok_or_else(no_space)?;
        let me = group.id().ok_or_else(no_space)?;
        if group.pending() {
            return Err(refused(
                Refused::Refused,
                "a commit is undecided: sync, then commit again",
            ));
        }
        let identity = group.agent().identity;
        let regroup = (me, group.confirmed());
        let kept = kept(group);
        if kept.is_empty() {
            return Ok(Vec::new());
        }
        let until = Instant::now() + WAIT;
        loop {
            let items = self.inbox(held, until + WAIT)?;
            let mut found = handovers(&items, &identity, regroup, &kept);
            if found.len() == kept.len() {
                found.sort_by_key(|(id, ..)| *id);
                return Ok(found.into_iter().map(|(.., package)| package).collect());
            }
            if Instant::now() > until {
                let missing: Vec<u32> = kept
                    .iter()
                    .map(|(id, _)| *id)
                    .filter(|id| found.iter().all(|(got, ..)| got != id))
                    .collect();
                let labels = self.labels(held, &missing)?;
                return Err(refused(
                    Refused::Refused,
                    format!(
                        "the new group waits for the key packages of the devices this \
                         regroup keeps, and {labels} handed over none: sync on each (its \
                         background job does too), then commit again; a device that is gone is \
                         removed first, and the regroup then leaves it out"
                    ),
                ));
            }
            std::thread::sleep(POLL);
        }
    }

    /// `devices` named as the chrome shows them: each label and number.
    fn labels(&self, held: &mut Held, devices: &[u32]) -> Result<String, Refusal> {
        let views = self.views(held)?;
        Ok(devices
            .iter()
            .map(|id| {
                views.iter().find(|view| view.id == *id).map_or_else(
                    || format!("device {id}"),
                    |view| {
                        format!(
                            "\"{}\" (device {id})",
                            String::from_utf8_lossy(&view.device.keys.label)
                        )
                    },
                )
            })
            .collect::<Vec<_>>()
            .join(", "))
    }

    /// This device's handover now, as its pass makes it: whether it
    /// handed over.
    pub(super) fn hand_over_now(&self, held: &mut Held) -> Result<bool, Refusal> {
        let key = held.light.sync_key().clone();
        let before = held.state.handover.clone();
        let handed = self.with_link(held, vos_light::route::Purpose::Personal, |link, held| {
            let Held { group, state, .. } = held;
            let group = group.as_mut().ok_or_else(no_space)?;
            hand_over(link, group, state, &key).map_err(unreached)
        });
        if held.state.handover != before
            && let Err(refusal) = self.keep(&held.state)
        {
            // Not kept: the next handover draws its package again.
            held.state.handover = before;
            return Err(refusal);
        }
        handed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(handover: &Handover, expires: u64) -> InboxItem {
        InboxItem {
            expires,
            id: handover.id(),
            item: vos_wire::personal::Item {
                to: Recipient::Devices,
                from: vos_wire::personal::Author::Device(handover.device),
                bytes: handover.encode(),
            },
        }
    }

    #[test]
    fn a_handover_is_taken_only_under_its_devices_sync_key() {
        let identity = [7; 32];
        let one = SigningKey::from_bytes(&[1; 32]);
        let two = SigningKey::from_bytes(&[2; 32]);
        let kept = [
            (1, one.verifying_key().to_bytes()),
            (2, two.verifying_key().to_bytes()),
        ];
        let regroup = (0, 4);
        let good = Handover::signed(&one, &identity, regroup, 1, vec![1, 2, 3]);
        // Device 2's handover signed by device 1's key: refused.
        let forged = Handover::signed(&one, &identity, regroup, 2, vec![9]);
        let elsewhere = Handover::signed(&two, &[8; 32], regroup, 2, vec![4]);
        let another = Handover::signed(&two, &identity, (3, 4), 2, vec![5]);
        // An earlier regroup's, by the same regrouper, put again later.
        let earlier = Handover::signed(&two, &identity, (0, 2), 2, vec![7]);
        let newer = Handover::signed(&one, &identity, regroup, 1, vec![6]);
        let items = [
            item(&good, 10),
            item(&forged, 10),
            item(&elsewhere, 10),
            item(&another, 10),
            item(&earlier, 12),
            item(&newer, 11),
        ];
        assert_eq!(
            handovers(&items, &identity, regroup, &kept),
            vec![(1, 11, vec![6])],
            "the newest of device 1's; none of device 2's is this regroup's"
        );
        assert!(handovers(&items[..1], &identity, regroup, &kept[1..]).is_empty());
    }
}
