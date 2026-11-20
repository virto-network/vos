//! The kit's own calls on the device set, from any install (a fresh one
//! too): the set read, a device removed (a lost phone left powered, whose
//! background `alive` would cancel every restore, §3.5 rule 7), and a
//! contest resolved (rule 5). Each is signed by the kit entered and found
//! at the agent the kit's index names, its evidence posted under the kit's
//! key; the call as signed is kept before it leaves, so a call whose
//! evidence was lost has it posted when the kit calls again.

use ed25519_dalek::Signer as _;
use vos_abi::Encode;
use vos_abi::ids::MethodId;
use vos_wire::homes;
use vos_wire::ingress::CallMessage;
use vos_wire::personal::{
    AdminClass, Attached, Body, DeviceView, Entry, KitKind, OpState, Operation, PersonalError,
    Recorded, Standing, method,
};

use super::link::{AgentLink, Signer, answer};
use super::set::{Device, evidence};
use super::{
    Error, Host, Kept, KitCall, Personal, Posted, Prompts, WAKES, entered_kit, link, unreached,
};
use crate::job::{Kind, Notice};
use crate::kit::KitSecret;
use crate::personal::Link as _;
use crate::route::Purpose;

/// The kit calls a device keeps whose evidence it has yet to post.
const KIT_CALLS: usize = 4;

/// The device set as the kit reads it: each device, and the operations
/// open, as the chrome raises them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KitView {
    pub devices: Vec<Device>,
    pub operations: Vec<Notice>,
}

fn agent_refused(error: PersonalError) -> Error {
    Error::AgentRefused(error)
}

impl<H: Host> Personal<H> {
    /// The device set and its open operations at the agent `home`'s
    /// `Homes` names for the kit of `kind` entered: what a fresh install
    /// shows before the kit removes a device or resolves a contest.
    pub fn kit_view(
        &self,
        prompts: &dyn Prompts,
        home: Kept,
        kind: KitKind,
    ) -> Result<KitView, Error> {
        let kit = entered_kit(prompts, kind)?;
        self.with_kit(&home, &kit, None, |link, _| {
            let views: Vec<DeviceView> = link
                .query(method::DEVICES, ())
                .map_err(unreached)?
                .map_err(agent_refused)?;
            let open: Vec<(u64, Operation)> = link
                .query(method::OPERATIONS, Option::<u64>::None)
                .map_err(unreached)?
                .map_err(agent_refused)?;
            Ok(KitView {
                devices: views.into_iter().map(device).collect(),
                operations: open
                    .into_iter()
                    .map(|(index, operation)| Notice::Operation {
                        index,
                        by: operation.by,
                        kind: Kind::of(&operation.op),
                        matures: operation.matures,
                        contested: operation.state == OpState::Contested,
                        at: Some(operation.at),
                        targeted: false,
                        kit_only: false,
                    })
                    .collect(),
            })
        })
    }

    /// `device` removed by the kit of `kind` entered, at the agent
    /// `home`'s `Homes` names for it: it matures after the kit's delay
    /// unless that device vetoes it with its admin key, and its sync key
    /// alone cannot. Called again for a removal whose evidence was lost,
    /// the evidence is posted and the removal answered.
    pub fn remove_by_kit(
        &self,
        prompts: &dyn Prompts,
        home: Kept,
        kind: KitKind,
        device: u32,
    ) -> Result<Posted, Error> {
        self.by_kit(prompts, home, kind, method::REMOVE, device.encode())
    }

    /// The contest of the operation at `index` resolved by the kit of
    /// `kind` entered, at once: `upheld`, it matures and its rival is
    /// dropped; else the reverse. What fell due is settled first, so a
    /// contest a removal lifted meanwhile is refused `Uncontested`.
    pub fn resolve_by_kit(
        &self,
        prompts: &dyn Prompts,
        home: Kept,
        kind: KitKind,
        index: u64,
        upheld: bool,
    ) -> Result<Posted, Error> {
        self.by_kit(
            prompts,
            home,
            kind,
            method::RESOLVE,
            (index, upheld).encode(),
        )
    }

    /// The kit's call of `method` with `arguments`, kept as signed before
    /// it leaves, its evidence posted under the kit's key; a call of the
    /// kit's whose evidence the log does not hold posted first.
    fn by_kit(
        &self,
        prompts: &dyn Prompts,
        home: Kept,
        kind: KitKind,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<Posted, Error> {
        let kit = entered_kit(prompts, kind)?;
        self.kit_call(&kit, home, None, method, arguments)
    }

    /// [`Personal::by_kit`] with the kit entered already, at `agent` when
    /// the device knows it.
    pub(super) fn kit_call(
        &self,
        kit: &KitSecret,
        home: Kept,
        agent: Option<(u32, [u8; 32])>,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<Posted, Error> {
        let signing = kit.signing();
        let origin = signing.verifying_key().to_bytes();
        self.with_kit(&home, kit, agent, |link, identity| {
            let entries = link.log_all(0).map_err(unreached)?.map_err(agent_refused)?;
            if let Some(posted) =
                self.post_kept(link, identity, &entries, origin, method, &arguments)?
            {
                return Ok(posted);
            }
            let sign = |message: &[u8]| Ok(signing.sign(message).to_bytes());
            let mut signer = Signer::new(origin);
            let mut previous: Option<Vec<u8>> = None;
            let mut hold = |message: &[u8], signature: &[u8; 64]| {
                self.keep_kit_call(
                    identity,
                    previous.replace(message.to_vec()),
                    Some((message, signature)),
                )
                .map_err(|error| error.to_string())
            };
            let called = link
                .settled_held(&mut signer, &sign, method, arguments, &mut hold)
                .map_err(unreached)?;
            let recorded = match answer::<Recorded>(&called.outcome).map_err(super::failed)? {
                Ok(recorded) => recorded,
                Err(error) => {
                    self.keep_kit_call(identity, Some(called.message), None)?;
                    return Err(agent_refused(error));
                }
            };
            evidence(
                link,
                recorded.index,
                (&called.message, &called.signature),
                Attached {
                    welcome: None,
                    r2: None,
                },
            )?;
            self.keep_kit_call(identity, Some(called.message), None)?;
            Ok(Posted {
                index: recorded.index,
                at: recorded.at,
            })
        })
    }

    /// The evidence of each call the kit's key `origin` made at the agent
    /// `identity` that the log `entries` hold open without it, posted; each
    /// kept no more once posted, refused, settled or not in the log: the
    /// call of `method` with `arguments` among them, answered while open.
    fn post_kept(
        &self,
        link: &mut AgentLink<'_, H>,
        identity: [u8; 32],
        entries: &[(u64, Entry)],
        origin: [u8; 32],
        method: MethodId,
        arguments: &[u8],
    ) -> Result<Option<Posted>, Error> {
        // The calls this kit's key made there: another entry's key posts
        // none of them.
        let kept: Vec<KitCall> = self
            .held()
            .state
            .kit_calls
            .iter()
            .filter(|call| {
                call.identity == identity
                    && CallMessage::parse(&call.message)
                        .is_some_and(|signed| signed.session.key == origin)
            })
            .cloned()
            .collect();
        let mut answered = None;
        for call in kept {
            let Some(signed) = CallMessage::parse(&call.message) else {
                continue;
            };
            // The latest such call, while it is open: an earlier one with
            // the same arguments, settled since, is not this one.
            let found = entries.iter().rev().find(|(_, entry)| match &entry.body {
                Body::Operation { call: logged, .. } | Body::Resolve { call: logged, .. } => {
                    logged.origin == signed.session.key
                        && logged.method == signed.method.0
                        && logged.arguments == signed.arguments
                }
                _ => false,
            });
            let open = found.filter(|(index, _)| {
                !entries.iter().any(
                    |(_, other)| matches!(&other.body, Body::Settled { op, .. } if op == index),
                )
            });
            if let Some((index, entry)) = open {
                let evidenced = entries.iter().any(|(_, other)| {
                    matches!(&other.body, Body::Evidence { index: of, .. } if of == index)
                });
                let posted = match evidenced {
                    true => Ok(()),
                    false => evidence(
                        link,
                        *index,
                        (&call.message, &call.signature),
                        Attached {
                            welcome: None,
                            r2: None,
                        },
                    ),
                };
                match posted {
                    // Refused for good: kept no more, the rest go on.
                    Ok(()) | Err(Error::AgentRefused(_)) => {}
                    Err(error) => return Err(error),
                }
                if signed.method == method && signed.arguments == arguments {
                    answered = Some(Posted {
                        index: *index,
                        at: entry.at,
                    });
                }
            }
            self.keep_kit_call(identity, Some(call.message), None)?;
        }
        Ok(answered)
    }

    /// The kit calls kept at the agent `identity`: `drop` kept no more,
    /// `add` kept as signed.
    fn keep_kit_call(
        &self,
        identity: [u8; 32],
        drop: Option<Vec<u8>>,
        add: Option<(&[u8], &[u8; 64])>,
    ) -> Result<(), Error> {
        let mut held = self.held();
        let calls = &mut held.state.kit_calls;
        if let Some(message) = drop {
            calls.retain(|call| call.message != message);
        }
        if let Some((message, signature)) = add {
            if calls.len() >= KIT_CALLS {
                calls.remove(0);
            }
            calls.push(KitCall {
                identity,
                message: message.to_vec(),
                signature: *signature,
            });
        }
        let state = held.state.clone();
        self.keep(&held.light, &state)
    }

    /// `f` over a link to `agent`, or to the agent `home`'s `Homes` names
    /// for `kit` when it is not given, under
    /// the kit's key, what fell due settled first; given the agent's
    /// identity.
    fn with_kit<T>(
        &self,
        home: &Kept,
        kit: &KitSecret,
        agent: Option<(u32, [u8; 32])>,
        f: impl FnOnce(&mut AgentLink<'_, H>, [u8; 32]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.pin(home);
        let (agent, identity) = match agent {
            Some(agent) => agent,
            None => {
                let found: Option<u32> = self.home_query(
                    &home.home,
                    Purpose::Personal,
                    home.home.homes.0,
                    homes::method::FIND,
                    kit.index().encode(),
                )?;
                let agent = found.ok_or(Error::NoAgentForKit)?;
                (agent, self.identity(&home.home, agent)?)
            }
        };
        let signing = kit.signing();
        let mut session = Signer::new(signing.verifying_key().to_bytes());
        let mut link = link(
            &self.host,
            home,
            Purpose::Personal,
            (agent, identity),
            &signing,
            &mut session,
        );
        for _ in 0..WAKES {
            let woken = link.wake().map_err(unreached)?.map_err(agent_refused)?;
            if woken.settled {
                break;
            }
        }
        f(&mut link, identity)
    }
}

/// A device of the set as the kit's screen lists it.
fn device(view: DeviceView) -> Device {
    Device {
        id: view.id,
        label: String::from_utf8_lossy(&view.device.keys.label).into_owned(),
        strong: view.device.keys.class == AdminClass::Strong,
        standing: view.standing,
        seen: view.seen,
        removed: view.removal.is_some() || view.standing == Standing::Removed,
        me: false,
    }
}
