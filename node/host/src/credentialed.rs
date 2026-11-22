//! Proven calls at ingress (`identity-and-authority.md` §5,
//! `light-node.md` §4.3): a call whose authority is a device proof of the
//! kernel its method's guard names, with no session and no signature.
//! Ingress runs every check on this replica's applied state, cheapest
//! first, each refusal its own code in check order; then, holding one of
//! the node's verification slots, verifies the proof on an executor, the
//! PoW before any decommitment. A call that passes goes to the agent's
//! leader carrying the origin the proof proved and its claim, never the
//! proof, and is answered once this replica has applied it.
//!
//! There is no bucket per scope or method for an attacker to drain: what
//! bounds the node's work is its connections and its verification budget
//! ([`crate::node::Config::verifications`]), past which a call is answered
//! `Busy` before its proof is decoded.
//!
//! **The kernel:** the stock `auth` and `owner` of the agent's credential
//! actor, whose checks run here (auth's scope, its root fresh in the
//! ring, `once`), or a device kernel of the method's own actor, whose
//! claim its handler checks at apply. Its program is one this node
//! computes from a release of the installed kernel
//! ([`vos_pvm_device::Program::from_kernel`], kept per release), its
//! io-hash the Poseidon2 `H_io` of the claim, and the claim's last 32
//! bytes the binding naming that program's id.
//!
//! **Compatibility windows** (`light-node.md` §4.4): a guard admits its
//! kernel's release and, until its date, the previous release an install
//! replaced (`Installed::window`), and the binding names which; ingress
//! admits the device formats this node verifies, the current and the
//! previous, each until its retirement ([`DEVICE_FORMATS`] or the node's
//! configured ones, with an earlier date if the agent's log sets one), and
//! verifies a proof against each release's
//! program in the proof's format. A proof of a retired release names a
//! program no guard admits (`Binding`); one of a retired format is refused
//! at once (`Format`). The call carries its format to apply, which refuses
//! one the release or the agent's log retired on every replica: a node's
//! configuration narrows what its ingress admits, never what the space
//! runs.

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use vos_abi::abi::Kind;
use vos_abi::abi::cap;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_abi::keys;
use vos_abi::records::{DeviceRelease, Installed, unstored};
use vos_abi::schema::CredentialGuard;
use vos_abi::{Decode, SpaceId};
use vos_pvm_device::{self as device, ReferenceProgram, Verifier};
use vos_wire::batch::CredentialedInput;
use vos_wire::credentials::{self, AuthClaim, Bound, OwnerClaim, Ring};
use vos_wire::defaults;
use vos_wire::ingress::{CredentialRefusal, Credentialed, Rejection, Response};
use vos_wire::ingress::{DeviceWindow, FormatWindow, KernelWindow, ProgramWindow};

use crate::calls::Forwardable;
use crate::fault::{Fault, read};
use crate::lock;
use crate::node::Inner;
use crate::store::Snapshot;

/// The device formats a node admits by default, newest first, each with the
/// retirement its release set, if any: at most the current and the
/// previous (`light-node.md` §4.4), the release's, which apply holds every
/// replica to ([`defaults::DEVICE_FORMATS`]). A release that brings a new
/// format sets the previous one's to 60 days on; the operator may set any
/// earlier date in an agent's log (`Node::retire_format`).
pub const DEVICE_FORMATS: &[(u32, Option<u64>)] = defaults::DEVICE_FORMATS;
const _: () = assert!(DEVICE_FORMATS[0].0 == device::FORMAT.number);

/// A device program's place, by its release and format: computed once however many
/// requests wait on it; `None` for a release whose program cannot be
/// computed (its reference does not run, its kernel does not run on it, or
/// its run is past the device format's shape), so a request naming it
/// costs no second attempt.
type Place = Arc<smol::lock::OnceCell<Option<Arc<Verifier>>>>;

/// The device programs this node holds, their verifiers alone, by release
/// and format; and the device formats it admits, each with its release's
/// retirement.
pub(crate) struct DevicePrograms {
    programs: Mutex<HashMap<(DeviceRelease, u32), Place>>,
    formats: Vec<(u32, Option<u64>)>,
}

impl Default for DevicePrograms {
    fn default() -> Self {
        Self::admitting(DEVICE_FORMATS).expect("the release's formats")
    }
}

impl DevicePrograms {
    /// None held yet, admitting `formats`, newest first: `None` unless they
    /// are one or two, distinct, each one this binary verifies.
    pub(crate) fn admitting(formats: &[(u32, Option<u64>)]) -> Option<Self> {
        let known = formats
            .iter()
            .all(|(format, _)| device::format(*format).is_some());
        let distinct = formats
            .iter()
            .enumerate()
            .all(|(at, (format, _))| formats[..at].iter().all(|(other, _)| other != format));
        (known && distinct && (1..=2).contains(&formats.len())).then(|| Self {
            programs: Mutex::default(),
            formats: formats.to_vec(),
        })
    }

    /// Keeps `programs`, each by its release, in the device format: an
    /// install's, computed before its entry is queued.
    pub(crate) fn pin(&self, programs: Vec<(DeviceRelease, Verifier)>) {
        let mut held = lock(&self.programs);
        for (release, program) in programs {
            let format = program.format().number;
            held.insert((release, format), Arc::new(Some(Arc::new(program)).into()));
        }
    }

    /// The place of `release`'s program in `format`, made empty if it has
    /// none.
    fn place(&self, release: DeviceRelease, format: u32) -> Place {
        Arc::clone(lock(&self.programs).entry((release, format)).or_default())
    }

    /// The device formats admitted at `now` in an agent whose log retires
    /// each at `logged`'s date, if any, newest first, each with its
    /// retirement, if one is set.
    pub(crate) fn formats(
        &self,
        now: u64,
        logged: impl Fn(u32) -> Option<u64>,
    ) -> Vec<FormatWindow> {
        self.formats
            .iter()
            .copied()
            .map(|(format, released)| FormatWindow {
                format,
                retires_ms: released.into_iter().chain(logged(format)).min(),
            })
            .filter(|window| window.retires_ms.is_none_or(|date| date > now))
            .collect()
    }
}

/// What the checks before the binding found: the space, the guard, and
/// the window of releases of the kernel the guard names, newest first.
struct Front {
    space: SpaceId,
    guard: CredentialGuard,
    /// The kernel the guard names, a method of its actor.
    kernel: MethodId,
    window: Vec<DeviceRelease>,
    /// The node's clock the expiry was checked at, which the root's
    /// freshness is judged at too.
    now: u64,
}

/// A verification's place among those in flight, given back when the
/// verification ends, however it ends: it goes with the executor's job, so
/// a request cancelled while its proof is verified holds its place until
/// the job is done.
pub(crate) type Verifying = crate::Held<Arc<AtomicUsize>>;

/// A proven call that passed every check but the proof's: the program and
/// io-hash it is verified against, and the input the log carries once it
/// verifies.
struct Checked {
    program: Arc<Verifier>,
    io: [u8; 32],
    proof: Vec<u8>,
    input: CredentialedInput,
}

/// Whether the proof in `bytes` proves `io` under `program`. A malformed
/// proof that panics the verifier proves nothing.
fn verifies(program: &Verifier, io: &[u8; 32], bytes: &[u8]) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        program.verify(io, bytes).is_ok()
    }))
    .unwrap_or(false)
}

/// Why a check refused: a code, or the node could not read its state.
enum Refused {
    Code(CredentialRefusal),
    Unavailable,
}

impl From<CredentialRefusal> for Refused {
    fn from(code: CredentialRefusal) -> Self {
        Refused::Code(code)
    }
}

impl From<Fault> for Refused {
    fn from(_: Fault) -> Self {
        Refused::Unavailable
    }
}

impl From<fjall::Error> for Refused {
    fn from(_: fjall::Error) -> Self {
        Refused::Unavailable
    }
}

impl From<Refused> for Response {
    fn from(refused: Refused) -> Self {
        match refused {
            Refused::Code(code) => Response::Rejected(Rejection::Credential(code)),
            Refused::Unavailable => Response::Unavailable,
        }
    }
}

impl Inner {
    /// A proven call to `agent`, as ingress takes it: checked, then
    /// verified, then run at the agent's leader, here or forwarded. `large`,
    /// its body's place if the transport held one, goes with the proof once
    /// it is verified: a call waiting to apply holds neither.
    pub(crate) async fn credentialed(
        self: &Arc<Self>,
        agent: AgentId,
        call: Credentialed,
        large: Option<crate::api::LargePlace>,
    ) -> Response {
        let run = match self.present(agent) {
            Ok(run) => run,
            Err(error) => return error.into(),
        };
        // The kernel's programs, once every check before the binding has
        // passed: each computed from its release the first time.
        let front = match self.front(&self.store.snapshot(), agent, &call) {
            Ok(front) => front,
            Err(refused) => return refused.into(),
        };
        let mut programs = Vec::with_capacity(front.window.len());
        for release in &front.window {
            match self.device_program(*release, call.format).await {
                Ok(program) => programs.push((*release, program)),
                Err(refused) => return refused.into(),
            }
        }
        if programs.iter().all(|(_, program)| program.is_none()) {
            return Response::Rejected(Rejection::Credential(CredentialRefusal::Kind));
        }
        // The lookups awaited, and the state may have moved (an install, a
        // guard, a retirement): the rest is checked on the state as it is
        // now, against the releases the programs are of.
        let snapshot = self.store.snapshot();
        let front = match self.front(&snapshot, agent, &call) {
            Ok(front) => front,
            Err(refused) => return refused.into(),
        };
        let Checked {
            program,
            io,
            proof,
            input,
        } = match self.check(&snapshot, front, agent, call, programs) {
            Ok(checked) => checked,
            Err(refused) => return refused.into(),
        };
        let Some(place) = Verifying::take(
            Arc::clone(&self.calls.verifying),
            self.settings.verifications,
        ) else {
            return Response::Busy;
        };
        let stats = Arc::clone(&self.stats);
        let queued = Instant::now();
        let verified = self
            .offload(move || {
                let started = Instant::now();
                stats.credential_queue.took(started - queued);
                let verified = verifies(&program, &io, &proof);
                stats.credential.took(started.elapsed());
                drop((place, proof, large));
                verified
            })
            .await;
        match verified {
            Some(true) => {}
            Some(false) => {
                return Response::Rejected(Rejection::Credential(CredentialRefusal::Proof));
            }
            None => return Response::Unavailable,
        }
        if let Err(error) = self.settled(agent).await {
            return error.into();
        }
        // Here if this replica leads, else at the leader, and on through
        // leader changes until it is answered.
        self.forward(&run, agent, Forwardable::Credentialed(input))
            .await
    }

    /// The device program of `release` in device format `format`: computed
    /// on an executor from the stored kernel and reference the first time,
    /// one computation however many requests wait on it, then kept; `None`,
    /// kept too, for a release whose program cannot be computed from its
    /// bytes in that format (its shape, its runs). A program this replica
    /// does not hold yet, any other failure, or an executor gone, is
    /// `Unavailable`, retryable, and not kept. `format` is one the node
    /// admits, which ingress checks first.
    async fn device_program(
        &self,
        release: DeviceRelease,
        format: u32,
    ) -> Result<Option<Arc<Verifier>>, Refused> {
        device::format(format).ok_or(Refused::Code(CredentialRefusal::Format))?;
        let place = self.calls.devices.place(release, format);
        let blobs = self.blobs.clone();
        place
            .get_or_try_init(|| async move {
                self.offload(move || {
                    let blob = |hash: [u8; 32]| {
                        blobs.get(&hash).ok().flatten().ok_or(Refused::Unavailable)
                    };
                    let (kernel, reference) = (blob(release.kernel.0)?, blob(release.reference.0)?);
                    let program = device::Program::from_kernel(
                        format,
                        &kernel,
                        ReferenceProgram(&reference),
                        release.headroom,
                    );
                    match program {
                        Ok(program) => Ok(Some(Arc::new(program.verifier()))),
                        Err(error) if error.is_of_the_kernel() => Ok(None),
                        Err(_) => Err(Refused::Unavailable),
                    }
                })
                .await
                .ok_or(Refused::Unavailable)?
            })
            .await
            .cloned()
    }

    /// The device window of `instance` of `agent` as this replica's applied
    /// state and this node hold it: the device formats it admits now, and
    /// for each device kernel the programs its guard admits, newest first,
    /// each release's in every format admitted, newest first, each with its
    /// retirement (`Kind::Devices`). `None` for an instance
    /// not installed; a release whose program cannot be computed is left
    /// out, and one this node cannot compute yet (a blob it does not hold)
    /// marks its kernel's window `unavailable`.
    pub(crate) async fn device_window(
        &self,
        agent: AgentId,
        instance: InstanceId,
    ) -> Option<DeviceWindow> {
        let now = (self.clock)();
        let snapshot = self.store.snapshot();
        let installed = installed(&snapshot, agent, instance).ok()??;
        let formats = self
            .calls
            .devices
            .formats(now, |format| logged(&snapshot, agent, format));
        let mut kernels = Vec::new();
        for method in &installed.schema.methods {
            if method.kind != Kind::Device {
                continue;
            }
            let retires = |release: &DeviceRelease| {
                installed
                    .previous
                    .iter()
                    .find(|previous| previous.method == method.id && previous.release == *release)
                    .map(|previous| previous.retires_ms)
            };
            let (mut programs, mut unavailable) = (Vec::new(), false);
            for release in installed.window(method.id, now) {
                for format in &formats {
                    match self.device_program(release, format.format).await {
                        Ok(Some(program)) => programs.push(ProgramWindow {
                            id: program.id().0,
                            format: format.format,
                            retires_ms: retires(&release),
                        }),
                        Ok(None) => {}
                        Err(_) => unavailable = true,
                    }
                }
            }
            kernels.push(KernelWindow {
                method: method.id,
                programs,
                unavailable,
            });
        }
        Some(DeviceWindow { formats, kernels })
    }

    /// The checks before the binding, in order, on `snapshot`: the space,
    /// the format, the sizes, the expiry, the method's guard, and the claim
    /// and the kernel: a stock kernel's claim of its length, and the
    /// kernel installed with a window of releases, which it returns.
    fn front(
        &self,
        snapshot: &Snapshot,
        agent: AgentId,
        call: &Credentialed,
    ) -> Result<Front, Refused> {
        let space = read::<SpaceId>(snapshot, agent, &keys::space())?
            .filter(|space| *space != SpaceId::NONE)
            .ok_or(CredentialRefusal::NoSpace)?;
        let now = (self.clock)();
        let logged = read::<u64>(snapshot, agent, &keys::format_retired(call.format))?;
        if !self
            .calls
            .devices
            .formats(now, |format| logged.filter(|_| format == call.format))
            .iter()
            .any(|window| window.format == call.format)
        {
            return Err(CredentialRefusal::Format.into());
        }
        if call.proof.len() > device::MAX_PROOF_BYTES
            || call.claim.len() > cap::CLAIM
            || call.arguments.len() > cap::REQUEST - cap::CLAIM
        {
            return Err(CredentialRefusal::Size.into());
        }
        if call.expires_ms < now || call.expires_ms > now + defaults::CREDENTIAL_HORIZON_MS {
            return Err(CredentialRefusal::Expiry { now }.into());
        }
        let record = installed(snapshot, agent, call.instance)?.ok_or(CredentialRefusal::Method)?;
        let guard = record
            .schema
            .method(call.method)
            .and_then(|method| method.credential.as_deref().cloned())
            .ok_or(CredentialRefusal::Method)?;
        let shaped = match guard {
            CredentialGuard::Auth { .. } => call.claim.len() == AuthClaim::BYTES,
            CredentialGuard::Owner => call.claim.len() == OwnerClaim::BYTES,
            CredentialGuard::Kernel { .. } => credentials::claim_binding(&call.claim).is_some(),
        };
        if !shaped {
            return Err(CredentialRefusal::Kind.into());
        }
        // A stock kernel is the credential actor's; a kernel guard's, the
        // method's own actor's.
        let (name, stock) = guard.kernel();
        let kernels = match stock {
            false => record,
            true => read::<InstanceId>(snapshot, agent, &keys::credentials())?
                .map(|actor| installed(snapshot, agent, actor))
                .transpose()?
                .flatten()
                .ok_or(CredentialRefusal::Kind)?,
        };
        let (kernel, window) = device_window(&kernels, name, now).ok_or(CredentialRefusal::Kind)?;
        Ok(Front {
            space,
            guard,
            kernel,
            window,
            now,
        })
    }

    /// Every check of `call` after `front`'s, in order, on `snapshot`,
    /// this replica's applied state, which `front` was checked on;
    /// `programs` the releases and programs the proof may be verified
    /// against ([`Inner::device_program`]), which must still be in the
    /// guard's window: the binding names the one it is.
    fn check(
        &self,
        snapshot: &Snapshot,
        front: Front,
        agent: AgentId,
        call: Credentialed,
        programs: Vec<(DeviceRelease, Option<Arc<Verifier>>)>,
    ) -> Result<Checked, Refused> {
        let Front {
            space,
            guard,
            kernel,
            window,
            now,
        } = front;
        // An install or a retirement between the programs' lookup and this
        // snapshot: a release no longer in the window is not admitted, and
        // one new to it was not looked up, so the call is asked again.
        if !window
            .iter()
            .all(|release| programs.iter().any(|(held, _)| held == release))
        {
            return Err(Refused::Unavailable);
        }
        // A release whose program cannot be computed admits no proof; the
        // window's others still do.
        let admitted = programs
            .into_iter()
            .filter(|(release, _)| window.contains(release))
            .filter_map(|(release, program)| Some((release, program?)))
            .collect::<Vec<_>>();
        if admitted.is_empty() {
            return Err(CredentialRefusal::Kind.into());
        }
        let auth = match &guard {
            CredentialGuard::Auth { name, .. } => {
                let claim = AuthClaim::decode_exact(&call.claim).ok_or(CredentialRefusal::Kind)?;
                if credentials::scope(&space, agent, call.instance, name) != claim.scope {
                    return Err(CredentialRefusal::Scope.into());
                }
                Some(claim)
            }
            _ => None,
        };
        let claimed = *credentials::claim_binding(&call.claim).ok_or(CredentialRefusal::Kind)?;
        // The binding names the program: one of the window's.
        let (binding, release, program) = admitted
            .into_iter()
            .map(|(release, program)| {
                let binding = Bound {
                    space: &space,
                    agent,
                    instance: call.instance,
                    method: call.method,
                    program: &program.id().0,
                    arguments: &call.arguments,
                    nonce: &call.nonce,
                    expires_ms: call.expires_ms,
                }
                .digest();
                (binding, release, program)
            })
            .find(|(binding, ..)| credentials::binding(binding) == claimed)
            .ok_or(CredentialRefusal::Binding)?;
        if snapshot.get(agent, &keys::binding(&binding))?.is_some() {
            return Err(CredentialRefusal::Replayed.into());
        }
        let origin = match (&guard, auth) {
            (CredentialGuard::Auth { once, .. }, Some(claim)) => {
                if *once
                    && snapshot
                        .get(agent, &keys::once(&claim.scope, &claim.nullifier))?
                        .is_some()
                {
                    return Err(CredentialRefusal::Once.into());
                }
                fresh(snapshot, agent, &claim.map_root, now)?;
                Principal::Anonymous {
                    scope: claim.scope,
                    nullifier: claim.nullifier,
                }
            }
            (CredentialGuard::Owner, _) => Principal::Owner(
                OwnerClaim::decode_exact(&call.claim)
                    .ok_or(CredentialRefusal::Kind)?
                    .owner,
            ),
            _ => Principal::Kernel {
                program: program.id().0,
            },
        };
        // A claim within the cap is far under `H_io`'s bound.
        let io = device::claim_io(&call.claim).ok_or(CredentialRefusal::Proof)?;
        Ok(Checked {
            program,
            io,
            proof: call.proof,
            input: CredentialedInput {
                origin,
                instance: call.instance,
                method: call.method,
                arguments: call.arguments,
                binding,
                expires_ms: call.expires_ms,
                claim: call.claim,
                kernel,
                format: call.format,
                release,
            },
        })
    }
}

/// Device format `format`'s retirement in `agent`'s log, as `snapshot`
/// holds it; none for a row that does not read, which apply refuses.
fn logged(snapshot: &Snapshot, agent: AgentId, format: u32) -> Option<u64> {
    read::<u64>(snapshot, agent, &keys::format_retired(format))
        .ok()
        .flatten()
}

/// The window of the device kernel `name` names in `installed` at `now`:
/// a method of the `Device` kind, its release and its previous one while
/// admitted, newest first.
fn device_window(
    installed: &Installed,
    name: &[u8],
    now: u64,
) -> Option<(MethodId, Vec<DeviceRelease>)> {
    let method = installed
        .schema
        .method_id(core::str::from_utf8(name).ok()?)?;
    if installed.schema.method(method)?.kind != Kind::Device {
        return None;
    }
    let window = installed.window(method, now);
    (!window.is_empty()).then_some((method, window))
}

/// The installed record of `instance`, if it has one.
fn installed(
    snapshot: &Snapshot,
    agent: AgentId,
    instance: InstanceId,
) -> Result<Option<Installed>, Fault> {
    Ok(snapshot
        .get(agent, &keys::installed(instance))?
        .and_then(|bytes| Installed::decode_exact(unstored(&bytes)?)))
}

/// That `root` is in the credential actor's ring and fresh at `now`, the
/// node's clock the call's expiry was checked at: `RootUnknown`
/// (retryable) when the ring does not hold it or the agent has no
/// credential actor; `RootStale` when it was superseded more than
/// [`defaults::ROOT_GRACE_MS`] before. Judged by the clock, not this
/// replica's latest batch time, which an idle space leaves behind: an
/// expiry at most the horizon past it puts apply's time
/// ([`credentials::judged_at`]) no later, so apply accepts what this
/// admits.
fn fresh(snapshot: &Snapshot, agent: AgentId, root: &[u8; 32], now: u64) -> Result<(), Refused> {
    let ring = ring(snapshot, agent)?.ok_or(CredentialRefusal::RootUnknown)?;
    ring.accepts(root, now).map_err(|refusal| match refusal {
        credentials::RootRefusal::Unknown => CredentialRefusal::RootUnknown.into(),
        credentials::RootRefusal::Stale => CredentialRefusal::RootStale.into(),
    })
}

/// The ring of `agent`'s credential actor, if it has one.
pub(crate) fn ring(snapshot: &Snapshot, agent: AgentId) -> Result<Option<Ring>, Fault> {
    let Some(actor) = read::<InstanceId>(snapshot, agent, &keys::credentials())? else {
        return Ok(None);
    };
    Ok(snapshot
        .get(agent, &credentials::ring_key(actor))?
        .and_then(|bytes| Ring::decode_exact(unstored(&bytes)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    /// The device formats a node admits are one or two, distinct, each one
    /// this binary verifies; the release's are.
    #[test]
    fn the_admitted_formats_are_checked() {
        assert!(DevicePrograms::admitting(DEVICE_FORMATS).is_some());
        let previous = device::TEST_FORMAT.number;
        assert!(DevicePrograms::admitting(&[(previous, None)]).is_some());
        assert!(DevicePrograms::admitting(&[]).is_none(), "none");
        assert!(
            DevicePrograms::admitting(&[(45, None)]).is_none(),
            "unknown"
        );
        assert!(
            DevicePrograms::admitting(&[(47, None), (47, None)]).is_none(),
            "twice"
        );
        assert!(
            DevicePrograms::admitting(&[(47, None), (previous, None), (previous, Some(1))])
                .is_none(),
            "three"
        );
    }

    /// A verification takes a place while fewer than the budget hold one,
    /// and gives it back when it ends.
    #[test]
    fn the_verification_budget_is_held_and_given_back() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let first = Verifying::take(Arc::clone(&in_flight), 2).expect("a place");
        let second = Verifying::take(Arc::clone(&in_flight), 2).expect("a place");
        assert!(
            Verifying::take(Arc::clone(&in_flight), 2).is_none(),
            "the budget spent"
        );
        drop(first);
        assert!(Verifying::take(Arc::clone(&in_flight), 2).is_some());
        drop(second);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert!(
            Verifying::take(Arc::clone(&in_flight), 0).is_none(),
            "no budget, no place"
        );
    }
}
