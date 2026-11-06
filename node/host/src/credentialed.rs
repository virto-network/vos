//! Credentialed calls at ingress (`identity-and-authority.md` §5): a call
//! whose authority is a credential proof, with no session and no
//! signature. Ingress runs every check on this replica's applied state,
//! cheapest first, each refusal its own code in check order; then, holding
//! one of the node's verification slots, verifies the proof on an
//! executor, the PoW before any decommitment. A call that passes goes to
//! the agent's leader carrying the origin the proof proved, never the
//! proof, and is answered once this replica has applied it.
//!
//! There is no bucket per scope or method for an attacker to drain: what
//! bounds the node's work is its connections and its verification budget
//! ([`crate::node::Config::verifications`]), past which a call is answered
//! `Busy` before its proof is decoded.
//!
//! **A device proof** (format 46, `proving.md` §8) authorizes as
//! an auth credential proof does, for a method whose auth guard names a
//! device kernel: its program is one this node computes from a release of
//! the installed kernel ([`vos_pvm_recair::device::Program::of`], kept per
//! release), its io-hash the Poseidon2 `H_io` of the request's auth words,
//! and the binding names that program's id. A guard that names no device
//! kernel takes no device proof (`Kind`).
//!
//! **Compatibility windows** (`light-node.md` §4.4): a guard admits its
//! kernel's release and, until its date, the previous release an install
//! replaced (`Installed::window`), and the binding names which; ingress
//! admits the device formats this node verifies, the current and the
//! previous, each until its retirement ([`DEVICE_FORMATS`], with the
//! operator's earlier date if it set one). A proof of a retired release
//! names a program no guard admits (`Binding`); one of a retired format is
//! refused at once (`Format`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use vos_pvm_final_verifier::credential::{self as verifier, CredentialKind};
use vos_pvm_recair::ProveError;
use vos_pvm_recair::device::{self as device, Verifier};
use vos_wire::abi::Kind;
use vos_wire::abi::cap;
use vos_wire::batch::CredentialedInput;
use vos_wire::credentials::{self, Bound, Ring};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::{CredentialPublic, CredentialRefusal, Credentialed, Rejection, Response};
use vos_wire::ingress::{DeviceWindow, FormatWindow, KernelWindow, ProgramWindow};
use vos_wire::keys;
use vos_wire::records::{DeviceRelease, Installed, unstored};
use vos_wire::schema::CredentialGuard;
use vos_wire::{Decode, Encode, SpaceId, defaults};

use crate::calls::Forwardable;
use crate::fault::{Fault, read};
use crate::lock;
use crate::node::Inner;
use crate::store::Snapshot;

/// The credential format the proof registry names, as the final verifier
/// pins it, with its proof's cap.
const CREDENTIAL: (u32, usize) = (verifier::FORMAT, verifier::MAX_PROOF_BYTES);

/// The device formats this node verifies, newest first, each with the
/// retirement its release set, if any: at most the current and the
/// previous (`light-node.md` §4.4). A release that brings a new format
/// sets the previous one's to 60 days on; the operator may set any earlier
/// date ([`DevicePrograms::retire_format`]).
pub(crate) const DEVICE_FORMATS: [(u32, Option<u64>); 1] = [(device::FORMAT.number, None)];

/// A device program's place, by its release: computed once however many
/// requests wait on it; `None` for a release whose program cannot be
/// computed (its reference does not run, its kernel does not run on it, or
/// its run is past the device format's shape), so a request naming it
/// costs no second attempt.
type Place = Arc<smol::lock::OnceCell<Option<Arc<Verifier>>>>;

/// The device programs this node holds, their verifiers alone, by release;
/// and the device formats' retirements its operator set.
#[derive(Default)]
pub(crate) struct DevicePrograms {
    programs: Mutex<HashMap<DeviceRelease, Place>>,
    retired: Mutex<HashMap<u32, u64>>,
}

impl DevicePrograms {
    /// Keeps `programs`, each by its release: an install's, computed before
    /// its entry is queued.
    pub(crate) fn pin(&self, programs: Vec<(DeviceRelease, Verifier)>) {
        let mut held = lock(&self.programs);
        for (release, program) in programs {
            held.insert(release, Arc::new(Some(Arc::new(program)).into()));
        }
    }

    /// The place of `release`'s program, made empty if it has none.
    fn place(&self, release: DeviceRelease) -> Place {
        Arc::clone(lock(&self.programs).entry(release).or_default())
    }

    /// Retires device format `format` at `at_ms`, if that is earlier than
    /// its retirement: its date kept, if this node verifies the format.
    pub(crate) fn retire_format(&self, format: u32, at_ms: u64) -> Option<u64> {
        let (_, released) = DEVICE_FORMATS
            .into_iter()
            .find(|(number, _)| *number == format)?;
        let mut retired = lock(&self.retired);
        let date = retired
            .get(&format)
            .copied()
            .into_iter()
            .chain(released)
            .chain([at_ms])
            .min()
            .expect("a date");
        retired.insert(format, date);
        Some(date)
    }

    /// The device formats admitted at `now`, newest first, each with its
    /// retirement, if one is set.
    pub(crate) fn formats(&self, now: u64) -> Vec<FormatWindow> {
        let retired = lock(&self.retired);
        DEVICE_FORMATS
            .into_iter()
            .map(|(format, released)| FormatWindow {
                format,
                retires_ms: retired
                    .get(&format)
                    .copied()
                    .into_iter()
                    .chain(released)
                    .min(),
            })
            .filter(|window| window.retires_ms.is_none_or(|date| date > now))
            .collect()
    }
}

/// What the checks before the binding found: the space, the guard, the
/// kind, and for a device proof the window of releases of the kernel its
/// guard names, newest first.
struct Front {
    space: SpaceId,
    guard: CredentialGuard,
    kind: CredentialKind,
    window: Option<Vec<DeviceRelease>>,
}

/// A verification's place among those in flight, given back when the
/// verification ends, however it ends: it goes with the executor's job, so
/// a request cancelled while its proof is verified holds its place until
/// the job is done.
pub(crate) struct Verifying(Arc<AtomicUsize>);

impl Verifying {
    /// A place, if fewer than `most` verifications are in flight.
    fn take(in_flight: &Arc<AtomicUsize>, most: usize) -> Option<Self> {
        in_flight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |held| {
                (held < most).then_some(held + 1)
            })
            .ok()
            .map(|_| Verifying(Arc::clone(in_flight)))
    }
}

impl Drop for Verifying {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A credentialed call that passed every check but the proof's: what the
/// verifier takes, and the input the log carries once it verifies.
struct Checked {
    statement: Statement,
    proof: Vec<u8>,
    input: CredentialedInput,
}

/// What a proof is verified against.
enum Statement {
    /// A credential proof of `kind` stating `words`; `None` when a word is
    /// at or above `p`, which proves nothing.
    Credential {
        kind: CredentialKind,
        words: Option<Vec<u32>>,
    },
    /// A device proof of `program` stating the io-hash `io`.
    Device {
        program: Arc<Verifier>,
        io: [u8; 32],
    },
}

impl Statement {
    /// Whether the proof in `bytes` proves it. A malformed proof that
    /// panics either verifier proves nothing.
    fn verify(&self, bytes: &[u8]) -> bool {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match self {
            Statement::Credential {
                kind,
                words: Some(words),
            } => verifier::verify_bytes(*kind, words, bytes).is_ok(),
            Statement::Credential { words: None, .. } => false,
            Statement::Device { program, io } => program.verify(io, bytes).is_ok(),
        }))
        .unwrap_or(false)
    }

    /// Whether it can be proven at all: no verification is spent on one
    /// that cannot.
    fn provable(&self) -> bool {
        !matches!(self, Statement::Credential { words: None, .. })
    }
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
    /// A credentialed call to `agent`, as ingress takes it: checked, then
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
        // A device proof's programs, once every check before the binding
        // has passed: each computed from its release the first time.
        let snapshot = self.store.snapshot();
        let front = match self.front(&snapshot, agent, &call) {
            Ok(front) => front,
            Err(refused) => return refused.into(),
        };
        let (snapshot, front, programs) = match front.window.clone() {
            None => (snapshot, front, None),
            Some(window) => {
                let mut programs = Vec::with_capacity(window.len());
                for release in &window {
                    match self.device_program(*release).await {
                        Ok(program) => programs.push((*release, program)),
                        Err(refused) => return refused.into(),
                    }
                }
                if programs.iter().all(|(_, program)| program.is_none()) {
                    return Response::Rejected(Rejection::Credential(CredentialRefusal::Kind));
                }
                // The lookups awaited, and the state may have moved (an
                // install, a guard, a retirement): the rest is checked on
                // the state as it is now, against the releases the
                // programs are of.
                let snapshot = self.store.snapshot();
                let front = match self.front(&snapshot, agent, &call) {
                    Ok(front) => front,
                    Err(refused) => return refused.into(),
                };
                (snapshot, front, Some(programs))
            }
        };
        let checked = match self.check(&snapshot, front, agent, call, programs) {
            Ok(checked) => checked,
            Err(refused) => return refused.into(),
        };
        let Checked {
            statement,
            proof,
            input,
        } = checked;
        // A word at or above p proves nothing: no verification is spent.
        if !statement.provable() {
            return Response::Rejected(Rejection::Credential(CredentialRefusal::Proof));
        }
        let Some(place) = Verifying::take(&self.calls.verifying, self.settings.verifications)
        else {
            return Response::Busy;
        };
        let stats = Arc::clone(&self.stats);
        let queued = Instant::now();
        let verified = self
            .offload(move || {
                let started = Instant::now();
                stats.credential_queue.took(started - queued);
                let verified = statement.verify(&proof);
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
        if run.agent.leading() {
            self.credentialed_call(agent, input).await
        } else {
            self.forward(&run, agent, Forwardable::Credentialed(input))
                .await
        }
    }

    /// The device program of `release`: computed on an executor from the
    /// stored kernel and reference the first time, one computation however
    /// many requests wait on it, then kept; `None`, kept too, for a release
    /// whose program cannot be computed from its bytes (its shape, its
    /// runs). A program this replica does not hold yet, any other failure,
    /// or an executor gone, is `Unavailable`, retryable, and not kept.
    async fn device_program(
        &self,
        release: DeviceRelease,
    ) -> Result<Option<Arc<Verifier>>, Refused> {
        let place = self.calls.devices.place(release);
        let blobs = self.blobs.clone();
        place
            .get_or_try_init(|| async move {
                self.offload(move || {
                    let blob = |hash: [u8; 32]| {
                        blobs.get(&hash).ok().flatten().ok_or(Refused::Unavailable)
                    };
                    let (kernel, reference) = (blob(release.kernel.0)?, blob(release.reference.0)?);
                    match device::Program::of(&kernel, &reference, release.headroom) {
                        Ok(program) => Ok(Some(Arc::new(program.verifier()))),
                        Err(error) if of_the_kernel(&error) => Ok(None),
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
    /// each with its retirement (`Kind::Devices`). `None` for an instance
    /// not installed; a release whose program cannot be computed is left
    /// out, and one this node cannot compute yet (a blob it does not hold)
    /// marks its kernel's window `unavailable`.
    pub(crate) async fn device_window(
        &self,
        agent: AgentId,
        instance: InstanceId,
    ) -> Option<DeviceWindow> {
        let now = (self.clock)();
        let installed = installed(&self.store.snapshot(), agent, instance).ok()??;
        let formats = self.calls.devices.formats(now);
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
                match self.device_program(release).await {
                    // Every program is computed under the current device
                    // format until a second one is verified.
                    Ok(Some(program)) => programs.push(ProgramWindow {
                        id: *program.id(),
                        format: device::FORMAT.number,
                        retires_ms: retires(&release),
                    }),
                    Ok(None) => {}
                    Err(_) => unavailable = true,
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
    /// the format, the sizes, the expiry, the method's guard and the kind;
    /// for a device proof, that the guard names a device kernel the
    /// instance installed, whose window of releases it returns.
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
        let device = call.format != CREDENTIAL.0;
        let cap = match device {
            false => CREDENTIAL.1,
            true if self
                .calls
                .devices
                .formats(now)
                .iter()
                .any(|window| window.format == call.format) =>
            {
                device::MAX_PROOF_BYTES
            }
            true => return Err(CredentialRefusal::Format.into()),
        };
        if call.proof.len() > cap || call.arguments.len() > cap::REQUEST {
            return Err(CredentialRefusal::Size.into());
        }
        if call.expires_ms < now || call.expires_ms > now + defaults::CREDENTIAL_HORIZON_MS {
            return Err(CredentialRefusal::Expiry { now }.into());
        }
        let installed =
            installed(snapshot, agent, call.instance)?.ok_or(CredentialRefusal::Method)?;
        let guard = installed
            .schema
            .method(call.method)
            .and_then(|method| method.credential.as_deref().cloned())
            .ok_or(CredentialRefusal::Method)?;
        let kind = match (&guard, &call.public) {
            (CredentialGuard::Auth { .. }, CredentialPublic::Auth { .. }) => CredentialKind::Auth,
            (CredentialGuard::Owner, CredentialPublic::Owner { .. }) => CredentialKind::Owner,
            _ => return Err(CredentialRefusal::Kind.into()),
        };
        // A device proof answers only a guard naming a device kernel.
        let window = match (device, &guard) {
            (false, _) => None,
            (
                true,
                CredentialGuard::Auth {
                    device: Some(name), ..
                },
            ) => Some(device_window(&installed, name, now).ok_or(CredentialRefusal::Kind)?),
            (true, _) => return Err(CredentialRefusal::Kind.into()),
        };
        Ok(Front {
            space,
            guard,
            kind,
            window,
        })
    }

    /// Every check of `call` after `front`'s, in order, on `snapshot`,
    /// this replica's applied state, which `front` was checked on;
    /// `programs` the releases and programs a device proof may be verified
    /// against ([`Inner::device_program`]), which must still be in the
    /// guard's window: the binding names the one it is.
    fn check(
        &self,
        snapshot: &Snapshot,
        front: Front,
        agent: AgentId,
        call: Credentialed,
        programs: Option<Vec<(DeviceRelease, Option<Arc<Verifier>>)>>,
    ) -> Result<Checked, Refused> {
        let Front {
            space,
            guard,
            kind,
            window,
        } = front;
        // An install or a retirement between the programs' lookup and this
        // snapshot: a release no longer in the window is not admitted, and
        // one new to it was not looked up, so the call is asked again.
        let programs = match (window, programs) {
            (None, _) => None,
            (Some(window), Some(programs))
                if window
                    .iter()
                    .all(|release| programs.iter().any(|(held, _)| held == release)) =>
            {
                // A release whose program cannot be computed admits no
                // proof; the window's others still do.
                let admitted = programs
                    .into_iter()
                    .filter(|(release, _)| window.contains(release))
                    .filter_map(|(_, program)| program)
                    .collect::<Vec<_>>();
                if admitted.is_empty() {
                    return Err(CredentialRefusal::Kind.into());
                }
                Some(admitted)
            }
            (Some(_), _) => return Err(Refused::Unavailable),
        };
        if let (CredentialGuard::Auth { name, .. }, CredentialPublic::Auth { scope, .. }) =
            (&guard, &call.public)
            && credentials::scope(&space, agent, call.instance, name) != *scope
        {
            return Err(CredentialRefusal::Scope.into());
        }
        let bound = |program: &[u8; 32]| {
            Bound {
                space: &space,
                agent,
                instance: call.instance,
                method: call.method,
                program,
                kind: call.public.kind(),
                arguments: &call.arguments,
                nonce: &call.nonce,
                expires_ms: call.expires_ms,
            }
            .digest()
        };
        // The binding names the program: a device proof's, one of the
        // window's; a credential proof's, its circuit.
        let (binding, device) = match programs {
            None => (bound(verifier::program(kind)), None),
            Some(programs) => programs
                .into_iter()
                .map(|program| (bound(program.id()), Some(program)))
                .find(|(binding, _)| credentials::binding(binding) == *call.public.binding())
                .ok_or(CredentialRefusal::Binding)?,
        };
        if credentials::binding(&binding) != *call.public.binding() {
            return Err(CredentialRefusal::Binding.into());
        }
        if snapshot.get(agent, &keys::binding(&binding))?.is_some() {
            return Err(CredentialRefusal::Replayed.into());
        }
        let root = match call.public {
            CredentialPublic::Auth {
                map_root,
                scope,
                nullifier,
                ..
            } => {
                let once = matches!(guard, CredentialGuard::Auth { once: true, .. });
                if once
                    && snapshot
                        .get(agent, &keys::once(&scope, &nullifier))?
                        .is_some()
                {
                    return Err(CredentialRefusal::Once.into());
                }
                fresh(snapshot, agent, &map_root)?;
                Some(map_root)
            }
            CredentialPublic::Owner { .. } => None,
        };
        let statement = match device {
            // A word at or above p proves nothing, whatever the kernel
            // compares; an auth statement's 129 bytes are far under
            // `H_io`'s bound.
            Some(program) => Statement::Device {
                io: call
                    .public
                    .words()
                    .and_then(|_| device::auth_io(&call.public.encode()))
                    .ok_or(CredentialRefusal::Proof)?,
                program,
            },
            None => Statement::Credential {
                kind,
                words: call.public.words(),
            },
        };
        Ok(Checked {
            statement,
            proof: call.proof,
            input: CredentialedInput {
                origin: call.public.origin(),
                instance: call.instance,
                method: call.method,
                arguments: call.arguments,
                binding,
                expires_ms: call.expires_ms,
                root,
            },
        })
    }
}

/// Whether a device program's computation failed for its kernel's bytes,
/// as it fails every time: its layout or shape, its run, its witness, the
/// wiring or the masking's layout. Any other failure may pass again.
fn of_the_kernel(error: &ProveError) -> bool {
    matches!(
        error,
        ProveError::TraceShape(_)
            | ProveError::Segment(_)
            | ProveError::Witness(_)
            | ProveError::Wiring(_)
            | ProveError::Masking(_)
    )
}

/// The window of the device kernel `name` names in `installed` at `now`:
/// a method of the `Device` kind, its release and its previous one while
/// admitted, newest first.
fn device_window(installed: &Installed, name: &[u8], now: u64) -> Option<Vec<DeviceRelease>> {
    let method = installed
        .schema
        .method_id(core::str::from_utf8(name).ok()?)?;
    if installed.schema.method(method)?.kind != Kind::Device {
        return None;
    }
    let window = installed.window(method, now);
    (!window.is_empty()).then_some(window)
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

/// That `root` is in the credential actor's ring and fresh by this
/// replica's latest applied batch time: `RootUnknown` (retryable) when the
/// ring does not hold it, the agent has no credential actor, or this
/// replica has applied no batch time yet; `RootStale` when it was
/// superseded more than [`defaults::ROOT_MAX_AGE`] before.
fn fresh(snapshot: &Snapshot, agent: AgentId, root: &[u8; 32]) -> Result<(), Refused> {
    let ring = ring(snapshot, agent)?.ok_or(CredentialRefusal::RootUnknown)?;
    let time =
        read::<u64>(snapshot, agent, &keys::batch_time())?.ok_or(CredentialRefusal::RootUnknown)?;
    ring.accepts(root, time).map_err(|refusal| match refusal {
        credentials::RootRefusal::Unknown => CredentialRefusal::RootUnknown.into(),
        credentials::RootRefusal::Stale => CredentialRefusal::RootStale.into(),
    })
}

/// The ring of `agent`'s credential actor, if it has one.
fn ring(snapshot: &Snapshot, agent: AgentId) -> Result<Option<Ring>, Fault> {
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

    /// A verification takes a place while fewer than the budget hold one,
    /// and gives it back when it ends.
    #[test]
    fn the_verification_budget_is_held_and_given_back() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let first = Verifying::take(&in_flight, 2).expect("a place");
        let second = Verifying::take(&in_flight, 2).expect("a place");
        assert!(Verifying::take(&in_flight, 2).is_none(), "the budget spent");
        drop(first);
        assert!(Verifying::take(&in_flight, 2).is_some());
        drop(second);
        assert_eq!(in_flight.load(Ordering::SeqCst), 0);
        assert!(
            Verifying::take(&in_flight, 0).is_none(),
            "no budget, no place"
        );
    }
}
