//! A workflow's read at a window's cut: its request recorded, then the
//! served rows checked and its kernel run on them.

use vos_pvm::refine::Machine;
use vos_wire::abi::{AttestError, Failure, Kind, cap, price};
use vos_wire::ids::{InstanceId, MethodId, ProgramHash, RequestId};
use vos_wire::records::{PendingRead, WorkflowState};
use vos_wire::result::{Attest, Attested};
use vos_wire::served::Served;
use vos_wire::{Decode, Encode, SpaceId, defaults, keys};

use super::Invocation;
use crate::memory::{kernel, parts, read};

impl Invocation<'_> {
    /// A workflow's read at the cut of the batch time's window of its
    /// instance's committed rows through attestable method φ7: its request
    /// recorded and its state while it awaits the rows, or why it is
    /// refused at once.
    pub(super) fn ask_at_cut(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        r: &[u64; 13],
    ) -> Result<Result<WorkflowState, AttestError>, Failure> {
        let awaiting = self.awaits.expect("only a workflow reads at a cut");
        let method = MethodId(r[7] as u32);
        let clock = match self.kit.space {
            Some((space, clock)) if space != SpaceId::NONE => clock,
            _ => return Ok(Err(AttestError::NoSpace)),
        };
        let Some(window) = clock.window(self.kit.time) else {
            return Ok(Err(AttestError::NoSpace));
        };
        let installed = self.kit.instances.get(&instance).ok_or(Failure::Unknown)?;
        let reading = installed
            .schema
            .method(method)
            .is_some_and(|schema| schema.kind == Kind::Reading);
        if !reading || installed.kernel(method).is_none() {
            return Ok(Err(AttestError::Unknown));
        }
        if r[9] > self.limits.attest as u64 {
            return Ok(Err(AttestError::Cap));
        }
        let arguments = read(machine, r[8], r[9], self.limits.attest)?;
        if r[11] > cap::REQUEST as u64 {
            return Ok(Err(AttestError::Reads));
        }
        let reads = read(machine, r[10], r[11], cap::REQUEST)?;
        let prefix = keys::instance_committed(instance);
        let rows = match <Vec<Vec<u8>>>::decode(&reads) {
            Ok((rows, used))
                if used == reads.len()
                    && !rows.is_empty()
                    && rows.len() <= defaults::MAX_READS
                    && rows.windows(2).all(|pair| pair[0] < pair[1])
                    && rows.iter().all(|row| {
                        row.starts_with(&prefix)
                            && keys::committed_entry(row).is_some()
                            && row.len() <= vos_tree::MAX_KEY
                    }) =>
            {
                rows
            }
            _ => return Ok(Err(AttestError::Reads)),
        };
        let request = RequestId {
            workflow: awaiting.workflow,
            awaits: awaiting.counter,
        };
        let key = keys::request(window, request);
        let value = PendingRead { instance, rows }.encode();
        self.write_bytes += key.len() + value.len();
        self.rows_written += 1;
        if self.write_bytes > self.limits.step_writes || self.rows_written > self.limits.step_rows {
            return Err(Failure::Cap);
        }
        self.frames
            .last_mut()
            .expect("a frame")
            .insert(key, Some(value));
        Ok(Ok(WorkflowState::Attesting {
            counter: awaiting.counter,
            window,
            method,
            arguments,
            deadline: clock
                .boundary(window.saturating_add(defaults::READ_WINDOWS))
                .unwrap_or(u64::MAX),
        }))
    }

    /// A workflow's read at window `window`'s cut, awaited at `request`, its
    /// rows `served` (`None`: unserved): attestable `method`'s kernel on
    /// `arguments` then the served rows, within `limit`, recorded as the
    /// step's attest. The answer the workflow resumes with, and the gas its
    /// machine pays for it: the attest's price, the kernel's gas and the
    /// check of its parts.
    pub(crate) fn at_cut(
        &mut self,
        instance: InstanceId,
        request: RequestId,
        (window, method, arguments): (u64, MethodId, &[u8]),
        served: Option<Vec<u8>>,
        limit: u64,
    ) -> (Attested, u64) {
        let Some((served, at)) = served.and_then(|served| {
            let at = self.serves(instance, window, request, &served)?;
            Some((served, at))
        }) else {
            return (Attested::Failed(AttestError::Unserved), 0);
        };
        let Some(installed) = self.kit.instances.get(&instance) else {
            return (Attested::Failed(AttestError::Unknown), 0);
        };
        let Some(program) = installed.kernel(method) else {
            return (Attested::Failed(AttestError::Unknown), 0);
        };
        if self.counted + cap::AT_CUT > self.limits.attests {
            return (Attested::Failed(AttestError::Failed), 0);
        }
        let declared = installed
            .schema
            .method(method)
            .and_then(|schema| schema.gas);
        let mut gas = limit.saturating_sub(price::ATTEST);
        for limits in [self.limits, installed.target.limits()] {
            if let Some(most) = limits.kernel_limit(declared) {
                gas = gas.min(most);
            }
        }
        let input = [arguments, &served].concat();
        let run = match kernel(program, &input, gas, self.limits.attest) {
            Ok(run) => run,
            Err((_, used)) => return (Attested::Failed(AttestError::Failed), price::ATTEST + used),
        };
        let spent = price::ATTEST + run.gas_used + price::io_hash(run.output.len());
        let Some(parts) = parts(&run.output, &run.io_hash) else {
            return (Attested::Failed(AttestError::Failed), spent);
        };
        self.counted += cap::AT_CUT;
        self.attests.push(Attest {
            program: ProgramHash::of(program),
            window: Some(at),
            witness_input: run.witness_input,
            output: parts.output.clone(),
            public_args: parts.public_args,
            roots: parts.roots,
        });
        (Attested::Done(parts.output), spent)
    }

    /// The window whose cut serves the request `request` asked in window
    /// `window` when `bytes` serve it: one [`Served`] within the target's
    /// cap, of this agent, its space, the window it was asked in or one
    /// its re-cuts moved it to, the request's instance and rows, and the
    /// close of that window the agent holds.
    fn serves(
        &self,
        instance: InstanceId,
        window: u64,
        request: RequestId,
        bytes: &[u8],
    ) -> Option<u64> {
        if bytes.len() > self.limits.served {
            return None;
        }
        let asked = self.read_state(&keys::request(window, request)).ok()??;
        let (asked, _) = PendingRead::decode(&asked).ok()?;
        let (served, used) = Served::decode(bytes).ok()?;
        let at = served.window;
        let windows = vos_wire::served::serving_windows(window, |window| {
            let moved = self.read_state(&keys::moved(window)).ok()??;
            u64::decode_exact(&moved)
        });
        if !windows.contains(&at) {
            return None;
        }
        let closed = self.read_state(&keys::closed(at)).ok()??;
        let closed = vos_wire::served::ClosedRow::decode_exact(&closed)?;
        let holds = used == bytes.len()
            && self.kit.space.map(|(space, _)| space) == Some(served.space)
            && served.agent == self.kit.agent
            && served.instance == instance
            && asked.instance == instance
            && (served.rep_root, served.rep_salt) == (closed.rep_root, closed.rep_salt)
            && served.space_path == closed.space_path
            && served.rows.iter().map(|(row, _)| row).eq(&asked.rows);
        holds.then_some(at)
    }
}
