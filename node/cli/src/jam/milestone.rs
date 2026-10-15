//! The JAM milestone: the default agent deployed on a running PolkaJam
//! testnet, with the counter's and the shop's programs, its workflows in
//! it, as the service's preimages, and run, a package each: the programs
//! solicited, the installs, a request that writes state, a workflow's
//! start, the sweeps that resume it until it ends, and a scan; then the
//! owner reads the workflow's result through the builder.
//!
//! Every package's roots continue the chain's. The work result the chain
//! holds, read back from DA, is the one the builder simulated, and the one
//! a VOS node in process gives for the same batch, byte for byte. The
//! record lists every attempt each package took, and is written whatever
//! the outcome.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use vos_jam::builder::{MAX_INPUT, admit};
use vos_jam::chain::{MAX_REFINE_OUTPUT, slot_of};
use vos_jam::live::{Live, Node, Parameters};
use vos_jam::{Attempt, Builder, Chain, Emulated, Error, Fate, Runner, Store, Taken};
use vos_pvm::refine::PreparedProgram;
use vos_pvm_compiler::service_blob;
use vos_wire::batch::{Admin, Input};
use vos_wire::ids::{InstanceId, MethodId, Principal, ProgramHash, Session};
use vos_wire::ingress::{Call, call_message};
use vos_wire::package::{MAX_SEGMENTS, SLOT_MS, identity};
use vos_wire::records::{Workflow, WorkflowState, unstored};
use vos_wire::result::{Outcome, Step, WorkResult, digest};
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, keys};

use super::METADATA;
use super::reference::Vos;
use crate::{at, link};

#[derive(clap::Args)]
pub struct MilestoneArgs {
    /// The directory of PolkaJam's binaries, `jamt` among them.
    #[arg(long, env = "POLKAJAM")]
    pub polkajam: PathBuf,
    /// The node's JSON-RPC, `host:port`.
    #[arg(long, default_value = "localhost:19800")]
    pub rpc: String,
    /// The agent program, as built by `just build-agent`.
    #[arg(long, env = "VOS_AGENT")]
    pub agent: PathBuf,
    /// The test actors' programs, as `just build-test-actors` builds them.
    #[arg(long)]
    pub actors: PathBuf,
    /// The builder's directory: its store, the files it hands `jamt`, and
    /// the record.
    #[arg(long)]
    pub data: PathBuf,
}

/// The service's endowment: its storage deposits, preimages included.
const ENDOWMENT: u64 = 10_000_000_000;
const COUNTER: InstanceId = InstanceId(1);
const SHOP: InstanceId = InstanceId(4);
/// How long a preimage may take to become available.
const PREIMAGE_TIMEOUT: Duration = Duration::from_secs(180);
/// The sweeps the computation may take to end.
const SWEEPS: u32 = 12;

/// Run the milestone and write its record.
pub fn run(args: MilestoneArgs) -> Result<(), String> {
    let mut milestone = Milestone::new(args)?;
    let outcome = milestone.run();
    if let Err(error) = &outcome {
        milestone.note(format!("the milestone fails: {error}"));
    }
    let file = milestone.args.data.join("record.txt");
    std::fs::write(&file, &milestone.record).map_err(at(&file))?;
    println!("its record: {}", file.display());
    outcome
}

/// The test actors the agent runs, each derived once from its ELF, as a VOS
/// node derives it: the counter and the shop, its workflows in its program.
struct Actors {
    counter: vos_jam::programs::Installable,
    shop: vos_jam::programs::Installable,
}

impl Actors {
    fn derive(dir: &std::path::Path) -> Result<Self, String> {
        let actor = |name: &str| {
            let path = dir.join(format!("{name}.elf"));
            let elf = std::fs::read(&path).map_err(at(&path))?;
            vos_jam::programs::derive(&elf).map_err(at(&path))
        };
        Ok(Self {
            counter: actor("counter")?,
            shop: actor("shop")?,
        })
    }

    /// Every program, by hash: what the agent's service solicits.
    fn programs(&self) -> HashMap<[u8; 32], Vec<u8>> {
        [&self.counter, &self.shop]
            .into_iter()
            .flat_map(|package| &package.programs)
            .map(|program| (digest(program), program.clone()))
            .collect()
    }
}

/// What each step drives: the builder, its chain, the agent as both run
/// it, and the VOS node each batch runs again on.
struct Rig {
    builder: Builder,
    chain: Live,
    runner: Runner,
    vos: Vos,
}

/// The milestone's run: the testnet's node, the agent and the actors,
/// Alice's client, the attempts each package took, and the record.
struct Milestone {
    args: MilestoneArgs,
    node: Node,
    agent: Vec<u8>,
    actors: Actors,
    alice: SigningKey,
    session: Option<Session>,
    sequence: u64,
    attempts: Vec<(String, usize)>,
    record: String,
}

/// A package as it landed.
struct Ran {
    result: WorkResult,
    imports: usize,
    exports: u32,
}

impl Milestone {
    fn new(args: MilestoneArgs) -> Result<Self, String> {
        let node = Node {
            rpc: args.rpc.clone(),
            jamt: args.polkajam.join("jamt"),
            files: args.data.join("files"),
        };
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).map_err(said)?;
        Ok(Self {
            agent: link(&args.agent)?,
            actors: Actors::derive(&args.actors)?,
            args,
            node,
            alice: SigningKey::from_bytes(&seed),
            session: None,
            sequence: 0,
            attempts: Vec::new(),
            record: String::new(),
        })
    }

    /// A line of the record, printed as it is made.
    fn note(&mut self, line: impl AsRef<str>) {
        println!("{}", line.as_ref());
        writeln!(self.record, "{}", line.as_ref()).expect("a string takes it");
    }

    fn run(&mut self) -> Result<(), String> {
        std::fs::create_dir_all(&self.args.data).map_err(at(&self.args.data))?;
        let parameters = self.node.parameters().map_err(said)?;
        self.note(format!("testnet: {parameters:?}"));
        check(&parameters)?;
        let blob = service_blob(&self.agent, &METADATA);
        let code = self.args.data.join("agent.jam");
        std::fs::write(&code, &blob).map_err(at(&code))?;
        let service = self.node.create_service(&code, ENDOWMENT).map_err(said)?;
        self.note(format!(
            "service {service}: the agent, {} bytes, code hash {}",
            blob.len(),
            hex::encode(digest(&blob))
        ));
        let since = self
            .node
            .await_preimage(service, &digest(&blob), blob.len() as u64, PREIMAGE_TIMEOUT)
            .map_err(said)?;
        self.note(format!("its code available since slot {since}"));

        let store = self.args.data.join("store");
        let _ = std::fs::remove_dir_all(&store);
        let prepared =
            Arc::new(PreparedProgram::new(&self.agent).map_err(|error| format!("{error:?}"))?);
        let runner = Runner::new(prepared, service, self.actors.programs().into_values());
        let mut rig = Rig {
            builder: Builder::new(
                Store::open(&store).map_err(said)?,
                parameters.max_refine_gas,
            )
            .map_err(said)?,
            chain: Live {
                node: self.node.clone(),
                service,
            },
            runner: runner.clone(),
            vos: Vos::new(runner),
        };

        // The programs the agent runs, solicited, then provided.
        let mut solicit = Vec::new();
        let mut files = Vec::new();
        let programs = self.actors.programs();
        let mut programs: Vec<&Vec<u8>> = programs.values().collect();
        programs.sort();
        for program in programs {
            let hash = digest(program);
            let file = self
                .args
                .data
                .join(format!("{}.pvm", hex::encode(&hash[..8])));
            std::fs::write(&file, program).map_err(at(&file))?;
            solicit.push((ProgramHash(hash), program.len() as u32));
            files.push(file);
        }
        self.step(&mut rig, "solicit the programs", vec![], &solicit)?;
        for file in &files {
            self.node.provide(service, file).map_err(said)?;
        }
        for (hash, len) in &solicit {
            let since = self
                .node
                .await_preimage(service, &hash.0, u64::from(*len), PREIMAGE_TIMEOUT)
                .map_err(said)?;
            self.note(format!(
                "program {} available since slot {since}",
                hex::encode(hash.0)
            ));
        }

        let installs = self.installs()?;
        self.step(&mut rig, "install the counter and the shop", installs, &[])?;
        let increment = method(&self.actors.counter.programs[0], "increment")?;
        let fill = method(&self.actors.counter.programs[0], "fill")?;
        let calls = vec![
            self.call(service, COUNTER, increment, 5u64.encode())?,
            self.call(service, COUNTER, fill, (12u32, 8u32).encode())?,
        ];
        let ran = self.step(&mut rig, "write state", calls, &[])?;
        expect_done(&ran.result)?;
        let start = method(&self.actors.shop.programs[0], "compute")?;
        let call = self.call(service, SHOP, start, (16_000u32, 2u32).encode())?;
        let ran = self.step(&mut rig, "start the computation", vec![call], &[])?;
        // The start's step, then, as the budget allows, the workflow's first.
        let workflow = match ran.result.steps.first() {
            Some(Step::Ran(run)) => match run.outcome {
                Outcome::Started(id) => id,
                ref other => return Err(format!("the computation did not start: {other:?}")),
            },
            _ => return Err("the start did not run".into()),
        };
        let owner = Principal::Client(self.alice.verifying_key().to_bytes());
        let (mut exported, mut imported) = (ran.exports, ran.imports);
        for round in 1.. {
            let record = rig
                .builder
                .workflow(&owner, workflow)
                .map_err(said)?
                .ok_or("the workflow is gone")?;
            if let WorkflowState::Ended(_) = record.state {
                break;
            }
            if round > SWEEPS {
                return Err("the computation never ended".into());
            }
            wait_until(record.due);
            let sweep = rig
                .builder
                .sweep(now())
                .map_err(said)?
                .ok_or("no sweep due")?;
            let ran = self.step(&mut rig, &format!("sweep {round}"), vec![sweep], &[])?;
            exported += ran.exports;
            imported += ran.imports;
        }
        let keys_of = method(&self.actors.counter.programs[0], "blob_keys")?;
        let call = self.call(service, COUNTER, keys_of, ().encode())?;
        let ran = self.step(&mut rig, "scan the table", vec![call], &[])?;
        expect_done(&ran.result)?;

        // The owner's read, through the builder, against the VOS node's.
        let record = rig
            .builder
            .workflow(&owner, workflow)
            .map_err(said)?
            .ok_or("the workflow is gone")?;
        let on_vos = rig
            .vos
            .state
            .get(&keys::workflow(workflow))
            .and_then(|bytes| unstored(bytes))
            .and_then(|bytes| Workflow::decode(bytes).ok())
            .map(|(record, _)| record.state)
            .ok_or("the VOS node lacks the workflow")?;
        if record.state != on_vos {
            return Err(format!(
                "the result differs: {:?} on JAM, {on_vos:?} on VOS",
                record.state
            ));
        }
        let WorkflowState::Ended(Outcome::Done(bytes)) = &record.state else {
            return Err(format!("the computation failed: {:?}", record.state));
        };
        let digest = u64::decode(bytes)
            .map_err(|_| "a result that is no digest")?
            .0;
        self.note(format!(
            "the owner reads workflow {}: done, digest {digest:#x}, as on VOS; its pages: {exported} exported, {imported} imported",
            workflow.0
        ));
        let landed = rig.chain.landed().map_err(said)?;
        if landed.root != rig.builder.store.root().map_err(said)? {
            return Err("the chain's root is not the builder's".into());
        }
        self.note(format!(
            "the chain's root {} is the builder's",
            hex::encode(landed.root)
        ));
        self.attempts_summary();
        Ok(())
    }

    /// `inputs` run through the builder until their package lands, again on
    /// the VOS node, and recorded with every attempt they took.
    fn step(
        &mut self,
        rig: &mut Rig,
        name: &str,
        inputs: Vec<Input>,
        solicit: &[(ProgramHash, u32)],
    ) -> Result<Ran, String> {
        let before = rig.builder.store.root().map_err(said)?;
        let mut clock = || {
            let time = now();
            (time, digest(&time.to_le_bytes()))
        };
        let taken = match rig
            .builder
            .run(&mut rig.chain, &rig.runner, &inputs, &mut clock, solicit)
        {
            Ok(taken) => taken,
            Err(Error::Attempts(attempts)) => {
                self.note(format!("{name}: no package landed"));
                self.note_attempts(&attempts);
                return Err(format!("{name}: {}", Error::Attempts(attempts)));
            }
            Err(error) => return Err(format!("{name}: {error}")),
        };
        let Taken {
            prepared,
            result,
            encoded,
            exports,
            attempts,
        } = taken;
        self.note(format!(
            "{name}: package {}, slot {}",
            hex::encode(exports.package),
            slot_of(prepared.package.batch.time),
        ));
        self.note_attempts(&attempts);
        self.attempts.push((name.to_string(), attempts.len()));
        let after = rig.builder.store.root().map_err(said)?;
        let landed = rig.chain.landed().map_err(said)?;
        if prepared.package.root != before
            || landed.root != after
            || landed.exports != Some(exports)
        {
            return Err(format!("{name}: the roots do not continue the chain's"));
        }
        // The chain's work result, as its exports hold it, against VOS's.
        let on_vos = rig
            .vos
            .batch(&prepared.package.batch)
            .map_err(said)?
            .encode();
        if on_vos != encoded {
            return Err(format!(
                "{name}: the chain's work result is not the VOS node's"
            ));
        }
        // PolkaJam reports no refine gas: this is the refine's on the
        // JAM-only host, which agrees with PolkaJam's at every host call
        // the probe measured.
        let imports = rig
            .builder
            .imports(&prepared, rig.chain.segments().as_ref())
            .map_err(said)?;
        let refined = Emulated::default()
            .refine(&rig.runner, &prepared.package, imports, prepared.gas)
            .map_err(|error| format!("{name}: refined here: {error}"))?;
        let witness = &prepared.package.witness;
        self.note(format!(
            "  root {} -> {}",
            hex::encode(before),
            hex::encode(after)
        ));
        self.note(format!(
            "  {} of {} inputs; witness {} keys, {} ranges of {} rows; payload {} bytes",
            prepared.package.batch.inputs.len(),
            inputs.len(),
            witness.keys.len(),
            witness.ranges.len(),
            witness
                .ranges
                .iter()
                .map(|range| range.rows.len())
                .sum::<usize>(),
            prepared.payload.len(),
        ));
        if !prepared.skipped.is_empty() {
            self.note(format!(
                "  left out, their pages gone from DA: workflows {:?}",
                prepared.skipped
            ));
        }
        self.note(format!(
            "  imports {}, exports {} ({} pages) at segment root {}",
            prepared.segments.len(),
            exports.segments,
            exports.pages,
            hex::encode(exports.root),
        ));
        self.note(format!(
            "  work result {} bytes, read back from DA: the one simulated, and the VOS node's, byte for byte",
            encoded.len()
        ));
        let simulations = match prepared.simulations {
            1 => "1 simulation".to_string(),
            count => format!("{count} simulations"),
        };
        self.note(format!(
            "  refine {} gas, measured on our JAM-only host (PolkaJam reports none); the builder gave {}: the batch's budget {}, {} for the package's own work, after {simulations}",
            refined.gas_used,
            prepared.gas,
            prepared.package.batch.budget,
            prepared.own,
        ));
        Ok(Ran {
            result,
            imports: prepared.segments.len(),
            exports: exports.pages,
        })
    }

    /// Every attempt, with its fate and what `jamt` said of it.
    fn note_attempts(&mut self, attempts: &[Attempt]) {
        for (at, attempt) in attempts.iter().enumerate() {
            let fate = match attempt.fate {
                Fate::Landed => "landed",
                Fate::Refused => {
                    "refused: the chain's root did not move before its window closed (see the testnet's errors)"
                }
                Fate::Overtaken => "overtaken: another package landed first, and was taken",
                Fate::Superseded => {
                    "superseded: an earlier attempt's package landed late, and was taken"
                }
            };
            self.note(format!(
                "  attempt {} at slot {} ({}): {fate}; jamt: {}",
                at + 1,
                slot_of(attempt.time),
                utc(attempt.time),
                attempt.submitted
            ));
        }
    }

    /// Whether each package, the first among them, landed first time.
    fn attempts_summary(&mut self) {
        let first = self.attempts.first().map(|(_, tries)| *tries);
        self.note(match first {
            Some(1) => "the first package landed at its first attempt".to_string(),
            Some(tries) => format!("the first package landed at attempt {tries}"),
            None => "no package landed".to_string(),
        });
        let retried: Vec<String> = self
            .attempts
            .iter()
            .filter(|(_, tries)| *tries > 1)
            .map(|(name, tries)| format!("{name} ({tries})"))
            .collect();
        self.note(match retried.is_empty() {
            true => format!(
                "every one of the {} packages landed at its first attempt",
                self.attempts.len()
            ),
            false => format!(
                "packages that took more than one attempt: {}",
                retried.join(", ")
            ),
        });
    }

    /// The counter's install, and the shop's, each naming the programs
    /// derived from its ELF.
    fn installs(&self) -> Result<Vec<Input>, String> {
        let install = |instance, package: &vos_jam::programs::Installable| {
            Input::Admin(Admin::Install {
                instance,
                derivation: package.derivation.clone(),
                roles: vec![],
            })
        };
        Ok(vec![
            install(COUNTER, &self.actors.counter),
            install(SHOP, &self.actors.shop),
        ])
    }

    /// Alice's next call, signed for the agent of `service`, as the
    /// builder admits it.
    fn call(
        &mut self,
        service: u64,
        instance: InstanceId,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Result<Input, String> {
        let key = self.alice.verifying_key().to_bytes();
        let session = *self.session.get_or_insert(Session {
            key,
            name: digest(&key)[..16].try_into().expect("16 bytes"),
            t0: now(),
        });
        self.sequence += 1;
        let message = call_message(
            &identity(service),
            &session,
            self.sequence,
            instance,
            method,
            &arguments,
        );
        let call = Call {
            session,
            sequence: self.sequence,
            instance,
            method,
            arguments,
            signature: self.alice.sign(&message).to_bytes(),
        };
        admit(service, call).map_err(said)
    }
}

/// The testnet's parameters, against the agent's and its builder's.
fn check(parameters: &Parameters) -> Result<(), String> {
    let checks = [
        ("slot period", parameters.slot_period_sec * 1000 == SLOT_MS),
        (
            "refine output",
            parameters.max_report_elective_data as usize == MAX_REFINE_OUTPUT,
        ),
        ("imports", parameters.max_imports as usize == MAX_SEGMENTS),
        ("exports", parameters.max_exports as usize == MAX_SEGMENTS),
        ("input", parameters.max_input as usize >= MAX_INPUT),
    ];
    let differ: Vec<&str> = checks
        .iter()
        .filter(|(_, agree)| !agree)
        .map(|(what, _)| *what)
        .collect();
    match differ.is_empty() {
        true => Ok(()),
        false => Err(format!(
            "the testnet's {} differ from the agent's",
            differ.join(", ")
        )),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64
}

/// A time, in milliseconds since the Unix epoch, as its time of day in UTC.
fn utc(time: u64) -> String {
    let seconds = time / 1000 % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03} UTC",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        time % 1000
    )
}

/// An error, said.
fn said(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// Wait until `time`, in milliseconds since the Unix epoch, has passed.
fn wait_until(time: u64) {
    let now = now();
    if time >= now {
        std::thread::sleep(Duration::from_millis(time - now + 1));
    }
}

fn expect_done(result: &WorkResult) -> Result<(), String> {
    for step in &result.steps {
        match step {
            Step::Ran(run) if matches!(run.outcome, Outcome::Done(_)) => {}
            Step::Ran(run) => return Err(format!("a step failed: {:?}", run.outcome)),
            Step::Refused { code, .. } => return Err(format!("a step was refused: {code:?}")),
            Step::Swept { .. } => {}
        }
    }
    Ok(())
}

fn schema(program: &[u8]) -> Result<Schema, String> {
    let parsed = vos_pvm::spi::parse_standard_program(program).ok_or("not a standard program")?;
    Schema::read(&parsed.ro_data).map_err(|error| format!("{error:?}"))
}

/// The id of `program`'s method `name`.
fn method(program: &[u8], name: &str) -> Result<MethodId, String> {
    schema(program)?
        .method_id(name)
        .ok_or_else(|| format!("no method {name}"))
}
