//! `vos jam testnet`: the default agent deployed on a running PolkaJam
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

mod alice;
mod record;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vos_jam::live::{Live, PolkaJam};
use vos_jam::programs::Installable;
use vos_jam::{Builder, Chain, Emulated, Error, Runner, Store, Taken};
use vos_pvm::refine::PreparedProgram;
use vos_wire::abi::cap::Target;
use vos_wire::batch::{Admin, Input};
use vos_wire::ids::{InstanceId, MethodId, ProgramHash};
use vos_wire::package::slot_of;
use vos_wire::records::{Workflow, WorkflowState, unstored};
use vos_wire::result::{Outcome, Step, WorkResult, digest};
use vos_wire::{Decode, Encode, keys};

use super::reference::Vos;
use super::{METADATA, write_service};
use crate::{at, link};
use alice::Alice;

#[derive(clap::Args)]
pub struct TestnetArgs {
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

/// Why a run failed, said at the end.
type Failed = Box<dyn std::error::Error>;

/// Run the agent on the testnet and write the run's record.
pub fn run(args: TestnetArgs) -> Result<(), String> {
    let mut testnet = Testnet::new(args)?;
    let outcome = testnet.run().map_err(|error| error.to_string());
    if let Err(error) = &outcome {
        testnet.note(format!("the run fails: {error}"));
    }
    let file = testnet.args.data.join("record.txt");
    std::fs::write(&file, &testnet.record).map_err(at(&file))?;
    println!("its record: {}", file.display());
    outcome
}

/// The test actors the agent runs, each derived once from its ELF, as a VOS
/// node derives it: the counter and the shop, its workflows in its program,
/// built with the default heap, which a JAM service's limits admit.
struct Actors {
    counter: Installable,
    shop: Installable,
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
            shop: actor("lean")?,
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

    /// The counter's install, and the shop's, each naming the programs
    /// derived from its ELF, for a JAM service.
    fn installs(&self) -> Vec<Input> {
        let install = |instance, package: &Installable| {
            Input::Admin(Admin::Install {
                instance,
                derivation: package.derivation.clone(),
                roles: vec![],
                target: Target::Jam,
                space: vos_wire::SpaceId::NONE,
                clock: vos_wire::WindowClock::DEFAULT,
            })
        };
        vec![install(COUNTER, &self.counter), install(SHOP, &self.shop)]
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

/// A run on the testnet: its node, the agent and the actors, Alice, the
/// attempts each package took, and the record.
struct Testnet {
    args: TestnetArgs,
    node: PolkaJam,
    agent: Vec<u8>,
    actors: Actors,
    alice: Alice,
    attempts: Vec<(String, usize)>,
    record: String,
}

/// A package as it landed.
struct Ran {
    result: WorkResult,
    imports: usize,
    exports: u32,
}

impl Testnet {
    fn new(args: TestnetArgs) -> Result<Self, String> {
        let node = PolkaJam {
            rpc: args.rpc.clone(),
            jamt: args.polkajam.join("jamt"),
            files: args.data.join("files"),
        };
        Ok(Self {
            agent: link(&args.agent)?,
            actors: Actors::derive(&args.actors)?,
            args,
            node,
            alice: Alice::new()?,
            attempts: Vec::new(),
            record: String::new(),
        })
    }

    fn run(&mut self) -> Result<(), Failed> {
        std::fs::create_dir_all(&self.args.data).map_err(at(&self.args.data))?;
        let parameters = self.node.parameters()?;
        self.note(format!("testnet: {parameters:?}"));
        let differ = parameters.disagreements();
        if !differ.is_empty() {
            let differ = differ.join(", ");
            return Err(format!("the testnet's {differ} differ from the agent's").into());
        }
        let code = self.args.data.join("agent.jam");
        let blob = write_service(&self.agent, &METADATA, &code)?;
        let service = self.node.create_service(&code, ENDOWMENT, None)?;
        self.note(format!(
            "service {service}: the agent, {} bytes, code hash {}",
            blob.len(),
            hex::encode(digest(&blob))
        ));
        let since = self.node.await_preimage(
            service,
            &digest(&blob),
            blob.len() as u64,
            PREIMAGE_TIMEOUT,
        )?;
        self.note(format!("its code available since slot {since}"));

        let store = self.args.data.join("store");
        let _ = std::fs::remove_dir_all(&store);
        let prepared =
            Arc::new(PreparedProgram::new(&self.agent).map_err(|error| format!("{error:?}"))?);
        let programs = self.actors.programs();
        let runner = Runner::new(prepared, service, programs.values().cloned());
        let mut rig = Rig {
            builder: Builder::new(Store::open(&store)?, parameters.max_refine_gas)?,
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
            self.node.provide(service, file)?;
        }
        for (hash, len) in &solicit {
            let since =
                self.node
                    .await_preimage(service, &hash.0, u64::from(*len), PREIMAGE_TIMEOUT)?;
            self.note(format!(
                "program {} available since slot {since}",
                hex::encode(hash.0)
            ));
        }

        let installs = self.actors.installs();
        self.step(&mut rig, "install the counter and the shop", installs, &[])?;
        let increment = method(&self.actors.counter, "increment")?;
        let fill = method(&self.actors.counter, "fill")?;
        let calls = vec![
            self.alice
                .call(service, COUNTER, increment, 5u64.encode())?,
            self.alice
                .call(service, COUNTER, fill, (12u32, 8u32).encode())?,
        ];
        let ran = self.step(&mut rig, "write state", calls, &[])?;
        expect_done(&ran.result)?;
        let start = method(&self.actors.shop, "compute")?;
        let call = self
            .alice
            .call(service, SHOP, start, (16_000u32, 2u32).encode())?;
        let ran = self.step(&mut rig, "start the computation", vec![call], &[])?;
        // The start's step, then, as the budget allows, the workflow's first.
        let workflow = match ran.result.steps.first() {
            Some(Step::Ran(run)) => match run.outcome {
                Outcome::Started(id) => id,
                ref other => {
                    return Err(format!("the computation did not start: {other:?}").into());
                }
            },
            _ => return Err("the start did not run".into()),
        };
        let owner = self.alice.principal();
        let (mut exported, mut imported) = (ran.exports, ran.imports);
        for round in 1.. {
            let record = rig
                .builder
                .workflow(&owner, workflow)?
                .ok_or("the workflow is gone")?;
            if let WorkflowState::Ended(_) = record.state {
                break;
            }
            if round > SWEEPS {
                return Err("the computation never ended".into());
            }
            sleep_until(record.due);
            let sweep = rig
                .builder
                .sweep(vos_node::wall_clock())?
                .ok_or("no sweep due")?;
            let ran = self.step(&mut rig, &format!("sweep {round}"), vec![sweep], &[])?;
            exported += ran.exports;
            imported += ran.imports;
        }
        let keys_of = method(&self.actors.counter, "blob_keys")?;
        let call = self.alice.call(service, COUNTER, keys_of, ().encode())?;
        let ran = self.step(&mut rig, "scan the table", vec![call], &[])?;
        expect_done(&ran.result)?;

        // The owner's read, through the builder, against the VOS node's.
        let record = rig
            .builder
            .workflow(&owner, workflow)?
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
            let on_jam = &record.state;
            return Err(format!("the result differs: {on_jam:?} on JAM, {on_vos:?} on VOS").into());
        }
        let WorkflowState::Ended(Outcome::Done(bytes)) = &record.state else {
            return Err(format!("the computation failed: {:?}", record.state).into());
        };
        let digest = u64::decode(bytes)
            .map_err(|_| "a result that is no digest")?
            .0;
        self.note(format!(
            "the owner reads workflow {}: done, digest {digest:#x}, as on VOS; its pages: {exported} exported, {imported} imported",
            workflow.0
        ));
        let landed = rig.chain.landed()?;
        if landed.root != rig.builder.store.root()? {
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
    ) -> Result<Ran, Failed> {
        let before = rig.builder.store.root()?;
        let mut clock = || {
            let time = vos_node::wall_clock();
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
                return Err(format!("{name}: {}", Error::Attempts(attempts)).into());
            }
            Err(error) => return Err(format!("{name}: {error}").into()),
        };
        let Taken {
            prepared,
            exports,
            attempts,
            ..
        } = &taken;
        self.note(format!(
            "{name}: package {}, slot {}",
            hex::encode(exports.package),
            slot_of(prepared.package.batch.time),
        ));
        self.note_attempts(attempts);
        self.attempts.push((name.to_string(), attempts.len()));
        let after = rig.builder.store.root()?;
        let landed = rig.chain.landed()?;
        if prepared.package.root != before
            || landed.root != after
            || landed.exports != Some(*exports)
        {
            return Err(format!("{name}: the roots do not continue the chain's").into());
        }
        // The chain's work result, as its exports hold it, against VOS's.
        let on_vos = rig.vos.batch(&prepared.package.batch)?.encode();
        if on_vos != taken.encoded {
            return Err(format!("{name}: the chain's work result is not the VOS node's").into());
        }
        // PolkaJam reports no refine gas: this is the refine's on the
        // JAM-only host, which charges PolkaJam's prices at every host call
        // (testkit's `the_jam_host_charges_polkajams_prices`).
        let imports = prepared.imports(rig.chain.segments().as_ref())?;
        let refined = Emulated::default()
            .refine(&rig.runner, &prepared.payload, imports, prepared.gas)
            .map_err(|error| format!("{name}: refined here: {error}"))?;
        self.note_package(&taken, inputs.len(), (before, after), refined.gas_used);
        Ok(Ran {
            imports: taken.prepared.segments.len(),
            exports: taken.exports.pages,
            result: taken.result,
        })
    }
}

/// Wait until `time`, in milliseconds since the Unix epoch, has passed.
fn sleep_until(time: u64) {
    let now = vos_node::wall_clock();
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

/// The id of `package`'s method `name`.
fn method(package: &Installable, name: &str) -> Result<MethodId, String> {
    package
        .schema
        .method_id(name)
        .ok_or_else(|| format!("no method {name}"))
}
