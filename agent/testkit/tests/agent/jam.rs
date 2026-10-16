//! JAM mode against a VOS node. Each batch runs on a VOS node's refine and
//! accumulate, and as a JAM package: simulated on the builder's store,
//! witnessed, refined on the JAM-only host with its imports from emulated
//! DA, accumulated, and its work result applied to the builder's store.
//! The work results are equal byte for byte, the pages equal by hash, the
//! roots continue from package to package, and the builder's rows are the
//! VOS node's, but for what only a VOS node keeps and the page rows.

use std::collections::BTreeMap;
use std::sync::Arc;

use vos_jam::builder::POLKAJAM_REFINE_GAS;
use vos_jam::{
    Builder, Chain, Emulated, Error, Fate, Fault, Landed, Refined, Runner, Store, Taken, builder,
    gas,
};
use vos_pvm::PvmBackend;
use vos_testkit::programs::{actor, method};
use vos_tree::{Blake2b, Hash, Hasher, empty_root};
use vos_wire::abi::cap::Target;
use vos_wire::abi::{Rows, cap};
use vos_wire::batch::{Admin, Answer, Await, Body, Input, Message, Request, Work};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash, Session, WorkflowId};
use vos_wire::keys::{self, Transform};
use vos_wire::package::slot_of;
use vos_wire::package::{Opened, Package};
use vos_wire::records::{Workflow, WorkflowState, stored, unstored};
use vos_wire::result::{Outcome, Outgoing, PAGE, Step, WorkResult, digest, split_output};
use vos_wire::{Decode, Encode, defaults};

mod agreement;
mod driven;

use crate::common::{
    AGENT, ALICE, Actors, BOB, CALLER, COUNTER, LEDGER, MINTER, Node, SHOP, done, install,
};

/// A batch time well past JAM's common era; the sessions start at it.
const T0: u64 = 1_760_000_000_000;

/// The agent the shop's workflows ask.
const RISK: AgentId = AgentId(9);

/// A package as it ran.
struct Ran {
    result: WorkResult,
    /// The refine's gas on JAM, and the simulation's.
    jam_gas: u64,
    simulated_gas: u64,
    /// The pages it imported and exported.
    imported: usize,
    exported: usize,
    /// The keys its witness opens, and the rows of its scanned ranges.
    witnessed: usize,
    scanned: usize,
    /// The batch's inputs, its budget, and the package's own work as the
    /// builder estimated it.
    inputs: usize,
    budget: u64,
    own: u64,
}

/// A VOS node, and beside it the agent's builder and its chain.
struct Paired {
    vos: Node,
    runner: Runner,
    builder: Builder,
    chain: Emulated,
    /// Every client's requests, numbered in its session started at `T0`.
    sequences: BTreeMap<Principal, u64>,
    /// Other agents' messages, numbered in their pairs.
    pairs: BTreeMap<AgentId, u64>,
}

impl Paired {
    /// The pair on `backend`, with `programs` the node's and the agent's
    /// preimages, the builder's work packages each of `refine_gas`.
    fn new(backend: PvmBackend, programs: &[&[u8]], refine_gas: u64) -> Self {
        let mut vos = Node::on(backend);
        for program in programs {
            vos.add(program);
        }
        let runner = Runner {
            program: vos.program(),
            service: u64::from(AGENT.0),
            preimages: vos.preimages(),
        };
        Self {
            vos,
            runner,
            builder: Builder::new(Store::temporary().unwrap(), refine_gas).unwrap(),
            chain: Emulated::default(),
            sequences: BTreeMap::new(),
            pairs: BTreeMap::new(),
        }
    }

    /// `caller`'s next request, in its session started at `T0`.
    fn request<A: Encode>(
        &mut self,
        caller: Principal,
        instance: InstanceId,
        method: MethodId,
        arguments: A,
    ) -> Input {
        let sequence = self.sequences.entry(caller).or_insert(0);
        *sequence += 1;
        let key = match caller {
            Principal::Client(key) => key,
            _ => [0; 32],
        };
        Input::Request(Request {
            session: Session {
                key,
                name: [0; 16],
                t0: T0,
            },
            sequence: *sequence,
            caller,
            instance,
            method,
            arguments: arguments.encode(),
        })
    }

    /// A message from `from`, next in its pair.
    fn message(&mut self, from: AgentId, body: Body) -> Input {
        let sequence = self.pairs.entry(from).or_insert(0);
        *sequence += 1;
        Input::Message(Message {
            from,
            sequence: *sequence,
            body,
        })
    }

    /// `inputs` at `time`, as a JAM package and on the VOS node, which must
    /// agree: the builder's batch, which the work package's refine gas
    /// shapes, runs on both.
    fn batch(&mut self, time: u64, inputs: Vec<Input>) -> Ran {
        let seed = Blake2b.hash(b"seed", &[&time.to_le_bytes()]);
        let root = self.builder.store.root().unwrap();
        assert_eq!(
            self.chain.root().unwrap_or_else(|| empty_root(&Blake2b)),
            root,
            "the chain holds the builder's root"
        );
        let prepared = self
            .builder
            .prepare(&self.runner, self.chain.segments(), inputs, time, seed, &[])
            .expect("a package");
        let work = Work::Batch(prepared.package.batch.clone());
        let batch = &prepared.package.batch;
        let (inputs, budget, own) = (batch.inputs.len(), batch.budget, prepared.own);
        assert_eq!(prepared.package.batch.version, self.vos.version);
        let on_vos = self.vos.refine(&work);
        self.vos.accumulate(&on_vos);
        self.vos.version += 1;
        let (vos_result, vos_pages) = split_output(&on_vos).expect("a VOS output");
        let vos_encoded = vos_result.encode();
        assert_eq!(on_vos[..vos_encoded.len()], vos_encoded[..]);
        assert_eq!(
            prepared.simulation.encoded, vos_encoded,
            "the simulation's work result is the VOS node's"
        );
        assert_eq!(prepared.package.root, root);
        assert!(shows(&prepared.package), "the witness verifies");
        assert!(prepared.gas <= self.builder.refine_gas());
        let imports = prepared
            .imports(self.chain.segments().as_ref())
            .expect("the pages in DA");
        let refined = self
            .chain
            .refine(&self.runner, &prepared.payload, imports, prepared.gas)
            .expect("the package refines within the gas the builder gives it");
        let output = &refined.output;
        assert_eq!(output.root_before, root);
        assert_eq!(output.root_after, prepared.pending.root);
        assert_eq!((output.time, output.seed), (time, seed));
        let slot = slot_of(time) + 1;
        let stored = self
            .chain
            .accumulate(&self.runner, &refined, slot)
            .expect("accumulate halts");
        assert_eq!(stored, Some(output.root_after), "accumulate takes the root");
        let landed = self.chain.landed().unwrap();
        assert_eq!(
            landed
                .exports
                .map(|exports| (exports.root, exports.pages, exports.segments)),
            Some((refined.segment_root, output.pages, output.exports))
        );
        let pages = output.pages as usize;
        let simulated = prepared.simulation.gas_used;
        assert!(
            refined.gas_used <= simulated + prepared.own,
            "the package's own work, {} beyond the simulation, within its estimate {}",
            refined.gas_used - simulated.min(refined.gas_used),
            prepared.own
        );
        let witness = prepared.package.witness.clone();
        let imported = prepared.package.imports.len();
        let (result, on_chain) = self
            .builder
            .accept(&prepared, &landed, self.chain.segments().as_ref())
            .expect("the builder takes the result");
        assert_eq!(on_chain, vos_encoded, "the chain's work result is VOS's");
        assert_eq!(result, vos_result);
        assert_eq!(self.builder.store.root().unwrap(), output.root_after);

        let exports = self
            .chain
            .da
            .exports(&refined.segment_root)
            .expect("the exports");
        let encoded = exports[pages..].concat();
        assert_eq!(
            encoded[..vos_encoded.len()],
            vos_encoded[..],
            "the work result, byte for byte"
        );
        assert!(encoded[vos_encoded.len()..].iter().all(|byte| *byte == 0));
        let on_jam: Vec<Hash> = exports[..pages]
            .iter()
            .map(|segment| digest(&segment[..PAGE]))
            .collect();
        let on_vos: Vec<Hash> = vos_pages.iter().map(|lz4| digest(&unpacked(lz4))).collect();
        assert_eq!(on_jam, on_vos, "the pages, by hash");
        self.rows_agree();
        Ran {
            result,
            jam_gas: refined.gas_used,
            simulated_gas: simulated,
            imported,
            exported: pages,
            witnessed: witness.keys.len(),
            scanned: witness.ranges.iter().map(|range| range.rows.len()).sum(),
            inputs,
            budget,
            own,
        }
    }

    /// The builder's rows are the VOS node's, but the dirty and seed rows
    /// only a VOS node's root builder needs, and a page row, which holds
    /// the page on a VOS node and its hash on JAM.
    fn rows_agree(&self) {
        let vos: BTreeMap<Vec<u8>, Vec<u8>> = self
            .vos
            .state
            .iter()
            .filter(|(key, _)| {
                !key.starts_with(&keys::dirty_prefix()) && !key.starts_with(&keys::seed_prefix())
            })
            .map(|(key, value)| match keys::page_entry(key) {
                Some(_) => {
                    let page = unpacked(unstored(value).expect("a stored page"));
                    (key.clone(), stored(&digest(&page)))
                }
                None => (key.clone(), value.clone()),
            })
            .collect();
        assert!(
            vos == self.builder.store.view().rows().unwrap(),
            "the builder's rows are the VOS node's"
        );
    }

    fn record(&self, id: u64) -> Workflow {
        self.vos
            .value(&keys::workflow(WorkflowId(id)))
            .expect("a workflow")
    }
}

/// A page LZ4-compressed, whole.
fn unpacked(lz4: &[u8]) -> Vec<u8> {
    lz4_flex::block::decompress(lz4, PAGE).expect("an LZ4 page")
}

/// Every step ran to `Done`, or was refused.
fn ran_or_refused(result: &WorkResult) {
    for step in &result.steps {
        if let Step::Ran(run) = step {
            assert!(
                matches!(run.outcome, vos_wire::result::Outcome::Done(_)),
                "{:?}",
                run.outcome
            );
        }
    }
}

/// The installs of the counter, the ledger with its programs and the
/// caller, and Alice a minter.
fn installs(paired: &mut Paired, actors: &Actors) -> Vec<Input> {
    let counter = ProgramHash::of(&actors.counter);
    let caller = ProgramHash::of(&actors.caller);
    vec![
        install(COUNTER, counter),
        actors.install_ledger(&mut paired.vos),
        install(CALLER, caller),
        Input::Admin(Admin::SetRole(vos_wire::ingress::Grant {
            principal: ALICE,
            role: Some(MINTER),
        })),
    ]
}

fn programs(actors: &Actors) -> Vec<&[u8]> {
    vec![
        &actors.counter,
        &actors.ledger,
        &actors.caller,
        &actors.checksum,
    ]
}

/// A pair with the test actors and the shop, its workflows in its
/// program, installed, and the shop's upgrade among its preimages: and the
/// shop's program.
fn with_shop(backend: PvmBackend, actors: &Actors) -> (Paired, Vec<u8>) {
    let (shop, lean) = (actor("shop"), actor("lean"));
    let mut all = programs(actors);
    all.extend([shop.as_slice(), lean.as_slice()]);
    let mut paired = Paired::new(backend, &all, POLKAJAM_REFINE_GAS);
    let mut first = installs(&mut paired, actors);
    first.push(Input::Admin(Admin::Install {
        instance: SHOP,
        derivation: vos_testkit::programs::bare(ProgramHash::of(&shop)),
        roles: vec![],
        target: Target::Vos,
    }));
    ran_or_refused(&paired.batch(T0, first).result);
    (paired, shop)
}

/// A witness's keys, each opened.
type WitnessKeys = Vec<(Vec<u8>, Opened)>;

/// Whether `package`'s witness verifies against its root, natively: its
/// keys under its multiproof, and each range complete.
fn shows(package: &Package) -> bool {
    use vos_tree::value_hash;
    let witness = &package.witness;
    let claims: Vec<(&[u8], Option<Hash>)> = witness
        .keys
        .iter()
        .map(|(key, opened)| {
            let claim = match opened {
                Opened::Absent => None,
                Opened::Value { salt, value } => Some(value_hash(&Blake2b, salt, value)),
                Opened::Written(hash) => Some(*hash),
            };
            (key.as_slice(), claim)
        })
        .collect();
    let keys = witness
        .proof
        .verify(&Blake2b, &package.root, &claims)
        .is_ok();
    keys && witness.ranges.iter().all(|range| {
        let rows: Vec<(&[u8], Hash)> = range
            .rows
            .iter()
            .map(|row| {
                (
                    row.key.as_slice(),
                    value_hash(&Blake2b, &row.salt, &row.value),
                )
            })
            .collect();
        range
            .proof
            .verify(
                &Blake2b,
                &package.root,
                &range.from,
                range.to.as_deref(),
                &rows,
            )
            .is_ok()
    })
}
