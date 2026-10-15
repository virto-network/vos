//! A builder driven over an emulated chain: its packages fitted to their
//! gas and segments, refused ones made again, and its store.

use super::*;

/// A builder over its own store, beside the test actors and the shop, and
/// an emulated chain it submits to.
struct Driven {
    actors: Actors,
    shop: Vec<u8>,
    runner: Runner,
    builder: Builder,
    chain: Emulated,
    /// Alice's requests, in her session started at `T0`.
    sequence: u64,
    time: u64,
}

impl Driven {
    /// A builder whose packages each have `refine_gas`, over `store`, and
    /// the actors and the shop installed through it.
    fn new(store: Store, refine_gas: u64) -> Self {
        let actors = Actors::load();
        let (paired, shop) = with_shop(PvmBackend::Default, &actors);
        let mut driven = Self {
            runner: paired.runner,
            builder: Builder::new(store, refine_gas).unwrap(),
            chain: Emulated::default(),
            actors,
            shop,
            sequence: 0,
            time: T0,
        };
        let installs = driven.installs();
        driven.run(installs);
        driven
    }

    fn installs(&mut self) -> Vec<Input> {
        let hash = ProgramHash::of;
        vec![
            install(COUNTER, hash(&self.actors.counter)),
            Input::Admin(Admin::Install {
                instance: SHOP,
                derivation: vos_testkit::programs::bare(hash(&self.shop)),
                roles: vec![],
            }),
        ]
    }

    /// Alice's next request.
    fn request<A: Encode>(
        &mut self,
        instance: InstanceId,
        method: MethodId,
        arguments: A,
    ) -> Input {
        self.sequence += 1;
        Input::Request(Request {
            session: Session {
                key: [1; 32],
                name: [0; 16],
                t0: T0,
            },
            sequence: self.sequence,
            caller: ALICE,
            instance,
            method,
            arguments: arguments.encode(),
        })
    }

    /// `inputs` run through the builder's loop, each attempt a second after
    /// the last: the work result.
    fn run(&mut self, inputs: Vec<Input>) -> WorkResult {
        self.try_run(inputs).expect("the package lands").result
    }

    fn try_run(&mut self, inputs: Vec<Input>) -> Result<Taken, Error> {
        let time = &mut self.time;
        let mut clock = || {
            *time += 1_000;
            (*time, Blake2b.hash(b"seed", &[&time.to_le_bytes()]))
        };
        let taken = self
            .builder
            .run(&mut self.chain, &self.runner, &inputs, &mut clock, &[])?;
        assert_eq!(self.chain.root(), Some(self.builder.store.root().unwrap()));
        assert_eq!(taken.encoded, taken.prepared.simulation.encoded);
        Ok(taken)
    }
}

/// A package the chain refused, accumulated past its time or refined out
/// of gas, is made again at a new time, and lands.
#[test]
fn the_builder_makes_a_refused_package_again() {
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let increment = driven.actors.method(COUNTER, "increment");
    driven.chain.faults = vec![Fault::Late, Fault::Starved];
    let request = driven.request(COUNTER, increment, 5u64);
    let taken = driven.try_run(vec![request.clone()]).expect("it lands");
    assert_eq!(done::<u64>(&taken.result.steps[0]), 5);
    let fates: Vec<Fate> = taken
        .attempts
        .iter()
        .map(|attempt| attempt.fate.clone())
        .collect();
    assert_eq!(fates, [Fate::Refused, Fate::Refused, Fate::Landed]);
    assert!(taken.attempts[1].submitted.contains("refine stopped"));
    // Refused as often as the builder tries, it stops.
    driven.chain.faults = vec![Fault::Late; 4];
    let again = driven.request(COUNTER, increment, 1u64);
    let Err(Error::Attempts(attempts)) = driven.try_run(vec![again]) else {
        panic!("it lands");
    };
    assert_eq!(attempts.len(), 4);
    assert!(attempts.iter().all(|attempt| attempt.fate == Fate::Refused));
}

/// A batch's budget is what a work package's refine gas leaves past the
/// margin and the bound on its own work: a package whose own work passes
/// the bound has it lowered, the refine fitting its gas all the same. A
/// chain whose refine gas leaves a batch less than the least a VOS node
/// refines with is refused, and a batch holds at most as many inputs as a
/// VOS node's.
#[test]
fn the_builder_fits_its_budget_to_a_packages_gas() {
    assert_eq!(builder::budget(POLKAJAM_REFINE_GAS), 900_000_000);
    let below = Builder::new(Store::temporary().unwrap(), 7 * POLKAJAM_REFINE_GAS / 10);
    let least = defaults::min_refine_gas(builder::MAX_INPUTS);
    assert!(
        matches!(below, Err(Error::RefineGas { least: refused, .. }) if refused == least),
        "refused below {least}"
    );
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let fill = driven.actors.method(COUNTER, "fill");
    let fills = (0..2)
        .map(|_| driven.request(COUNTER, fill, (300u32, 8u32)))
        .collect();
    let taken = driven.try_run(fills).expect("it lands");
    let prepared = &taken.prepared;
    let budget = prepared.package.batch.budget;
    let start = prepared.gas - budget - prepared.own;
    assert!(
        prepared.own + start > builder::OWN_BOUND,
        "{} of own work",
        prepared.own
    );
    assert_eq!(
        budget,
        POLKAJAM_REFINE_GAS - POLKAJAM_REFINE_GAS / 1000 * builder::MARGIN - prepared.own - start
    );
    assert!(prepared.gas <= POLKAJAM_REFINE_GAS);
    assert_eq!(
        prepared.simulations, 2,
        "simulated again at the lowered budget"
    );
    assert!(
        taken
            .result
            .steps
            .iter()
            .all(|step| done::<u32>(step) == 300)
    );
    // A batch holds at most a VOS node's inputs; the later ones wait.
    let ack = Input::Ack {
        to: AgentId(5),
        sequence: 1,
    };
    let acks = vec![ack; builder::MAX_INPUTS + 4];
    let segments = driven.chain.segments();
    let time = driven.time + 1_000;
    let prepared = driven
        .builder
        .prepare(&driven.runner, segments, acks, time, [1; 32], &[])
        .expect("a package");
    assert_eq!(prepared.package.batch.inputs.len(), builder::MAX_INPUTS);
}

/// A workflow holding nearly as many pages as a snapshot may, at the
/// largest limit a workflow may declare, runs to its end at the builder's
/// budget, on JAM as on VOS: its last step restores every page and drops
/// every page's row, and its package's own work stays within the bound the
/// builder asserts for it. Requests beside that step, each putting a
/// thousand rows, would leave the batch less than its keep: the batch
/// loses them rather than its budget its floor, and they wait for later
/// packages.
#[test]
fn a_workflow_at_its_page_cap_runs_to_its_end_at_the_builders_budget() {
    let actors = Actors::load();
    let (mut paired, shop) = with_shop(PvmBackend::Default, &actors);
    // Two chunks of whole pages, each a few bytes short of whole pages,
    // which with the workflow's stack and vectors leave it a few pages
    // under the cap.
    let first = cap::HELD_PAGES / 2;
    let second = cap::HELD_PAGES - first - 12;
    let sizes: Vec<u32> = [first, second]
        .map(|pages| (pages * PAGE - 256) as u32)
        .to_vec();
    let total: u64 = sizes.iter().map(|&size| u64::from(size)).sum();
    let start = paired.request(ALICE, SHOP, method(&shop, "fill"), (0u32, sizes));
    let mut time = T0 + 1_000;
    paired.batch(time, vec![start]);
    assert_eq!(paired.record(0).gas, defaults::MAX_HANDLER_GAS);
    // Its steps until it holds every chunk, asleep before its last.
    let mut held = 0;
    while held < cap::HELD_PAGES - 16 {
        let state = paired.record(0).state;
        assert!(
            matches!(
                state,
                WorkflowState::Sleeping { .. } | WorkflowState::Preempted(_)
            ),
            "{state:?}"
        );
        time += 1_000;
        let sweep = paired.vos.sweep(time);
        ran_or_refused(&paired.batch(time, vec![sweep]).result);
        held = paired
            .record(0)
            .snapshot
            .map_or(0, |snapshot| snapshot.pages.len());
    }
    assert!(held <= cap::HELD_PAGES, "{held} pages held");
    // Its last step, beside two requests putting a thousand rows each.
    let ops = actors.method(COUNTER, "ops");
    let requests: Vec<Input> = [0u32, 1_000]
        .map(|start| {
            let puts = vec![(3u8, start, 1_000u32)];
            paired.request(ALICE, COUNTER, ops, (puts, COUNTER.0, 0u32))
        })
        .to_vec();
    time += 1_000;
    let sweep = paired.vos.sweep(time);
    let ending = paired.batch(time, [vec![sweep], requests.clone()].concat());
    ran_or_refused(&ending.result);
    assert_eq!(ending.inputs, 1, "the requests wait");
    assert!(ending.budget >= defaults::min_refine_gas(builder::MAX_INPUTS));
    assert_eq!(
        paired.record(0).state,
        WorkflowState::Ended(Outcome::Done(total.encode()))
    );
    let held = held as u64;
    let bound = gas::ENDING + held * (gas::PAGE_READ + gas::PAGE_DROP);
    assert!(
        ending.own <= bound,
        "the ending's own work {} within {bound}",
        ending.own
    );
    println!(
        "JAM: a workflow's end, {held} pages restored and dropped: own work {}, its budget {}",
        ending.own, ending.budget
    );
    // Later packages take the requests, as many each as keep the floor.
    let mut waiting = requests;
    while !waiting.is_empty() {
        time += 1_000;
        let next = paired.batch(time, waiting.clone());
        assert!(next.inputs >= 1);
        assert!(next.result.steps.iter().all(|step| done::<u64>(step) == 0));
        waiting.drain(..next.inputs);
    }
}

/// Every workflow whose pages DA no longer holds is left out of the sweep
/// before the batch is simulated: however many there are, the package
/// takes at most two simulations, and lands with the rest of the batch,
/// the workflows due still.
#[test]
fn workflows_whose_pages_da_lacks_are_left_out_at_once() {
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let nap = method(&driven.shop, "nap");
    let starts = (0..3).map(|_| driven.request(SHOP, nap, 500u64)).collect();
    driven.run(starts);
    let naps = [WorkflowId(0), WorkflowId(1), WorkflowId(2)];
    let asleep = |driven: &Driven, id| {
        let workflow = driven.builder.workflow(&ALICE, id).unwrap().unwrap();
        assert!(!workflow.snapshot.unwrap().pages.is_empty(), "its pages");
        matches!(workflow.state, WorkflowState::Sleeping { .. })
    };
    assert!(naps.iter().all(|&id| asleep(&driven, id)));
    // DA forgets every segment exported so far.
    driven.chain.da = vos_jam::Da::default();
    let time = driven.time + 1_000;
    let sweep = driven
        .builder
        .sweep(time)
        .unwrap()
        .expect("the naps are due");
    let increment = driven.actors.method(COUNTER, "increment");
    let request = driven.request(COUNTER, increment, 4u64);
    let taken = driven.try_run(vec![sweep, request]).expect("it lands");
    assert_eq!(taken.prepared.skipped, naps);
    assert!(
        taken.prepared.simulations <= 2,
        "{} simulations",
        taken.prepared.simulations
    );
    assert_eq!(
        taken.prepared.package.batch.inputs.len(),
        1,
        "the sweep left out"
    );
    assert_eq!(done::<u64>(&taken.result.steps[0]), 4);
    assert!(naps.iter().all(|&id| asleep(&driven, id)), "still due");
}

/// A package another builder's landed before: the builder takes that one
/// from its exports, then makes its own again on it. One that cannot be
/// reached from the store stops the builder, its store left as it was.
#[test]
fn the_builder_takes_a_package_that_landed_first() {
    let mut first = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let mut second = Builder::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS).unwrap();
    let landed = first.chain.landed().unwrap();
    second
        .resync(&first.chain.da, &landed)
        .expect("one package behind");
    assert_eq!(second.store.root().unwrap(), landed.root);
    // The second lands a package of Bob's.
    let increment = first.actors.method(COUNTER, "increment");
    let bob = Input::Request(Request {
        session: Session {
            key: [2; 32],
            name: [0; 16],
            t0: T0,
        },
        sequence: 1,
        caller: BOB,
        instance: COUNTER,
        method: increment,
        arguments: 3u64.encode(),
    });
    let mut time = first.time + 1_000;
    let mut clock = || {
        time += 1_000;
        (time, [9; 32])
    };
    second
        .run(&mut first.chain, &first.runner, &[bob], &mut clock, &[])
        .expect("the second's package lands");
    first.time = time;
    // The first, a package behind, takes the second's, then lands its own.
    let alice = first.request(COUNTER, increment, 4u64);
    let taken = first.try_run(vec![alice]).expect("it lands");
    assert_eq!(done::<u64>(&taken.result.steps[0]), 7, "on Bob's increment");
    let fates: Vec<Fate> = taken
        .attempts
        .iter()
        .map(|attempt| attempt.fate.clone())
        .collect();
    assert_eq!(fates, [Fate::Overtaken, Fate::Landed]);
    // Two packages behind, the second cannot reach the chain's root.
    let third = first.request(COUNTER, increment, 1u64);
    first.run(vec![third]);
    let before = second.store.root().unwrap();
    let landed = first.chain.landed().unwrap();
    assert_eq!(
        second.resync(&first.chain.da, &landed),
        Err(Error::Diverged)
    );
    assert_eq!(second.store.root().unwrap(), before);
}

/// A batch whose pages pass a work package's exports loses its later
/// inputs, which a later package takes; a package's refine fits its gas.
#[test]
fn the_builder_fits_a_batch_to_a_packages_segments() {
    let mut driven = Driven::new(Store::temporary().unwrap(), 8_000_000_000);
    let compute = method(&driven.shop, "compute");
    let starts: Vec<Input> = (0..7)
        .map(|_| driven.request(SHOP, compute, (262_144u32, 1u32)))
        .collect();
    let (time, seed) = (driven.time + 1_000, [1; 32]);
    let prepared = driven
        .builder
        .prepare(
            &driven.runner,
            driven.chain.segments(),
            starts.clone(),
            time,
            seed,
            &[],
        )
        .expect("a package");
    let exports = prepared.exports() as usize;
    let inputs = prepared.package.batch.inputs.len();
    assert!(inputs < starts.len(), "{inputs} of the starts");
    assert!(
        exports <= vos_wire::package::MAX_SEGMENTS,
        "{exports} exports"
    );
    assert!(
        exports > vos_wire::package::MAX_SEGMENTS / 3,
        "{exports} exports"
    );
    let refined = driven
        .chain
        .refine(&driven.runner, &prepared.payload, vec![], prepared.gas)
        .expect("the package refines within its gas");
    assert!(refined.gas_used <= prepared.gas);
    println!(
        "JAM: {inputs} of 7 computations in a package: {exports} exports, refine {} of {} gas",
        refined.gas_used, prepared.gas
    );
}

/// The builder's store outlives it: reopened, it holds the same root and
/// where the pages it took were exported, so a workflow it suspended
/// resumes from their imports. The packages it lands solicit what it
/// names.
#[test]
fn the_builders_store_outlives_it() {
    let scratch =
        Scratch(std::env::temp_dir().join(format!("vos-jam-outlives-{}", std::process::id())));
    let path = &scratch.0;
    let _ = std::fs::remove_dir_all(path);
    let mut driven = Driven::new(Store::open(path).unwrap(), POLKAJAM_REFINE_GAS);
    let nap = method(&driven.shop, "nap");
    let start = driven.request(SHOP, nap, 500u64);
    driven.run(vec![start]);
    let root = driven.builder.store.root().unwrap();
    let program = ProgramHash::of(&driven.actors.counter);
    let len = driven.actors.counter.len() as u32;
    // The builder gone, its store reopened: the old one is dropped first,
    // which releases its lock on the directory, a temporary store standing
    // in meanwhile.
    driven.builder = Builder::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS).unwrap();
    driven.builder = Builder::new(Store::open(path).unwrap(), POLKAJAM_REFINE_GAS).unwrap();
    assert_eq!(driven.builder.store.root().unwrap(), root);
    let time = driven.time + 1_000;
    let sweep = driven.builder.sweep(time).unwrap().expect("the nap is due");
    let mut clock = || (time, [7; 32]);
    let Taken {
        prepared, result, ..
    } = driven
        .builder
        .run(
            &mut driven.chain,
            &driven.runner,
            &[sweep],
            &mut clock,
            &[(program, len)],
        )
        .expect("the nap resumes");
    assert!(!prepared.package.imports.is_empty(), "its pages imported");
    let workflow = driven
        .builder
        .workflow(&ALICE, WorkflowId(0))
        .unwrap()
        .expect("Alice's workflow");
    assert!(
        matches!(workflow.state, WorkflowState::Ended(_)),
        "{result:?}"
    );
    assert_eq!(driven.builder.workflow(&BOB, WorkflowId(0)).unwrap(), None);
    assert!(
        driven
            .chain
            .solicited
            .contains(&(program.0, u64::from(len)))
    );
}

/// A directory removed when dropped, so a test that panics leaves none.
struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A workflow keeps the program it started on through an upgrade on JAM
/// too: its program is a preimage the builder never forgets, so the
/// workflow resumes on it and ends there, while a start since runs the
/// upgrade.
#[test]
fn a_workflow_resumes_on_its_program_through_an_upgrade_on_jam() {
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let hash = ProgramHash::of;
    let (shop, lean) = (hash(&driven.shop), hash(&actor("lean")));
    let nap = method(&driven.shop, "nap");
    let start = driven.request(SHOP, nap, 2_500u64);
    driven.run(vec![start]);
    driven.run(vec![Input::Admin(Admin::Install {
        instance: SHOP,
        derivation: vos_testkit::programs::bare(lean),
        roles: vec![],
    })]);
    let record = |driven: &Driven, id: u64| {
        let row = driven
            .builder
            .store
            .view()
            .get(&keys::workflow(WorkflowId(id)));
        Workflow::decode(unstored(&row.unwrap().unwrap()).unwrap())
            .unwrap()
            .0
    };
    for _ in 0..10 {
        if matches!(record(&driven, 0).state, WorkflowState::Ended(_)) {
            break;
        }
        if let Some(sweep) = driven.builder.sweep(driven.time + 1_000).unwrap() {
            driven.run(vec![sweep]);
        } else {
            driven.time += 1_000;
        }
    }
    let napped = record(&driven, 0);
    assert_eq!(napped.program, shop);
    assert!(
        matches!(napped.state, WorkflowState::Ended(Outcome::Done(_))),
        "{:?}",
        napped.state
    );
    let start = driven.request(SHOP, nap, 1u64);
    driven.run(vec![start]);
    assert_eq!(record(&driven, 1).program, lean);
}
