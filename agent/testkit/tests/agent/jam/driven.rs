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
            install_for(Target::Jam, COUNTER, hash(&self.actors.counter)),
            install_for(Target::Jam, SHOP, hash(&self.shop)),
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

/// A JAM service's agent runs on JAM alone: the builder refuses an install
/// for VOS before it makes a package, its store as it was.
#[test]
fn the_builder_refuses_an_install_for_vos() {
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let root = driven.builder.store.root().unwrap();
    let counter = ProgramHash::of(&driven.actors.counter);
    let increment = driven.actors.method(COUNTER, "increment");
    let inputs = vec![
        driven.request(COUNTER, increment, 1u64),
        install_for(Target::Vos, InstanceId(7), counter),
    ];
    assert!(matches!(
        driven.try_run(inputs),
        Err(Error::Target(Target::Vos))
    ));
    assert_eq!(driven.builder.store.root().unwrap(), root);
}

/// The agent refined from a witness, a JAM service's, refuses an install
/// for VOS itself, its first included: a package naming one past the
/// builder fails it `Target`, its detail JAM, and installs nothing.
#[test]
fn the_refine_refuses_an_install_for_vos() {
    use vos_wire::abi::Failure;
    use vos_wire::abi::cap::Refused;

    let actors = Actors::load();
    let mut paired = Paired::new(PvmBackend::Default, &programs(&actors), POLKAJAM_REFINE_GAS);
    let counter = ProgramHash::of(&actors.counter);
    let seed = Blake2b.hash(b"seed", &[&T0.to_le_bytes()]);
    let install = install_for(Target::Jam, COUNTER, counter);
    let mut prepared = paired
        .builder
        .prepare(
            &paired.runner,
            paired.chain.segments(),
            vec![install],
            T0,
            seed,
            &[],
        )
        .expect("a package");
    let Input::Admin(Admin::Install { target, .. }) = &mut prepared.package.batch.inputs[0] else {
        panic!("the install");
    };
    *target = Target::Vos;
    let payload = Work::encode_package(&prepared.package);
    let refined = paired
        .chain
        .refine(&paired.runner, &payload, Vec::new(), prepared.gas)
        .expect("the package refines");
    let exports = paired
        .chain
        .da
        .exports(&refined.segment_root)
        .expect("the exports");
    let encoded = exports[refined.output.pages as usize..].concat();
    let (result, _) = WorkResult::decode(&encoded).expect("a work result");
    let Step::Ran(run) = &result.steps[0] else {
        panic!("the install runs");
    };
    let refused = Refused::Target { agent: Target::Jam };
    assert_eq!(
        run.outcome,
        Outcome::Failed {
            code: Failure::Target,
            detail: refused.encode(),
        }
    );
    assert!(run.writes.is_empty());
    assert_ne!(refined.output.root_after, prepared.pending.root);
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
    let ops = driven.actors.method(COUNTER, "ops");
    // Steps putting rows at JAM's limit, each its own, whose own work
    // passes the bound together.
    let rows = cap::JAM.step_rows as u32 - 8;
    let fills = (0..4u32)
        .map(|index| {
            let puts = vec![(3u8, index * rows, rows)];
            driven.request(COUNTER, ops, (puts, COUNTER.0, 0u32))
        })
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
    assert!(taken.result.steps.iter().all(|step| done::<u64>(step) == 0));
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

/// A workflow holding nearly as many pages as JAM lets a snapshot hold, at
/// the largest limit a workflow may declare, runs to its end at the
/// builder's budget: its last step restores every page and drops every
/// page's row. Requests beside that step, each putting rows at JAM's
/// limit, would leave the batch less than its keep together: the batch
/// loses some rather than its budget its floor, and they wait for later
/// packages.
#[test]
fn a_workflow_at_its_page_cap_runs_to_its_end_at_the_builders_budget() {
    let actors = Actors::load();
    let (mut paired, shop) = with_shop(PvmBackend::Default, &actors);
    let most = cap::JAM.held_pages;
    // Two chunks of whole pages, each a few bytes short of whole pages,
    // which with the workflow's stack and vectors leave it a few pages
    // under the cap.
    let first = most / 2;
    let second = most - first - 12;
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
    while held < most - 16 {
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
    assert!(held <= most, "{held} pages held");
    // Its last step, beside requests putting rows at JAM's limit.
    let ops = actors.method(COUNTER, "ops");
    let rows = cap::JAM.step_rows as u32 - 8;
    let requests: Vec<Input> = (0..32u32)
        .map(|index| {
            let puts = vec![(3u8, index * rows, rows)];
            paired.request(ALICE, COUNTER, ops, (puts, COUNTER.0, 0u32))
        })
        .collect();
    time += 1_000;
    let sweep = paired.vos.sweep(time);
    let ending = paired.batch(time, [vec![sweep], requests.clone()].concat());
    ran_or_refused(&ending.result);
    assert!(ending.inputs <= requests.len(), "some requests wait");
    assert!(ending.budget >= defaults::min_refine_gas(builder::MAX_INPUTS));
    assert_eq!(
        paired.record(0).state,
        WorkflowState::Ended(Outcome::Done(total.encode()))
    );
    println!(
        "JAM: a workflow's end, {held} pages restored and dropped, beside {} requests: own work \
         {}, its budget {}",
        ending.inputs - 1,
        ending.own,
        ending.budget
    );
    // Later packages take the requests, as many each as keep the floor.
    let mut waiting = requests[ending.inputs - 1..].to_vec();
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

/// A workflow on JAM whose pages DA no longer
/// holds is left out of the sweep while its target keeps them; past that,
/// its step ends it, `Expired`, in a package that imports none of them.
#[test]
fn a_jam_workflow_past_its_pages_keep_ends_without_them() {
    const LEAN: InstanceId = InstanceId(5);
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let lean = actor("lean");
    driven.run(vec![install_for(Target::Jam, LEAN, ProgramHash::of(&lean))]);
    let nap = method(&lean, "nap");
    let start = driven.request(LEAN, nap, 500u64);
    driven.run(vec![start]);
    let workflow = WorkflowId(0);
    driven.chain.da = vos_jam::Da::default();
    let increment = driven.actors.method(COUNTER, "increment");
    let sweep = driven
        .builder
        .sweep(driven.time + 1_000)
        .unwrap()
        .expect("due");
    let request = driven.request(COUNTER, increment, 1u64);
    let taken = driven.try_run(vec![sweep, request]).expect("it lands");
    assert_eq!(taken.prepared.skipped, [workflow], "kept, so left out");
    let kept = cap::JAM.pages_kept.expect("JAM keeps pages for a time");
    driven.time += kept;
    let sweep = driven
        .builder
        .sweep(driven.time + 1_000)
        .unwrap()
        .expect("due");
    let taken = driven.try_run(vec![sweep]).expect("it lands");
    assert!(taken.prepared.skipped.is_empty());
    assert!(
        taken.prepared.package.imports.is_empty(),
        "no page imported"
    );
    let expired = Outcome::failed(vos_wire::abi::Failure::Expired);
    let record = driven.builder.workflow(&ALICE, workflow).unwrap().unwrap();
    assert_eq!(record.state, WorkflowState::Ended(expired));
    assert!(record.snapshot.is_none(), "its pages dropped");
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
    // Each start writes 48 pages of data, within JAM's pages a step
    // writes, and more than a package's segments together.
    let starts: Vec<Input> = (0..64)
        .map(|_| driven.request(SHOP, compute, (24_576u32, 1u32)))
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
        "JAM: {inputs} of 64 computations in a package: {exports} exports, refine {} of {} gas",
        refined.gas_used, prepared.gas
    );
}

/// A batch whose package would pass CE 133's bound on a work package,
/// 204,800 bytes past its core's index, loses its later inputs, which a
/// later package takes: PolkaJam's guarantors refuse a package past it.
#[test]
fn the_builder_fits_a_batch_to_ce_133s_package_bound() {
    let mut driven = Driven::new(Store::temporary().unwrap(), POLKAJAM_REFINE_GAS);
    let increment = driven.actors.method(COUNTER, "increment");
    // Requests of 4 KiB of arguments each, 256 KiB together.
    let requests: Vec<Input> = (0..64)
        .map(|_| driven.request(COUNTER, increment, vec![7u8; 4096]))
        .collect();
    let (time, seed) = (driven.time + 1_000, [1; 32]);
    let prepared = driven
        .builder
        .prepare(
            &driven.runner,
            driven.chain.segments(),
            requests.clone(),
            time,
            seed,
            &[],
        )
        .expect("a package");
    let inputs = prepared.package.batch.inputs.len();
    println!(
        "{inputs} of 64 requests of 4 KiB in a package: payload {} B, the package at most {} B",
        prepared.payload.len(),
        prepared.package_bytes()
    );
    assert!(
        requests.len() * 4096 > builder::MAX_PACKAGE,
        "the batch's arguments alone pass the bound"
    );
    assert!(inputs < requests.len(), "{inputs} of the requests");
    assert!(prepared.package_bytes() <= builder::MAX_PACKAGE);
    assert!(prepared.payload.len() > builder::MAX_PACKAGE / 4);
    let rest = requests[inputs..].to_vec();
    let later = driven
        .builder
        .prepare(
            &driven.runner,
            driven.chain.segments(),
            rest,
            time,
            seed,
            &[],
        )
        .expect("a later package");
    assert!(later.package_bytes() <= builder::MAX_PACKAGE);
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
    let (shop, compact) = (hash(&driven.shop), hash(&actor("compact")));
    let nap = method(&driven.shop, "nap");
    let start = driven.request(SHOP, nap, 2_500u64);
    driven.run(vec![start]);
    driven.run(vec![install_for(Target::Jam, SHOP, compact)]);
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
    assert_eq!(record(&driven, 1).program, compact);
}
