//! A workflow's life: started, awaiting, asleep, failed, upgraded under,
//! capped and collected, and its state lost.

use super::*;

/// A transfer: a request starts it, answered with its id, and its first
/// step follows in the same batch, pausing at its request of the risk
/// agent. The answer resumes it: it moves the funds and counts the sale,
/// and ends with its result, kept for its owner, its pin and its place
/// among the live workflows gone, its collection due. Batches of the
/// default budget.
#[test]
fn a_transfer_awaits_one_answer_then_calls_this_agents_actors() {
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let mint = flows.actors.method(LEDGER, "mint");
        let minted = flows.sessions.request(ALICE, LEDGER, mint, (1u64, 100u64));
        let start = flows.start("transfer", transfer(30));
        let result = flows.batch(1, vec![minted, start]);
        assert_eq!(
            ran(&result.steps[1]).outcome,
            Outcome::Started(WorkflowId(0))
        );
        let first = due(&result, 0);
        asks_risk(&flows, first, 0, 0, 30);
        let record = flows.record(0);
        assert_eq!(
            record.state,
            WorkflowState::Awaiting {
                agent: RISK,
                counter: 0,
                deadline: flows.time + 30_000,
            }
        );
        assert_eq!(record.owner, ALICE);
        assert_eq!(record.awaits, 1);
        let held = flows.pages(0);
        assert!(!held.is_empty() && held.len() < 16, "{} pages", held.len());
        let program = flows.program("shop");
        assert_eq!(flows.count(&keys::workflow_pins(&program)), Some(1));
        assert_eq!(flows.count(&keys::live_workflows()), Some(1));
        assert!(
            flows
                .node
                .get(&keys::due(
                    flows.time + 30_000,
                    Due::Workflow(WorkflowId(0))
                ))
                .is_some()
        );

        let answer = flows.reply(RISK, 0, 0, Answer::Done(30u64.encode()));
        let result = flows.batch(5, vec![answer]);
        let resumed = ran(&result.steps[0]);
        assert_eq!(resumed.outcome, Outcome::Done(vec![]));
        assert!(resumed.pages.iter().all(|page| page.hash.is_none()));
        let record = flows.record(0);
        assert_eq!(ended(&record), &Outcome::Done(30u64.encode()));
        assert_eq!(record.snapshot, None);
        let collected = flows.time + defaults::WORKFLOW_KEPT_MS;
        assert_eq!(record.due, collected);
        assert!(flows.pages(0).is_empty());
        for (index, _) in held {
            assert_eq!(flows.node.get(&keys::page(WorkflowId(0), index)), None);
        }
        assert_eq!(flows.count(&keys::workflow_pins(&program)), None);
        assert_eq!(flows.count(&keys::live_workflows()), None);
        assert_eq!(flows.sales(), 30);
        let balance = flows.actors.method(LEDGER, "balance");
        let balance = |id: u64| flows.node.query(ALICE, LEDGER, balance, id.encode());
        assert_eq!(balance(1), Outcome::Done(70u64.encode()));
        assert_eq!(balance(2), Outcome::Done(30u64.encode()));

        // Collected once its result has been kept long enough.
        let result = flows.sweep(defaults::WORKFLOW_KEPT_MS - 1);
        assert!(result.steps.len() == 1, "not yet: {:?}", result.steps);
        let result = flows.sweep(1);
        assert_eq!(due(&result, 0).writes.len(), 2, "its record and its row");
        assert_eq!(flows.node.get(&keys::workflow(WorkflowId(0))), None);
        assert_eq!(
            flows
                .node
                .get(&keys::due(collected, Due::Workflow(WorkflowId(0)))),
            None
        );
        assert_eq!(flows.count(&keys::live_workflows()), None);
        assert_eq!(flows.count(&keys::next_workflow()), Some(1));
    }
}

/// A saga: five awaits in turn, each answer counted as a sale before the
/// next request, the workflow's memory carried from step to step. Batches
/// of the default budget.
#[test]
fn a_saga_awaits_five_answers() {
    for backend in Node::backends() {
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let start = flows.start("saga", (RISK.0, 5u32));
        let result = flows.batch(1, vec![start]);
        asks_risk(&flows, due(&result, 0), 0, 0, 1);
        for step in 0..5u64 {
            let answer = flows.reply(RISK, 0, step, Answer::Done((10 * (step + 1)).encode()));
            let result = flows.batch(1, vec![answer]);
            if step < 4 {
                asks_risk(&flows, ran(&result.steps[0]), 0, step + 1, step + 2);
                assert_eq!(flows.record(0).awaits, step + 2);
            }
        }
        let answers: Vec<u64> = vec![10, 20, 30, 40, 50];
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(answers.encode()));
        assert_eq!(flows.sales(), 150);
    }
}

/// A long computation, pausing at a sleep after filling 2 MiB with
/// pseudo-random words and after each round: its first pause stores every
/// page it wrote, far past the 64 KiB a result takes inline, and its
/// result is the uninterrupted computation's. Batches of the default
/// budget.
#[test]
fn a_long_computation_pauses_at_its_sleeps() {
    for backend in Node::backends() {
        let (words, rounds) = (262_144u32, 16u32);
        let mut flows = Flows::at_default_budget(Node::on(backend));
        let start = flows.start("compute", (words, rounds));
        let refined = flows.refine(1, vec![start.clone()]);
        let output = refined.output_bounded(cap::OUTPUT).unwrap();
        assert!(output.len() > 2 << 20, "{} bytes", output.len());
        let result = flows.batch(1, vec![start]);
        let first = due(&result, 0);
        let stored = first
            .pages
            .iter()
            .filter(|page| page.hash.is_some())
            .count();
        assert!((512..600).contains(&stored), "{stored} pages");
        assert!(matches!(
            flows.record(0).state,
            WorkflowState::Sleeping { .. }
        ));
        for _ in 0..=rounds {
            let result = flows.sweep(1);
            assert_eq!(result.steps.len(), 2, "a sweep, then the step");
        }
        let mut data = vec![0u64; words as usize];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for value in data.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *value = state;
        }
        let chunk = data.len() / rounds as usize;
        for round in 0..rounds as usize {
            data[round * chunk..(round + 1) * chunk].sort_unstable();
        }
        let mut digest = 0u64;
        for (index, value) in data.iter().enumerate().step_by(997) {
            digest = digest.rotate_left(5) ^ value ^ index as u64;
        }
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(digest.encode()));
    }
}

/// A reply is consumed in its pair's order whatever it answers: one from
/// an agent the workflow does not await, for an await it does not hold, or
/// after its await is gone, is dropped, and the workflow goes on awaiting
/// the one it does.
#[test]
fn replies_from_others_late_or_stale_are_dropped() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("transfer", transfer(0));
        flows.batch(1, vec![start]);
        let awaiting = flows.record(0);
        let other = AgentId(8);
        let inputs = vec![
            flows.reply(other, 0, 0, Answer::Done(1u64.encode())),
            flows.reply(RISK, 0, 1, Answer::Done(1u64.encode())),
            flows.reply(RISK, 7, 0, Answer::Done(1u64.encode())),
        ];
        let result = flows.batch(1, inputs);
        for step in &result.steps {
            let run = ran(step);
            assert_eq!(run.outcome, Outcome::Done(vec![]));
            assert!(run.writes.is_empty() && run.messages.is_empty() && run.pages.is_empty());
        }
        assert_eq!(flows.record(0), awaiting, "still awaiting the risk agent");
        assert_eq!(flows.count(&keys::pair_in(other)), Some(1));
        assert_eq!(flows.count(&keys::pair_in(RISK)), Some(2));

        let answer = flows.reply(RISK, 0, 0, Answer::Done(0u64.encode()));
        let again = flows.reply(RISK, 0, 0, Answer::Done(0u64.encode()));
        let result = flows.batch(1, vec![answer, again]);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(0u64.encode()));
        let late = ran(&result.steps[1]);
        assert!(
            late.writes.is_empty() && late.pages.is_empty(),
            "the late one"
        );
        assert_eq!(flows.count(&keys::pair_in(RISK)), Some(4));
    }
}

/// An await's deadline is batch time: the step at it answers the await
/// `TimedOut`, and a reply at or after it is dropped, before that step as
/// after. A timer wakes its workflow in the first sweep at or past it.
#[test]
fn deadlines_expire_and_timers_fire_at_batch_time() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let transfer = flows.start("transfer", transfer(5));
        let nap = flows.start("nap", 5_000u64);
        let result = flows.batch(1, vec![transfer, nap]);
        assert_eq!(result.steps.len(), 4, "two starts, each with its step");
        let started = flows.time;
        assert_eq!(
            flows.record(1).state,
            WorkflowState::Sleeping {
                until: started + 5_000
            }
        );
        let result = flows.sweep(4_999);
        assert_eq!(result.steps.len(), 1, "nothing due yet");
        let result = flows.sweep(1);
        let woke = due(&result, 1);
        assert_eq!(woke.outcome, Outcome::Done(vec![]));
        assert_eq!(
            ended(&flows.record(1)),
            &Outcome::Done((started + 5_000).encode())
        );

        let result = flows.sweep(25_000 - 1);
        assert_eq!(result.steps.len(), 1, "the deadline is not yet");
        // A reply at the deadline, before the deadline's step: dropped, the
        // deadline being batch time.
        let at_deadline = flows.reply(RISK, 0, 0, Answer::Done(5u64.encode()));
        let awaiting = flows.record(0);
        let result = flows.batch(1, vec![at_deadline]);
        assert!(ran(&result.steps[0]).writes.is_empty());
        assert_eq!(flows.record(0), awaiting);
        let result = flows.sweep(0);
        due(&result, 0);
        // The shop's `ShopError::TimedOut`.
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Failed {
                code: Failure::Handler,
                detail: vec![1],
            }
        );
        let late = flows.reply(RISK, 0, 0, Answer::Done(5u64.encode()));
        let result = flows.batch(1, vec![late]);
        assert!(ran(&result.steps[0]).writes.is_empty());
        assert_eq!(flows.sales(), 0);
    }
}

/// A step that traps fails its workflow: its own effects go, the earlier
/// steps' stay, and the workflow ends failed, its pages and pin gone.
#[test]
fn a_trap_fails_the_workflow_and_keeps_its_earlier_steps() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("fragile", RISK.0);
        flows.batch(1, vec![start]);
        assert_eq!(flows.sales(), 1, "the first step's sale");
        let held = flows.pages(0);
        let answer = flows.reply(RISK, 0, 0, Answer::Done(1u64.encode()));
        let result = flows.batch(1, vec![answer]);
        let trapped = ran(&result.steps[0]);
        assert_eq!(
            trapped.outcome,
            Outcome::Failed {
                code: Failure::Trapped,
                detail: vec![],
            }
        );
        assert_eq!(trapped.pages.len(), held.len());
        assert!(trapped.pages.iter().all(|page| page.hash.is_none()));
        assert_eq!(flows.sales(), 1, "the trapping step's sale went");
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Failed {
                code: Failure::Trapped,
                detail: vec![],
            }
        );
        let program = flows.program("shop");
        assert_eq!(flows.count(&keys::workflow_pins(&program)), None);
        for (index, _) in held {
            assert_eq!(flows.node.get(&keys::page(WorkflowId(0), index)), None);
        }
    }
}

/// A page written back to its base, zeros or the program's image, is
/// dropped: its row goes, and a restore gives the base again.
#[test]
fn pages_written_back_to_their_base_are_dropped() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("scratch", RISK.0);
        flows.batch(1, vec![start]);
        let first = flows.pages(0);
        let marked: Vec<u32> = first
            .iter()
            .filter(|(_, bytes)| {
                bytes.iter().all(|byte| *byte == 0xab) || bytes.iter().all(|byte| *byte == 0x55)
            })
            .map(|(index, _)| *index)
            .collect();
        assert_eq!(marked.len(), 2, "the zeroed page and the image's");
        let answer = flows.reply(RISK, 0, 0, Answer::Done(1u64.encode()));
        let result = flows.batch(1, vec![answer]);
        let dropped: Vec<u32> = ran(&result.steps[0])
            .pages
            .iter()
            .filter(|page| page.hash.is_none())
            .map(|page| page.index)
            .collect();
        for index in &marked {
            assert!(dropped.contains(index), "page {index:#x} dropped");
            assert_eq!(flows.node.get(&keys::page(WorkflowId(0), *index)), None);
        }
        let answer = flows.reply(RISK, 0, 1, Answer::Done(1u64.encode()));
        flows.batch(1, vec![answer]);
        let sums = (4096 * (0xab + 0x55u64), 4096 * 7u64);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(sums.encode()));
    }
}

/// An agent that starts a workflow is answered `Started` with its id, and
/// its wait for the result is answered once the workflow ends, or at once
/// when it has; only the owner may wait.
#[test]
fn an_owning_agent_waits_for_a_result_by_its_id() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let owner = AgentId(5);
        let nap = flows.method("nap");
        let theirs = Await {
            workflow: WorkflowId(70),
            counter: 0,
        };
        let call = Body::Call {
            instance: SHOP,
            method: nap,
            arguments: 1_000u64.encode(),
            awaiting: Some(theirs),
        };
        let start = flows.message(owner, call);
        let result = flows.batch(1, vec![start]);
        let started = Outgoing {
            to: owner,
            body: Body::Reply {
                awaiting: theirs,
                answer: Answer::Started(WorkflowId(0)),
            },
        };
        assert_eq!(ran(&result.steps[0]).messages, [started]);
        assert_eq!(flows.record(0).owner, Principal::Agent(owner));

        let second = Await {
            counter: 1,
            ..theirs
        };
        let wait = flows.message(
            owner,
            Body::Wait {
                workflow: WorkflowId(0),
                awaiting: second,
            },
        );
        let stranger = flows.message(
            AgentId(6),
            Body::Wait {
                workflow: WorkflowId(0),
                awaiting: theirs,
            },
        );
        let result = flows.batch(1, vec![wait, stranger]);
        assert!(
            ran(&result.steps[0]).messages.is_empty(),
            "held until it ends"
        );
        assert_eq!(flows.record(0).waiter, Some(second));
        let unknown = Answer::Failed {
            code: Failure::Unknown,
            detail: vec![],
        };
        assert_eq!(
            ran(&result.steps[1]).messages[0].body,
            Body::Reply {
                awaiting: theirs,
                answer: unknown,
            }
        );

        let result = flows.sweep(1_000);
        let woke = flows.time;
        let answered = Outgoing {
            to: owner,
            body: Body::Reply {
                awaiting: second,
                answer: Answer::Done(woke.encode()),
            },
        };
        assert_eq!(due(&result, 0).messages, [answered]);
        assert_eq!(flows.record(0).waiter, None);

        let third = Await {
            counter: 2,
            ..theirs
        };
        let again = flows.message(
            owner,
            Body::Wait {
                workflow: WorkflowId(0),
                awaiting: third,
            },
        );
        let result = flows.batch(1, vec![again]);
        assert_eq!(
            ran(&result.steps[0]).messages[0].body,
            Body::Reply {
                awaiting: third,
                answer: Answer::Done(woke.encode()),
            }
        );
    }
}

/// A workflow starts another agent's workflow and awaits its result: two
/// awaits, the first answered `Started`, the second with the result.
#[test]
fn a_workflow_starts_another_agents_and_awaits_its_result() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("delegate", (RISK.0, SHOP.0, 500u64));
        let result = flows.batch(1, vec![start]);
        let nap = flows.method("nap");
        let starting = Outgoing {
            to: RISK,
            body: Body::Call {
                instance: SHOP,
                method: nap,
                arguments: 500u64.encode(),
                awaiting: Some(Await {
                    workflow: WorkflowId(0),
                    counter: 0,
                }),
            },
        };
        assert_eq!(due(&result, 0).messages, [starting]);
        let started = flows.reply(RISK, 0, 0, Answer::Started(WorkflowId(77)));
        let result = flows.batch(1, vec![started]);
        let waiting = Outgoing {
            to: RISK,
            body: Body::Wait {
                workflow: WorkflowId(77),
                awaiting: Await {
                    workflow: WorkflowId(0),
                    counter: 1,
                },
            },
        };
        assert_eq!(ran(&result.steps[0]).messages, [waiting]);
        let result_in = flows.reply(RISK, 0, 1, Answer::Done(12_345u64.encode()));
        flows.batch(1, vec![result_in]);
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Done((WorkflowId(77), 12_345u64).encode())
        );
    }
}

/// A workflow keeps the program it started on, its instance's actor
/// program, whatever an upgrade installs meanwhile: it pins it until it
/// ends.
#[test]
fn a_workflow_keeps_its_program_through_an_upgrade() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("transfer", transfer(0));
        flows.batch(1, vec![start]);
        let upgrade = flows.install("lean");
        let result = flows.batch(1, vec![upgrade]);
        ran(&result.steps[0]);
        let shop = flows.program("shop");
        assert_eq!(flows.record(0).program, shop);
        assert_eq!(flows.count(&keys::workflow_pins(&shop)), Some(1));
        let answer = flows.reply(RISK, 0, 0, Answer::Done(9u64.encode()));
        flows.batch(1, vec![answer]);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(9u64.encode()));
        assert_eq!(flows.count(&keys::workflow_pins(&shop)), None);

        // A start now runs the program installed since.
        let start = flows.start("transfer", transfer(0));
        let result = flows.batch(1, vec![start]);
        assert_eq!(flows.record(1).program, flows.program("lean"));
        asks_risk(&flows, due(&result, 1), 1, 0, 0);
    }
}

/// The caps: a start past the agent's workflows fails, as does one of a
/// program that may write more than a workflow's pages; a step that writes
/// past its pages, or would leave its snapshot holding more than it may,
/// fails its workflow.
#[test]
fn the_caps_hold() {
    for backend in Node::backends() {
        let cap = Outcome::Failed {
            code: Failure::Cap,
            detail: vec![],
        };
        let mut flows = Flows::new(Node::on(backend));
        flows.node.state.insert(
            keys::live_workflows(),
            stored(&(defaults::MAX_WORKFLOWS - 1).encode()),
        );
        let inputs = vec![flows.start("nap", 1u64), flows.start("nap", 1u64)];
        let work = flows.node.work(flows.time + 1, inputs);
        let result = split_output(&flows.node.refine(&work)).unwrap().0;
        assert_eq!(
            ran(&result.steps[0]).outcome,
            Outcome::Started(WorkflowId(0))
        );
        assert_eq!(ran(&result.steps[2]).outcome, cap, "one past the agent's");

        let mut flows = Flows::new(Node::on(backend));
        let install = flows.install("huge");
        flows.batch(1, vec![install]);
        let start = flows.start("hog", 1u32);
        let result = flows.batch(1, vec![start]);
        assert_eq!(ran(&result.steps[0]).outcome, cap, "a program too large");

        let mut flows = Flows::new(Node::on(backend));
        let install = flows.install("big");
        flows.batch(1, vec![install]);
        let past = (cap::STEP_PAGES + 4096) as u32;
        let start = flows.start("hog", past);
        let result = flows.batch(1, vec![start]);
        assert_eq!(
            due(&result, 0).outcome,
            cap,
            "a step writing past its pages"
        );
        assert_eq!(ended(&flows.record(0)), &cap);
    }
}

/// A workflow of an instance installed for JAM holds its memory to JAM's
/// limits, on every host: a step writing past its pages fails `Cap`, and so
/// does one leaving its snapshot more pages than it may hold, where one
/// installed for VOS pauses.
#[test]
fn a_workflow_installed_for_jam_holds_its_pages_to_jam_limits() {
    use vos_wire::abi::cap::JAM;
    use vos_wire::result::PAGE;
    let cap = Outcome::failed(Failure::Cap);
    let paused = Outcome::Done(vec![]);
    let half = (JAM.held_pages * PAGE * 3 / 4) as u32;
    for target in [Target::Vos, Target::Jam] {
        for node in [Node::new(), Node::jam(true)] {
            let mut flows = Flows::new(node);
            let install = flows.install_for("lean", target);
            flows.batch(1, vec![install]);
            let past = (JAM.step_pages + PAGE) as u32;
            let inputs = vec![
                flows.start("hog", past),
                flows.start("fill", (0u32, vec![half; 2])),
            ];
            let result = flows.batch(1, inputs);
            let jam = target == Target::Jam;
            let expected = |capped: bool| if capped { &cap } else { &paused };
            assert_eq!(
                &due(&result, 0).outcome,
                expected(jam),
                "{target:?}: past its step's pages"
            );
            assert_eq!(&due(&result, 1).outcome, &paused, "{target:?}: within them");
            let result = flows.sweep(1);
            assert_eq!(
                &due(&result, 1).outcome,
                expected(jam),
                "{target:?}: past its held pages"
            );
        }
    }
}

/// A workflow of an instance installed for JAM whose step comes past what
/// its target keeps of its pages ends at that step, `Expired`, without
/// restoring them, and drops them: on every host, as in the model. Within
/// it, as for VOS, it resumes.
#[test]
fn a_jam_workflow_past_its_pages_keep_expires() {
    use vos_wire::abi::cap::JAM;
    let kept = JAM.pages_kept.expect("JAM keeps pages for a time");
    for target in [Target::Vos, Target::Jam] {
        for node in [Node::new(), Node::jam(true)] {
            let mut flows = Flows::new(node);
            let install = flows.install_for("lean", target);
            flows.batch(1, vec![install]);
            let inputs = vec![flows.start("nap", kept - 10), flows.start("nap", kept + 10)];
            flows.batch(1, inputs);
            let held = |flows: &Flows, id| flows.record(id).snapshot.unwrap().pages.len();
            assert!(
                held(&flows, 0) > 0 && held(&flows, 1) > 0,
                "they hold pages"
            );
            let result = flows.sweep(kept - 5);
            assert_eq!(due(&result, 0).outcome, Outcome::Done(vec![]), "within");
            let woke = ended(&flows.record(0)).clone();
            assert!(matches!(woke, Outcome::Done(_)), "{woke:?}");
            let result = flows.sweep(20);
            let late = &due(&result, 1);
            if target == Target::Jam {
                let expired = Outcome::failed(Failure::Expired);
                assert_eq!(late.outcome, expired);
                assert!(late.pages.iter().all(|page| page.hash.is_none()));
                assert_eq!(ended(&flows.record(1)), &expired);
            } else {
                assert_eq!(late.outcome, Outcome::Done(vec![]));
                assert!(matches!(ended(&flows.record(1)), Outcome::Done(_)));
            }
        }
    }
}

/// A derived program holds the heap a handler maps, and a workflow's
/// machine maps the rest of its actor's heap past it: a computation larger
/// than a handler's heap runs to its end, beside handlers, on every host
/// and as the model runs it.
#[test]
fn a_workflow_maps_the_heap_its_program_leaves_out() {
    use vos_pvm_compiler::INVOCATION_HEAP;
    let words = (2 * INVOCATION_HEAP / 8) as u32;
    for node in [Node::new(), Node::jam(true)] {
        let mut flows = Flows::new(node);
        let install = flows.install_derived("shop");
        flows.batch(1, vec![install]);
        let sell = flows.method("sell");
        let sold = flows.sessions.request(ALICE, SHOP, sell, 5u64);
        let start = flows.start("compute", (words, 2u32));
        let result = flows.batch(1, vec![sold, start]);
        assert_eq!(ran(&result.steps[0]).outcome, Outcome::Done(5u64.encode()));
        assert_eq!(due(&result, 0).outcome, Outcome::Done(vec![]));
        let held = flows.record(0).snapshot.unwrap().pages.len();
        assert!(
            held as u64 * PAGE_U64 > INVOCATION_HEAP,
            "{held} pages held"
        );
        for _ in 0..3 {
            flows.sweep(1);
        }
        assert!(matches!(ended(&flows.record(0)), Outcome::Done(_)));
    }
}

/// The bytes of a page.
const PAGE_U64: u64 = vos_wire::result::PAGE as u64;

/// A workflow's machine counts toward the machines a step may hold, though
/// it is on no call stack: its chain of nested calls fails one call shorter
/// than a handler's, on the depth rule, never on the host's machines.
#[test]
fn a_workflows_nested_calls_count_its_own_machine() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        flows.callers(100..=170);
        let inputs = vec![
            flows.start("chain", (100u32, 61u32)),
            flows.start("chain", (100u32, 62u32)),
        ];
        let result = flows.batch(1, inputs);
        assert_eq!(due(&result, 0).outcome, Outcome::Done(vec![]));
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(61u32.encode()));
        let depth = Outcome::Failed {
            code: Failure::Depth,
            detail: vec![],
        };
        assert_eq!(due(&result, 1).outcome, depth, "a sixty-fourth machine");
        assert_eq!(ended(&flows.record(1)), &depth);
    }
}

/// An attest a workflow's call makes commits with the step's snapshot.
#[test]
fn a_nested_attest_commits_with_its_step() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let values = vec![1u64, 2, 3];
        let start = flows.start("audit", (LEDGER.0, values.clone()));
        let result = flows.batch(1, vec![start]);
        let attests = &due(&result, 0).attests;
        assert_eq!(attests.len(), 1);
        assert_eq!(attests[0].arguments, values.encode());
        let checksum = attests[0].output.clone();
        flows.sweep(1);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(checksum));
    }
}

/// A precompile the agent serves writes its output into a page the
/// workflow never wrote itself, through the agent's tracked write: the
/// page is held, restored, and written again, step after step.
#[test]
fn a_precompiles_output_is_tracked_across_pauses() {
    let rounds = 3u32;
    let mut h = [0u64; 8];
    for round in 0..rounds {
        let block = [u64::from_le_bytes([round as u8; 8]); 16];
        let counter = u128::from(round + 1) * 128;
        h = vos_pvm::precompile::compress(&h, &block, counter, round + 1 == rounds);
    }
    let digest: Vec<u8> = h.iter().flat_map(|word| word.to_le_bytes()).collect();
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("digest", rounds);
        let result = flows.batch(1, vec![start]);
        let stored = due(&result, 0)
            .pages
            .iter()
            .filter(|page| page.hash.is_some())
            .count();
        assert!(stored >= 2, "the stack's and the state's: {stored}");
        for _ in 0..rounds {
            flows.sweep(1);
        }
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Done(digest[..32].to_vec().encode())
        );
    }
}

/// Two steps of one workflow in one batch: the second, resumed by a reply,
/// restores the pages the first stored, from the batch's own writes.
#[test]
fn a_workflow_steps_twice_in_one_batch() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("transfer", transfer(0));
        let answer = flows.reply(RISK, 0, 0, Answer::Done(7u64.encode()));
        let result = flows.batch(1, vec![start, answer]);
        assert_eq!(result.steps.len(), 3, "the start, its step, the reply's");
        assert!(due(&result, 0).pages.iter().any(|page| page.hash.is_some()));
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(7u64.encode()));
    }
}

/// A workflow's request of its own agent traps: it calls it instead.
#[test]
fn a_request_of_its_own_agent_traps() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("saga", (crate::common::AGENT.0, 1u32));
        let result = flows.batch(1, vec![start]);
        let trapped = Outcome::Failed {
            code: Failure::Trapped,
            detail: vec![],
        };
        assert_eq!(due(&result, 0).outcome, trapped);
    }
}

/// A sleep until the batch's own time lies a millisecond ahead: a sweep in
/// the same millisecond leaves it, and the next wakes it, so the head of
/// the due index never stays where a sweep left it.
#[test]
fn a_sleep_lies_ahead_of_its_own_batch() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("nap", 0u64);
        flows.batch(1, vec![start]);
        let slept = flows.time;
        assert_eq!(
            flows.record(0).state,
            WorkflowState::Sleeping { until: slept + 1 }
        );
        let result = flows.sweep(0);
        assert_eq!(result.steps.len(), 1, "not in its own millisecond");
        let result = flows.sweep(1);
        due(&result, 0);
        assert_eq!(
            ended(&flows.record(0)),
            &Outcome::Done((slept + 1).encode())
        );
    }
}

/// A row of the due index whose workflow is gone, or whose workflow's
/// record lies elsewhere, is deleted by the step it makes, and nothing
/// else moves.
#[test]
fn orphan_and_stale_rows_of_the_due_index_go() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("nap", 60_000u64);
        flows.batch(1, vec![start]);
        let record = flows.record(0);
        let stale = keys::due(flows.time, Due::Workflow(WorkflowId(0)));
        let orphan = keys::due(flows.time, Due::Workflow(WorkflowId(9)));
        for row in [&stale, &orphan] {
            flows.node.state.insert(row.clone(), stored(&[]));
        }
        let result = flows.sweep(1);
        assert_eq!(result.steps.len(), 3, "the sweep, then each row's step");
        assert_eq!(flows.node.get(&stale), None);
        assert_eq!(flows.node.get(&orphan), None);
        assert_eq!(flows.record(0), record, "the workflow sleeps on");
        assert!(
            flows
                .node
                .get(&keys::due(record.due, Due::Workflow(WorkflowId(0))))
                .is_some()
        );
    }
}

/// Only workflows that have not ended count toward the agent's: one that
/// ends makes room for a start, though its result is kept.
#[test]
fn ended_workflows_leave_room_for_starts() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        flows.node.state.insert(
            keys::live_workflows(),
            stored(&(defaults::MAX_WORKFLOWS - 1).encode()),
        );
        let live = (defaults::MAX_WORKFLOWS - 1).encode();
        flows.kit.set_row(keys::live_workflows(), live);
        let inputs = vec![flows.start("nap", 0u64), flows.start("nap", 0u64)];
        let result = flows.batch(1, inputs);
        let cap = Outcome::Failed {
            code: Failure::Cap,
            detail: vec![],
        };
        assert_eq!(ran(&result.steps[2]).outcome, cap, "one past the agent's");
        flows.sweep(1);
        ended(&flows.record(0));
        let start = flows.start("nap", 0u64);
        let result = flows.batch(1, vec![start]);
        assert_eq!(
            ran(&result.steps[0]).outcome,
            Outcome::Started(WorkflowId(1))
        );
    }
}

/// The agent's state lost data it wrote: a page row gone, or not what its
/// hash says, or a record that does not decode. The refine stops at the
/// agent's report to the node, which halts, rather than fail the workflow
/// or drop its reply as their fault.
#[test]
fn lost_workflow_state_stops_the_refine() {
    for backend in Node::backends() {
        let mut flows = Flows::new(Node::on(backend));
        let start = flows.start("transfer", transfer(0));
        flows.batch(1, vec![start]);
        let (index, _) = flows.pages(0)[0];
        let row = keys::page(WorkflowId(0), index);
        let held = flows.node.state[&row].clone();
        let answer = flows.reply(RISK, 0, 0, Answer::Done(7u64.encode()));
        let mut corrupt = held.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let record = keys::workflow(WorkflowId(0));
        let kept = flows.node.state[&record].clone();
        for (key, value) in [
            (row.clone(), None),
            (row.clone(), Some(corrupt)),
            (record.clone(), Some(stored(&[9]))),
        ] {
            match value {
                Some(value) => flows.node.state.insert(key.clone(), value),
                None => flows.node.state.remove(&key),
            };
            let refined = flows.refine(1, vec![answer.clone()]);
            assert_eq!(
                refined.exit,
                vos_pvm::ExitReason::HostCall(vos_wire::abi::surface::LOST),
                "{key:?}"
            );
            flows.node.state.insert(row.clone(), held.clone());
            flows.node.state.insert(record.clone(), kept.clone());
        }
        flows.batch(1, vec![answer]);
        assert_eq!(ended(&flows.record(0)), &Outcome::Done(7u64.encode()));
    }
}

/// A program the agent's state pins, a workflow's or an installed
/// instance's, that a VOS node no longer holds is data the node lost: the
/// refine stops rather than fail the step for the node's fault. A JAM
/// node's preimages lacking it fail the workflow, `Unloadable`.
#[test]
fn a_lost_pinned_program_stops_the_refine() {
    let mut flows = Flows::new(Node::new());
    let start = flows.start("transfer", transfer(0));
    flows.batch(1, vec![start]);
    let answer = flows.reply(RISK, 0, 0, Answer::Done(7u64.encode()));
    let program = flows.program("shop");
    let blob = flows.node.forget(&program);
    let refined = flows.refine(1, vec![answer.clone()]);
    let lost = vos_pvm::ExitReason::HostCall(vos_wire::abi::surface::LOST);
    assert_eq!(refined.exit, lost, "a workflow's program");
    flows.node.add(&blob);
    let counter = flows.node.forget(&ProgramHash::of(&flows.actors.counter));
    let increment = flows.actors.method(COUNTER, "increment");
    let request = flows.sessions.request(ALICE, COUNTER, increment, 1u64);
    assert_eq!(flows.refine(1, vec![request]).exit, lost, "a handler's");
    flows.node.add(&counter);
    flows.batch(1, vec![answer]);
    assert_eq!(ended(&flows.record(0)), &Outcome::Done(7u64.encode()));

    let mut flows = Flows::new(Node::jam(true));
    let start = flows.start("transfer", transfer(0));
    flows.unmodelled(1, vec![start]);
    let program = flows.program("shop");
    flows.node.forget(&program);
    let answer = flows.reply(RISK, 0, 0, Answer::Done(7u64.encode()));
    flows.unmodelled(1, vec![answer]);
    let unloadable = Outcome::Failed {
        code: Failure::Unloadable,
        detail: vec![],
    };
    assert_eq!(ended(&flows.record(0)), &unloadable);
}
