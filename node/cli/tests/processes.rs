//! Node processes and the relay between them: a leader the relay cuts off
//! from the others is replaced, its calls go on, and it catches up once
//! the cut heals.

mod support;

use ed25519_dalek::SigningKey;
use support::{Options, Processes, converged, counter_agent, increment, method, wait_until};
use vos_node::client::Client;
use vos_wire::ids::InstanceId;

const COUNTER: InstanceId = InstanceId(1);

#[test]
fn a_leader_cut_off_by_the_relay_is_replaced_and_catches_up() {
    let space = Processes::start(3, Options::default());
    let agent = counter_agent(&space, COUNTER);
    let mut client = Client::new(space.target(1), SigningKey::from_bytes(&[31; 32]));
    let add = method(&mut client, agent, COUNTER, "increment");
    let mut total = 0;
    for by in 1..=5 {
        total += by;
        assert_eq!(increment(&mut client, agent, COUNTER, add, by), total);
    }
    let cut = space.leader(agent);
    space.relay.isolate(cut, 3);
    wait_until("another node leads", || {
        (1..=3).filter(|number| *number != cut).any(|number| {
            space
                .status(number, agent)
                .is_some_and(|status| status.leads)
        })
    });
    for by in 6..=10 {
        total += by;
        assert_eq!(increment(&mut client, agent, COUNTER, add, by), total);
    }
    space.relay.heal();
    converged(&space, agent);
    let status = space.status(cut, agent).expect("the cut node's replica");
    assert!(!status.leads, "the cut leader stepped down");
    assert_eq!(
        space.relay.own_drops(),
        0,
        "the relay lost nothing of itself"
    );
    assert!(space.troubles().is_empty(), "{:?}", space.troubles());
}
