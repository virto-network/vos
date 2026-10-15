//! A client's reads of its counter and its inbox, each checked.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vos_node::client::ClientError;
use vos_wire::Decode;
use vos_wire::ids::InstanceId;
use vos_wire::ingress::{Consistency, Rejection, Response};
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;

use super::{Client, post};
use crate::calls;
use crate::model::{INBOX, Nodes};

impl Client {
    /// Read the counter until `done`, at every node in turn, by read index
    /// and at the floor its answers give, and check each read. Now and
    /// then it reads its inbox, which `previous` forwards to.
    pub fn read(&self, nodes: &dyn Nodes, done: &AtomicBool, previous: &Client) {
        let mut floor = 0;
        let mut last = 0;
        let mut inbox = 0;
        // The most any read showed.
        let mut seen = 0;
        let mut turn = u64::from(self.number);
        while !done.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
            turn += 1;
            let at = super::node_at(turn, nodes.count());
            let (prefix, prefix_at) = {
                let acked = self.acked.lock().unwrap();
                (acked.prefix, acked.at)
            };
            let linearizable = turn.is_multiple_of(2);
            let consistency = if linearizable {
                Consistency::Linearizable
            } else {
                floor = floor.max(prefix_at);
                Consistency::Applied { at: floor }
            };
            // Now and then the inbox: what the previous client forwarded,
            // in its order.
            if turn.is_multiple_of(3) {
                let answer = self.read_at(nodes, at, INBOX, Consistency::Applied { at: floor });
                let sent = previous.sent();
                if let Ok((value, answered_at)) = answer {
                    // Reads never go back only at the client's floor, which
                    // this one raises.
                    floor = floor.max(answered_at);
                    assert!(
                        previous.is_prefix(sent, value, true),
                        "client {}: its inbox at node {at} holds {value}, no prefix of what was forwarded",
                        self.number
                    );
                    assert!(
                        value >= inbox,
                        "client {}: its inbox at node {at} went back, from {inbox} to {value}",
                        self.number
                    );
                    inbox = value;
                    nodes.log().saw("read of an inbox");
                }
                continue;
            }
            let answer = self.read_at(nodes, at, self.instance, consistency);
            let sent = self.sent();
            let (value, answered_at) = match answer {
                Ok(read) => read,
                // Signed before every clock jumped, a query may be stale.
                Err(Ok(
                    Response::Rejected(Rejection::Behind | Rejection::StaleQuery { .. })
                    | Response::TimedOut
                    | Response::Stopped
                    | Response::Unavailable
                    | Response::NotLeader { .. }
                    | Response::Elsewhere { .. },
                ))
                | Err(Err(_)) => {
                    nodes.log().saw("read unanswered");
                    continue;
                }
                Err(Ok(other)) => {
                    panic!("client {}: a read at node {at}: {other:?}", self.number)
                }
            };
            let earlier = seen;
            seen = seen.max(value);
            // The applied requests are a prefix of those sent: the value is
            // the total of one. A forward leaves the total as it was, so
            // reads compare totals.
            assert!(
                self.is_prefix(sent, value, false),
                "client {}: read {value} at node {at}, no total of up to {sent} requests",
                self.number
            );
            let answered = self.total(prefix);
            if linearizable {
                // Every read before it showed committed state, which a read
                // index taken later covers.
                assert!(
                    value >= earlier,
                    "client {}: a linearizable read at node {at} saw {value}, an earlier read {earlier}",
                    self.number
                );
                assert!(
                    value >= answered,
                    "client {}: a linearizable read at node {at} saw {value}, {prefix} requests answered before it made {answered}",
                    self.number
                );
                nodes.log().saw("read linearizable");
            } else {
                assert!(
                    value >= last,
                    "client {}: a read at node {at} went back, from {last} to {value}",
                    self.number
                );
                assert!(
                    value >= answered,
                    "client {}: a read at node {at} floored at {floor} saw {value}, {prefix} requests answered at {prefix_at} made {answered}",
                    self.number
                );
                last = value;
                floor = floor.max(answered_at);
                nodes.log().saw("read at a floor");
            }
        }
    }

    /// A counter's value read at node `at`, signed by this client's key,
    /// with the applied index it was read at; or the answer, or the
    /// error, it met instead.
    pub fn read_at(
        &self,
        nodes: &dyn Nodes,
        at: NodeNumber,
        instance: InstanceId,
        consistency: Consistency,
    ) -> Result<(u64, u64), Result<Response, ClientError>> {
        let path = format!("/agents/{}/queries", self.agent.0);
        match post(nodes, at, &path, &self.query(nodes, instance, consistency)) {
            Ok(Response::Ran {
                outcome: Outcome::Done(bytes),
                at,
            }) => Ok((u64::decode(&bytes).unwrap().0, at)),
            other => Err(other),
        }
    }

    /// A signed query of a counter's value.
    fn query(&self, nodes: &dyn Nodes, instance: InstanceId, consistency: Consistency) -> Vec<u8> {
        calls::signed_query(
            &self.identity,
            &self.key,
            nodes.time() + 60_000,
            consistency,
            instance,
            self.methods.value,
        )
    }
}
