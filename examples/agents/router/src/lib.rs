// Router agent — stateless message forwarder.
//
// Receives a `route` message with a target service ID and a dynamic message,
// invokes the target with a one-off invoke, and returns the reply.

use vos::lifecycle::InvokeResult;
use vos::prelude::*;
#[actor]
struct Router {
    children: Vec<u32>,
}

#[messages]
impl Router {
    fn new(children: Vec<u32>) -> Self {
        log::info!("router: init");
        Router { children }
    }

    /// Accept incoming messages and route them to children.
    #[msg]
    async fn start(&mut self, _ctx: &mut Context<Self>) {
        log::info!("router: ready with {} children", self.children.len());
    }

    /// Route a dynamic message to a target and return the reply.
    #[msg]
    async fn route(&mut self, target: u32, msg_name: String) -> vos::value::Value {
        match lifecycle::invoke(target, &Msg::new(msg_name), &[]) {
            InvokeResult::Done { reply, .. } | InvokeResult::Yielded { reply, .. } => {
                if reply.is_empty() {
                    vos::value::Value::Unit
                } else {
                    <vos::value::Value as Decode>::decode(&reply)
                }
            }
            InvokeResult::Panicked => {
                log::info!("router: target {} panicked", target);
                vos::value::Value::Unit
            }
            InvokeResult::NotFound => {
                log::info!("router: target {} not found", target);
                vos::value::Value::Unit
            }
            _ => vos::value::Value::Unit,
        }
    }
}

