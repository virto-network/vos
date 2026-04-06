//! Nushell agent — stub for a nu script interpreter.
//!
//! Actors appear as pipeable commands in nu scripts. Not yet implemented.

use vos::actors::context::ServiceId;
use vos::{actor, messages, lifecycle};

#[actor]
struct Nushell {
    children: Vec<u32>,
}

#[messages]
impl Nushell {
    fn new(children: Vec<u32>) -> Self {
        println!("nushell: init (stub)");

        let self_id = lifecycle::service_id();
        vos::hostcalls::transfer(ServiceId(self_id), 0, 0, &NushellMsg::Run(Run).to_bytes());

        Nushell { children }
    }

    #[msg]
    async fn run(&mut self, _ctx: &mut Context<Self>) {
        println!("nushell: not yet implemented");
    }
}
