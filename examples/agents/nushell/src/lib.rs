//! Nushell agent — stub for a nu script interpreter.
//!
//! Actors appear as pipeable commands in nu scripts. Not yet implemented.

use vos::prelude::*;
#[actor]
struct Nushell {
    children: Vec<u32>,
}

#[messages]
impl Nushell {
    fn new(children: Vec<u32>) -> Self {
        log::info!("nushell: init (stub)");
        Nushell { children }
    }

    #[msg]
    async fn start(&mut self, _ctx: &mut Context<Self>) {
        log::info!("nushell: not yet implemented");
    }
}

