use embassy_executor::SendSpawner;

use super::io::{Input, Output};
#[embassy_executor::task]
pub async fn handle_connections(_s: SendSpawner) {
    let sh = Shell::new();
    sh.eval_input().await;
}

pub struct Shell {
    engine: interpreter::Engine,
    io: (Input, Output),
}

impl Shell {
    pub fn new() -> Self {
        Shell {
            engine: interpreter::Engine::new(),
            io: (Input::new(), Output::new()),
        }
    }

    pub async fn eval_input(&self) {}

    fn eval(&mut self, input: &str) {
        self.engine.eval(input);
    }
}

mod interpreter {
    use nu_engine::command_prelude::{EngineState, Stack, StateWorkingSet};

    pub struct Engine {
        state: EngineState,
    }

    impl Engine {
        pub fn new() -> Self {
            Self {
                state: EngineState::new(),
            }
        }

        pub fn eval(&mut self, prompt: &str) {
            let engine = EngineState::new();
            let stack = Stack::new();
            let delta = {
                let ws = StateWorkingSet::new(&engine);
                // ws.add_decl(Box::new());
                ws.render()
            };
            self.state.merge_delta(delta);
            self.state.cwd()
        }
    }
}
