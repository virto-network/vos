use embassy_executor::SendSpawner;

use super::io::{Input, Output};

#[embassy_executor::task]
pub async fn handle_connections(_s: SendSpawner) {
    let sh = Shell::new();
    sh.eval_input().await;
}

pub struct Shell {
    io: (Input, Output),
}

impl Shell {
    pub fn new() -> Self {
        Shell {
            io: (Input::new(), Output::new()),
        }
    }

    pub async fn eval_input(&self) {}

    fn eval(&self, input: &str) {}
}
