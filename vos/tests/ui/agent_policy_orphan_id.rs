use vos::prelude::*;

struct Example;

#[messages(agent)]
impl Example {
    fn new() -> Self { Self }
    #[msg(query, actor_role_id = "1111111111111111111111111111111111111111111111111111111111111111")]
    fn read(&self) {}
}

fn main() {}
