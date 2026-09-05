use vos::prelude::*;

struct Example;

#[messages(agent)]
impl Example {
    fn new() -> Self { Self }
    #[msg(query, space_role = SpaceRole::Member, space_role_id = "0000000000000000000000000000000000000000000000000000000000000000")]
    fn read(&self) {}
}

fn main() {}
