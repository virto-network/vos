use vos::prelude::*;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
enum Role { User = 0, Admin = 1 }
impl vos::RoleByte for Role {
    fn from_byte(value: u8) -> Option<Self> { (value == 0).then_some(Self::User) }
    fn as_byte(self) -> u8 { self as u8 }
}

struct Example;

#[messages(agent)]
impl Example {
    fn new() -> Self { Self }
    #[msg(query, role = Role::Admin)]
    fn read(&self) {}
}

fn main() {}
