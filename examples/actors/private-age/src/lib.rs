//! Private claim producer with ordinary and attested methods on one actor.

use vos::prelude::*;

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Debug, Clone, PartialEq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct AgeClaim {
    pub minimum_age: u8,
    pub adult: bool,
}

#[actor]
pub struct PrivateAge {
    age: u8,
}

#[messages]
impl PrivateAge {
    /// Keep the standalone package runnable from an empty root installation.
    fn new() -> Self {
        Self { age: 21 }
    }

    /// An ordinary method may coexist with attested methods.
    #[msg]
    fn configured(&self) -> bool {
        self.age != 0
    }

    /// The caller's member credential is a private proof input. The returned
    /// statement reveals the generated role predicate, never the member.
    #[msg(attested, space_role = SpaceRole::Member)]
    fn is_adult(&self, minimum_age: u8) -> AgeClaim {
        AgeClaim {
            minimum_age,
            adult: self.age >= minimum_age,
        }
    }
}
