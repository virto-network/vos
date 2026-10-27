//! A poll of a space's members, each voting by its pseudonym: auth guards
//! (`identity-and-authority.md` §5), one `once` in the scope `"vote"`,
//! another in `"vote/2"`, and a plain one, `"login"`. Its agent needs the
//! credential actor.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub enum PollError {
    /// Choice 0 is no choice: the handler refuses it.
    #[codec(index = 0)]
    NoChoice,
}

#[actor]
pub struct Poll {
    votes: Table<u8, u32>,
    logins: u64,
}

#[messages]
impl Poll {
    pub fn new() -> Self {
        Self {
            votes: Table::default(),
            logins: 0,
        }
    }

    /// One vote for `choice`, once a member: the count after it.
    #[msg(credential = Auth("vote"), once)]
    pub async fn vote(&mut self, choice: u8) -> Result<u32, PollError> {
        self.cast(choice)
    }

    /// One vote of the next round, a scope of its own.
    #[msg(credential = Auth("vote/2"), once)]
    pub async fn vote_again(&mut self, choice: u8) -> Result<u32, PollError> {
        self.cast(choice)
    }

    /// A member signed in: its pseudonym in the scope `"login"`.
    #[msg(credential = Auth("login"))]
    pub async fn login(&mut self, ctx: &mut Command<Self>) -> Option<[u8; 32]> {
        self.logins += 1;
        ctx.nullifier()
    }

    /// The votes `choice` holds.
    #[msg]
    pub async fn tally(&self, choice: u8) -> u32 {
        self.votes.get(&choice).unwrap_or(0)
    }

    /// The sign-ins so far.
    #[msg]
    pub async fn logins(&self) -> u64 {
        self.logins
    }
}

impl Poll {
    fn cast(&mut self, choice: u8) -> Result<u32, PollError> {
        if choice == 0 {
            return Err(PollError::NoChoice);
        }
        let count = self.votes.get(&choice).unwrap_or(0) + 1;
        self.votes.insert(&choice, &count);
        Ok(count)
    }
}
