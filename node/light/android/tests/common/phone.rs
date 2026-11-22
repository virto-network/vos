// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A phone over the world: its facility as `:vos` serves it, its user and
//! its keys (the shared [`Phone`]), stopped and started again from its
//! files ([`Held::restart`]), or killed at a request and started again from
//! its files as they were then ([`Held::kill`], [`Held::reborn`]).

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signer as _, SigningKey};
use s4_credential_contract::KeyAnswer;
use vos_facility::Enroll;
use vos_facility::chrome::Field;
use vos_facility::node::{Device, Node, Prompts};
use vos_facility::personal::{Claim, KitKind};

use super::*;

/// The first home's handle, and the second's.
pub const HOME: [u8; 32] = [0x61; 32];
pub const ELSEWHERE: [u8; 32] = [0x62; 32];

/// A phone: its facility over `world`, under a directory of its own, its
/// requests tagged with its seed.
pub struct Held {
    pub node: Node,
    pub hand: Arc<Phone>,
    pub tag: u8,
    pub _directory: tempfile::TempDir,
}

/// The facility of the phone tagged `tag`, its device `hand`'s, under
/// `directory`.
pub fn node_as(
    world: &Arc<World>,
    directory: &std::path::Path,
    tag: u8,
    hand: &Arc<Phone>,
) -> Node {
    node_over(
        world.dial_as(tag),
        directory,
        Arc::clone(hand) as Arc<dyn Device>,
    )
}

/// A phone of the world tagged `seed`, under a directory of its own.
pub fn phone(world: &Arc<World>, seed: u8) -> Held {
    let directory = tempfile::tempdir().unwrap();
    let hand = Arc::new(Phone::new(seed));
    Held {
        node: node_as(world, directory.path(), seed, &hand),
        hand,
        tag: seed,
        _directory: directory,
    }
}

/// What a process killed by [`Held::kill`] left: the phone's files as they
/// were as it died.
pub struct Corpse(Arc<Mutex<Option<tempfile::TempDir>>>);

/// `from`'s files and directories copied under `into`.
fn copy_tree(from: &std::path::Path, into: &std::path::Path) {
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let to = into.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            std::fs::create_dir(&to).unwrap();
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

impl Held {
    /// This phone's process dies at the `nth` request asking `step`, as
    /// Android kills `:vos`: its files are kept as they are at that
    /// moment, its user prompted for nothing it asks after, and nothing it
    /// asks after reaches the world. What it writes after is lost with it:
    /// [`Held::reborn`] starts the next process from the files kept.
    pub fn kill(
        &self,
        world: &World,
        step: world::Step,
        nth: usize,
        death: world::Death,
    ) -> Corpse {
        let kept = Arc::new(Mutex::new(None));
        let (from, into, hand) = (
            self._directory.path().to_owned(),
            Arc::clone(&kept),
            Arc::clone(&self.hand),
        );
        world.kill(self.tag, step, nth, death);
        world.on_death(
            self.tag,
            Box::new(move || {
                hand.die();
                let copy = tempfile::tempdir().unwrap();
                copy_tree(&from, copy.path());
                *into.lock().unwrap() = Some(copy);
            }),
        );
        Corpse(kept)
    }

    /// The process after `corpse`'s, started from the files kept as it
    /// died, its keys and its user the same.
    pub fn reborn(self, world: &Arc<World>, corpse: Corpse) -> Self {
        let Held {
            node: dead,
            hand,
            tag,
            _directory,
        } = self;
        drop(dead);
        drop(_directory);
        let directory = corpse.0.lock().unwrap().take().expect("the process died");
        world.revive(tag);
        hand.live();
        Held {
            node: node_as(world, directory.path(), tag, &hand),
            hand,
            tag,
            _directory: directory,
        }
    }

    /// The same phone's facility stopped and opened again from its files,
    /// its keys and its user the same: a process Android killed, started
    /// anew.
    pub fn restart(self, world: &Arc<World>) -> Self {
        let Held {
            node: stopped,
            hand,
            tag,
            _directory,
        } = self;
        drop(stopped);
        world.revive(tag);
        Held {
            node: node_as(world, _directory.path(), tag, &hand),
            hand,
            tag,
            _directory,
        }
    }

    /// Enrolled in the world's one space (the club) by its s4 session:
    /// its member.
    pub fn enroll(&self) -> [u8; 32] {
        let session = self.node.open_session(gateway());
        let enrolled = self
            .node
            .enroll(
                session,
                Enroll::read(&enrollment()).unwrap(),
                Arc::clone(&self.hand) as Arc<dyn Prompts>,
            )
            .unwrap();
        self.node.close(session);
        enrolled.member
    }

    pub fn claim(
        &self,
        world: &World,
        home: u32,
        kit: KitKind,
        label: &str,
    ) -> vos_facility::personal::Claimed {
        self.node
            .personal()
            .unwrap()
            .claim(
                &*self.hand,
                Claim {
                    home: home_of(world, home),
                    kit,
                    label: label.into(),
                },
            )
            .unwrap()
    }

    /// `joiner` paired from this phone: the code shown here, scanned there.
    pub fn pair(
        &self,
        joiner: &Held,
        label: &str,
    ) -> (
        vos_facility::personal::Paired,
        vos_facility::personal::Paired,
    ) {
        let code = self
            .node
            .personal()
            .unwrap()
            .pair_offer(&*self.hand)
            .unwrap();
        assert!(code.expires_ms > wall());
        std::thread::scope(|scope| {
            let opener = scope.spawn(|| self.node.personal().unwrap().pair_await(&*self.hand));
            let joined =
                joiner
                    .node
                    .personal()
                    .unwrap()
                    .pair_join(&*joiner.hand, &code.code, label);
            // The opener's refusal first: the joiner's is its wait running out.
            let opened = opener.join().unwrap().unwrap();
            (opened, joined.unwrap())
        })
    }
}

/// The club's tree holds `member`.
pub fn in_club(world: &World, member: &[u8; 32]) -> bool {
    world.state.lock().unwrap().spaces[&AGENT]
        .tree
        .holds(member)
}

/// Every connection so far: what it reached, on which circuit, under which
/// SSH key, carrying what.
pub fn seen(world: &World) -> Vec<world::Seen> {
    world.state.lock().unwrap().seen.clone()
}

/// The personal agents' ids.
pub fn personal_agents(world: &World) -> HashSet<u32> {
    world
        .state
        .lock()
        .unwrap()
        .personal
        .keys()
        .copied()
        .collect()
}

pub fn after(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms + 300));
}

/// A sign-in on `session` under `prompts`, once the path is held: a
/// refusal for a path not read yet syncs and asks again, `attempts` times
/// at most.
pub fn signs_in<P: Prompts + 'static>(
    node: &Node,
    session: u64,
    prompts: impl Fn() -> Arc<P>,
    attempts: usize,
) {
    for _ in 0..attempts {
        match node.sign_in(session, sign_in(), prompts()) {
            Err(refusal) if matches!(refusal.code, Code::NoPath | Code::Unclaimed) => {
                node.sync().unwrap();
            }
            signed => {
                signed.unwrap();
                return;
            }
        }
    }
    panic!("no path");
}
