// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A phone over the world: its facility as `:vos` serves it, its user and
//! its keys ([`Hand`]), stopped and started again from its files
//! ([`Held::restart`]).

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

pub struct Phone;

impl Device for Phone {
    fn kinds(&self) -> Vec<Kind> {
        vec![Kind::Keystore]
    }
}

/// A user and their phone's keys, in memory, kept across the facility's
/// restarts as the Keystore keeps them: each Keystore key its own HMAC key
/// (another alias, another secret; an alias never made, no key), a security
/// key's, and the admin keys made behind the biometric. It confirms every
/// form, writes down the phrase it is shown and enters the words it was
/// given.
pub struct Hand {
    pub source: [u8; 32],
    /// The Keystore's aliases made so far.
    pub aliases: Mutex<HashSet<Vec<u8>>>,
    pub security_key: [u8; 32],
    pub admins: Mutex<HashMap<[u8; 32], SigningKey>>,
    pub made: Mutex<u8>,
    /// Every phrase shown, the newest last.
    pub phrases: Mutex<Vec<String>>,
    /// The words to enter when asked.
    pub words: Mutex<Option<String>>,
    /// The admin key that signed last.
    pub signed: Mutex<Option<[u8; 32]>>,
    /// Every security-key kit's card shown: its rows.
    pub cards: Mutex<Vec<Vec<(String, String)>>>,
}

impl Hand {
    pub fn new(seed: u8) -> Arc<Self> {
        Arc::new(Self {
            source: [seed; 32],
            aliases: Mutex::new(HashSet::new()),
            security_key: [seed ^ 0x80; 32],
            admins: Mutex::new(HashMap::new()),
            made: Mutex::new(seed.wrapping_mul(16)),
            phrases: Mutex::new(Vec::new()),
            words: Mutex::new(None),
            signed: Mutex::new(None),
            cards: Mutex::new(Vec::new()),
        })
    }

    pub fn phrase(&self) -> String {
        self.phrases
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a phrase shown")
    }

    pub fn will_enter(&self, words: String) {
        *self.words.lock().unwrap() = Some(words);
    }

    pub fn admin_keys(&self) -> usize {
        self.admins.lock().unwrap().len()
    }

    pub fn signed_by(&self) -> [u8; 32] {
        self.signed.lock().unwrap().expect("an admin signature")
    }
}

pub fn hmac(key: &[u8; 32], input: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    mac.update(input);
    mac.finalize().into_bytes().to_vec()
}

impl Prompts for Hand {
    fn confirm(&self, form: Form) -> Answer {
        if form.title == "Your recovery phrase" {
            let words: Vec<String> = form
                .rows
                .iter()
                .filter(|(label, _)| label.parse::<u8>().is_ok())
                .map(|(_, word)| word.clone())
                .collect();
            assert!(
                form.rows.iter().any(|(label, _)| label == "Home"),
                "the kit's card"
            );
            assert_eq!(words.len(), 24);
            self.phrases.lock().unwrap().push(words.join(" "));
        }
        if form.title == "Your recovery key's card" {
            self.cards.lock().unwrap().push(form.rows.clone());
        }
        let values = form
            .fields
            .iter()
            .map(|Field { label, value }| match label.as_str() {
                "Words" => self.words.lock().unwrap().clone().expect("words to enter"),
                _ => value.clone(),
            })
            .collect();
        Answer::Confirmed { choice: 0, values }
    }

    fn create_key(&self, kind: Kind) -> KeyAnswer {
        let mut made = self.made.lock().unwrap();
        *made = made.wrapping_add(1);
        match kind {
            Kind::Keystore => {
                let alias = format!("vos.device.{made}").into_bytes();
                self.aliases.lock().unwrap().insert(alias.clone());
                KeyAnswer::Done(alias.into())
            }
            Kind::SecurityKey | Kind::Kit => KeyAnswer::Done(vec![*made; 16].into()),
            Kind::Admin => {
                let key = SigningKey::from_bytes(&[*made; 32]);
                let public = key.verifying_key().to_bytes();
                self.admins.lock().unwrap().insert(public, key);
                // Hardware-backed, verified boot.
                KeyAnswer::Done([&public[..], &[3]].concat().into())
            }
        }
    }

    fn evaluate_key(&self, kind: Kind, key: &[u8], input: &[u8; 32]) -> KeyAnswer {
        match kind {
            // One security key, its discoverable credential the kit's.
            Kind::SecurityKey | Kind::Kit => {
                KeyAnswer::Done(hmac(&self.security_key, input).into())
            }
            Kind::Keystore => {
                if !self.aliases.lock().unwrap().contains(key) {
                    return KeyAnswer::Failed("the Keystore holds no such key".into());
                }
                let alias: [u8; 32] = hmac(&self.source, key).try_into().unwrap();
                KeyAnswer::Done(hmac(&alias, input).into())
            }
            Kind::Admin => KeyAnswer::Failed("an admin key evaluates nothing".into()),
        }
    }

    fn sign_key(&self, kind: Kind, key: &[u8], message: &[u8]) -> KeyAnswer {
        assert_eq!(kind, Kind::Admin, "only the admin key signs");
        let admins = self.admins.lock().unwrap();
        let Some(admin) = <[u8; 32]>::try_from(key)
            .ok()
            .and_then(|key| admins.get(&key))
        else {
            return KeyAnswer::Failed("no such key".into());
        };
        *self.signed.lock().unwrap() = Some(admin.verifying_key().to_bytes());
        KeyAnswer::Done(admin.sign(message).to_bytes().to_vec().into())
    }
}

/// A phone: its facility over `world`, under a directory of its own, its
/// requests tagged with its seed.
pub struct Held {
    pub node: Node,
    pub hand: Arc<Hand>,
    pub tag: u8,
    pub _directory: tempfile::TempDir,
}

/// The facility of the phone tagged `tag` under `directory`.
pub fn node_as(world: &Arc<World>, directory: &std::path::Path, tag: u8) -> Node {
    node_over(world.dial_as(tag), directory, Arc::new(Phone))
}

/// A phone of the world tagged `seed`, under a directory of its own.
pub fn phone(world: &Arc<World>, seed: u8) -> Held {
    let directory = tempfile::tempdir().unwrap();
    Held {
        node: node_as(world, directory.path(), seed),
        hand: Hand::new(seed),
        tag: seed,
        _directory: directory,
    }
}

impl Held {
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
            node: node_as(world, _directory.path(), tag),
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
                    home: world.home_of(home),
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
