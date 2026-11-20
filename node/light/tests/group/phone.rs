//! A phone: its light node's store, its device group, its sync key and its
//! admin key, and the calls it makes at the home: commits under the admin
//! key, evidence and votes under the sync key, and its reads of the log.

use ed25519_dalek::{Signer, SigningKey};
use vos_abi::Encode;
use vos_light::group::{DeviceGroup, Event, Pairing, Prepared};
use vos_light::kit::{KitKey, KitSecret, SecurityKey, Split};
use vos_wire::personal::{
    AdminClass, Attached, Attestation, Candidacy, NewDevice, PersonalError, Vote,
};
use zeroize::Zeroizing;

use vos_light::{Config, Light, Store};

use crate::home::Home;

pub struct Phone {
    pub light: Light,
    pub store: Store,
    pub group: Option<DeviceGroup>,
    pub sync: SigningKey,
    pub admin: SigningKey,
    pub keys: NewDevice,
    pub _dir: tempfile::TempDir,
}

impl Phone {
    /// Phone `n`: its sync key its light node's, its scopes' author, its
    /// admin key's seed `[n | 0x80; 32]`, a strong admin.
    pub fn new(n: u8) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let light = Light::open(dir.path(), crate::common::agent(), Config::default()).unwrap();
        let store = light.store().clone();
        let sync = light.sync_key().clone();
        let admin = SigningKey::from_bytes(&[n | 0x80; 32]);
        let keys = NewDevice {
            sync: sync.verifying_key().to_bytes(),
            admin: admin.verifying_key().to_bytes(),
            class: AdminClass::Strong,
            attestation: Attestation {
                hardware: true,
                verified_boot: true,
            },
            nullifier: [n; 32],
            label: vec![n; 8],
        };
        Self {
            light,
            store,
            group: None,
            sync,
            admin,
            keys,
            _dir: dir,
        }
    }

    pub fn group(&mut self) -> &mut DeviceGroup {
        self.group.as_mut().expect("a device group")
    }

    pub fn sync_key(&self) -> [u8; 32] {
        self.keys.sync
    }

    /// Phone `n`, a delayed admin.
    pub fn delayed(n: u8) -> Self {
        let mut phone = Self::new(n);
        phone.keys.class = AdminClass::Delayed;
        phone
    }

    /// The claiming phone: its group made, the home assigned to it with
    /// the kit of [`kit_key`]`(0)`, `R` split: the split.
    pub fn claim(&mut self, home: &mut Home) -> Split {
        self.claim_with(home, vec![kit_key(0)])
    }

    /// The claiming phone with the kit of `keys`.
    pub fn claim_with(&mut self, home: &mut Home, keys: Vec<KitKey>) -> Split {
        let split = Split::draw(&keys, &home.identity).unwrap();
        let assigned = home.claim(&self.keys, split.claim());
        let mut group = DeviceGroup::create(
            &self.store,
            home.agent(),
            self.keys.clone(),
            keys,
            home.now(),
        )
        .unwrap();
        group.set_recovery(assigned, *split.r()).unwrap();
        self.group = Some(group);
        split
    }

    /// Read the log to its head and act on it, posting every vote and
    /// evidence it asks for, until it asks for none: every other event.
    /// A phone the agent no longer admits reads nothing.
    pub fn read(&mut self, home: &mut Home) -> Vec<Event> {
        let mut seen = Vec::new();
        for _ in 0..8 {
            let cursor = self.group().cursor();
            let Ok(entries) = home.log(self.sync_key(), cursor) else {
                return seen;
            };
            let events = self.group().follow(entries).unwrap();
            let mut posted = false;
            for event in events {
                match event {
                    Event::Vote {
                        epoch,
                        vote,
                        message,
                    } => {
                        self.vote(home, epoch, vote, &message);
                        posted = true;
                    }
                    Event::Evidence {
                        index,
                        message,
                        signature,
                        attached,
                    } => {
                        self.evidence(home, index, message, signature, attached);
                        posted = true;
                    }
                    Event::Alive => {
                        self.alive(home);
                        posted = true;
                    }
                    other => seen.push(other),
                }
            }
            if !posted {
                return seen;
            }
        }
        panic!("the phone keeps posting");
    }

    /// Post a vote signed by the sync key over `message`.
    pub fn vote(&mut self, home: &mut Home, epoch: u64, vote: Vote, message: &[u8]) {
        let signature = self.sync.sign(message).to_bytes();
        let reply = match vote {
            Vote::Confirm(h) => home.call(&self.sync, "confirm", (epoch, h, signature).encode()),
            Vote::Nack => home.call(&self.sync, "nack", (epoch, signature).encode()),
        };
        self.group().called(reply.at);
    }

    /// Post the evidence of the admin call at `index`.
    pub fn evidence(
        &mut self,
        home: &mut Home,
        index: u64,
        message: Vec<u8>,
        signature: [u8; 64],
        attached: Attached,
    ) {
        let reply = home.call(
            &self.sync,
            "evidence",
            ((index, message), (signature, attached)).encode(),
        );
        self.group().called(reply.at);
    }

    /// Make `prepared`'s commit call under the admin key and post its
    /// evidence; refused with `Settling`, wake the agent and call again; a
    /// refused call abandons the commit.
    pub fn send(
        &mut self,
        home: &mut Home,
        prepared: &Prepared,
    ) -> Result<Candidacy, PersonalError> {
        let reply = loop {
            let signed = home.sign(&self.admin, "commit", prepared.arguments());
            self.group()
                .signed_commit(signed.message.clone(), signed.signature)
                .unwrap();
            let reply = home.send(signed);
            if !reply.settling() || !home.wake(&self.sync) {
                break reply;
            }
        };
        self.group().called(reply.at);
        match reply.answer::<Candidacy>() {
            Ok(candidacy) => {
                let event = self.group().called_commit(candidacy.index).unwrap();
                let Event::Evidence {
                    index,
                    message,
                    signature,
                    attached,
                } = event
                else {
                    unreachable!()
                };
                self.evidence(home, index, message, signature, attached);
                Ok(candidacy)
            }
            Err(error) => {
                self.group().abandon().unwrap();
                Err(error)
            }
        }
    }

    /// Commit an update now ("Commit now"), carrying every matured
    /// removal.
    pub fn update(&mut self, home: &mut Home) -> Result<Candidacy, PersonalError> {
        let prepared = self.group().commit(None, home.now()).unwrap();
        self.send(home, &prepared)
    }

    /// A call any phone makes: liveness, which the log counts seen.
    pub fn alive(&mut self, home: &mut Home) {
        let reply = home.call(&self.sync, "alive", ().encode());
        reply.answer::<vos_wire::personal::Recorded>().unwrap();
        if let Some(group) = &mut self.group {
            group.called(reply.at);
        }
    }

    /// Pair `new` from this phone: `new`'s key package, this phone's commit
    /// adding it and its evidence posted, and `new`'s group from the
    /// pairing. The commit is the candidate; nothing is confirmed yet.
    pub fn pair(&mut self, home: &mut Home, new: &mut Phone) -> Candidacy {
        let package = DeviceGroup::key_package(&new.store, &new.keys, home.now()).unwrap();
        let (prepared, pairing) = self
            .group()
            .pair(new.keys.clone(), package, home.now())
            .unwrap();
        let pairing = Pairing::from_bytes(&pairing.to_bytes()).unwrap();
        new.group =
            Some(DeviceGroup::join(&new.store, new.keys.clone(), pairing, Vec::new()).unwrap());
        self.send(home, &prepared).unwrap()
    }
}

/// A security key's double: its `hmac-secret` a hash of its seed and the
/// salt, the same at every touch.
pub struct Touch(pub u8);

impl SecurityKey for Touch {
    type Error = ();

    fn hmac_secret(&mut self, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, ()> {
        let mut out = Zeroizing::new([0; 32]);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = salt[i] ^ self.0.wrapping_mul(31).wrapping_add(i as u8);
        }
        Ok(out)
    }
}

/// Kit `n`: the security key [`Touch`]`(n)`'s.
pub fn kit_secret(n: u8) -> KitSecret {
    KitSecret::security_key(&mut Touch(0x4b + n)).unwrap()
}

/// Kit `n`'s signing key.
pub fn kit(n: u8) -> SigningKey {
    kit_secret(n).signing()
}

/// Kit `n`'s keys.
pub fn kit_key(n: u8) -> KitKey {
    kit_secret(n).key()
}
