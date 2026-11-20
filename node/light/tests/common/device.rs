//! A device: its light node at a directory of its own, its store's archive
//! the devices' shared one, one local actor installed.

use std::collections::BTreeSet;

use ed25519_dalek::SigningKey;
use merkle_crdt::{Author, Node};
use vos_abi::Decode;
use vos_abi::ids::{InstanceId, MethodId, Principal};
use vos_abi::result::Outcome;
use vos_light::group::{Archive, archive};
use vos_light::release::Package;
use vos_light::sync::{self, Blake2b256, Cid, Ops};
use vos_light::{Config, Error, Light};
use vos_testkit::programs;

/// The principal the devices' queries are asked as.
pub const DEVICE: Principal = Principal::Client([0xd1; 32]);

/// The naming secret the tests' devices share, as pairing gives it.
pub const NAMING: [u8; 32] = [0x11; 32];

/// A light node at `dir`, its store's archive the devices' shared one.
pub fn open(dir: &std::path::Path, agent: &[u8], config: Config) -> Light {
    let light = Light::open(dir, agent, config).unwrap();
    let shared = Archive {
        naming: NAMING,
        previous: Vec::new(),
        scopes: Vec::new(),
        keys: Vec::new(),
        recovery: None,
        drawn: Vec::new(),
    };
    light.store().adopt(&shared).unwrap();
    light
}

/// A device: its light node with `package` installed at `instance`.
pub struct Device {
    pub light: Light,
    pub package: Package,
    pub instance: InstanceId,
    pub dir: tempfile::TempDir,
}

impl Device {
    pub fn new(agent: &[u8], instance: InstanceId, package: &Package) -> Self {
        Self::with(agent, instance, package, Config::default())
    }

    pub fn with(agent: &[u8], instance: InstanceId, package: &Package, config: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let light = open(dir.path(), agent, config);
        let installed = light.install(instance, package, Vec::new()).unwrap();
        assert!(matches!(installed, Outcome::Done(_)), "{installed:?}");
        Self {
            light,
            package: package.clone(),
            instance,
            dir,
        }
    }

    /// A device over `light`, opened elsewhere, `package` at `instance`.
    pub fn over(light: Light, instance: InstanceId, package: Package) -> Self {
        Self {
            light,
            package,
            instance,
            dir: tempfile::tempdir().unwrap(),
        }
    }

    /// Its light node closed and opened again over the same store.
    pub fn reopen(self, agent: &[u8], config: Config) -> Self {
        drop(self.light);
        let light = Light::open(self.dir.path(), agent, config).unwrap();
        Self { light, ..self }
    }

    pub fn method(&self, name: &str) -> MethodId {
        programs::method(&self.package.programs[0], name)
    }

    pub fn call(&self, name: &str, arguments: Vec<u8>) -> Result<Outcome, Error> {
        self.light.call(self.instance, self.method(name), arguments)
    }

    /// A call that is done: its reply.
    pub fn done(&self, name: &str, arguments: Vec<u8>) -> Vec<u8> {
        match self.call(name, arguments).unwrap() {
            Outcome::Done(reply) => reply,
            other => panic!("{name}: {other:?}"),
        }
    }

    pub fn query<T: Decode>(&self, name: &str, arguments: Vec<u8>) -> T {
        match self
            .light
            .query(DEVICE, self.instance, self.method(name), arguments)
            .unwrap()
        {
            Outcome::Done(reply) => T::decode_exact(&reply).unwrap(),
            other => panic!("{name}: {other:?}"),
        }
    }

    /// The local nodes not yet pushed, marked pushed.
    pub fn push(&self) -> Vec<Vec<u8>> {
        let outbox = self.light.outbox(self.instance).unwrap();
        let pushed: Vec<(Author, u64)> =
            outbox.iter().map(|node| (node.author, node.seq)).collect();
        self.light.pushed(self.instance, &pushed).unwrap();
        outbox.into_iter().map(|node| node.bytes).collect()
    }
}

/// A node of `ops` at `seq` in `key`'s chain of `instance`'s scope, after
/// `parents`.
pub fn node(
    instance: InstanceId,
    key: &SigningKey,
    seq: u64,
    ops: Ops,
    parents: BTreeSet<Cid>,
) -> Vec<u8> {
    let scope = merkle_crdt::Scope(archive::scope_id(&NAMING, &sync::scope_name(instance)));
    Node::<Blake2b256, Ops>::sign(key, &scope, seq, ops, parents).to_bytes()
}

pub fn cid(bytes: &[u8]) -> Cid {
    merkle_crdt::Cid(<Blake2b256 as merkle_crdt::Hasher>::hash(bytes))
}
