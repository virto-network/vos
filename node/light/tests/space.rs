//! The personal space's flows as `vos_light::space` runs them, over the
//! shared doubles (`vos_light::testing`): homes behind an in-process
//! gateway, each phone's host a Tor client over it, its prompts the shared
//! phone's. The same orchestration the facility's tests drive through
//! `:vos`; here with no facility at all. A claim, a pairing, a regroup
//! whose removal set is the agent's for a device still on probation and
//! one added while the regroup was open, and the regrouper's new group.

use std::sync::Arc;
use std::time::Duration;

use vos_abi::Encode;
use vos_light::space::{Artifacts, CREDENTIAL_BOOK, Claim, DEVICE_BOOK, Error, Personal};
use vos_light::testing::{Phone, Reach, World, policy};
use vos_testkit::programs::program_elf;
use vos_wire::personal::{KitKind, Standing};

const HOME: [u8; 32] = [0x61; 32];

/// The light node's artifacts from this tree's guests.
fn artifacts() -> &'static Artifacts {
    static ARTIFACTS: std::sync::OnceLock<Artifacts> = std::sync::OnceLock::new();
    ARTIFACTS.get_or_init(|| {
        let read = |name| std::fs::read(program_elf(name)).unwrap();
        let package = |name| {
            vos_light::release::package(&read(name), 1)
                .unwrap()
                .encode()
        };
        Artifacts {
            agent: vos_light::release::agent(&read("vos-agent")).unwrap(),
            books: vec![
                (CREDENTIAL_BOOK, package("vos-credential-book")),
                (DEVICE_BOOK, package("vos-device-book")),
            ],
        }
    })
}

/// A device: its personal space over the world, its phone, its store.
struct Device {
    space: Personal<Reach>,
    phone: Phone,
    _directory: tempfile::TempDir,
}

fn device(world: &Arc<World>, seed: u8) -> Device {
    let directory = tempfile::tempdir().unwrap();
    let space = Personal::open(directory.path(), artifacts(), Reach::new(world, seed)).unwrap();
    space.set_wait(30_000);
    Device {
        space,
        phone: Phone::new(seed),
        _directory: directory,
    }
}

impl Device {
    fn claim(&self, world: &World, home: u32) {
        let claimed = self
            .space
            .claim(
                &self.phone,
                Claim {
                    home: world.home_of(home),
                    kit: KitKind::SecurityKey,
                    label: format!("phone {}", self.phone.source[0]),
                },
            )
            .unwrap();
        assert_eq!(claimed.device, 0);
    }

    /// `joiner` paired from this device: the code shown here, scanned
    /// there. Its id in the set.
    fn pair(&self, joiner: &Device) -> u32 {
        let code = self.space.pair_offer().unwrap();
        std::thread::scope(|scope| {
            let opener = scope.spawn(|| self.space.pair_await(&self.phone));
            let joined = joiner.space.pair_join(&joiner.phone, &code.code, "joiner");
            let opened = opener.join().unwrap().unwrap();
            assert_eq!(opened.device, joined.unwrap().device);
            opened.device
        })
    }

    /// The device set's standing of `id`.
    fn standing(&self, id: u32) -> Option<Standing> {
        let devices = self.space.devices().unwrap();
        devices
            .iter()
            .find(|device| device.id == id)
            .map(|device| device.standing)
    }
}

fn after(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms + 300));
}

/// A claim and a pairing through `space::Personal` alone: both devices
/// read the same set, the joiner on probation; a claim again is refused as
/// the state it names.
#[test]
fn a_space_is_claimed_and_paired_through_the_light_node() {
    let world = World::new();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x11);
    first.claim(&world, home);
    assert_eq!(first.phone.cards.lock().unwrap().len(), 1, "the key's card");
    assert_eq!(first.phone.cards.lock().unwrap()[0].handle, HOME);
    let again = first.space.claim(
        &first.phone,
        Claim {
            home: world.home_of(home),
            kit: KitKind::Phrase,
            label: "again".into(),
        },
    );
    assert_eq!(again.unwrap_err(), Error::AlreadyHeld);

    let second = device(&world, 0x22);
    let id = second_of(&first, &second);
    assert_eq!(id, 1);
    assert_eq!(second.space.devices().unwrap().len(), 2);
    assert_eq!(first.standing(1), Some(Standing::Probation));
    // The joiner's code scanned again: it is in that space already.
    let code = first.space.pair_offer().unwrap();
    assert_eq!(
        second
            .space
            .pair_join(&second.phone, &code.code, "again")
            .unwrap_err(),
        Error::InSetAlready
    );
    first.space.pair_cancel();
}

fn second_of(first: &Device, second: &Device) -> u32 {
    first.pair(second)
}

/// A regroup's removal set is the agent's: the regrouper's commit names
/// every device the agent's live set removes, or the agent refuses it
/// (`MissingRemoval`, `NotMatured`). A device still on probation when the
/// regroup opens and one paired while it is open (whose add the regroup
/// voids, dropping it) are both out once it matures; the regrouper's
/// commit takes, and it alone stays in the set.
#[test]
fn a_regroup_removes_what_the_agent_removes() {
    let world = World::new();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x31);
    first.claim(&world, home);
    // Seasoned, so it may regroup.
    after(policy().seasoning_ms);
    let probation = device(&world, 0x32);
    let on_probation = first.pair(&probation);
    first.space.regroup(&first.phone).unwrap();
    assert_eq!(first.standing(on_probation), Some(Standing::Probation));
    // Paired while the regroup is open.
    let late = device(&world, 0x33);
    let added = first.pair(&late);
    assert_ne!(added, on_probation);
    after(policy().operation_delay_ms);
    first.space.update(&first.phone).unwrap();
    let devices = first.space.devices().unwrap();
    eprintln!("after the regroup: {devices:?}");
    for device in &devices {
        if device.me {
            assert!(!device.removed, "the regrouper stays: {devices:?}");
            assert_eq!(device.standing, Standing::Active);
        } else {
            assert!(
                matches!(device.standing, Standing::Removed | Standing::Dropped),
                "device {} out: {devices:?}",
                device.id
            );
        }
    }
    for id in [on_probation, added] {
        assert!(devices.iter().any(|device| device.id == id), "{id} listed");
    }
    let refused = late.space.update(&late.phone).unwrap_err();
    eprintln!("the late device's next update: {refused:?}");
    assert!(
        matches!(refused, Error::Regrouped { by: 0 } | Error::AgentRefused(_)),
        "{refused:?}"
    );
}
