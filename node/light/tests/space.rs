//! The personal space's flows as `vos_light::space` runs them, over the
//! shared doubles (`vos_light::testing`): homes behind an in-process
//! gateway, each phone's host a Tor client over it, its prompts the shared
//! phone's. The same orchestration the facility's tests drive through
//! `:vos`; here with no facility at all. A claim, a pairing, a regroup
//! whose removal set is the agent's for a device still on probation and
//! one added while the regroup was open, and the regrouper's new group;
//! the recovery flows: an evidence post lost and made again, a dropped
//! veto seen, a removal maturing between the reading and the commit, a
//! restore on a phone whose clock runs ahead at a home of its own policy,
//! the kit removing a lost phone left powered and the restore after it,
//! and a joiner cut short pairing again on the same phone.

use std::sync::Arc;
use std::time::Duration;

use vos_abi::Encode;
use vos_light::group::Alarm;
use vos_light::space::{Artifacts, CREDENTIAL_BOOK, Claim, DEVICE_BOOK, Error, Personal, Phase};
use vos_light::testing::{Death, Phone, Reach, Step, World, policy};
use vos_testkit::programs::program_elf;
use vos_wire::personal::method;
use vos_wire::personal::{KitKind, PersonalError, Policy, Standing};

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

/// The suite's policy: a joiner on probation, and an operation open, long
/// past a pairing's time over the in-process Tor, so each is seen as it is
/// while the next step runs.
fn suite() -> Policy {
    Policy {
        probation_ms: 60_000,
        operation_delay_ms: 15_000,
        kit_delay_ms: 20_000,
        ..policy()
    }
}

fn world() -> Arc<World> {
    world_of(suite())
}

fn world_of(policy: Policy) -> Arc<World> {
    let world = World::new();
    world.state.lock().unwrap().policy = Some(policy);
    world
}

impl Device {
    /// A claim with a phrase kit: its words.
    fn claim_phrase(&self, world: &World, home: u32) -> String {
        self.space
            .claim(
                &self.phone,
                Claim {
                    home: world.home_of(home),
                    kit: KitKind::Phrase,
                    label: "claimer".into(),
                },
            )
            .unwrap();
        self.phone.phrase()
    }

    /// One pass of the background job.
    fn pass(&self) -> vos_light::space::Passed {
        self.space.pass(vos_light::testing::wall()).unwrap()
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
    let world = world();
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
    let id = first.pair(&second);
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

/// A regroup's removal set is the agent's: the regrouper's commit carries
/// the removals the light node voices, which the agent takes only when
/// they are exactly its live set's (`check_removals`). A device still on
/// probation when the regroup opens and one paired while it is open are
/// both out once it matures; the regrouper's commit takes, and it alone
/// stays in the set.
#[test]
fn a_regroup_removes_what_the_agent_removes() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x31);
    first.claim(&world, home);
    // Seasoned, so it may regroup.
    after(suite().seasoning_ms);
    let probation = device(&world, 0x32);
    let on_probation = first.pair(&probation);
    first.space.regroup(&first.phone).unwrap();
    assert_eq!(first.standing(on_probation), Some(Standing::Probation));
    // Paired while the regroup is open.
    let late = device(&world, 0x33);
    let added = first.pair(&late);
    assert_ne!(added, on_probation);
    after(suite().operation_delay_ms);
    first.space.update(&first.phone).unwrap();
    let devices = first.space.devices().unwrap();
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
    assert!(
        matches!(
            refused,
            Error::Regrouped { by: 0 } | Error::AgentRefused(PersonalError::NotAdmitted)
        ),
        "{refused:?}"
    );
}

/// An admin call whose evidence post dies on the way (`:vos` killed after
/// the call) is held: the next pass posts its evidence, the removal
/// matures rather than being cancelled for want of it, and the commit
/// carries it.
#[test]
fn a_lost_evidence_post_is_made_again_by_the_next_pass() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x41);
    first.claim(&world, home);
    let second = device(&world, 0x42);
    let id = first.pair(&second);
    world.kill(0x41, Step::call(method::EVIDENCE), 1, Death::Before);
    first.space.remove(&first.phone, id).unwrap_err();
    world.revive(0x41);
    first.pass();
    after(suite().operation_delay_ms);
    first.space.update(&first.phone).unwrap();
    assert_eq!(first.standing(id), Some(Standing::Removed));
    assert!(first.pass().notices.is_empty(), "nothing owed");
}

/// A veto the operators answer and never log is this device's to see: it
/// raises `Dropped` once the log shows another entry where the agent said
/// it took the veto.
#[test]
fn a_veto_the_operators_drop_is_seen() {
    let world = world_of(Policy {
        probation_ms: 1_000,
        operation_delay_ms: 30_000,
        ..suite()
    });
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x51);
    first.claim(&world, home);
    let second = device(&world, 0x52);
    let id = first.pair(&second);
    after(1_000);
    let removal = first.space.remove(&first.phone, id).unwrap();
    world.forge(0x52, Step::call(method::VETO));
    // Its evidence is refused: the log holds no call there.
    second.space.veto(&second.phone, removal.index).unwrap_err();
    // The next entry logged takes the place the agent named the veto's.
    first.space.update(&first.phone).unwrap();
    let alarms = second.pass().alarms;
    assert!(
        alarms
            .iter()
            .any(|alarm| matches!(alarm, Alarm::Dropped { .. })),
        "{alarms:?}"
    );
}

/// A removal that matures between the commit's reading of the log and its
/// call is refused as the commit's to carry: the commit reads again and is
/// made once more, carrying it.
#[test]
fn a_removal_maturing_before_the_commit_call_is_read_again() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x61);
    first.claim(&world, home);
    let second = device(&world, 0x62);
    let id = first.pair(&second);
    first.space.remove(&first.phone, id).unwrap();
    world.pass_at(
        0x61,
        Step::call(method::COMMIT),
        suite().operation_delay_ms + 1,
    );
    first.space.update(&first.phone).unwrap();
    assert_eq!(first.standing(id), Some(Standing::Removed));
}

/// A restore on a phone whose clock runs a minute ahead of the home's, at a
/// home whose policy is not the default: the restored device takes the
/// log's policy and the agent's batch time, so it follows its own agent,
/// and a removal it makes matures by the home's delay and is carried.
#[test]
fn a_restore_follows_the_homes_policy_and_time() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x71);
    let words = first.claim_phrase(&world, home);
    let restoring = device(&world, 0x72);
    restoring
        .space
        .host()
        .ahead
        .store(60_000, std::sync::atomic::Ordering::Relaxed);
    restoring.phone.will_enter(words);
    restoring
        .space
        .restore(
            &restoring.phone,
            Claim {
                home: world.home_of(home),
                kit: KitKind::Phrase,
                label: "restored".into(),
            },
            KitKind::Phrase,
        )
        .unwrap();
    after(suite().kit_delay_ms);
    restoring
        .space
        .restored(&restoring.phone, KitKind::Phrase)
        .unwrap();
    let paired = device(&world, 0x73);
    let id = restoring.pair(&paired);
    restoring.space.remove(&restoring.phone, id).unwrap();
    after(suite().operation_delay_ms);
    restoring.space.update(&restoring.phone).unwrap();
    assert_eq!(restoring.standing(id), Some(Standing::Removed));
    let passed = restoring.pass();
    assert!(passed.alarms.is_empty(), "{:?}", passed.alarms);
    assert_eq!(restoring.space.status().unwrap().phase, Phase::Held);
}

/// The facility's twin of A14: the only phone is lost, left powered, its
/// background job answering every restore with `alive`. From a fresh
/// install the kit removes it (a sync key alone vetoes nothing), the
/// removal matures, and the restore after it completes.
#[test]
fn the_kit_removes_a_lost_phone_and_the_restore_completes() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let lost = device(&world, 0x81);
    let words = lost.claim_phrase(&world, home);
    let fresh = device(&world, 0x82);
    fresh.phone.will_enter(words);
    let restore = Claim {
        home: world.home_of(home),
        kit: KitKind::Phrase,
        label: "fresh".into(),
    };
    fresh
        .space
        .restore(&fresh.phone, restore.clone(), KitKind::Phrase)
        .unwrap();
    lost.pass();
    let view = fresh
        .space
        .kit_view(&fresh.phone, world.home_of(home), KitKind::Phrase)
        .unwrap();
    assert!(
        view.operations.is_empty(),
        "the lost phone's alive cancelled the restore: {view:?}"
    );
    assert_eq!(view.devices.len(), 1);
    let removal = fresh
        .space
        .remove_by_kit(&fresh.phone, world.home_of(home), KitKind::Phrase, 0)
        .unwrap();
    // Called again, the removal is the one the kit made.
    let again = fresh
        .space
        .remove_by_kit(&fresh.phone, world.home_of(home), KitKind::Phrase, 0);
    assert!(
        matches!(
            again,
            Err(Error::AgentRefused(PersonalError::Pending)) | Ok(_)
        ),
        "{again:?}"
    );
    lost.pass();
    after(suite().kit_delay_ms);
    let view = fresh
        .space
        .kit_view(&fresh.phone, world.home_of(home), KitKind::Phrase)
        .unwrap();
    assert!(view.devices[0].removed, "{view:?}");
    let _ = lost.space.pass(vos_light::testing::wall());
    fresh
        .space
        .restore(&fresh.phone, restore, KitKind::Phrase)
        .unwrap();
    let _ = lost.space.pass(vos_light::testing::wall());
    after(suite().kit_delay_ms);
    fresh.space.restored(&fresh.phone, KitKind::Phrase).unwrap();
    assert_eq!(fresh.space.status().unwrap().phase, Phase::Held);
    assert!(removal.index > 0);
}

/// A quiet home reads at its last batch's time: a joiner just paired, its
/// probation past by the home's clock with no call since, reads as in
/// probation there. The Devices read wakes the home first, so it reads
/// active.
#[test]
fn the_devices_read_wakes_a_quiet_home() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x86);
    first.claim(&world, home);
    let second = device(&world, 0x87);
    let id = first.pair(&second);
    let quiet = vos_light::job::STALE_MS + suite().probation_ms;
    world.pass(quiet);
    first
        .space
        .host()
        .ahead
        .store(quiet, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(first.standing(id), Some(Standing::Active));
}

/// The home's onion not yet published at the first contact: every attempt
/// of the first burst finds it so, and the light node tries once more
/// after a pause, so the claim goes through.
#[test]
fn a_first_contact_with_an_unpublished_onion_is_tried_again() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x85);
    world.unpublished(0x85, vos_light::tor::Config::default().attempts);
    first.claim(&world, home);
    assert_eq!(first.space.status().unwrap().phase, Phase::Held);
}

/// A phone the kit removed while it was off, a restore by the kit after
/// that: once on again, its pass reads that it is out of the personal
/// space, and says so, rather than failing at every pass.
#[test]
fn a_phone_the_kit_removed_while_off_reads_its_removal() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let lost = device(&world, 0x83);
    let words = lost.claim_phrase(&world, home);
    let fresh = device(&world, 0x84);
    fresh.phone.will_enter(words);
    let restore = Claim {
        home: world.home_of(home),
        kit: KitKind::Phrase,
        label: "fresh".into(),
    };
    fresh
        .space
        .remove_by_kit(&fresh.phone, world.home_of(home), KitKind::Phrase, 0)
        .unwrap();
    after(suite().kit_delay_ms);
    fresh
        .space
        .restore(&fresh.phone, restore, KitKind::Phrase)
        .unwrap();
    after(suite().kit_delay_ms);
    fresh.space.restored(&fresh.phone, KitKind::Phrase).unwrap();
    assert_eq!(fresh.space.status().unwrap().phase, Phase::Held);
    let passed = lost.space.pass(vos_light::testing::wall()).unwrap();
    assert_eq!(passed.stopped, None);
    assert!(
        passed.notices.contains(&vos_light::job::Notice::Removed),
        "{:?}",
        passed.notices
    );
    assert_eq!(lost.space.status().unwrap().phase, Phase::Removed);
    let again = lost.space.pass(vos_light::testing::wall()).unwrap();
    assert_eq!(again.stopped, None);
}

/// A joiner whose acknowledgement never left (its process killed at the
/// put) pairs again on the same phone from a new code: the group it joined
/// at that agent, never added, is left at the new offer.
#[test]
fn a_joiner_cut_short_pairs_again_on_the_same_phone() {
    let world = world_of(Policy {
        slot_ttl_ms: 15_000,
        ..suite()
    });
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0x91);
    first.claim(&world, home);
    let joiner = device(&world, 0x92);
    let code = first.space.pair_offer().unwrap();
    // The joiner's puts: the handshake's second message, its hello, its
    // acknowledgement.
    world.kill(0x92, Step::call(method::PUT), 3, Death::Before);
    std::thread::scope(|scope| {
        let opener = scope.spawn(|| first.space.pair_await(&first.phone));
        joiner
            .space
            .pair_join(&joiner.phone, &code.code, "joiner")
            .unwrap_err();
        opener.join().unwrap().unwrap_err();
    });
    world.revive(0x92);
    let _ = joiner.space.pass(vos_light::testing::wall());
    let id = first.pair(&joiner);
    assert_eq!(joiner.space.status().unwrap().device, Some(id));
    assert_eq!(first.standing(id), Some(Standing::Probation));
}

/// The pairing's check: both phones show the same, and an opener whose
/// user does not confirm it puts nothing in the slot but the handshake's
/// last message, which carries nothing, and closes it, which the joiner
/// reads as the pairing declined; confirmed, the pairing runs to its end.
#[test]
fn a_pairing_hands_nothing_over_until_its_check_is_confirmed() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0xa1);
    first.claim(&world, home);
    let joiner = device(&world, 0xa2);
    *first.phone.decline_check.lock().unwrap() = true;
    // The user compares the two screens before declining: the new device
    // shows its check meanwhile.
    *first.phone.comparing.lock().unwrap() = Duration::from_secs(3);
    let code = first.space.pair_offer().unwrap();
    world.trace_from_now(0xa1);
    std::thread::scope(|scope| {
        let opener = scope.spawn(|| first.space.pair_await(&first.phone));
        let joined = joiner.space.pair_join(&joiner.phone, &code.code, "joiner");
        assert_eq!(opener.join().unwrap().unwrap_err(), Error::Declined);
        assert_eq!(
            joined.unwrap_err(),
            Error::PairingDeclined,
            "said as the opener's"
        );
    });
    let puts = world
        .trace(0xa1)
        .into_iter()
        .filter(|step| *step == Step::call(method::PUT))
        .count();
    assert_eq!(puts, 1, "the handshake's last message alone, no offer");
    let checks = |phone: &Phone| phone.checks.lock().unwrap().clone();
    assert_eq!(checks(&first.phone), checks(&joiner.phone));
    assert_eq!(checks(&first.phone)[0].len(), 7, "six digits");
    assert_ne!(joiner.space.status().unwrap().phase, Phase::Joining);

    let id = first.pair(&joiner);
    assert_eq!(id, 1);
    assert_eq!(checks(&first.phone)[1], checks(&joiner.phone)[1]);
    assert_ne!(checks(&first.phone)[0], checks(&first.phone)[1]);
}

/// A cosign whose evidence post dies on the way is held past the maturity
/// it caused: the devices take that maturity only with the cosign's
/// evidence, which the cosigner's next pass posts, and the commit carries
/// the removal.
#[test]
fn a_cosigns_lost_evidence_is_posted_after_the_maturity_it_caused() {
    let world = world_of(Policy {
        probation_ms: 500,
        seasoning_ms: 3_000,
        operation_delay_ms: 60_000,
        ..suite()
    });
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0xb1);
    first.claim(&world, home);
    let second = device(&world, 0xb2);
    first.pair(&second);
    let third = device(&world, 0xb3);
    let target = first.pair(&third);
    after(3_000);
    for device in [&first, &second, &third] {
        device.pass();
    }
    let removal = first.space.remove(&first.phone, target).unwrap();
    second.pass();
    world.kill(0xb2, Step::call(method::EVIDENCE), 1, Death::Before);
    second
        .space
        .cosign(&second.phone, removal.index)
        .unwrap_err();
    world.revive(0xb2);
    second.pass();
    first.space.update(&first.phone).unwrap();
    assert_eq!(first.standing(target), Some(Standing::Removed));
    let passed = second.pass();
    assert!(passed.alarms.is_empty(), "{:?}", passed.alarms);
}

/// A phone whose admin key is a software key (a keystore with no Ed25519
/// in its TEE) is a delayed admin, as its own report says: the set
/// records it so, claimed or paired, and it opens no pairing (a strong
/// admin's phone pairs it).
#[test]
fn a_software_admin_key_is_a_delayed_admin() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let first = device(&world, 0xc1);
    *first.phone.software.lock().unwrap() = true;
    first.claim(&world, home);
    let strong = |device: &Device, id: u32| {
        let devices = device.space.devices().unwrap();
        devices
            .iter()
            .find(|device| device.id == id)
            .unwrap()
            .strong
    };
    assert!(
        !strong(&first, 0),
        "a software key claims as a delayed admin"
    );
    // Its add would wait as an operation past any slot: it opens none.
    assert_eq!(first.space.pair_offer().unwrap_err(), Error::DelayedAdmin);

    let other = world.home([0x62; 32], 2, 1);
    let opener = device(&world, 0xc2);
    opener.claim(&world, other);
    let joiner = device(&world, 0xc3);
    *joiner.phone.software.lock().unwrap() = true;
    let id = opener.pair(&joiner);
    assert!(strong(&opener, 0));
    assert!(
        !strong(&opener, id),
        "a software key joins as a delayed admin"
    );
}

/// The home's onion set is read again from its registrar by a pass: a
/// second onion the home names is pinned, under the home's own routes'
/// key, after a reopen too; a later read that no longer names the first
/// keeps it pinned beside the new set for a while. The home's routes are
/// never the handle's, which an enrolled space's routes are kept under.
#[test]
fn a_pass_reads_the_homes_onions_again_and_keeps_them() {
    let world = world();
    let home = world.home(HOME, 2, 1);
    let directory = tempfile::tempdir().unwrap();
    let phone = Phone::new(0xd1);
    let space = Personal::open(directory.path(), artifacts(), Reach::new(&world, 0xd1)).unwrap();
    space.set_wait(30_000);
    space
        .claim(
            &phone,
            Claim {
                home: world.home_of(home),
                kit: KitKind::SecurityKey,
                label: "phone".into(),
            },
        )
        .unwrap();
    let keys = |space: &Personal<Reach>| -> Vec<u8> {
        let routes = space
            .host()
            .client()
            .routes(&vos_light::route::home(&HOME))
            .expect("the home's routes");
        routes.onions.iter().map(|onion| onion.key[0]).collect()
    };
    assert_eq!(keys(&space), vec![2]);
    assert!(
        space.host().client().routes(&HOME).is_none(),
        "not the handle's"
    );
    world
        .state
        .lock()
        .unwrap()
        .spaces
        .get_mut(&home)
        .unwrap()
        .onions = vec![world.onion(2), world.onion(5)];
    space.pass(vos_light::testing::wall()).unwrap();
    assert_eq!(keys(&space), vec![2, 5]);
    drop(space);
    let space = Personal::open(directory.path(), artifacts(), Reach::new(&world, 0xd1)).unwrap();
    assert_eq!(keys(&space), vec![2, 5], "kept across a reopen");
    // A day on, the home names the second alone: the first stays pinned
    // beside it.
    world
        .state
        .lock()
        .unwrap()
        .spaces
        .get_mut(&home)
        .unwrap()
        .onions = vec![world.onion(5)];
    let day = vos_light::space::ONIONS_EVERY_MS;
    space.pass(vos_light::testing::wall() + day).unwrap();
    assert_eq!(keys(&space), vec![5, 2]);
    // Past the time a dropped onion is kept, the next read leaves it out.
    let later = vos_light::testing::wall() + day + vos_light::space::ONIONS_KEPT_MS + day;
    space.pass(later).unwrap();
    assert_eq!(keys(&space), vec![5]);
}
