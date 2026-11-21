//! The device set's rules property-tested against the adversaries of
//! `light-node.md` §8 (A3, A4, A14, D3), each a strategy over the calls it
//! may send, in any order and at any batch time, on a test home's policy
//! (a day a minute):
//! - one holding an active device and its biometric, who may also pair
//!   devices: the owner, with one device and the kit or with two other
//!   seasoned devices, always removes it, and every device it paired,
//!   within the delay, and it never removes an owner device the owner
//!   contests; a removal it signs may name its own device, a leave, which
//!   matures at once and only lowers its power;
//! - one holding only a sync key: the kit alone removes its device after
//!   the kit's delay unvetoed, and the kit's restore matures the kit's
//!   delay later, the removed device's `alive` ignored;
//! - a leaked kit alone completes nothing while a device vetoes.

use std::collections::BTreeSet;

use proptest::prelude::*;
use vos_wire::personal::{
    DeviceView, NewAdmin, Op, OpState, Operation, RECOVERY, RecoveryView, Signer, Standing, Status,
};

use super::*;

/// The cases each property runs: `PROPTEST_CASES`, as a longer run sets
/// it, else 24.
fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|cases| cases.parse().ok())
        .unwrap_or(24)
}

/// The open operations, read by `reader`.
fn open(home: &Home, reader: Principal) -> Vec<(u64, Operation)> {
    home.query(reader, "operations", None::<u64>).unwrap()
}

fn devices(home: &Home, reader: Principal) -> Vec<DeviceView> {
    home.query(reader, "devices", ()).unwrap()
}

/// Every device of `set` votes `epoch` with one `h`, those that may.
fn confirm(home: &mut Home, epoch: u64, set: &[DeviceId]) {
    for device in set {
        let _ = home.call::<Voted>(
            Principal::Client(device_keys(*device).sync),
            "confirm",
            (epoch, [epoch as u8; 32], [0u8; 64]),
        );
    }
}

// ===== The thief with a device and its biometric =====

/// What the owner holds against the thief.
#[derive(Clone, Copy, Debug)]
enum Owner {
    /// Device 0 and the kit; the thief holds device 1.
    DeviceAndKit,
    /// Devices 0 and 1, both seasoned; the thief holds device 2. `hasty`,
    /// the owner removes at once; else it lets its removal wait.
    TwoSeasoned { hasty: bool },
}

impl Owner {
    fn devices(self) -> &'static [DeviceId] {
        match self {
            Owner::DeviceAndKit => &[0],
            Owner::TwoSeasoned { .. } => &[0, 1],
        }
    }
}

/// A call the thief makes, with whichever of its devices `who` picks;
/// `pick` chooses among the devices or the open operations.
#[derive(Clone, Debug)]
enum Theft {
    /// Pair a device of its own, the owner's devices confirming.
    Pair,
    Remove {
        who: u8,
        pick: u8,
    },
    Veto {
        who: u8,
        pick: u8,
    },
    Cosign {
        who: u8,
        pick: u8,
    },
    Resolve {
        who: u8,
        pick: u8,
        upheld: bool,
    },
    Replace {
        who: u8,
        pick: u8,
    },
    Rotate {
        who: u8,
    },
    Regroup {
        who: u8,
    },
    Add {
        who: u8,
    },
    Alive {
        who: u8,
    },
    /// Batch time passes, in seconds.
    Pass(u16),
}

fn theft() -> impl Strategy<Value = Theft> {
    let who = any::<u8>();
    let pick = any::<u8>();
    prop_oneof![
        2 => Just(Theft::Pair),
        3 => (who, pick).prop_map(|(who, pick)| Theft::Remove { who, pick }),
        3 => (who, pick).prop_map(|(who, pick)| Theft::Veto { who, pick }),
        1 => (who, pick).prop_map(|(who, pick)| Theft::Cosign { who, pick }),
        1 => (who, pick, any::<bool>())
            .prop_map(|(who, pick, upheld)| Theft::Resolve { who, pick, upheld }),
        1 => (who, pick).prop_map(|(who, pick)| Theft::Replace { who, pick }),
        1 => who.prop_map(|who| Theft::Rotate { who }),
        1 => who.prop_map(|who| Theft::Regroup { who }),
        1 => who.prop_map(|who| Theft::Add { who }),
        1 => who.prop_map(|who| Theft::Alive { who }),
        3 => (1u16..180).prop_map(Theft::Pass),
    ]
}

/// The longest the owner takes to react, after its first notice and in its
/// head start alike: under the delay and the probation, 3 minutes.
const LAG_S: u64 = 170;

/// The thief's game: its devices, the next kit it may draw, and when the
/// owner first moved against each of its devices.
struct Game {
    home: Home,
    owner: Owner,
    thief: DeviceId,
    kits: u8,
    /// The batch time the thief's head start has used.
    head: u64,
    noticed: BTreeMap<DeviceId, u64>,
    vetoed: BTreeSet<(u64, DeviceId)>,
}

impl Game {
    fn new(owner: Owner) -> Self {
        let mut home = Home::with(minutes());
        let thief = owner.devices().len() as DeviceId;
        for n in 1..=thief {
            home.pair(0, n as u8);
        }
        home.pass(10 * MINUTE);
        for n in 0..=thief {
            home.call::<Recorded>(sync(n as u8), "alive", ()).unwrap();
        }
        Self {
            home,
            owner,
            thief,
            kits: 0,
            head: 0,
            noticed: BTreeMap::new(),
            vetoed: BTreeSet::new(),
        }
    }

    fn reader(&self) -> Principal {
        sync(0)
    }

    /// The live devices that are not the owner's: the thief's.
    fn thiefs(&self) -> Vec<DeviceId> {
        devices(&self.home, self.reader())
            .into_iter()
            .filter(|view| {
                !self.owner.devices().contains(&view.id)
                    && matches!(view.standing, Standing::Active | Standing::Probation)
            })
            .map(|view| view.id)
            .collect()
    }

    fn picked(&self, pick: u8) -> Option<u64> {
        let open = open(&self.home, self.reader());
        open.get(pick as usize % open.len().max(1))
            .map(|(index, _)| *index)
    }

    /// One call of the thief's, its refusals ignored: a refused call
    /// writes nothing. Between two of the owner's rounds, and in all of the
    /// head start before the owner notices, at most [`LAG_S`] passes.
    fn steal(&mut self, theft: &Theft, head_start: bool) {
        let who = match *theft {
            Theft::Pass(seconds) => {
                let mut seconds = u64::from(seconds).min(LAG_S);
                if head_start {
                    seconds = seconds.min(LAG_S - self.head);
                    self.head += seconds;
                }
                return self.home.pass(seconds * 1000);
            }
            Theft::Pair => return self.pair(),
            Theft::Remove { who, .. }
            | Theft::Veto { who, .. }
            | Theft::Cosign { who, .. }
            | Theft::Resolve { who, .. }
            | Theft::Replace { who, .. }
            | Theft::Rotate { who }
            | Theft::Regroup { who }
            | Theft::Add { who }
            | Theft::Alive { who } => who,
        };
        let thiefs = self.thiefs();
        let Some(&id) = thiefs.get(who as usize % thiefs.len().max(1)) else {
            return;
        };
        let keys = device_keys(id);
        let admin = Principal::Client(keys.admin);
        let views = devices(&self.home, self.reader());
        let all: Vec<DeviceId> = views.iter().map(|view| view.id).collect();
        let device_at = |pick: u8| all[pick as usize % all.len()];
        let _ = match *theft {
            Theft::Remove { pick, .. } => self.home.operate(admin, "remove", device_at(pick)),
            Theft::Veto { pick, .. } => match self.picked(pick) {
                Some(index) => self.home.operate(admin, "veto", index),
                None => return,
            },
            Theft::Cosign { pick, .. } => match self.picked(pick) {
                Some(index) => self.home.operate(admin, "cosign", index),
                None => return,
            },
            Theft::Resolve { pick, upheld, .. } => match self.picked(pick) {
                Some(index) => self.home.operate(admin, "resolve", (index, upheld)),
                None => return,
            },
            Theft::Replace { pick, .. } => {
                let key = NewAdmin {
                    key: [0x90 + self.kits; 32],
                    class: AdminClass::Strong,
                    attestation: device(0).attestation,
                };
                self.kits += 1;
                self.home.operate(admin, "replace", (device_at(pick), key))
            }
            Theft::Rotate { .. } => {
                let (kit, r2) = new_kit(self.kits);
                self.kits += 1;
                let index = self.home.operate(admin, "rotate", kit.clone());
                if let Ok(index) = index {
                    let posted = Principal::Client(keys.sync);
                    let _ = self
                        .home
                        .deposit(posted, keys.admin, index, "rotate", kit, r2);
                }
                index
            }
            Theft::Regroup { .. } => {
                // A regroup names every other live device.
                let named: Vec<DeviceId> = views
                    .iter()
                    .filter(|view| view.id != id && view.device.status == Status::Live)
                    .map(|view| view.id)
                    .collect();
                self.home.operate(admin, "regroup", named)
            }
            Theft::Add { .. } => self
                .home
                .operate(admin, "add", device(all.len() as u8 + 16)),
            Theft::Alive { .. } => self.home.operate(Principal::Client(keys.sync), "alive", ()),
            Theft::Pair | Theft::Pass(_) => unreachable!(),
        };
    }

    /// The thief pairs a device of its own, every device of the set
    /// confirming, the owner's among them.
    fn pair(&mut self) {
        let Some(&by) = self.thiefs().first() else {
            return;
        };
        let views = devices(&self.home, self.reader());
        let id = views.len() as u8;
        let epoch = self.home.overview().confirmed + 1;
        // The commit carries every matured removal it owes.
        let owed = views
            .iter()
            .filter(|view| {
                view.removal
                    .is_some_and(|removal| removal.committed.is_none())
            })
            .map(|view| view.id)
            .collect::<Vec<_>>();
        let rekey = (!owed.is_empty()).then(|| self.home.rekey(self.reader(), id).0);
        let effect = Effect {
            add: Some(device(id)),
            remove: owed,
            rekey,
        };
        let made = self.home.call::<Candidacy>(
            Principal::Client(device_keys(by).admin),
            "commit",
            commit(epoch, effect, vec![id; 600]),
        );
        if let Ok(candidacy) = made {
            confirm(&mut self.home, epoch, &candidacy.set);
        }
    }

    /// The owner's device settles what fell due before it reads again: a
    /// read shows what the agent stores, and every call settles first, so
    /// once a resolution removed a thief device its operations may be
    /// cancelled by then, and a contest resting on its vetoes pending again.
    fn settle(&mut self) {
        self.home.wake(self.reader()).unwrap();
    }

    /// The owner's round: veto every operation of the thief's but a removal
    /// of its devices, remove each of its devices, and settle every contest
    /// over those removals in the owner's favour.
    fn defend(&mut self) {
        let owners = self.owner.devices();
        let acting = owners[0];
        self.settle();
        let open = open(&self.home, self.reader());
        let thiefs = self.thiefs();
        for (index, operation) in &open {
            let thiefs_own = matches!(operation.by, Signer::Device(by) if !owners.contains(&by));
            let removes_thief =
                matches!(operation.op, Op::Remove(target) if thiefs.contains(&target));
            if thiefs_own && !removes_thief && self.vetoed.insert((*index, acting)) {
                self.home
                    .operate(admin(acting as u8), "veto", *index)
                    .unwrap();
            }
        }
        for thief in thiefs {
            self.noticed.entry(thief).or_insert(self.home.now());
            let open = open_removal(&self.home, self.reader(), thief);
            let Some((index, operation)) = open else {
                self.home
                    .operate(admin(acting as u8), "remove", thief)
                    .unwrap();
                continue;
            };
            let owners_own = matches!(operation.by, Signer::Device(by) if owners.contains(&by));
            match self.owner {
                Owner::DeviceAndKit => {
                    if !owners_own && operation.state == OpState::Pending {
                        self.home
                            .operate(admin(acting as u8), "veto", index)
                            .unwrap();
                    }
                    if !owners_own || operation.state == OpState::Contested {
                        self.home.operate(KIT, "resolve", (index, true)).unwrap();
                    }
                }
                Owner::TwoSeasoned { hasty } => {
                    if owners_own {
                        let Signer::Device(by) = operation.by else {
                            unreachable!()
                        };
                        let other = if by == 0 { 1 } else { 0 };
                        if hasty || operation.state == OpState::Contested {
                            self.home.operate(admin(other), "cosign", index).unwrap();
                        }
                    } else {
                        if operation.state == OpState::Pending {
                            self.home
                                .operate(admin(acting as u8), "veto", index)
                                .unwrap();
                        }
                        for owner in owners {
                            let _ =
                                self.home
                                    .operate(admin(*owner as u8), "resolve", (index, true));
                        }
                    }
                }
            }
            self.settle();
        }
    }

    /// Defend until the thief has no device, within the delay.
    fn finish(&mut self) {
        for _ in 0..12 {
            self.defend();
            if self.thiefs().is_empty() {
                return;
            }
            self.home.pass(30 * 1000);
        }
        panic!("the thief's devices {:?} outlived the owner", self.thiefs());
    }

    /// The owner removed every device of the thief's within the delay of
    /// first moving against it, and lost none of its own, nor its kit, nor
    /// an admin key.
    fn check(&mut self) {
        self.home.wake(sync(0)).unwrap();
        let delay = minutes().operation_delay_ms;
        for view in devices(&self.home, self.reader()) {
            if self.owner.devices().contains(&view.id) {
                assert_eq!(view.standing, Standing::Active, "the owner's {}", view.id);
                assert_eq!(view.device.keys.admin, device_keys(view.id).admin);
                continue;
            }
            if view.standing == Standing::Dropped {
                continue;
            }
            assert_eq!(view.standing, Standing::Removed, "the thief's {}", view.id);
            let removal = view.removal.unwrap();
            // A thief's device that left by its own removal needed no
            // move of the owner's.
            let by = self.home.operation(self.reader(), removal.index).by;
            if by == Signer::Device(view.id) {
                continue;
            }
            let noticed = self.noticed[&view.id];
            let removed = removal.at;
            assert!(
                removed <= noticed + delay,
                "device {} removed {} ms after the owner moved",
                view.id,
                removed - noticed
            );
        }
        let recovery: RecoveryView = self.home.query(KIT, "recovery", ()).unwrap();
        assert_eq!(recovery.entries, kit().entries, "the owner's kit");
    }
}

/// The open removal of `target`.
fn open_removal(home: &Home, reader: Principal, target: DeviceId) -> Option<(u64, Operation)> {
    open(home, reader)
        .into_iter()
        .find(|(_, operation)| operation.op == Op::Remove(target))
}

/// Run the thief's `thefts`, the owner noticing after the first `notice`
/// of them, then defending after each.
fn play(owner: Owner, thefts: Vec<Theft>, notice: usize) {
    let mut game = Game::new(owner);
    let thief = game.thief;
    assert_eq!(game.thiefs(), vec![thief]);
    for (n, theft) in thefts.iter().enumerate() {
        game.steal(theft, n < notice);
        if n + 1 >= notice {
            game.defend();
        }
    }
    game.finish();
    game.check();
}

/// The thief removes the owner's device, pairs a device, and vetoes the
/// owner's removal of it; the kit upholds the owner's removal of the
/// thief's own device, so that veto lifts with its silencing at the next
/// call, the removal of the paired device pending again and maturing at
/// its own time.
#[test]
fn a_veto_lifted_by_its_vetoers_removal_leaves_the_removal_pending() {
    play(
        Owner::DeviceAndKit,
        vec![
            Theft::Remove { who: 0, pick: 66 },
            Theft::Pair,
            Theft::Remove { who: 5, pick: 0 },
            Theft::Alive { who: 0 },
            Theft::Veto { who: 92, pick: 38 },
        ],
        4,
    );
}

/// The same, the thief pairing first and the owner noticing at its
/// removal.
#[test]
fn a_veto_lifted_by_its_vetoers_removal_after_a_pairing() {
    play(
        Owner::DeviceAndKit,
        vec![
            Theft::Pair,
            Theft::Veto { who: 0, pick: 0 },
            Theft::Remove { who: 68, pick: 129 },
            Theft::Veto { who: 254, pick: 80 },
        ],
        3,
    );
}

/// The same with two paired devices, the thief vetoing the owner's removal
/// of the second.
#[test]
fn a_veto_lifted_by_its_vetoers_removal_leaves_a_second_removal_pending() {
    play(
        Owner::DeviceAndKit,
        vec![
            Theft::Remove { who: 0, pick: 84 },
            Theft::Pair,
            Theft::Veto { who: 0, pick: 44 },
            Theft::Pair,
            Theft::Veto {
                who: 175,
                pick: 142,
            },
            Theft::Veto { who: 114, pick: 35 },
        ],
        5,
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// A4, A14: a thief with the owner's device and its biometric, pairing
    /// devices and making any operation, against the owner's device and
    /// the kit.
    #[test]
    fn the_owner_with_a_device_and_the_kit_removes_a_thief_with_the_biometric(
        thefts in prop::collection::vec(theft(), 1..24),
        notice in 0usize..6,
    ) {
        play(Owner::DeviceAndKit, thefts, notice);
    }

    /// A4, A14: the same thief against two other seasoned devices, which
    /// remove at once or let the removal wait.
    #[test]
    fn two_other_seasoned_devices_remove_a_thief_with_the_biometric(
        thefts in prop::collection::vec(theft(), 1..24),
        notice in 0usize..6,
        hasty in any::<bool>(),
    ) {
        play(Owner::TwoSeasoned { hasty }, thefts, notice);
    }
}

// ===== The thief with a sync key alone =====

/// A call the thief with the device's sync key alone makes.
#[derive(Clone, Debug)]
enum Sync {
    Alive,
    Push(u8),
    Wake,
    /// An admin call under the sync key, which it holds in place of the
    /// admin key.
    Veto(u8),
    Remove,
    Pass(u16),
}

fn sync_theft() -> impl Strategy<Value = Sync> {
    prop_oneof![
        4 => Just(Sync::Alive),
        1 => any::<u8>().prop_map(Sync::Push),
        1 => Just(Sync::Wake),
        2 => any::<u8>().prop_map(Sync::Veto),
        1 => Just(Sync::Remove),
        4 => (1u16..240).prop_map(Sync::Pass),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// A3, A4: the thief holds the owner's only device's sync key and
    /// calls as it likes; the kit alone removes the device after its delay
    /// unvetoed, and its restore matures its delay later, the removed
    /// device's `alive` ignored, `R2` released to the restore's device.
    #[test]
    fn the_kit_alone_removes_a_thief_with_a_sync_key_and_restores(
        thefts in prop::collection::vec(sync_theft(), 1..40),
    ) {
        let policy = minutes();
        let mut home = Home::with(policy);
        let start = home.now();
        let removal = home.operate(KIT, "remove", 0u32).unwrap();
        let removed = start + policy.kit_delay_ms;
        let (next, r2) = new_kit(1);
        let restoring = (device(5), next.clone());
        let mut restore: Option<(u64, u64)> = None;
        let mut thefts = thefts.into_iter();
        while restore.is_none_or(|(_, at)| home.now() <= at + policy.kit_delay_ms) {
            match thefts.next().unwrap_or(Sync::Pass(60)) {
                Sync::Alive => {
                    let _ = home.call::<Recorded>(sync(0), "alive", ());
                }
                Sync::Push(fill) => {
                    let epoch = home.query::<Overview>(KIT, "overview", ()).map_or(0, |o| o.confirmed);
                    let _ = home.push(0, envelope(scope(1), epoch, fill, 200));
                }
                Sync::Wake => {
                    let _ = home.wake(sync(0));
                }
                Sync::Veto(pick) => {
                    let target = [removal, restore.map_or(removal, |(index, _)| index)];
                    let _ = home.operate(sync(0), "veto", target[pick as usize % 2]);
                }
                Sync::Remove => {
                    let _ = home.operate(sync(0), "remove", 0u32);
                }
                Sync::Pass(seconds) => home.pass(u64::from(seconds) * 1000),
            }
            if restore.is_none() && home.now() > removed {
                home.wake(KIT).unwrap();
                let index = home.operate(KIT, "restore", restoring.clone()).unwrap();
                home.deposit(KIT, KIT_KEY, index, "restore", restoring.clone(), r2).unwrap();
                restore = Some((index, home.now() - 2));
            }
        }
        let (index, posted) = restore.unwrap();
        home.wake(KIT).or_else(|_| home.wake(kit_key(1, 0))).unwrap();
        let reader = sync(5);
        let operation = home.operation(reader, removal);
        prop_assert_eq!(operation.state, OpState::Matured { at: removed });
        let operation = home.operation(reader, index);
        prop_assert_eq!(operation.state, OpState::Matured { at: posted + policy.kit_delay_ms });
        let views = devices(&home, reader);
        prop_assert_eq!(views[0].standing, Standing::Removed);
        prop_assert_eq!(views[0].removal.unwrap().at, removed);
        prop_assert_eq!(views[1].standing, Standing::Active);
        let recovery: RecoveryView = home.query(reader, "recovery", ()).unwrap();
        prop_assert_eq!(recovery.released, Some(kit().r2));
        prop_assert_eq!(recovery.entries, next.entries);
    }
}

// ===== A leaked kit alone =====

/// A call the leaked kit makes.
#[derive(Clone, Debug)]
enum Leak {
    Remove(u8),
    Restore,
    Rotate,
    Replace(u8),
    Veto(u8),
    Resolve(u8, bool),
    Cosign(u8),
    Wake,
    Pass(u16),
}

fn leak() -> impl Strategy<Value = Leak> {
    prop_oneof![
        3 => any::<u8>().prop_map(Leak::Remove),
        2 => Just(Leak::Restore),
        2 => Just(Leak::Rotate),
        1 => any::<u8>().prop_map(Leak::Replace),
        1 => any::<u8>().prop_map(Leak::Veto),
        1 => (any::<u8>(), any::<bool>()).prop_map(|(pick, upheld)| Leak::Resolve(pick, upheld)),
        1 => any::<u8>().prop_map(Leak::Cosign),
        1 => Just(Leak::Wake),
        4 => (1u16..360).prop_map(Leak::Pass),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// D3: a leaked kit makes any of its operations, in any order, while
    /// the owner's two devices post `alive` and veto each, in either
    /// order: none matures, no device is removed or added, and the kit and
    /// the recovery scope stay the owner's.
    #[test]
    fn a_leaked_kit_alone_completes_nothing_while_a_device_vetoes(
        leaks in prop::collection::vec((leak(), any::<bool>()), 1..32),
    ) {
        let mut home = Home::with(minutes());
        home.pair(0, 1);
        home.pass(3 * MINUTE);
        let epoch = home.overview().confirmed;
        home.push(0, envelope(RECOVERY, epoch, 1, 300)).unwrap();
        let mut kits = 0u8;
        let mut made: Vec<u64> = Vec::new();
        let mut vetoed: BTreeSet<u64> = BTreeSet::new();
        let leaks = leaks
            .into_iter()
            .chain(std::iter::repeat_n((Leak::Pass(300), false), 4));
        for (leak, alive_first) in leaks {
            let picked = |home: &Home, pick: u8| {
                let open = open(home, sync(0));
                open.get(pick as usize % open.len().max(1)).map(|(index, _)| *index)
            };
            let result = match leak {
                Leak::Remove(pick) => home.operate(KIT, "remove", u32::from(pick % 2)),
                Leak::Restore => {
                    let (kit, r2) = new_kit(kits);
                    kits += 1;
                    let arguments = (device(9 + kits), kit);
                    let index = home.operate(KIT, "restore", arguments.clone());
                    if let Ok(index) = index {
                        home.deposit(KIT, KIT_KEY, index, "restore", arguments, r2).unwrap();
                    }
                    index
                }
                Leak::Rotate => {
                    let (kit, r2) = new_kit(kits);
                    kits += 1;
                    let index = home.operate(KIT, "rotate", kit.clone());
                    if let Ok(index) = index {
                        home.deposit(KIT, KIT_KEY, index, "rotate", kit, r2).unwrap();
                    }
                    index
                }
                Leak::Replace(pick) => {
                    let key = NewAdmin {
                        key: [0x90 + kits; 32],
                        class: AdminClass::Strong,
                        attestation: device(0).attestation,
                    };
                    kits += 1;
                    home.operate(KIT, "replace", (u32::from(pick % 2), key))
                }
                Leak::Veto(pick) => match picked(&home, pick) {
                    Some(index) => {
                        prop_assert_eq!(home.operate(KIT, "veto", index), Err(PersonalError::KitVeto));
                        continue;
                    }
                    None => continue,
                },
                Leak::Resolve(pick, upheld) => match picked(&home, pick) {
                    Some(index) => home.operate(KIT, "resolve", (index, upheld)),
                    None => continue,
                },
                Leak::Cosign(pick) => match picked(&home, pick) {
                    Some(index) => home.operate(KIT, "cosign", index),
                    None => continue,
                },
                Leak::Wake => home.wake(KIT).map(|_| 0),
                Leak::Pass(seconds) => {
                    home.pass(u64::from(seconds) * 1000);
                    Ok(0)
                }
            };
            if let (Leak::Remove(_) | Leak::Restore | Leak::Rotate | Leak::Replace(_), Ok(index)) = (&leak, result) {
                made.push(index);
            }
            // The owner's round: its devices' `alive`, before or after a
            // veto of each of the kit's operations.
            if alive_first {
                for n in 0..2 {
                    home.call::<Recorded>(sync(n), "alive", ()).unwrap();
                }
            }
            for (index, operation) in open(&home, sync(0)) {
                if matches!(operation.by, Signer::Kit(_)) && vetoed.insert(index) {
                    home.operate(admin((index % 2) as u8), "veto", index).unwrap();
                }
            }
            for n in 0..2 {
                home.call::<Recorded>(sync(n), "alive", ()).unwrap();
            }
        }
        for index in made {
            let state = home.operation(sync(0), index).state;
            prop_assert!(matches!(state, OpState::Cancelled { .. }), "{index}: {state:?}");
        }
        for view in devices(&home, sync(0)) {
            prop_assert_eq!(view.standing, Standing::Active);
            prop_assert_eq!(view.device.keys.admin, device_keys(view.id).admin);
        }
        let recovery: RecoveryView = home.query(KIT, "recovery", ()).unwrap();
        prop_assert_eq!(recovery.entries, kit().entries);
        prop_assert_eq!(recovery.from, 0, "no rotation moved the recovery scope's start");
        prop_assert_eq!(devices(&home, sync(0)).len(), 2, "no restore added a device");
    }
}
