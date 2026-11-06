//! The inbox: written by the user's devices and a pairing slot's holder,
//! read by the devices and a slot's two parties, its items expiring
//! lazily; and the pairing slot, admitted for its slot alone.

use vos_wire::personal::{
    Author, Candidacy, Effect, InboxItem, Item, PersonalError, Recipient, Recorded,
};

use super::*;

/// The arguments of a `put`.
fn put(to: Recipient, id: u8, expires: u64, bytes: Vec<u8>) -> impl Encode {
    ((to, [id; 16]), (expires, bytes))
}

/// C7: only the user's devices write the inbox for their devices, within
/// its bounds (64 items, 16 KiB an item, a week's life); reads skip
/// expired items, and each write deletes a few, so the bound frees with
/// time and no timer.
#[test]
fn the_inbox_takes_the_devices_items_and_expires_them_lazily() {
    let mut home = Home::new();
    home.pair(0, 1);
    let soon = home.now + HOUR_MS;
    for caller in [STRANGER, KIT, admin(0)] {
        assert_eq!(
            home.call::<u64>(caller, "put", put(Recipient::Devices, 1, soon, vec![1; 10])),
            Err(PersonalError::NotAdmitted),
            "{caller:?}"
        );
    }
    assert_eq!(
        home.call::<u64>(
            sync(0),
            "put",
            put(Recipient::Devices, 1, home.now + 7 * DAY + 10, vec![1])
        ),
        Err(PersonalError::Expiry)
    );
    assert_eq!(
        home.call::<u64>(
            sync(0),
            "put",
            put(Recipient::Devices, 1, home.now, vec![1])
        ),
        Err(PersonalError::Expiry)
    );
    assert_eq!(
        home.call::<u64>(
            sync(0),
            "put",
            put(Recipient::Devices, 1, soon, vec![1; (16 << 10) + 1])
        ),
        Err(PersonalError::TooLarge)
    );
    home.call::<u64>(
        sync(0),
        "put",
        put(Recipient::Devices, 1, soon, vec![1; 10]),
    )
    .unwrap();
    home.call::<u64>(
        sync(0),
        "put",
        put(Recipient::Devices, 1, soon, vec![1; 10]),
    )
    .unwrap();
    let later = home.now + 2 * HOUR_MS;
    home.call::<u64>(
        sync(1),
        "put",
        put(Recipient::Devices, 2, later, vec![2; 10]),
    )
    .unwrap();
    let items: Vec<InboxItem> = home
        .query(sync(1), "inbox", None::<(u64, [u8; 16])>)
        .unwrap();
    assert_eq!(
        items,
        vec![
            InboxItem {
                expires: soon,
                id: [1; 16],
                item: Item {
                    to: Recipient::Devices,
                    from: Author::Device(0),
                    bytes: vec![1; 10],
                },
            },
            InboxItem {
                expires: later,
                id: [2; 16],
                item: Item {
                    to: Recipient::Devices,
                    from: Author::Device(1),
                    bytes: vec![2; 10],
                },
            },
        ],
        "the same item stored once"
    );
    for caller in [KIT, STRANGER] {
        assert_eq!(
            home.query::<Vec<InboxItem>>(caller, "inbox", None::<(u64, [u8; 16])>),
            Err(PersonalError::NotAdmitted)
        );
    }
    let after: Vec<InboxItem> = home
        .query(sync(0), "inbox", Some((soon, [1u8; 16])))
        .unwrap();
    assert_eq!(after, items[1..]);
    // Past the first item's expiry, reads skip it.
    home.pass(HOUR_MS);
    let items: Vec<InboxItem> = home
        .query(sync(0), "inbox", None::<(u64, [u8; 16])>)
        .unwrap();
    assert_eq!(items.len(), 1);
    // Full at 64: an expiry frees it, the next write deleting the expired.
    let expires = home.now + 3 * HOUR_MS;
    for id in 10..73 {
        home.call::<u64>(
            sync(0),
            "put",
            put(Recipient::Devices, id, expires, vec![id; 10]),
        )
        .unwrap();
    }
    assert_eq!(
        home.call::<u64>(
            sync(0),
            "put",
            put(Recipient::Devices, 99, expires, vec![9])
        ),
        Err(PersonalError::InboxFull)
    );
    home.pass(HOUR_MS);
    home.call::<u64>(
        sync(0),
        "put",
        put(Recipient::Devices, 99, expires, vec![9]),
    )
    .unwrap();
    let items: Vec<InboxItem> = home
        .query(sync(0), "inbox", None::<(u64, [u8; 16])>)
        .unwrap();
    assert_eq!(items.len(), 64);
}

/// A pairing slot admits its key for that slot alone: the slot's holder
/// writes and reads its slot's items and nothing else, for ten minutes;
/// its opener's add closes it, and a closed slot's key reads nothing.
#[test]
fn a_pairing_slot_admits_its_key_for_its_slot_alone() {
    let mut home = Home::new();
    let slot: Scope = [0x51; 16];
    let holder = Principal::Client([0x52; 32]);
    assert_eq!(
        home.call::<u64>(sync(0), "open_slot", (slot, device(0).admin)),
        Err(PersonalError::KeyTaken)
    );
    home.call::<u64>(sync(0), "open_slot", (slot, [0x52u8; 32]))
        .unwrap();
    assert_eq!(
        home.call::<u64>(sync(0), "open_slot", (slot, [0x53u8; 32])),
        Err(PersonalError::SlotTaken)
    );
    let ten = home.now + 10 * 60 * 1000 - 5;
    assert_eq!(
        home.call::<u64>(holder, "put", put(Recipient::Devices, 1, ten, vec![1])),
        Err(PersonalError::NotAdmitted)
    );
    assert_eq!(
        home.call::<u64>(
            holder,
            "put",
            put(Recipient::Slot(slot), 1, ten + 100, vec![1])
        ),
        Err(PersonalError::Expiry),
        "past the slot's life"
    );
    home.call::<u64>(holder, "put", put(Recipient::Slot(slot), 1, ten, vec![1]))
        .unwrap();
    home.call::<u64>(sync(0), "put", put(Recipient::Slot(slot), 2, ten, vec![2]))
        .unwrap();
    home.call::<u64>(sync(0), "put", put(Recipient::Devices, 3, ten, vec![3]))
        .unwrap();
    let read: Vec<InboxItem> = home
        .query(holder, "inbox", None::<(u64, [u8; 16])>)
        .unwrap();
    assert_eq!(
        read.iter().map(|item| item.item.from).collect::<Vec<_>>(),
        vec![Author::Slot(slot), Author::Device(0)],
        "its slot's items alone"
    );
    for name in ["overview", "devices"] {
        assert_eq!(
            home.query::<Overview>(holder, name, ()).map(|_| ()),
            Err(PersonalError::NotAdmitted),
            "{name}"
        );
    }
    assert_eq!(
        home.call::<Recorded>(holder, "alive", ()),
        Err(PersonalError::NotAdmitted)
    );
    // The opener's add closes it: its key reads and writes no more.
    let effect = Effect {
        add: Some(device(1)),
        remove: Vec::new(),
    };
    let candidacy: Candidacy = home
        .call(admin(0), "commit", commit(1, effect, vec![1; 700]))
        .unwrap();
    home.confirm_all(1, &candidacy.set);
    assert_eq!(
        home.query::<Vec<InboxItem>>(holder, "inbox", None::<(u64, [u8; 16])>),
        Err(PersonalError::NotAdmitted)
    );
    assert!(
        home.node
            .get(&vos_wire::keys::admitted(PERSONAL, &[0x52; 32]))
            .is_none()
    );
    // A slot left open expires in ten minutes.
    let other: Scope = [0x61; 16];
    let key = Principal::Client([0x62; 32]);
    home.call::<u64>(sync(0), "open_slot", (other, [0x62u8; 32]))
        .unwrap();
    home.query::<Vec<InboxItem>>(key, "inbox", None::<(u64, [u8; 16])>)
        .unwrap();
    home.pass(10 * 60 * 1000);
    assert_eq!(
        home.query::<Vec<InboxItem>>(key, "inbox", None::<(u64, [u8; 16])>),
        Err(PersonalError::NotAdmitted)
    );
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    assert!(
        home.node
            .get(&vos_wire::keys::admitted(PERSONAL, &[0x62; 32]))
            .is_none(),
        "its key admitted no more once a call settled it"
    );
    assert_eq!(
        home.call::<u64>(sync(0), "close_slot", other),
        Err(PersonalError::NoSlot)
    );
}

/// One open slot an opener, and a few an agent; a slot's holder writes a
/// few items; closing a slot deletes its items, so a slot id opened again
/// reads none of them; and an item key holds one item.
#[test]
fn slots_and_their_items_are_bounded() {
    let mut home = Home::new();
    home.pair(0, 1);
    let soon = home.now + 5 * 60 * 1000;
    let slot: Scope = [0x71; 16];
    home.call::<u64>(sync(0), "open_slot", (slot, [0x72u8; 32]))
        .unwrap();
    assert_eq!(
        home.call::<u64>(sync(0), "open_slot", ([0x73u8; 16], [0x74u8; 32])),
        Err(PersonalError::SlotTaken),
        "one an opener"
    );
    let holder = Principal::Client([0x72; 32]);
    for id in 0..4 {
        home.call::<u64>(
            holder,
            "put",
            put(Recipient::Slot(slot), id, soon, vec![id]),
        )
        .unwrap();
    }
    assert_eq!(
        home.call::<u64>(holder, "put", put(Recipient::Slot(slot), 9, soon, vec![9])),
        Err(PersonalError::InboxFull)
    );
    assert_eq!(
        home.call::<u64>(
            sync(1),
            "put",
            put(Recipient::Slot(slot), 0, soon, vec![0xff])
        ),
        Err(PersonalError::ItemTaken)
    );
    home.call::<u64>(sync(1), "close_slot", slot).unwrap();
    home.call::<u64>(sync(0), "open_slot", (slot, [0x75u8; 32]))
        .unwrap();
    let read: Vec<InboxItem> = home
        .query(
            Principal::Client([0x75; 32]),
            "inbox",
            None::<(u64, [u8; 16])>,
        )
        .unwrap();
    assert!(read.is_empty(), "the closed slot's items deleted");
}
