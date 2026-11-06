//! L10: `Personal`'s queries answer only the keys it admits: any key may
//! sign a query, and admission covers sessions alone, so each read checks
//! its caller.

use vos_wire::personal::{
    Acknowledged, DeviceView, Entry, Envelope, InboxItem, PersonalError, Recorded, Scope,
};

use vos_wire::ids::AgentId;

use super::*;

/// Every read's arguments, by name.
fn reads() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("overview", Vec::new()),
        ("devices", Vec::new()),
        ("log", 0u64.encode()),
        ("since", (scope(1), 0u64).encode()),
        ("inbox", None::<(u64, [u8; 16])>.encode()),
        ("acknowledgements", (scope(1), 0u64).encode()),
        ("frontier", 0u32.encode()),
    ]
}

/// What `caller`'s read `name` answers: `Ok` or the refusal.
fn read(home: &Home, caller: Principal, name: &str, arguments: &[u8]) -> Result<(), PersonalError> {
    let work = Work::Query(Query {
        time: home.now,
        seed: [0; 32],
        caller,
        instance: PERSONAL,
        method: home.method(name),
        arguments: arguments.to_vec(),
    });
    match Outcome::decode(&home.node.refine(&work)).unwrap().0 {
        Outcome::Done(_) => Ok(()),
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => Err(PersonalError::decode_exact(&detail).unwrap()),
        other => panic!("{name}: {other:?}"),
    }
}

/// A stranger, another member, the home and a device whose removal
/// matured read nothing, before the assignment and after; the devices
/// read everything, by either key; the kit reads all but the inbox and
/// the scopes other than recovery's; the version answers anyone.
#[test]
fn queries_answer_only_admitted_keys() {
    let mut home = Home::installed();
    for (name, arguments) in reads() {
        assert_eq!(
            read(&home, sync(0), name, &arguments),
            Err(PersonalError::NotAdmitted),
            "{name} before the assignment"
        );
    }
    home.call::<Recorded>(HOMES, "assign", (device(0), kit()))
        .unwrap();
    home.pair(0, 1);
    home.push(1, envelope(scope(1), 1, 1, 100)).unwrap();
    for (name, arguments) in reads() {
        for caller in [STRANGER, HOMES, Principal::Agent(AgentId(3))] {
            assert_eq!(
                read(&home, caller, name, &arguments),
                Err(PersonalError::NotAdmitted),
                "{name} by {caller:?}"
            );
        }
        for caller in [sync(0), admin(0), sync(1)] {
            assert_eq!(read(&home, caller, name, &arguments), Ok(()), "{name}");
        }
        let kit = read(&home, KIT, name, &arguments);
        if matches!(name, "inbox" | "since") {
            assert_eq!(kit, Err(PersonalError::NotAdmitted), "{name} by the kit");
        } else {
            assert_eq!(kit, Ok(()), "{name} by the kit");
        }
    }
    // Device 1's removal matured: before a call settles it, its reads are
    // refused by its standing.
    home.call::<Recorded>(admin(0), "remove", 1u32).unwrap();
    home.pass(72 * HOUR_MS);
    for (name, arguments) in reads() {
        assert_eq!(
            read(&home, sync(1), name, &arguments),
            Err(PersonalError::Removed),
            "{name}"
        );
    }
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    for (name, arguments) in reads() {
        assert_eq!(
            read(&home, sync(1), name, &arguments),
            Err(PersonalError::NotAdmitted),
            "{name}"
        );
    }
    // Its frontier: the last position it pushed to, a scope.
    let frontier: Vec<(Scope, u64)> = home.query(KIT, "frontier", 1u32).unwrap();
    assert_eq!(frontier, vec![(scope(1), 1)]);
    let version: u32 = home.query(STRANGER, "version", ()).unwrap();
    assert_eq!(version, 1);
    // The answers decode as their types.
    let _: Vec<DeviceView> = home.query(KIT, "devices", ()).unwrap();
    let _: Vec<(u64, Entry)> = home.query(KIT, "log", 0u64).unwrap();
    let _: Vec<Envelope> = home.query(sync(0), "since", (scope(1), 0u64)).unwrap();
    let _: Vec<InboxItem> = home
        .query(sync(0), "inbox", None::<(u64, [u8; 16])>)
        .unwrap();
    let _: Vec<Acknowledged> = home
        .query(KIT, "acknowledgements", (scope(1), 0u64))
        .unwrap();
}
