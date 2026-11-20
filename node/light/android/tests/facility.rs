// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The facility against the world's space over its Tor client: enrollment
//! pins what the chrome showed, the space's onions among it; a sign-in
//! proves on the path the tree's feed gave, and the facility sends the
//! proof over Tor itself, the server answered the node's answer; a payment
//! pays what the chrome confirmed, whatever the server pre-filled; requests
//! naming what was not pinned are refused; and every proof and read is a
//! connection's own, none of them on the clearnet.

mod common;

use common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_sign_in_and_pay_as_the_chrome_confirmed() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(Phone::new(9));
    let facility = facility(
        &world,
        directory.path(),
        Arc::clone(&source) as Arc<dyn Source>,
    );
    let session = facility.session(gateway());
    let chrome = Scripted::default();

    // Enrollment: what the chrome showed is pinned, and the digests are the
    // secret's.
    chrome.will(confirm(&[]));
    chrome.will(confirm(&[]));
    let enrolled = session.ask("enroll", &enrollment(), &chrome).await.unwrap();
    let digests = chrome.last();
    let shown = chrome.shown.lock().unwrap()[0].clone();
    assert_eq!(shown.choices, vec!["Use this phone's lock"]);
    assert!(
        shown
            .rows
            .iter()
            .any(|(_, value)| value.contains("vote (once in scope “vote”)"))
    );
    // The phone's first keystore key, the enrollment's source.
    let alias = format!("vos.device.{}", 9u8 * 16 + 1);
    let output = vos_light::testing::hmac(
        &vos_light::testing::hmac(&[9; 32], alias.as_bytes()),
        &vos_light::source_input(&HANDLE),
    );
    let secret = vos_light::derive_secret(&output, &HANDLE);
    let member = vos_light::member(&secret).to_bytes();
    assert_eq!(bytes(field(&enrolled, "member")), member.to_vec());
    assert_eq!(
        bytes(field(&enrolled, "owner")),
        vos_light::owner(&secret).to_bytes().to_vec()
    );
    // The digests as a code for the operator's camera, its six-digit
    // check, and whole.
    let owner = vos_light::owner(&secret).to_bytes();
    assert_eq!(
        digests.rows[0],
        (
            "Check".to_owned(),
            vos_api::enrollment_check(&member, &owner)
        )
    );
    assert_eq!(digests.rows[1], ("Member".to_owned(), hex::encode(member)));
    assert_eq!(digests.rows[2], ("Owner".to_owned(), hex::encode(owner)));
    assert_eq!(
        digests
            .code
            .as_deref()
            .and_then(vos_api::read_enrollment_code),
        Some((member, owner))
    );
    world.enroll(AGENT, &member);
    session.granted();

    // A different enrollment for the same server is refused.
    let mut other = enrollment();
    if let Value::Map(map) = &mut other {
        *map.get_mut("space").unwrap() = Value::Bytes(vec![0x52; 32]);
    }
    let refused = session.ask("enroll", &other, &chrome).await.unwrap_err();
    assert_eq!(refused.code, Code::NotPinned);

    // The session that showed the digests signs in nothing: its server
    // would join the sign-in to them. A new session signs in, and pays
    // nothing; the first pays.
    let login = login();
    let forms = chrome.shown.lock().unwrap().len();
    let refused = loop {
        match session.ask("sign_in", &login, &chrome).await.unwrap_err() {
            refused if matches!(refused.code, Code::NoPath | Code::Unclaimed) => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            refused => break refused,
        }
    };
    assert_eq!(refused.code, Code::Refused);
    assert!(refused.message.contains("new session"), "{refused:?}");
    assert_eq!(
        chrome.shown.lock().unwrap().len(),
        forms,
        "before any prompt"
    );
    let named = session;
    let session = facility.session(gateway());
    session.granted();

    // The tree arrives apart, from its feed; a sign-in proves on it.
    let signed = sign_in_held(&session, &chrome).await.unwrap();
    assert!(chrome.last().notice.is_none(), "login spends nothing");
    assert!(matches!(
        Response::decode_exact(&bytes(field(&signed, "answer"))),
        Some(Response::Ran {
            outcome: Outcome::Done(_),
            ..
        })
    ));
    let (agent, request) = world.last_credentialed();
    assert_eq!(agent, AgentId(AGENT));
    assert_eq!(request.method.0, vos_light::method_id("login"));
    verified(&request, agent, &Stock::embedded().auth, Some(b"login"));
    assert!(matches!(
        field(&signed, "proving_ms"),
        Value::Integer(Integer::Unsigned(_))
    ));

    // A `once` guard is named for what it spends; declining proves nothing.
    let vote = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(POLL)),
        ("method", Value::from("vote")),
        ("arguments", Value::Bytes(Vec::new())),
    ]);
    let uses = *source.uses.lock().unwrap();
    chrome.will(Answer::Declined);
    let declined = session.ask("sign_in", &vote, &chrome).await.unwrap_err();
    assert_eq!(declined.code, Code::Declined);
    let shown = chrome.last();
    assert!(shown.title.contains("one vote"));
    assert!(
        shown
            .notice
            .unwrap()
            .contains("one admission in the scope “vote”")
    );
    assert_eq!(
        *source.uses.lock().unwrap(),
        uses,
        "no source use when declined"
    );

    // What was not pinned is refused before any chrome.
    let forms = chrome.shown.lock().unwrap().len();
    for (agent, instance, name) in [
        (AGENT, POLL, "vote_again"),
        (AGENT + 1, POLL, "login"),
        (AGENT, PAYMENTS, "login"),
        (AGENT, POLL, "transfer"),
    ] {
        let request = object(&[
            ("agent", Value::from(agent)),
            ("instance", Value::from(instance)),
            ("method", Value::from(name)),
            ("arguments", Value::Bytes(Vec::new())),
        ]);
        let refused = session.ask("sign_in", &request, &chrome).await.unwrap_err();
        assert_eq!(refused.code, Code::NotPinned, "{name}");
    }
    let transfer_as_sign_in = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(POLL)),
        ("method", Value::from("login")),
        ("payee", Value::from("shop")),
        ("amount", Value::from(1u64)),
    ]);
    let refused = session
        .ask("pay", &transfer_as_sign_in, &chrome)
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::NotPinned);
    assert_eq!(chrome.shown.lock().unwrap().len(), forms);

    // The session that signed in pays nothing; the one that enrolled does.
    let refused = session
        .ask(
            "pay",
            &object(&[
                ("agent", Value::from(AGENT)),
                ("instance", Value::from(PAYMENTS)),
                ("method", Value::from("transfer")),
                ("payee", Value::from("shop")),
                ("amount", Value::from(1u64)),
            ]),
            &chrome,
        )
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::Refused);
    assert!(refused.message.contains("sign-in"), "{refused:?}");
    let session = named;

    // A hostile pre-fill: the server asks for 500 to "mallory"; the user
    // confirms 20 to "shop", after a first answer the form refuses.
    let pay = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(PAYMENTS)),
        ("method", Value::from("transfer")),
        ("payee", Value::from("mallory")),
        ("amount", Value::from(500u64)),
    ]);
    chrome.will(confirm(&["shop", "twenty"]));
    chrome.will(confirm(&[" shop ", "20"]));
    chrome.stages.lock().unwrap().clear();
    let paid = session.ask("pay", &pay, &chrome).await.unwrap();
    assert_eq!(
        *chrome.stages.lock().unwrap(),
        ["Proving…", "Sending…"],
        "the chrome shows where the payment is"
    );
    let forms = chrome.shown.lock().unwrap().clone();
    let (first, second) = (&forms[forms.len() - 2], &forms[forms.len() - 1]);
    assert_eq!(
        first
            .fields
            .iter()
            .map(|field| field.value.as_str())
            .collect::<Vec<_>>(),
        vec!["mallory", "500"],
        "the pre-fill, shown to be changed"
    );
    assert!(second.notice.as_ref().unwrap().contains("whole number"));
    assert!(
        first
            .rows
            .iter()
            .any(|(label, value)| label == "From" && value == "this device's account")
    );
    let (agent, request) = world.last_credentialed();
    assert_eq!(
        request.arguments,
        (b"shop".to_vec(), 20u64).encode(),
        "what the chrome confirmed, not what the server asked"
    );
    assert_eq!(request.method.0, vos_light::method_id("transfer"));
    verified(&request, agent, &Stock::embedded().owner, None);
    assert_eq!(field(&paid, "payee"), &Value::from("shop"));
    assert_eq!(field(&paid, "amount"), &Value::from(20u64));

    // The same payment asked again while its proof may still run is that
    // proof again, so it runs once; another amount is a new proof.
    chrome.will(confirm(&["shop", "20"]));
    session.ask("pay", &pay, &chrome).await.unwrap();
    assert_eq!(world.last_credentialed().1, request, "sent again as it was");
    chrome.will(confirm(&["shop", "21"]));
    session.ask("pay", &pay, &chrome).await.unwrap();
    assert_ne!(world.last_credentialed().1, request);

    // A once-guarded call with arguments the chrome cannot read is refused.
    let ballot = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(POLL)),
        ("method", Value::from("vote")),
        ("arguments", Value::Bytes(vec![2])),
    ]);
    let refused = facility
        .session(gateway())
        .ask("sign_in", &ballot, &chrome)
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::Arguments);

    // A `refresh` makes the feed due again at a drawn delay (at most the
    // refresh's 5 s and the keeper's 10 s), honoured once in a while
    // whoever asks: a read follows, on the feed's connection.
    let feeds = world.feed_reads();
    session.ask("refresh", &Value::Null, &chrome).await.unwrap();
    let until = std::time::Instant::now() + Duration::from_secs(20);
    while world.feed_reads() == feeds && std::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(world.feed_reads() > feeds);

    // Another server asking to enroll the same space is refused.
    let elsewhere = facility.session(vos_facility::Gateway {
        fingerprint: "SHA256:elsewhere".into(),
        ..gateway()
    });
    let refused = elsewhere
        .ask("enroll", &enrollment(), &chrome)
        .await
        .unwrap_err();
    assert_eq!(refused.code, Code::NotPinned);

    // Every connection is its own circuit under its own SSH key, all to
    // the space's onion; each proof went on a connection that carried
    // nothing else.
    let seen = world.state.lock().unwrap().seen.clone();
    assert!(
        seen.iter()
            .all(|seen| matches!(seen.target, vos_light::tor::Target::Onion { .. }))
    );
    for (at, one) in seen.iter().enumerate() {
        for other in &seen[..at] {
            assert_ne!(one.circuit, other.circuit);
            assert_ne!(one.key, other.key);
        }
    }
    for proof in seen.iter().filter(|seen| {
        seen.requests
            .iter()
            .any(|(kind, _)| *kind == ApiKind::Credentialed as u16)
    }) {
        assert!(
            proof
                .requests
                .iter()
                .all(|(kind, _)| *kind == ApiKind::Credentialed as u16),
            "{proof:?}"
        );
    }
}

/// A proof is made only for a session the facility carries: on one s4
/// made itself (the enrolling one, over the clearnet), a sign-in and a
/// payment are refused before any prompt, "reconnect over Tor", unless
/// the user opted the space out of Tor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_not_carried_over_tor_proves_nothing() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(Phone::new(9));
    let facility = facility(
        &world,
        directory.path(),
        Arc::clone(&source) as Arc<dyn Source>,
    );
    let clearnet = || vos_facility::Gateway {
        host_key: Some(ssh_host_key()),
        carried: false,
        ..gateway()
    };
    let enrolling = facility.session(clearnet());
    let chrome = Scripted::default();
    chrome.will(confirm(&[]));
    chrome.will(confirm(&[]));
    let enrolled = enrolling
        .ask("enroll", &enrollment(), &chrome)
        .await
        .unwrap();
    let member: [u8; 32] = bytes(field(&enrolled, "member")).try_into().unwrap();
    world.enroll(AGENT, &member);
    let session = facility.session(clearnet());
    session.granted();
    let login = login();
    let pay = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(PAYMENTS)),
        ("method", Value::from("transfer")),
        ("payee", Value::from("shop")),
        ("amount", Value::from(1u64)),
    ]);
    let (forms, uses) = (
        chrome.shown.lock().unwrap().len(),
        *source.uses.lock().unwrap(),
    );
    for (operation, request) in [("sign_in", &login), ("pay", &pay)] {
        let refused = session.ask(operation, request, &chrome).await.unwrap_err();
        assert_eq!(refused.code, Code::Refused, "{operation}");
        assert!(refused.message.contains("reconnect"), "{refused:?}");
    }
    assert_eq!(chrome.shown.lock().unwrap().len(), forms, "no prompt");
    assert_eq!(*source.uses.lock().unwrap(), uses, "no use of the secret");
    // Opted out of Tor, the user accepted the clearnet's session.
    facility
        .net()
        .opt_out(vos_light::route::space(&HANDLE), true)
        .unwrap();
    sign_in_held(&session, &chrome).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nothing_is_proved_before_enrollment_or_for_an_unknown_operation() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let facility = facility(&world, directory.path(), Arc::new(Phone::new(9)));
    let session = facility.session(gateway());
    let chrome = Scripted::default();
    let login = login();
    let error = session.ask("sign_in", &login, &chrome).await.unwrap_err();
    assert_eq!(error.code, Code::NotEnrolled);
    let error = session
        .ask("export", &Value::Null, &chrome)
        .await
        .unwrap_err();
    assert_eq!(error.code, Code::Operation);
    chrome.will(Answer::Declined);
    let error = session
        .ask("enroll", &enrollment(), &chrome)
        .await
        .unwrap_err();
    assert_eq!(error.code, Code::Declined);
    assert_eq!(
        Store::new(directory.path()).all().unwrap(),
        Vec::new(),
        "nothing enrolled"
    );
}

/// s4's screens to an onion service no space was enrolled through go over
/// Tor all the same, on a circuit of their own, with no host key pinned
/// (the client's known hosts decide it, as for any first contact): the
/// world's gateway answers with its SSH banner. A name that is no onion
/// service's address is refused, never resolved.
#[test]
fn a_first_contact_with_an_onion_goes_over_tor() {
    use std::os::fd::OwnedFd;

    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let node = node(&world, directory.path(), Arc::new(Phone::new(9)));
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let pinned = node
        .screens(
            vos_facility::StreamTarget {
                host: world::address(&world, 1).to_ascii_uppercase(),
                port: 22,
            },
            OwnedFd::from(theirs),
        )
        .unwrap();
    assert_eq!(pinned, None, "no key pinned at first contact");
    gateways_banner(&mut ours);
    let seen = world.state.lock().unwrap().seen.clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        world::onion_of(&seen[0].target),
        Some(world::address(&world, 1))
    );
    let (_ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let refused = node
        .screens(
            vos_facility::StreamTarget {
                host: "nowhere.onion".into(),
                port: 22,
            },
            OwnedFd::from(theirs),
        )
        .unwrap_err();
    assert_eq!(refused.code, Code::Api);
}

/// s4's screens with an enrolled space's gateway go over its onion, on a
/// circuit of their own, between the UI's end of a socket pair and the
/// onion's port 22, whose host key is answered for the UI to pin; once
/// the user opted the space out, over its clearnet port. The gateway's
/// name matches in any case and with its root's dot; a gateway no space
/// was enrolled through is the UI's own to reach. The app going to
/// the background ends the session.
#[test]
fn the_screens_go_over_the_spaces_onion_or_its_opt_out() {
    use std::io::Read as _;
    use std::os::fd::OwnedFd;

    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let node = node(&world, directory.path(), Arc::new(Phone::new(9)));
    // The app in the foreground: a dormant client closes the screens.
    node.foreground(true);
    let session = node.open_session(vos_facility::Gateway {
        host_key: Some(ssh_host_key()),
        ..gateway()
    });
    node.enroll(
        session,
        vos_facility::Enroll::read(&enrollment()).unwrap(),
        Arc::new(Phone::new(9)),
    )
    .unwrap();
    let screens = |host: &str| {
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let target = vos_facility::StreamTarget {
            host: host.into(),
            port: gateway().port,
        };
        node.screens(target, OwnedFd::from(theirs)).inspect(|_| {
            gateways_banner(&mut ours);
        })
    };
    let before = world.state.lock().unwrap().seen.len();
    assert_eq!(
        screens("GATEWAY.test").unwrap(),
        Some(world.onion(1).ssh_host_key)
    );
    // The screens' stream among any the background job dialled meanwhile:
    // to the onion, on a circuit no earlier stream took.
    let seen = world.state.lock().unwrap().seen.clone();
    assert!(
        seen[before..].iter().any(|stream| {
            world::onion_of(&stream.target) == Some(world::address(&world, 1))
                && seen[..before]
                    .iter()
                    .all(|other| other.circuit != stream.circuit)
        }),
        "the onion's port, on a circuit of its own"
    );
    assert_eq!(
        screens("elsewhere.test").unwrap_err().code,
        Code::NotEnrolled
    );
    assert_eq!(
        screens("gateway.test.").unwrap(),
        Some(world.onion(1).ssh_host_key),
        "the gateway's name with its root's dot"
    );
    let (_ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let own = node
        .screens(
            vos_facility::StreamTarget {
                host: world::address(&world, 1),
                port: 22,
            },
            OwnedFd::from(theirs),
        )
        .unwrap();
    assert_eq!(
        own,
        Some(world.onion(1).ssh_host_key),
        "the space's own onion is the space's, its key pinned"
    );
    node.opt_out(HANDLE, true).unwrap();
    assert_eq!(screens("gateway.test").unwrap(), Some(ssh_host_key()));
    let seen = world.state.lock().unwrap().seen.clone();
    assert_eq!(
        world::onion_of(&seen.last().unwrap().target),
        None,
        "the clearnet"
    );
    // Dormant, the client closes the screens.
    let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    node.screens(
        vos_facility::StreamTarget {
            host: "gateway.test".into(),
            port: gateway().port,
        },
        OwnedFd::from(theirs),
    )
    .unwrap();
    node.foreground(false);
    // Past the timeout the read fails: a session carried on is no end.
    ours.set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .unwrap();
    let mut rest = Vec::new();
    ours.read_to_end(&mut rest).unwrap();
    assert!(rest.len() < 256, "ended, not carried on");
}

/// Two spaces enrolled through one gateway, one of them opted out of Tor:
/// s4's screens with that gateway go over the other's onion, never the
/// opted-out one's clearnet port; with both opted out, its clearnet port.
/// A gateway presenting the host key a space pinned to its onion is that
/// space's however its name or port is written: s4's own connection to it
/// is refused while any space's routes take the onion, and allowed once
/// none do.
#[test]
fn the_onion_is_preferred_and_a_gateway_spelled_otherwise_is_refused() {
    use std::os::fd::OwnedFd;

    const OTHER: u32 = 6;
    const OTHER_HANDLE: [u8; 32] = [0x43; 32];
    let world = world();
    world.space_at(OTHER, [0x1e; 32], OTHER_HANDLE, [0x52; 32], 2);
    let directory = tempfile::tempdir().unwrap();
    let node = node(&world, directory.path(), Arc::new(Phone::new(9)));
    node.foreground(true);
    // Two applications at one gateway, a space each.
    for (application, enrollment) in [
        ("vos.test", enrollment()),
        (
            "vos.other",
            enrollment_at(OTHER_HANDLE, [0x52; 32], OTHER, [0x1e; 32], 2),
        ),
    ] {
        let session = node.open_session(vos_facility::Gateway {
            host_key: Some(ssh_host_key()),
            application: application.into(),
            ..gateway()
        });
        node.enroll(
            session,
            vos_facility::Enroll::read(&enrollment).unwrap(),
            Arc::new(Phone::new(9)),
        )
        .unwrap();
        node.close(session);
    }
    let screens = || {
        let (mut ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let target = vos_facility::StreamTarget {
            host: "gateway.test".into(),
            port: gateway().port,
        };
        let key = node.screens(target, OwnedFd::from(theirs)).unwrap();
        gateways_banner(&mut ours);
        let last = world
            .state
            .lock()
            .unwrap()
            .seen
            .last()
            .unwrap()
            .target
            .clone();
        (key, world::onion_of(&last))
    };
    let (key, onion) = screens();
    assert_eq!(key, Some(world.onion(1).ssh_host_key));
    assert!(onion.is_some(), "an onion");
    // The first opted out: the second's onion, not the first's clearnet.
    node.opt_out(HANDLE, true).unwrap();
    for _ in 0..3 {
        let (_, onion) = screens();
        assert_eq!(onion, Some(world::address(&world, 2)), "the other's onion");
    }
    // The key the spaces pinned, presented to s4's own connection under any
    // name: refused while the second keeps the onion.
    let refused = node.clearnet(ssh_host_key()).unwrap_err();
    assert_eq!(refused.code, Code::Refused);
    assert!(
        refused.message.contains("gateway.test:2222"),
        "{}",
        refused.message
    );
    assert!(node.clearnet(world.onion(2).ssh_host_key).is_err());
    assert!(node.clearnet([0x99; 32]).is_ok(), "another gateway's key");
    // Both opted out: the clearnet port, and s4's own connection allowed.
    node.opt_out(OTHER_HANDLE, true).unwrap();
    let (key, onion) = screens();
    assert_eq!((key, onion), (Some(ssh_host_key()), None));
    node.clearnet(ssh_host_key()).unwrap();
    node.opt_out(HANDLE, false).unwrap();
    assert!(node.clearnet(ssh_host_key()).is_err(), "back on Tor");
}

/// A sign-in whose root the node no longer judges current is proved again
/// on the root the keeper's next read brought, with no second prompt; a
/// root the read did not move, or a second refusal, is the server's to
/// see. A proof the node no longer admits
/// for its device format, at ingress or at apply, asks for an update and
/// answers the server nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_root_is_proved_again_and_a_retired_format_asks_for_an_update() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(Phone::new(9));
    let facility = facility(
        &world,
        directory.path(),
        Arc::clone(&source) as Arc<dyn Source>,
    );
    let session = facility.session(gateway());
    let chrome = Scripted::default();
    chrome.will(confirm(&[]));
    chrome.will(confirm(&[]));
    let enrolled = session.ask("enroll", &enrollment(), &chrome).await.unwrap();
    world.enroll(
        AGENT,
        &bytes(field(&enrolled, "member")).try_into().unwrap(),
    );
    // A session apart from the enrolling one, which showed the digests.
    let session = facility.session(gateway());
    session.granted();
    sign_in_held(&session, &chrome).await.unwrap();
    let stale = || {
        Response::Rejected(ingress::Rejection::Credential(
            ingress::CredentialRefusal::RootStale,
        ))
    };
    let proofs = || world.state.lock().unwrap().credentialed.len();

    // Refused as stale while the tree moved on: proved again on the root
    // the keeper read, the user asked once and the source used once.
    let (forms, uses, sent, reads) = (
        chrome.shown.lock().unwrap().len(),
        *source.uses.lock().unwrap(),
        proofs(),
        world.feed_reads(),
    );
    let claim_root = |index: usize| {
        let state = world.state.lock().unwrap();
        vos_wire::credentials::AuthClaim::decode_exact(&state.credentialed[index].1.claim)
            .unwrap()
            .map_root
    };
    world
        .state
        .lock()
        .unwrap()
        .refusing
        .push_back((stale(), Some([0x77; 32])));
    let signed = sign_in_held(&session, &chrome).await.unwrap();
    assert!(matches!(
        Response::decode_exact(&bytes(field(&signed, "answer"))),
        Some(Response::Ran {
            outcome: Outcome::Done(_),
            ..
        })
    ));
    assert_eq!(proofs(), sent + 2, "proved twice");
    assert_ne!(claim_root(sent), claim_root(sent + 1), "on the new root");
    assert!(world.feed_reads() > reads, "the feed read between");
    assert_eq!(chrome.shown.lock().unwrap().len(), forms + 1, "one prompt");
    assert_eq!(*source.uses.lock().unwrap(), uses + 1, "one source use");

    // Refused as stale with the tree where it was: no proof on the same
    // root, the refusal is the answer.
    let sent = proofs();
    world
        .state
        .lock()
        .unwrap()
        .refusing
        .push_back((stale(), None));
    let signed = sign_in_held(&session, &chrome).await.unwrap();
    assert_eq!(
        Response::decode_exact(&bytes(field(&signed, "answer"))),
        Some(stale())
    );
    assert_eq!(proofs(), sent + 1, "no second proof on a stale root");

    // Refused twice, the tree moved between: one retry, its refusal the
    // answer.
    let sent = proofs();
    {
        let mut state = world.state.lock().unwrap();
        state.refusing.push_back((stale(), Some([0x78; 32])));
        state.refusing.push_back((stale(), None));
    }
    let signed = sign_in_held(&session, &chrome).await.unwrap();
    assert_eq!(
        Response::decode_exact(&bytes(field(&signed, "answer"))),
        Some(stale())
    );
    assert_eq!(proofs(), sent + 2, "one retry");

    // A device format the space no longer admits.
    for retired in [
        Response::Refused(vos_abi::abi::Refusal::Format),
        Response::Rejected(ingress::Rejection::Credential(
            ingress::CredentialRefusal::Format,
        )),
    ] {
        world
            .state
            .lock()
            .unwrap()
            .refusing
            .push_back((retired, None));
        let refused = sign_in_held(&session, &chrome).await.unwrap_err();
        assert_eq!(refused.code, Code::Refused);
        assert!(refused.message.contains("update the app"), "{refused:?}");
    }
}

/// A sign-in before the claim, the tree read to its end and no leaf of
/// the member's in it, is refused as unclaimed, not as a path still being
/// read; once the member is claimed and the tree read again, it signs in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_in_before_the_claim_says_to_claim_first() {
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(Phone::new(9));
    let facility = facility(&world, directory.path(), source as Arc<dyn Source>);
    let session = facility.session(gateway());
    let chrome = Scripted::default();
    chrome.will(confirm(&[]));
    chrome.will(confirm(&[]));
    let enrolled = session.ask("enroll", &enrollment(), &chrome).await.unwrap();
    let member: [u8; 32] = bytes(field(&enrolled, "member")).try_into().unwrap();
    let session = facility.session(gateway());
    session.granted();
    let login = login();
    let refused = loop {
        match session.ask("sign_in", &login, &chrome).await.unwrap_err() {
            refused if refused.code == Code::NoPath => {
                tokio::time::sleep(Duration::from_millis(50)).await
            }
            refused => break refused,
        }
    };
    assert_eq!(refused.code, Code::Unclaimed, "{refused:?}");
    assert!(
        refused.message.contains("claim your invitation first"),
        "{refused:?}"
    );
    world.enroll(AGENT, &member);
    let signed = sign_in_held(&session, &chrome).await.unwrap();
    assert!(matches!(
        Response::decode_exact(&bytes(field(&signed, "answer"))),
        Some(Response::Ran { .. })
    ));
}

/// A sign-in or a payment reads the space's device window first (§4.4):
/// a space whose window admits none of this app's programs, the app or the
/// space behind the other, is refused with the window's words before any
/// prompt, any use of the secret or any proof; a window the node cannot
/// compute yet is refused to be asked again; the stock window proves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_window_without_this_apps_programs_is_refused_before_proving() {
    let world = world();
    // The space's window is ahead of the app from the start: the grant's
    // read of it finds it so.
    let mut ahead = world.stock.window();
    for kernel in &mut ahead.kernels {
        kernel.programs[0].id = [0x77; 32];
    }
    world.state.lock().unwrap().window = Some(ahead.clone());
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(Phone::new(9));
    let facility = facility(
        &world,
        directory.path(),
        Arc::clone(&source) as Arc<dyn Source>,
    );
    let session = facility.session(gateway());
    let chrome = Scripted::default();
    chrome.will(confirm(&[]));
    chrome.will(confirm(&[]));
    let enrolled = session.ask("enroll", &enrollment(), &chrome).await.unwrap();
    world.enroll(
        AGENT,
        &<[u8; 32]>::try_from(bytes(field(&enrolled, "member"))).unwrap(),
    );
    // A session apart from the enrolling one, which showed the digests.
    let session = facility.session(gateway());
    session.granted();
    let login = login();
    let pay = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(PAYMENTS)),
        ("method", Value::from("transfer")),
        ("payee", Value::from("shop")),
        ("amount", Value::from(20u64)),
    ]);

    let (forms, uses, sent) = (
        chrome.shown.lock().unwrap().len(),
        *source.uses.lock().unwrap(),
        world.state.lock().unwrap().credentialed.len(),
    );
    for (operation, request) in [("sign_in", &login), ("pay", &pay)] {
        let refused = session.ask(operation, request, &chrome).await.unwrap_err();
        assert_eq!(refused.code, Code::Refused, "{operation}");
        assert!(refused.message.contains("must update"), "{refused:?}");
    }
    for kernel in &mut ahead.kernels {
        kernel.unavailable = true;
    }
    world.state.lock().unwrap().window = Some(ahead);
    let refused = session.ask("sign_in", &login, &chrome).await.unwrap_err();
    assert_eq!(refused.code, Code::Api);
    assert_eq!(chrome.shown.lock().unwrap().len(), forms, "no prompt");
    assert_eq!(*source.uses.lock().unwrap(), uses, "no use of the secret");
    assert_eq!(
        world.state.lock().unwrap().credentialed.len(),
        sent,
        "nothing proved, nothing sent"
    );

    world.state.lock().unwrap().window = None;
    sign_in_held(&session, &chrome).await.unwrap();
    // A stock kernel is the credential actor's method: its window is the
    // one read, whichever instance the call goes to.
    let asked = world.state.lock().unwrap().windows_asked.clone();
    assert!(!asked.is_empty());
    assert!(
        asked.iter().all(|&asked| asked == (AGENT, CREDENTIALS)),
        "{asked:?}"
    );
}

/// The gateway's SSH version line on `ours`, s4's own sent first as s4
/// sends it: over Tor, the gateway's line leaves once the client's arrives.
fn gateways_banner(ours: &mut std::os::unix::net::UnixStream) {
    use std::io::{Read as _, Write as _};
    ours.write_all(b"SSH-2.0-s4\r\n").unwrap();
    let mut banner = [0; 8];
    ours.read_exact(&mut banner).unwrap();
    assert_eq!(&banner, b"SSH-2.0-");
}

/// A call's expiry is set from the node's time as its own session read it,
/// on a fetch of its own: a gateway that answers each connection's time
/// marked (here, five seconds ahead a connection) finds in a proof's expiry
/// one reading alone, made in that session's time on a connection that
/// carried nothing else, never another session's nor the feed's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proofs_expiry_carries_its_own_sessions_reading_alone() {
    const SKEW_MS: u64 = 5_000;
    let world = world();
    let directory = tempfile::tempdir().unwrap();
    let source = Arc::new(Phone::new(9));
    let facility = facility(
        &world,
        directory.path(),
        Arc::clone(&source) as Arc<dyn Source>,
    );
    let chrome = Scripted::default();
    let enrolling = facility.session(gateway());
    chrome.will(confirm(&[]));
    chrome.will(confirm(&[]));
    let enrolled = enrolling
        .ask("enroll", &enrollment(), &chrome)
        .await
        .unwrap();
    world.enroll(
        AGENT,
        &<[u8; 32]>::try_from(bytes(field(&enrolled, "member"))).unwrap(),
    );
    world.skew_times(SKEW_MS);

    // The connection whose marked time the last proof's expiry carries,
    // the call having been set within three seconds of `from`, the tap.
    let marked = |from: u64| -> usize {
        let expires = world.last_credentialed().1.expires_ms - 60_000;
        let connections = world.state.lock().unwrap().seen.len();
        // Past 60 connections a mark is minutes off, and refused.
        assert!(connections < 50, "{connections} connections");
        let found: Vec<usize> = (0..connections)
            .filter(|&index| {
                let set = expires.checked_sub(SKEW_MS * index as u64);
                set.is_some_and(|set| (from.saturating_sub(1_000)..=from + 3_000).contains(&set))
            })
            .collect();
        assert_eq!(found.len(), 1, "one reading: {found:?}");
        found[0]
    };
    let pay = object(&[
        ("agent", Value::from(AGENT)),
        ("instance", Value::from(PAYMENTS)),
        ("method", Value::from("transfer")),
        ("payee", Value::from("shop")),
        ("amount", Value::from(20u64)),
    ]);
    let login = login();

    // Session A pays; session B, opened after, signs in.
    let paying = facility.session(gateway());
    let opened_a = world.state.lock().unwrap().seen.len();
    paying.granted();
    chrome.will(confirm(&["shop", "20"]));
    let from = wall();
    paying.ask("pay", &pay, &chrome).await.unwrap();
    let a = marked(from);

    let signing = facility.session(gateway());
    let opened_b = world.state.lock().unwrap().seen.len();
    signing.granted();
    let b = loop {
        chrome.will(confirm(&[]));
        let from = wall();
        match signing.ask("sign_in", &login, &chrome).await {
            Ok(_) => break marked(from),
            Err(error) if matches!(error.code, Code::NoPath | Code::Unclaimed) => {
                chrome.answers.lock().unwrap().clear();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("{error:?}"),
        }
    };
    // A second payment in A carries A's reading still.
    chrome.will(confirm(&["shop", "21"]));
    let from = wall();
    paying.ask("pay", &pay, &chrome).await.unwrap();
    assert_eq!(marked(from), a, "a session's calls share its reading");

    let seen = world.state.lock().unwrap().seen.clone();
    assert_ne!(a, b);
    for (reading, opened) in [(a, opened_a), (b, opened_b)] {
        assert!(reading >= opened, "read in its session's time");
        let kinds: Vec<u16> = seen[reading]
            .requests
            .iter()
            .map(|(kind, _)| *kind)
            .collect();
        assert_eq!(
            kinds,
            [ApiKind::Time as u16],
            "a connection that carried it alone"
        );
    }
    assert!(b >= opened_b && a < opened_b, "B's reading is B's own");
}
