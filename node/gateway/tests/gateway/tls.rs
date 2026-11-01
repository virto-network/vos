//! A client's TLS to the gateway: it pins the gateway's key, or trusts a
//! CA, and nothing else; plain HTTP on loopback, `localhost` without a
//! resolver; and a kept connection the gateway's restart breaks.

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use vos_http::tls::{IngressTls, server_config};
use vos_node::client::ClientError;
use vos_node::tls::Trust;

use super::*;

/// A gateway serving `tls` in front of `served`'s socket.
fn front(served: &Served, tls: Option<Arc<rustls::ServerConfig>>) -> Front {
    Front::start_with(
        vec![(served.node.id().0, Address::Socket(served.socket.clone()))],
        PerAddress::default(),
        tls,
    )
}

#[test]
fn a_client_pins_the_gateway_s_key() {
    let served = Served::start(PerAddress::default());
    let tls = server_config(&IngressTls::NodeKey { names: Vec::new() }, &GATEWAY).unwrap();
    let front = front(&served, Some(tls));
    let url = format!("https://{}", front.address);
    let gateway = SigningKey::from_bytes(&GATEWAY).verifying_key().to_bytes();
    let pinned = Target::new(&url, Trust::Gateway(gateway)).unwrap();
    assert_eq!(
        vos_node::client::node_id(&pinned).unwrap(),
        served.node.id()
    );
    // A client signs for the agent's identity, its record's hash.
    let client = Client::new(&pinned, SigningKey::from_bytes(&[3; 32]));
    let record = vos_node::client::agent_info(&pinned, served.agent)
        .unwrap()
        .expect("its record")
        .record;
    assert_eq!(
        client.identity(served.agent).unwrap(),
        vos_node::identity(&record)
    );

    // Another key is refused in the handshake, before any request.
    let other = SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
    let wrong = Target::new(&url, Trust::Gateway(other)).unwrap();
    assert!(matches!(
        vos_node::client::node_id(&wrong),
        Err(ClientError::Http(_))
    ));
    // Plain HTTP does not reach a TLS front.
    let plain = Target::loopback(&format!("http://{}", front.address)).unwrap();
    assert!(vos_node::client::node_id(&plain).is_err());
}

/// A CA, and a certificate it signed for `localhost` with `key`.
fn ca_and_leaf(dir: &std::path::Path, key: &KeyPair) {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .signed_by(key, &ca, &ca_key)
        .unwrap();
    std::fs::write(dir.join("chain.pem"), leaf.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), key.serialize_pem()).unwrap();
    std::fs::write(dir.join("ca.pem"), ca.pem()).unwrap();
}

#[test]
fn a_client_trusts_a_ca() {
    let served = Served::start(PerAddress::default());
    let pem = tempfile::tempdir().unwrap();
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    ca_and_leaf(pem.path(), &leaf_key);
    let files = IngressTls::Files {
        chain: pem.path().join("chain.pem"),
        key: pem.path().join("key.pem"),
    };
    let front = front(&served, Some(server_config(&files, &GATEWAY).unwrap()));
    let url = format!("https://localhost:{}", front.address.port());
    let trusted = Target::new(&url, Trust::ca_file(&pem.path().join("ca.pem")).unwrap()).unwrap();
    assert_eq!(
        vos_node::client::node_id(&trusted).unwrap(),
        served.node.id()
    );

    // Another CA is not trusted, nor is the gateway's key, which this
    // certificate does not hold.
    let other = tempfile::tempdir().unwrap();
    ca_and_leaf(
        other.path(),
        &KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
    );
    let untrusted =
        Target::new(&url, Trust::ca_file(&other.path().join("ca.pem")).unwrap()).unwrap();
    assert!(vos_node::client::node_id(&untrusted).is_err());
    let gateway = SigningKey::from_bytes(&GATEWAY).verifying_key().to_bytes();
    let pinned = Target::new(&url, Trust::Gateway(gateway)).unwrap();
    assert!(vos_node::client::node_id(&pinned).is_err());

    // A client pinning the certificate's own key as a gateway's gets
    // through TLS; as a node's it is refused before it dials: a node's key
    // pins QUIC alone.
    let key: [u8; 32] = leaf_key.public_key_raw().try_into().unwrap();
    let certificate_key = Target::new(&url, Trust::Gateway(key)).unwrap();
    assert!(vos_node::client::node_id(&certificate_key).is_ok());
    assert!(Target::new(&url, Trust::NodeKey(key)).is_err());
}

#[test]
fn localhost_is_reached_on_loopback_addresses_without_a_resolver() {
    let served = Served::start(PerAddress::default());
    let target =
        Target::loopback(&format!("http://localhost:{}", served.front.address.port())).unwrap();
    assert_eq!(
        vos_node::client::node_id(&target).unwrap(),
        served.node.id()
    );
}

#[test]
fn a_repeatable_request_survives_the_gateway_restarting_under_a_kept_connection() {
    let served = Served::start(PerAddress::default());
    let first = front(&served, None);
    let address = first.address;
    let target = Target::loopback(&format!("http://{address}")).unwrap();
    let client = Client::new(&target, SigningKey::from_bytes(&[5; 32]));
    let nothing = |client: &Client| client.schema(AgentId(99), InstanceId(1)).unwrap();
    // The client keeps its connection, which the restart breaks.
    assert!(nothing(&client).is_none());
    drop(first);
    let listener = (0..500)
        .find_map(|_| {
            std::net::TcpListener::bind(address)
                .inspect_err(|_| std::thread::sleep(Duration::from_millis(10)))
                .ok()
        })
        .expect("the gateway's address again");
    let _second = Front::start_on(
        listener,
        vec![(served.node.id().0, Address::Socket(served.socket.clone()))],
        PerAddress::default(),
        None,
    );
    assert!(nothing(&client).is_none());
}
