//! TLS on the client ingress: plain HTTP serves loopback addresses only; a
//! client pins the node's key, or trusts a CA, and nothing else.

use std::path::Path;

use ed25519_dalek::SigningKey;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use vos_node::client::{Client, ClientError, Operator, Target};
use vos_node::tls::{IngressTls, Trust};
use vos_node::{ADMIN_TOKEN, Config, Node};
use vos_wire::ingress::Answer;

fn agent_program() -> Vec<u8> {
    let path = format!(
        "{}/../../agent/default/target/riscv64em-vos/release/vos-agent.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let elf = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("{path}: {error}; run `just build-agent`"));
    vos_pvm_compiler::link_elf_spi(&elf).expect("links")
}

fn open(dir: &Path, tls: Option<IngressTls>) -> Node {
    let mut config = Config::new(agent_program());
    config.executors = 1;
    config.ingress_tls = tls;
    Node::open(dir, config).unwrap()
}

#[test]
fn plain_http_serves_loopback_addresses_only() {
    let dir = tempfile::tempdir().unwrap();
    let node = open(dir.path(), None);
    for address in ["0.0.0.0:0", "[::]:0"] {
        assert!(
            node.serve(address.parse().unwrap()).is_err(),
            "{address} served plain HTTP"
        );
    }
    assert!(node.serve("127.0.0.1:0".parse().unwrap()).is_ok());
}

#[test]
fn addresses_and_trust_must_agree() {
    let key = Trust::NodeKey([1; 32]);
    for (url, trust) in [
        ("http://10.1.2.3:7700", Trust::Loopback),
        ("http://example.org", Trust::Loopback),
        ("https://127.0.0.1:7700", Trust::Loopback),
        ("http://127.0.0.1:7700", key.clone()),
        ("https://127.0.0.1:7700/path", key.clone()),
        ("ftp://127.0.0.1:7700", key.clone()),
        ("https://127.0.0.1:port", key.clone()),
    ] {
        assert!(Target::new(url, trust).is_err(), "{url} was taken");
    }
    for (url, trust) in [
        ("http://127.0.0.1:7700", Trust::Loopback),
        ("http://localhost:7700/", Trust::Loopback),
        ("http://[::1]:7700", Trust::Loopback),
        ("https://10.1.2.3:7700", key.clone()),
        ("https://node.example.org", key),
    ] {
        assert!(Target::new(url, trust).is_ok(), "{url} was refused");
    }
}

#[test]
fn a_client_pins_the_node_s_key() {
    let dir = tempfile::tempdir().unwrap();
    let node = open(dir.path(), Some(IngressTls::NodeKey { names: Vec::new() }));
    // TLS lets the node listen beyond loopback; the test stays on it.
    let address = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
    let url = format!("https://{address}");
    let pinned = Target::new(&url, Trust::NodeKey(node.id().0)).unwrap();
    assert_eq!(vos_node::client::node_id(&pinned).unwrap(), node.id());
    let token = std::fs::read_to_string(dir.path().join(ADMIN_TOKEN)).unwrap();
    assert!(matches!(
        Operator::new(&pinned, &token).create_agent().unwrap(),
        Answer::Created(_)
    ));
    let client = Client::open(
        &pinned,
        SigningKey::from_bytes(&[3; 32]),
        vos_node::wall_clock(),
    )
    .unwrap();
    assert_eq!(client.node(), node.id());

    // Another key is refused in the handshake, before any request.
    let other = SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
    let wrong = Target::new(&url, Trust::NodeKey(other)).unwrap();
    assert!(matches!(
        vos_node::client::node_id(&wrong),
        Err(ClientError::Http(_))
    ));
    // Plain HTTP does not reach a TLS ingress.
    let plain = Target::loopback(&format!("http://{address}")).unwrap();
    assert!(vos_node::client::node_id(&plain).is_err());
}

/// A CA, and a certificate it signed for `localhost` with `key`.
fn ca_and_leaf(dir: &Path, key: &KeyPair) -> (rcgen::Certificate, KeyPair) {
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
    (ca, ca_key)
}

#[test]
fn a_client_trusts_a_ca() {
    let dir = tempfile::tempdir().unwrap();
    let pem = tempfile::tempdir().unwrap();
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    ca_and_leaf(pem.path(), &leaf_key);
    let node = open(
        dir.path(),
        Some(IngressTls::Files {
            chain: pem.path().join("chain.pem"),
            key: pem.path().join("key.pem"),
        }),
    );
    let address = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
    let url = format!("https://localhost:{}", address.port());
    let trusted = Target::new(&url, Trust::ca_file(&pem.path().join("ca.pem")).unwrap()).unwrap();
    assert_eq!(vos_node::client::node_id(&trusted).unwrap(), node.id());

    // Another CA is not trusted, nor is the node's key, which this
    // certificate does not hold.
    let other = tempfile::tempdir().unwrap();
    ca_and_leaf(
        other.path(),
        &KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap(),
    );
    let untrusted =
        Target::new(&url, Trust::ca_file(&other.path().join("ca.pem")).unwrap()).unwrap();
    assert!(vos_node::client::node_id(&untrusted).is_err());
    let pinned = Target::new(&url, Trust::NodeKey(node.id().0)).unwrap();
    assert!(vos_node::client::node_id(&pinned).is_err());

    // A client pinning the certificate's own key gets through TLS, but the
    // node names itself by its own key: not the node pinned.
    let key: [u8; 32] = leaf_key.public_key_raw().try_into().unwrap();
    let certificate_key = Target::new(&url, Trust::NodeKey(key)).unwrap();
    assert!(matches!(
        vos_node::client::node_id(&certificate_key),
        Err(ClientError::NotTheNode)
    ));
}

#[test]
fn localhost_is_reached_on_loopback_addresses_without_a_resolver() {
    let dir = tempfile::tempdir().unwrap();
    let node = open(dir.path(), None);
    let address = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
    let target = Target::loopback(&format!("http://localhost:{}", address.port())).unwrap();
    assert_eq!(vos_node::client::node_id(&target).unwrap(), node.id());
}

#[test]
fn a_repeatable_request_survives_the_node_restarting_under_a_kept_connection() {
    let dir = tempfile::tempdir().unwrap();
    let node = open(dir.path(), None);
    let address = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
    let target = Target::loopback(&format!("http://{address}")).unwrap();
    let client = Client::open(
        &target,
        SigningKey::from_bytes(&[5; 32]),
        vos_node::wall_clock(),
    )
    .unwrap();
    let nothing = |client: &Client| {
        client
            .schema(vos_wire::ids::AgentId(1), vos_wire::ids::InstanceId(1))
            .unwrap()
    };
    // The client keeps its connection, which the restart breaks.
    assert!(nothing(&client).is_none());
    node.shutdown();
    let node = open(dir.path(), None);
    assert_eq!(node.serve(address).unwrap(), address);
    assert!(nothing(&client).is_none());
}
