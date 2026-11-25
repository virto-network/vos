//! TLS 1.3 bound to node keys. Each side presents its ed25519 key as a raw
//! public key (RFC 7250), with no certificate, and proves it holds the key
//! by the handshake's signature. Each side checks the other's key: the
//! dialing side against the one peer it dialed, the accepting side against
//! every configured peer's.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use ring::signature::KeyPair;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::{NodeKey, NodeNumber};

/// The peers' protocol.
pub(crate) const ALPN: &[u8] = b"vos/1";

/// An ed25519 key's SubjectPublicKeyInfo, before the key.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// An ed25519 seed's PKCS #8 document, before the seed.
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// What an endpoint's stateless-reset key is derived under, apart from
/// every other use of the node's secret, followed by the endpoint's
/// protocol.
const RESET_DOMAIN: &[u8] = b"vos/net/stateless-reset/v2/";
/// What the key that marks an endpoint's connection ids is derived under,
/// followed by the endpoint's protocol.
const CONNECTION_IDS_DOMAIN: &[u8] = b"vos/net/connection-ids/v2/";
/// A connection id's random bytes, then its mark's.
const ID_RANDOM: usize = 8;
const ID_MARK: usize = 8;

/// The configured peers, by key: what the accepting side takes.
pub(crate) type Table = Arc<RwLock<HashMap<NodeKey, NodeNumber>>>;

/// The public key of the node whose secret seed is `secret`.
pub fn public_key(secret: &[u8; 32]) -> NodeKey {
    ring::signature::Ed25519KeyPair::from_seed_unchecked(secret)
        .expect("any 32 bytes are an ed25519 seed")
        .public_key()
        .as_ref()
        .try_into()
        .expect("an ed25519 public key is 32 bytes")
}

/// The SubjectPublicKeyInfo of the ed25519 key `key`, in DER.
pub fn spki(key: &NodeKey) -> Vec<u8> {
    [&SPKI_PREFIX[..], key].concat()
}

/// The PKCS #8 document of the ed25519 seed `secret`, in DER.
pub fn pkcs8(secret: &[u8; 32]) -> Vec<u8> {
    [&PKCS8_PREFIX[..], secret].concat()
}

/// The key a raw public key holds, if it is exactly an ed25519 one.
fn key_of(spki: &[u8]) -> Option<NodeKey> {
    spki.strip_prefix(&SPKI_PREFIX[..])?.try_into().ok()
}

/// The peer key a connection was authenticated with.
pub(crate) fn peer_key(connection: &quinn::Connection) -> Option<NodeKey> {
    let identity = connection.peer_identity()?;
    let keys = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    match keys.as_slice() {
        [key] => key_of(key),
        _ => None,
    }
}

/// The name a dialing side gave, which carries its incarnation.
pub(crate) fn server_name(connection: &quinn::Connection) -> Option<String> {
    connection
        .handshake_data()?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?
        .server_name
}

/// A node's key, and the TLS configurations built on it.
pub(crate) struct Identity {
    pub key: NodeKey,
    certified: Arc<CertifiedKey>,
    provider: Arc<CryptoProvider>,
    /// What an endpoint's keys are derived from.
    derive: ring::hmac::Key,
}

/// An endpoint's keys: each of a node's endpoints has its own, so neither
/// takes the other's connection ids for its own, nor gives out their
/// reset tokens.
struct EndpointKeys {
    reset: ring::hmac::Key,
    connection_ids: ring::hmac::Key,
}

impl Identity {
    pub fn new(secret: &[u8; 32]) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = public_key(secret);
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8(secret)));
        let signer = provider
            .key_provider
            .load_private_key(der)
            .expect("an ed25519 seed loads");
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(spki(&key))],
            signer,
        ));
        Self {
            key,
            certified,
            provider,
            derive: ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret),
        }
    }

    /// The keys of the endpoint of protocol `alpn`.
    fn keys(&self, alpn: &[u8]) -> EndpointKeys {
        let key = |domain: &[u8]| {
            let label = [domain, alpn].concat();
            ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                ring::hmac::sign(&self.derive, &label).as_ref(),
            )
        };
        EndpointKeys {
            reset: key(RESET_DOMAIN),
            connection_ids: key(CONNECTION_IDS_DOMAIN),
        }
    }

    /// The configuration of the endpoint of protocol `alpn`, QUIC version
    /// 1 only. A restarted node resets at once the connections its last
    /// run held: its stateless resets are keyed by the node's secret and
    /// the protocol, and so is the mark on its connection ids, which it
    /// checks before resetting (a packet for an id it never made, or the
    /// node's other endpoint made, is dropped).
    pub fn endpoint(&self, alpn: &[u8]) -> quinn::EndpointConfig {
        let keys = self.keys(alpn);
        let mut config = quinn::EndpointConfig::new(Arc::new(keys.reset));
        let key = keys.connection_ids;
        config.cid_generator(move || {
            Box::new(MarkedIds {
                key: key.clone(),
                random: ring::rand::SystemRandom::new(),
            })
        });
        config.supported_versions(vec![1]);
        config
    }

    /// The accepting side: any configured peer. Peers have configured
    /// addresses, so a connection never moves to another.
    pub fn server(
        &self,
        peers: Table,
        transport: Arc<quinn::TransportConfig>,
    ) -> quinn::ServerConfig {
        let configured: Expect =
            Arc::new(move |key| peers.read().expect("the peer table").contains_key(key));
        let mut config = self.server_with(configured, ALPN, transport);
        config.migration(false);
        config
    }

    /// The accepting side of protocol `alpn`, taking the keys `expect`
    /// takes.
    pub fn server_with(
        &self,
        expect: Expect,
        alpn: &[u8],
        transport: Arc<quinn::TransportConfig>,
    ) -> quinn::ServerConfig {
        let verifier = Arc::new(Verifier {
            expect,
            provider: Arc::clone(&self.provider),
        });
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 with ring")
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(
                rustls::server::AlwaysResolvesServerRawPublicKeys::new(Arc::clone(&self.certified)),
            ));
        tls.alpn_protocols = vec![alpn.to_vec()];
        // A resumed session skips the key check, so a peer removed since
        // could still connect: every handshake is a full one.
        tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        tls.send_tls13_tickets = 0;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .expect("a TLS 1.3 configuration for QUIC");
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport);
        config
    }

    /// The dialing side, pinned to the one peer it dials.
    pub fn client(
        &self,
        peer: NodeKey,
        transport: Arc<quinn::TransportConfig>,
    ) -> quinn::ClientConfig {
        self.client_with(ALPN, peer, transport)
    }

    /// The dialing side of protocol `alpn`, pinned to the one key it
    /// dials.
    pub fn client_with(
        &self,
        alpn: &[u8],
        peer: NodeKey,
        transport: Arc<quinn::TransportConfig>,
    ) -> quinn::ClientConfig {
        let verifier = Arc::new(Verifier {
            expect: Arc::new(move |key| *key == peer),
            provider: Arc::clone(&self.provider),
        });
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 with ring")
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_cert_resolver(Arc::new(
                rustls::client::AlwaysResolvesClientRawPublicKeys::new(Arc::clone(&self.certified)),
            ));
        tls.alpn_protocols = vec![alpn.to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .expect("a TLS 1.3 configuration for QUIC");
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport);
        config
    }
}

/// The connection ids a node makes: random bytes, then a mark over them
/// keyed by the node's secret. Every id is new, so a reset token, which
/// anyone may learn for an id, never serves for another. A restarted node
/// knows the ids its last run made by their mark, and resets their
/// connections; it drops packets for any other id.
struct MarkedIds {
    key: ring::hmac::Key,
    random: ring::rand::SystemRandom,
}

impl MarkedIds {
    fn mark(&self, random: &[u8]) -> [u8; ID_MARK] {
        ring::hmac::sign(&self.key, random).as_ref()[..ID_MARK]
            .try_into()
            .expect("a mark's bytes")
    }
}

impl quinn_proto::ConnectionIdGenerator for MarkedIds {
    fn generate_cid(&mut self) -> quinn::ConnectionId {
        let mut id = [0u8; ID_RANDOM + ID_MARK];
        ring::rand::SecureRandom::fill(&self.random, &mut id[..ID_RANDOM])
            .expect("the operating system's randomness");
        let mark = self.mark(&id[..ID_RANDOM]);
        id[ID_RANDOM..].copy_from_slice(&mark);
        quinn::ConnectionId::new(&id)
    }

    fn validate(&self, id: &quinn::ConnectionId) -> Result<(), quinn_proto::InvalidCid> {
        if id.len() != ID_RANDOM + ID_MARK {
            return Err(quinn_proto::InvalidCid);
        }
        if equal(&self.mark(&id[..ID_RANDOM]), &id[ID_RANDOM..]) {
            Ok(())
        } else {
            Err(quinn_proto::InvalidCid)
        }
    }

    fn cid_len(&self) -> usize {
        ID_RANDOM + ID_MARK
    }

    fn cid_lifetime(&self) -> Option<std::time::Duration> {
        None
    }
}

/// Whether `a` and `b` hold the same bytes, in a time that depends only
/// on their lengths.
fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |differ, (a, b)| differ | (a ^ b)) == 0
}

/// TLS 1.2, which neither side offers.
fn tls12_refused() -> Result<HandshakeSignatureValid, rustls::Error> {
    Err(rustls::Error::PeerIncompatible(
        rustls::PeerIncompatible::Tls12NotOffered,
    ))
}

/// The one signature scheme a node key signs with.
const SCHEMES: [SignatureScheme; 1] = [SignatureScheme::ED25519];

/// The keys a side takes.
pub(crate) type Expect = Arc<dyn Fn(&NodeKey) -> bool + Send + Sync>;

struct Verifier {
    expect: Expect,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier").finish_non_exhaustive()
    }
}

impl Verifier {
    fn check(&self, end: &CertificateDer, rest: &[CertificateDer]) -> Result<(), rustls::Error> {
        let expected = rest.is_empty() && key_of(end).is_some_and(|key| (self.expect)(&key));
        if expected {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    /// The handshake's signature, against the key presented.
    fn signature(
        &self,
        message: &[u8],
        key: &CertificateDer,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(key.as_ref()),
            signed,
            &self.provider.signature_verification_algorithms,
        )
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end: &CertificateDer,
        rest: &[CertificateDer],
        _: &ServerName,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end, rest)
            .map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        tls12_refused()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        key: &CertificateDer,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(message, key, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end: &CertificateDer,
        rest: &[CertificateDer],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end, rest)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        tls12_refused()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        key: &CertificateDer,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.signature(message, key, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SCHEMES.to_vec()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raw_key_is_exactly_an_ed25519_one() {
        let key = public_key(&[7; 32]);
        assert_eq!(key_of(&spki(&key)), Some(key));
        // A longer document, or one with another prefix, is no key.
        assert_eq!(key_of(&[spki(&key), vec![0]].concat()), None);
        assert_eq!(key_of(&spki(&key)[1..]), None);
        let mut other = spki(&key);
        other[8] ^= 1;
        assert_eq!(key_of(&other), None);
    }

    #[test]
    fn connection_ids_are_new_and_marked() {
        use quinn_proto::ConnectionIdGenerator;
        let identity = Identity::new(&[5; 32]);
        let mut ids = MarkedIds {
            key: identity.keys(ALPN).connection_ids,
            random: ring::rand::SystemRandom::new(),
        };
        let first = ids.generate_cid();
        let second = ids.generate_cid();
        assert_ne!(first, second);
        assert_eq!(first.len(), 16);
        assert!(ids.validate(&first).is_ok());
        // A restarted run knows them; another node's, or a forged one, not.
        let restarted = MarkedIds {
            key: Identity::new(&[5; 32]).keys(ALPN).connection_ids,
            random: ring::rand::SystemRandom::new(),
        };
        assert!(restarted.validate(&first).is_ok());
        let other = MarkedIds {
            key: Identity::new(&[6; 32]).keys(ALPN).connection_ids,
            random: ring::rand::SystemRandom::new(),
        };
        assert!(other.validate(&first).is_err());
        // Nor does the node's other endpoint.
        let api = MarkedIds {
            key: identity.keys(crate::api::ALPN).connection_ids,
            random: ring::rand::SystemRandom::new(),
        };
        assert!(api.validate(&first).is_err());
        let mut forged = first.to_vec();
        forged[15] ^= 1;
        assert!(ids.validate(&quinn::ConnectionId::new(&forged)).is_err());
        assert!(
            ids.validate(&quinn::ConnectionId::new(&first[..8]))
                .is_err()
        );
    }

    #[test]
    fn the_public_key_is_ed25519_dalek_s() {
        let secret = [3; 32];
        let dalek = ed25519_dalek::SigningKey::from_bytes(&secret);
        assert_eq!(public_key(&secret), dalek.verifying_key().to_bytes());
    }

    #[test]
    fn the_reset_key_is_not_the_secret() {
        let secret = [9; 32];
        let identity = Identity::new(&secret);
        let tag = |key: &ring::hmac::Key| ring::hmac::sign(key, b"x").as_ref().to_vec();
        let raw = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret);
        let reset = identity.keys(ALPN).reset;
        assert_ne!(tag(&reset), tag(&raw));
        // It is the same across runs, so resets survive a restart; and
        // each endpoint has its own.
        assert_eq!(tag(&reset), tag(&Identity::new(&secret).keys(ALPN).reset));
        assert_ne!(tag(&reset), tag(&identity.keys(crate::api::ALPN).reset));
    }

    /// The node API's endpoint, sent a packet bearing a connection id the
    /// peers' endpoint made, takes it for no id of its own: it answers
    /// nothing, so it gives out no reset token of a peer connection.
    #[test]
    fn the_api_endpoint_gives_out_no_peer_connection_s_reset_token() {
        use crate::quic::executor::{Runner, Runtime};
        use quinn_proto::ConnectionIdGenerator;

        let secret = [5; 32];
        let identity = Identity::new(&secret);
        let mut ids = MarkedIds {
            key: identity.keys(ALPN).connection_ids,
            random: ring::rand::SystemRandom::new(),
        };
        let id = ids.generate_cid();
        let runner = Runner::start().unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let api = socket.local_addr().unwrap();
        let _endpoint = quinn::Endpoint::new(
            crate::api::endpoint_config(&secret),
            None,
            socket,
            Arc::new(Runtime(runner.spawner())),
        )
        .unwrap();
        // A short-header packet for that id, from anyone.
        let mut packet = vec![0x40u8];
        packet.extend_from_slice(&id);
        packet.resize(64, 0xaa);
        let anyone = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        anyone
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        anyone.send_to(&packet, api).unwrap();
        let mut answer = [0u8; 128];
        assert!(
            anyone.recv_from(&mut answer).is_err(),
            "the API endpoint answered a peer connection's id"
        );
        // An id of its own it does answer, with that id's reset token.
        let keys = identity.keys(crate::api::ALPN);
        let own = MarkedIds {
            key: keys.connection_ids,
            random: ring::rand::SystemRandom::new(),
        }
        .generate_cid();
        packet[1..1 + own.len()].copy_from_slice(&own);
        anyone.send_to(&packet, api).unwrap();
        let (length, _) = anyone.recv_from(&mut answer).expect("a stateless reset");
        let token = ring::hmac::sign(&keys.reset, &own);
        assert_eq!(&answer[length - 16..length], &token.as_ref()[..16]);
    }
}
