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

const ALPN: &[u8] = b"vos/1";

/// An ed25519 key's SubjectPublicKeyInfo, before the key.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// An ed25519 seed's PKCS #8 document, before the seed.
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// What the stateless-reset key is derived under, apart from every other
/// use of the node's secret.
const RESET_DOMAIN: &[u8] = b"vos/net/stateless-reset/1";
/// What the key that marks this node's connection ids is derived under.
const CONNECTION_IDS_DOMAIN: &[u8] = b"vos/net/connection-ids/1";
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

fn spki(key: &NodeKey) -> Vec<u8> {
    [&SPKI_PREFIX[..], key].concat()
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
    reset: ring::hmac::Key,
    connection_ids: ring::hmac::Key,
}

impl Identity {
    pub fn new(secret: &[u8; 32]) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let key = public_key(secret);
        let pkcs8 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            [&PKCS8_PREFIX[..], secret].concat(),
        ));
        let signer = provider
            .key_provider
            .load_private_key(pkcs8)
            .expect("an ed25519 seed loads");
        let certified = Arc::new(CertifiedKey::new(
            vec![CertificateDer::from(spki(&key))],
            signer,
        ));
        let derive = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let reset = ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            ring::hmac::sign(&derive, RESET_DOMAIN).as_ref(),
        );
        let connection_ids = ring::hmac::Key::new(
            ring::hmac::HMAC_SHA256,
            ring::hmac::sign(&derive, CONNECTION_IDS_DOMAIN).as_ref(),
        );
        Self {
            key,
            certified,
            provider,
            reset,
            connection_ids,
        }
    }

    /// The endpoint's configuration. A restarted node resets at once the
    /// connections its last run held: its stateless resets are keyed by
    /// the node's secret, and so is the mark on its connection ids, which
    /// it checks before resetting (a packet for an id it never made is
    /// dropped).
    pub fn endpoint(&self) -> quinn::EndpointConfig {
        let mut config = quinn::EndpointConfig::new(Arc::new(self.reset.clone()));
        let key = self.connection_ids.clone();
        config.cid_generator(move || {
            Box::new(MarkedIds {
                key: key.clone(),
                random: ring::rand::SystemRandom::new(),
            })
        });
        config
    }

    /// The accepting side: any configured peer.
    pub fn server(
        &self,
        peers: Table,
        transport: Arc<quinn::TransportConfig>,
    ) -> quinn::ServerConfig {
        let verifier = Arc::new(Verifier {
            expect: Expect::Configured(peers),
            provider: Arc::clone(&self.provider),
        });
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("TLS 1.3 with ring")
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(Arc::new(
                rustls::server::AlwaysResolvesServerRawPublicKeys::new(Arc::clone(&self.certified)),
            ));
        tls.alpn_protocols = vec![ALPN.to_vec()];
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
        let verifier = Arc::new(Verifier {
            expect: Expect::Pinned(peer),
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
        tls.alpn_protocols = vec![ALPN.to_vec()];
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

/// The keys a side takes.
#[derive(Debug)]
enum Expect {
    /// The one peer this side dialed.
    Pinned(NodeKey),
    /// Any configured peer.
    Configured(Table),
}

#[derive(Debug)]
struct Verifier {
    expect: Expect,
    provider: Arc<CryptoProvider>,
}

impl Verifier {
    fn check(&self, end: &CertificateDer, rest: &[CertificateDer]) -> Result<(), rustls::Error> {
        let expected = rest.is_empty()
            && key_of(end).is_some_and(|key| match &self.expect {
                Expect::Pinned(pinned) => key == *pinned,
                Expect::Configured(peers) => {
                    peers.read().expect("the peer table").contains_key(&key)
                }
            });
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
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
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
        vec![SignatureScheme::ED25519]
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
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
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
        vec![SignatureScheme::ED25519]
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
            key: identity.connection_ids.clone(),
            random: ring::rand::SystemRandom::new(),
        };
        let first = ids.generate_cid();
        let second = ids.generate_cid();
        assert_ne!(first, second);
        assert_eq!(first.len(), 16);
        assert!(ids.validate(&first).is_ok());
        // A restarted run knows them; another node's, or a forged one, not.
        let restarted = MarkedIds {
            key: Identity::new(&[5; 32]).connection_ids,
            random: ring::rand::SystemRandom::new(),
        };
        assert!(restarted.validate(&first).is_ok());
        let other = MarkedIds {
            key: Identity::new(&[6; 32]).connection_ids,
            random: ring::rand::SystemRandom::new(),
        };
        assert!(other.validate(&first).is_err());
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
        assert_ne!(tag(&identity.reset), tag(&raw));
        // And it is the same across runs, so resets survive a restart.
        assert_eq!(tag(&identity.reset), tag(&Identity::new(&secret).reset));
    }
}
