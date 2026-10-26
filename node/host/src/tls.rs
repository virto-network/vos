//! TLS 1.3 on the client ingress. The node serves either a certificate
//! made for its own key, which clients pin by the key, or one from PEM
//! files, which clients trust through its CA. Plain HTTP serves loopback
//! addresses only.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use vos_http::tls::{ALPN, certificates, provider};
pub use vos_http::tls::{IngressTls, server_config};

/// How a client trusts a node's ingress.
#[derive(Clone, Debug)]
pub enum Trust {
    /// Plain HTTP, to a loopback address only.
    Loopback,
    /// TLS from the node with this key.
    NodeKey([u8; 32]),
    /// TLS from a gateway with this key, in front of nodes it routes to:
    /// kept across redirects, and the node key it answers not compared.
    Gateway([u8; 32]),
    /// TLS with a certificate for the host, from one of these CAs.
    Ca(Vec<CertificateDer<'static>>),
}

impl Trust {
    /// The CAs in the PEM file at `path`.
    pub fn ca_file(path: &Path) -> Result<Self, String> {
        Ok(Trust::Ca(certificates(path)?))
    }
}

/// A client's TLS configuration for `trust`: an error for plain HTTP,
/// which has none.
pub(crate) fn client_config(trust: &Trust) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| error.to_string())?;
    let mut config = match trust {
        Trust::Loopback => return Err("plain HTTP has no TLS".into()),
        Trust::NodeKey(key) | Trust::Gateway(key) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedKey {
                key: *key,
                provider,
            }))
            .with_no_client_auth(),
        Trust::Ca(certificates) => {
            let mut roots = rustls::RootCertStore::empty();
            for certificate in certificates {
                roots
                    .add(certificate.clone())
                    .map_err(|error| format!("a CA certificate: {error}"))?;
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// Takes a server whose certificate holds one key, whatever else it
/// says: its names, issuer and dates do not matter once the key is known.
#[derive(Debug)]
struct PinnedKey {
    key: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedKey {
    fn verify_server_cert(
        &self,
        end: &CertificateDer,
        _: &[CertificateDer],
        _: &ServerName,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // The key webpki reads is the one the handshake's signature is
        // checked against, below.
        let certificate = webpki::EndEntityCert::try_from(end).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if certificate.subject_public_key_info().as_ref() == vos_net::spki(&self.key) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
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
        certificate: &CertificateDer,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signed,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
