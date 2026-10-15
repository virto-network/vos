//! TLS 1.3 on the client ingress. The node serves either a certificate
//! made for its own key, which clients pin by the key, or one from PEM
//! files, which clients trust through its CA. Plain HTTP serves loopback
//! addresses only.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

const ALPN: &[u8] = b"http/1.1";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// How the ingress serves TLS.
#[derive(Clone, Debug)]
pub enum IngressTls {
    /// A certificate for the node's own key, self-signed and naming
    /// `names` (host names or addresses). Clients pin the node's key.
    NodeKey { names: Vec<String> },
    /// A certificate chain and its key, from PEM files. Clients trust the
    /// chain's CA.
    Files { chain: PathBuf, key: PathBuf },
}

/// The ingress's TLS configuration, for the node whose secret seed is
/// `secret`.
pub(crate) fn server_config(
    tls: &IngressTls,
    secret: &[u8; 32],
) -> Result<Arc<rustls::ServerConfig>, String> {
    let (chain, key) = match tls {
        IngressTls::NodeKey { names } => {
            let pkcs8 = PrivatePkcs8KeyDer::from(vos_net::pkcs8(secret));
            let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)
                .map_err(|error| format!("the node's key: {error}"))?;
            let names = if names.is_empty() {
                vec!["localhost".to_string()]
            } else {
                names.clone()
            };
            let certificate = rcgen::CertificateParams::new(names)
                .and_then(|params| params.self_signed(&pair))
                .map_err(|error| format!("a certificate for the node's key: {error}"))?;
            (vec![certificate.der().clone()], PrivateKeyDer::Pkcs8(pkcs8))
        }
        IngressTls::Files { chain, key } => {
            let chain = certificates(chain)?;
            let key = PrivateKeyDer::from_pem_file(key)
                .map_err(|error| format!("{}: {error}", key.display()))?;
            (chain, key)
        }
    };
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| error.to_string())?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|error| format!("the ingress certificate: {error}"))?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// How a client trusts a node's ingress.
#[derive(Clone, Debug)]
pub enum Trust {
    /// Plain HTTP, to a loopback address only.
    Loopback,
    /// TLS from the node with this key.
    NodeKey([u8; 32]),
    /// TLS with a certificate for the host, from one of these CAs.
    Ca(Vec<CertificateDer<'static>>),
}

impl Trust {
    /// The CAs in the PEM file at `path`.
    pub fn ca_file(path: &Path) -> Result<Self, String> {
        Ok(Trust::Ca(certificates(path)?))
    }
}

/// The certificates in the PEM file at `path`: at least one.
fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certificates = CertificateDer::pem_file_iter(path)
        .and_then(|certificates| certificates.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if certificates.is_empty() {
        return Err(format!("{}: no certificate", path.display()));
    }
    Ok(certificates)
}

/// A client's TLS configuration for `trust`: none for plain HTTP.
pub(crate) fn client_config(trust: &Trust) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = provider();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| error.to_string())?;
    let mut config = match trust {
        Trust::Loopback => return Err("plain HTTP has no TLS".into()),
        Trust::NodeKey(key) => builder
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
