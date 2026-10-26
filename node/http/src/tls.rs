//! Public TLS 1.3 for HTTP: a certificate made for a key, which clients
//! pin by the key, or one from PEM files, which clients trust through its
//! CA.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// The protocol a TLS connection names: HTTP/1.1.
pub const ALPN: &[u8] = b"http/1.1";

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// How HTTP serves TLS.
#[derive(Clone, Debug)]
pub enum IngressTls {
    /// A certificate for the server's own key, self-signed and naming
    /// `names` (host names or addresses). Clients pin the key.
    NodeKey { names: Vec<String> },
    /// A certificate chain and its key, from PEM files. Clients trust the
    /// chain's CA.
    Files { chain: PathBuf, key: PathBuf },
}

/// The TLS configuration of `tls`, for the server whose secret seed is
/// `secret`.
pub fn server_config(
    tls: &IngressTls,
    secret: &[u8; 32],
) -> Result<Arc<rustls::ServerConfig>, String> {
    let (chain, key) = match tls {
        IngressTls::NodeKey { names } => {
            let pkcs8 = PrivatePkcs8KeyDer::from(vos_net::pkcs8(secret));
            let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)
                .map_err(|error| format!("the key: {error}"))?;
            let names = if names.is_empty() {
                vec!["localhost".to_string()]
            } else {
                names.clone()
            };
            let certificate = rcgen::CertificateParams::new(names)
                .and_then(|params| params.self_signed(&pair))
                .map_err(|error| format!("a certificate for the key: {error}"))?;
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
        .map_err(|error| format!("the certificate: {error}"))?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// The certificates in the PEM file at `path`: at least one.
pub fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certificates = CertificateDer::pem_file_iter(path)
        .and_then(|certificates| certificates.collect::<Result<Vec<_>, _>>())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if certificates.is_empty() {
        return Err(format!("{}: no certificate", path.display()));
    }
    Ok(certificates)
}
