//! A committer that runs other code: a device's group state loaded by a
//! client of its own, whose crypto seals every HPKE ciphertext of a commit
//! to garbage except those to the keys it spares, and whose rules let it
//! build anything mls-rs builds.

use mls_rs::client_builder::{MlsConfig, PaddingMode};
use mls_rs::group::{GroupContext, Roster};
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle,
};
use mls_rs::{Client, Group, MlsRules};
use mls_rs_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePsk, HpkePublicKey,
    HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use vos_light::Store;
use vos_mls::Identity;
use zeroize::Zeroizing;

type Suite = <RustCryptoProvider as CryptoProvider>::CipherSuiteProvider;
type SuiteError = <Suite as CipherSuiteProvider>::Error;

/// RustCrypto, but every HPKE seal to a key not in `spare` garbled.
#[derive(Clone)]
pub struct Garbling {
    spare: Option<Vec<HpkePublicKey>>,
}

impl CryptoProvider for Garbling {
    type CipherSuiteProvider = GarblingSuite;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        RustCryptoProvider::default().supported_cipher_suites()
    }

    fn cipher_suite_provider(&self, suite: CipherSuite) -> Option<GarblingSuite> {
        Some(GarblingSuite {
            inner: RustCryptoProvider::default().cipher_suite_provider(suite)?,
            spare: self.spare.clone(),
        })
    }
}

#[derive(Clone)]
pub struct GarblingSuite {
    inner: Suite,
    spare: Option<Vec<HpkePublicKey>>,
}

impl CipherSuiteProvider for GarblingSuite {
    type Error = SuiteError;
    type HpkeContextS = <Suite as CipherSuiteProvider>::HpkeContextS;
    type HpkeContextR = <Suite as CipherSuiteProvider>::HpkeContextR;

    fn cipher_suite(&self) -> CipherSuite {
        self.inner.cipher_suite()
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, SuiteError> {
        self.inner.hash(data)
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, SuiteError> {
        self.inner.mac(key, data)
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, SuiteError> {
        self.inner.aead_seal(key, data, aad, nonce)
    }

    fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SuiteError> {
        self.inner.aead_open(key, ciphertext, aad, nonce)
    }

    fn aead_key_size(&self) -> usize {
        self.inner.aead_key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.inner.aead_nonce_size()
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, SuiteError> {
        self.inner.kdf_extract(salt, ikm)
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, SuiteError> {
        self.inner.kdf_expand(prk, info, len)
    }

    fn kdf_extract_size(&self) -> usize {
        self.inner.kdf_extract_size()
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, SuiteError> {
        let mut sealed = self.inner.hpke_seal(remote_key, info, aad, pt)?;
        if let Some(spare) = &self.spare
            && !spare.contains(remote_key)
        {
            for byte in &mut sealed.ciphertext {
                *byte ^= 0x5a;
            }
        }
        Ok(sealed)
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, SuiteError> {
        self.inner.hpke_seal_psk(remote_key, info, aad, pt, psk)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, SuiteError> {
        self.inner
            .hpke_open(ciphertext, local_secret, local_public, info, aad)
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, SuiteError> {
        self.inner
            .hpke_open_psk(ciphertext, local_secret, local_public, info, aad, psk)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), SuiteError> {
        self.inner.hpke_setup_s(remote_key, info)
    }

    fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, SuiteError> {
        self.inner
            .hpke_setup_r(kem_output, local_secret, local_public, info)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), SuiteError> {
        self.inner.kem_derive(ikm)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), SuiteError> {
        self.inner.kem_generate()
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), SuiteError> {
        self.inner.kem_public_key_validate(key)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), SuiteError> {
        self.inner.random_bytes(out)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), SuiteError> {
        self.inner.signature_key_generate()
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, SuiteError> {
        self.inner.signature_key_derive_public(secret_key)
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, SuiteError> {
        self.inner.sign(secret_key, data)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), SuiteError> {
        self.inner.verify(public_key, signature, data)
    }
}

/// Rules that build anything: with or without a path, encrypted or not.
#[derive(Clone, Copy)]
pub struct Anything {
    pub path: bool,
    pub encrypt: bool,
}

impl MlsRules for Anything {
    type Error = std::convert::Infallible;

    fn filter_proposals(
        &self,
        _: CommitDirection,
        _: CommitSource,
        _: &Roster,
        _: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        Ok(proposals)
    }

    fn commit_options(
        &self,
        _: &Roster,
        _: &GroupContext,
        _: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        Ok(CommitOptions::new()
            .with_path_required(self.path)
            .with_ratchet_tree_extension(true)
            .with_single_welcome_message(true))
    }

    fn encryption_options(
        &self,
        _: &Roster,
        _: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(EncryptionOptions::new(self.encrypt, PaddingMode::Padme))
    }
}

/// The group of the device whose light node store is `store`, loaded by a
/// client of other code: sealing honestly to `spare` alone (to every key
/// when `None`), under `rules`. It works on a copy of the device's
/// namespace, so the device's own state stays as it was.
pub fn hostile(
    store: &Store,
    spare: Option<Vec<HpkePublicKey>>,
    rules: Anything,
) -> Group<impl MlsConfig + use<>> {
    let namespace = vos_light::group::mls_namespace(store).copy();
    let id = namespace
        .get(b"group")
        .unwrap()
        .expect("the device has a group");
    let client = Client::builder()
        .group_state_storage(namespace.clone())
        .key_package_repo(namespace)
        .identity_provider(Identity::default())
        .crypto_provider(Garbling { spare })
        .mls_rules(rules)
        .build();
    client.load_group(&id).unwrap()
}

/// The HPKE key of the leaf of `group` whose credential is `credential`.
pub fn leaf_key<C: MlsConfig>(group: &Group<C>, credential: &[u8]) -> HpkePublicKey {
    let tree = group.export_tree();
    tree.nodes()
        .iter()
        .flatten()
        .find_map(|node| match node {
            mls_rs::group::Node::Leaf(leaf)
                if leaf
                    .signing_identity
                    .credential
                    .as_basic()
                    .is_some_and(|basic| basic.identifier == credential) =>
            {
                Some(leaf.public_key.clone())
            }
            _ => None,
        })
        .expect("a member's leaf")
}
