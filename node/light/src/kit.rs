//! The recovery kit (`light-node.md` §3.5): 32 bytes, from which the kit's
//! ed25519 signing key and X25519 sealing key derive, and the split wrap
//! key `R = R1 ⊕ R2` its recovery envelopes are sealed under.
//!
//! - **Two kinds:** a phrase, 32 bytes drawn by the operating system and
//!   shown once as 24 words ([`KitSecret::phrase`], [`KitSecret::words`]);
//!   or a security key's `hmac-secret` over a fixed salt, the same 32 bytes
//!   at every touch ([`KitSecret::security_key`], behind [`SecurityKey`]).
//!   A [`KitSecret`] is zeroized on drop and has no `Clone` and no `Debug`.
//! - **The split** ([`Split`]): `R` and `R1` drawn, `R2 = R ⊕ R1`; `R1`
//!   sealed to each entry's X25519 key, so a kit's keys alone re-seal it
//!   ([`seal_r1`]), and `R2` kept at the personal agent, released only to a
//!   matured restore.
//! - **The agent's index:** `Homes` indexes the personal agent by
//!   [`index`] of a kit's signing key, so a kit needs no agent id.
//!
//! `R1` is sealed to an entry's X25519 key with an ephemeral key: the
//! ephemeral public key, then `R1` under XChaCha20-Poly1305 with a key
//! hashed from the agreement, the agent and both public keys, the agent's
//! identity bound as the AAD (80 bytes).

use blake2::Blake2b;
use blake2::digest::Digest as _;
use blake2::digest::consts::U32;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::SigningKey;
use sha2::Sha256;
use vos_abi::{Decode, Encode};
use vos_wire::personal::{Kit, KitEntry, KitKind, NewKit, r_hash, r2_hash};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// The words a phrase is shown as.
pub const WORDS: usize = 24;

/// The bytes of `R1` sealed to an entry: the ephemeral key and the sealed
/// `R1` with its tag.
const SEALED_R1: usize = 32 + 32 + 16;

const SALT_DOMAIN: &[u8] = b"vos/personal/kit/v1";
const SIGNING: &[u8] = b"vos/personal/kit/signing";
const SEALING: &[u8] = b"vos/personal/kit/sealing";
const SEAL: &[u8] = b"vos/personal/kit/r1";

/// The salt a security key's `hmac-secret` takes for its kit:
/// `SHA-256("vos/personal/kit/v1")`, apart from every space's handle a
/// member secret's source takes.
pub fn salt() -> [u8; 32] {
    Sha256::new().chain_update(SALT_DOMAIN).finalize().into()
}

/// A FIDO2 security key's `hmac-secret` extension: 32 bytes for `salt`,
/// the same at every touch of the same credential, behind its PIN and a
/// touch. The app's is YubiKit's; tests hold a double.
pub trait SecurityKey {
    type Error;

    fn hmac_secret(&mut self, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Self::Error>;
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    Zeroizing::new(hasher.finalize().into())
}

/// The kit's public keys: its kind, its signing key (its client key at the
/// agent) and its sealing key (`R1`'s).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct KitKey {
    pub kind: KitKind,
    pub signing: [u8; 32],
    pub sealing: [u8; 32],
}

impl KitKey {
    pub fn of(entry: &KitEntry) -> Self {
        Self {
            kind: entry.kind,
            signing: entry.signing,
            sealing: entry.sealing,
        }
    }
}

/// A kit's 32 bytes and its kind. No `Clone`, no `Debug`; zeroized on
/// drop.
pub struct KitSecret {
    bytes: Zeroizing<[u8; 32]>,
    kind: KitKind,
}

impl KitSecret {
    /// A new phrase: 32 bytes from the operating system.
    pub fn phrase() -> Option<Self> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::getrandom(&mut bytes[..]).ok()?;
        Some(Self {
            bytes,
            kind: KitKind::Phrase,
        })
    }

    /// The phrase its 24 words name: `None` for words that are not a
    /// phrase's (an unknown word, a count other than 24, a checksum that
    /// does not hold).
    pub fn from_words(words: &str) -> Option<Self> {
        let mnemonic = bip39::Mnemonic::parse_normalized(words).ok()?;
        let (mut entropy, len) = mnemonic.to_entropy_array();
        let bytes = (len == 32).then(|| {
            let mut bytes = Zeroizing::new([0; 32]);
            bytes.copy_from_slice(&entropy[..32]);
            bytes
        });
        entropy.zeroize();
        Some(Self {
            bytes: bytes?,
            kind: KitKind::Phrase,
        })
    }

    /// A phrase's 24 words, shown once at its making; none for a security
    /// key's kit, which is never shown.
    pub fn words(&self) -> Option<Zeroizing<String>> {
        if self.kind != KitKind::Phrase {
            return None;
        }
        let mnemonic = bip39::Mnemonic::from_entropy(&self.bytes[..]).ok()?;
        let mut words = Zeroizing::new(String::new());
        for (i, word) in mnemonic.words().enumerate() {
            if i > 0 {
                words.push(' ');
            }
            words.push_str(word);
        }
        Some(words)
    }

    /// A security key's kit: its `hmac-secret` over [`salt`].
    pub fn security_key<K: SecurityKey>(key: &mut K) -> Result<Self, K::Error> {
        Ok(Self {
            bytes: key.hmac_secret(&salt())?,
            kind: KitKind::SecurityKey,
        })
    }

    pub fn kind(&self) -> KitKind {
        self.kind
    }

    /// Its signing key: `BLAKE2b-256("vos/personal/kit/signing" ‖ bytes)`
    /// as an ed25519 seed, which signs the kit's admin calls.
    pub fn signing(&self) -> SigningKey {
        SigningKey::from_bytes(&hash(SIGNING, &[&self.bytes[..]]))
    }

    fn sealing(&self) -> StaticSecret {
        StaticSecret::from(*hash(SEALING, &[&self.bytes[..]]))
    }

    /// Its public keys.
    pub fn key(&self) -> KitKey {
        KitKey {
            kind: self.kind,
            signing: self.signing().verifying_key().to_bytes(),
            sealing: PublicKey::from(&self.sealing()).to_bytes(),
        }
    }

    /// `R1`, opened from `entry` at the agent whose identity is `agent`:
    /// none for an entry sealed to another key, or bytes that do not open.
    pub fn open_r1(&self, entry: &KitEntry, agent: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
        let sealed = entry.sealed_r1.as_slice();
        if sealed.len() != SEALED_R1 {
            return None;
        }
        let ephemeral = PublicKey::from(<[u8; 32]>::try_from(&sealed[..32]).ok()?);
        let secret = self.sealing();
        let public = PublicKey::from(&secret);
        if public.to_bytes() != entry.sealing {
            return None;
        }
        let shared = secret.diffie_hellman(&ephemeral);
        if !shared.was_contributory() {
            return None;
        }
        let key = hash(
            SEAL,
            &[
                agent,
                ephemeral.as_bytes(),
                public.as_bytes(),
                shared.as_bytes(),
            ],
        );
        let plain = XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&[0; 24]),
                Payload {
                    msg: &sealed[32..],
                    aad: agent,
                },
            )
            .ok()?;
        let plain = Zeroizing::new(plain);
        Some(Zeroizing::new(plain[..].try_into().ok()?))
    }

    /// The agent's index at `Homes` of this kit: [`index`] of its signing
    /// key.
    pub fn index(&self) -> [u8; 32] {
        index(&self.signing().verifying_key().to_bytes())
    }
}

/// The index `Homes` keeps a personal agent under for a kit whose signing
/// key is `signing`: `BLAKE2b-256("vos/personal/kit/index" ‖ signing)`.
pub fn index(signing: &[u8; 32]) -> [u8; 32] {
    vos_wire::personal::kit_index(signing)
}

/// `R1` sealed to `key`'s sealing key at the agent whose identity is
/// `agent`, as its entry: none for a sealing key no agreement is
/// contributory with, or when the operating system has no randomness.
pub fn seal_r1(key: &KitKey, r1: &[u8; 32], agent: &[u8; 32]) -> Option<KitEntry> {
    let mut drawn = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut drawn[..]).ok()?;
    let ephemeral = StaticSecret::from(*drawn);
    let public = PublicKey::from(&ephemeral);
    let theirs = PublicKey::from(key.sealing);
    let shared = ephemeral.diffie_hellman(&theirs);
    if !shared.was_contributory() {
        return None;
    }
    let seal = hash(
        SEAL,
        &[
            agent,
            public.as_bytes(),
            theirs.as_bytes(),
            shared.as_bytes(),
        ],
    );
    let sealed = XChaCha20Poly1305::new((&*seal).into())
        .encrypt(
            XNonce::from_slice(&[0; 24]),
            Payload {
                msg: &r1[..],
                aad: agent,
            },
        )
        .ok()?;
    Some(KitEntry {
        kind: key.kind,
        signing: key.signing,
        sealing: key.sealing,
        sealed_r1: [&public.to_bytes()[..], &sealed].concat(),
    })
}

/// `R1 ⊕ R2`: `R`.
pub fn join(r1: &[u8; 32], r2: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut r = Zeroizing::new([0; 32]);
    for (at, (one, two)) in r.iter_mut().zip(r1.iter().zip(r2)) {
        *at = one ^ two;
    }
    r
}

/// A kit split at an agent: `R` and `R1` drawn, `R2 = R ⊕ R1`, `R1` sealed
/// to each of the kit's keys. What a claim, a kit rotation, a restore and
/// a commit carrying a removal bring.
pub struct Split {
    pub kit: NewKit,
    r: Zeroizing<[u8; 32]>,
    r2: Zeroizing<[u8; 32]>,
}

impl Split {
    /// A split for `keys` at the agent whose identity is `agent`: none for
    /// no key, a key no agreement is contributory with, or no randomness.
    pub fn draw(keys: &[KitKey], agent: &[u8; 32]) -> Option<Self> {
        if keys.is_empty() {
            return None;
        }
        let mut r = Zeroizing::new([0; 32]);
        let mut r1 = Zeroizing::new([0; 32]);
        getrandom::getrandom(&mut r[..]).ok()?;
        getrandom::getrandom(&mut r1[..]).ok()?;
        let r2 = join(&r, &r1);
        let entries = keys
            .iter()
            .map(|key| seal_r1(key, &r1, agent))
            .collect::<Option<Vec<KitEntry>>>()?;
        Some(Self {
            kit: NewKit {
                entries,
                r2_hash: r2_hash(&r2),
                r_hash: r_hash(&r),
            },
            r,
            r2,
        })
    }

    /// `R`, which the device that drew it holds.
    pub fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// `R2`, for the agent alone: in the evidence of the call that brings
    /// the kit, or in a claim.
    pub fn r2(&self) -> &[u8; 32] {
        &self.r2
    }

    /// The kit a claim brings: its entries and `R2`.
    pub fn claim(&self) -> Kit {
        Kit {
            entries: self.kit.entries.clone(),
            r2: *self.r2,
        }
    }
}

/// What a phrase kit is shown with, beside its words: the home's handle
/// (its stable 32 bytes, so a re-founded home still matches) and its
/// onions at the claim, each with its SSH host key; never a QR.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Card {
    pub handle: [u8; 32],
    pub onions: Vec<vos_wire::credentials::Onion>,
}
