//! Invite tokens — the `vos1…` bearer credential that carries a node
//! into a space with one command (`vosx space up <token>`).
//!
//! A token is a *pointer + credential, never policy*: it names the space
//! (id, human name, bootnodes) and carries a single-use redemption
//! secret plus an admin's signature delegating a role. What the role
//! *means* lives in the registry and can evolve after the token is
//! minted.
//!
//! ## Wire shape
//!
//! ```text
//! "vos1" + bs58( [version] ‖ rkyv(InvitePayload) ‖ blake2b(body)[..4] )
//! ```
//!
//! The leading raw `version` byte lets a reader reject a wrong-version
//! token before touching rkyv; the trailing 4-byte blake2b checksum
//! catches transcription errors (a truncated or fat-fingered token fails
//! `parse` instead of half-decoding).
//!
//! ## Delegated-grant chain (admin → token → node)
//!
//! [`mint`] generates a fresh token keypair `T`, has the operator key
//! sign the invite canonical (`invite`, `[space_id, [role], expires_le,
//! token_pub]`) — byte-for-byte what `space-registry::redeem_invite`
//! rebuilds — and packs the token secret so the joiner can later prove
//! possession. [`redeem_sig`] signs the joiner's own node peer-id (bound
//! into the `redeem_invite` canonical) with that token secret. The
//! registry verifies both offline: `admin_sig` under `admin_peer_id`
//! (which must be a current-epoch effective admin) and `redeem_sig`
//! under `token_pub`.
//!
//! ed25519 throughout, produced via `libp2p::identity::Keypair` so no
//! signing-side ed25519 dependency reaches vosx (the verifier's
//! `ed25519-dalek` stays in the actor crate).

use anyhow::{Context, anyhow};
use libp2p::identity::Keypair;
use vos::registry::{
    AUTH_ROLE_DEVELOPER, AUTH_ROLE_READONLY, OP_SIG_LEN, canonical_op_bytes,
    ed25519_pubkey_from_peer_id,
};

/// Human-readable prefix. A space name may not start with `vos1`, which
/// keeps `space up <arg>` disambiguation unambiguous.
pub const TOKEN_HRP: &str = "vos1";

/// Current token format version — the first raw byte inside the bs58
/// blob. Bump on any breaking `InvitePayload` layout change.
pub const TOKEN_VERSION: u8 = 1;

/// Domain tag for the token's integrity checksum.
const CHECKSUM_DOMAIN: &[u8] = b"vos-invite/v1";

/// Trailing checksum length (bytes of a domain-separated blake2b).
const CHECKSUM_LEN: usize = 4;

/// The decoded contents of a `vos1…` token. `token_secret` is the whole
/// point — it is the bearer credential; treat the token string as
/// sensitive (it is single-use and short-lived, but anyone holding it
/// can redeem the role).
#[derive(vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq)]
#[rkyv(crate = vos::rkyv)]
pub struct InvitePayload {
    /// blake2b-256 space id — which space this token joins.
    pub space_id: [u8; 32],
    /// The space's human short name (seeds the local spaces index).
    pub name: String,
    /// Bootnode multiaddrs to dial for the redeem invoke + first sync.
    pub bootnodes: Vec<String>,
    /// `AUTH_ROLE_*` the token grants.
    pub role: u8,
    /// Expiry (unix seconds). Bound into the signed invite canonical,
    /// checked host-side at admission — never at CRDT replay.
    pub expires_at: u64,
    /// The minting admin's libp2p peer-id bytes — the key `admin_sig`
    /// verifies under. Named so the registry verifies in O(1) instead of
    /// scanning the grant table; a false claim fails verification.
    pub admin_peer_id: Vec<u8>,
    /// The token keypair's raw ed25519 public key — the row identity and
    /// the key `redeem_sig` verifies under.
    pub token_pub: [u8; 32],
    /// The operator's signature over the invite canonical.
    pub admin_sig: [u8; OP_SIG_LEN],
    /// The token keypair's ed25519 secret — used by [`redeem_sig`] to
    /// prove possession.
    pub token_secret: [u8; 32],
}

/// Mint a `vos1…` invite token: generate a fresh token keypair, have
/// `operator` sign the invite canonical, and encode the payload. Returns
/// the token string. `expires_at` is an absolute unix-seconds deadline
/// (the caller resolves `--expires` against its wall clock).
///
/// The invite canonical binds `space_id`: the redeeming registry rebuilds
/// it from its OWN anchored `space_id`, so an invite is non-replayable at
/// a different space even when the minting operator is an admin of both.
/// (The genesis root can't distinguish two spaces one operator runs — it
/// is the shared operator identity — but each space's `space_id` differs,
/// since it derives from a fresh per-space genesis origin.)
pub fn mint(
    operator: &Keypair,
    space_id: [u8; 32],
    name: String,
    bootnodes: Vec<String>,
    role: u8,
    expires_at: u64,
) -> anyhow::Result<String> {
    validate_role(role)?;
    // Fresh single-use token keypair from OS entropy.
    let mut token_secret = [0u8; 32];
    getrandom::getrandom(&mut token_secret)
        .map_err(|e| anyhow!("OS entropy for the invite token key: {e}"))?;
    let token_kp = Keypair::ed25519_from_bytes(token_secret)
        .map_err(|e| anyhow!("derive invite token keypair: {e}"))?;
    let token_pub = raw_ed25519_pubkey(&token_kp)?;

    // The operator (an admin) signs the invite canonical — byte-for-byte
    // what `redeem_invite` rebuilds to verify, binding the space_id.
    let invite_canon = canonical_op_bytes(
        "invite",
        &[&space_id, &[role], &expires_at.to_le_bytes(), &token_pub],
    );
    let admin_sig = sig64(
        &operator
            .sign(&invite_canon)
            .map_err(|e| anyhow!("sign invite: {e}"))?,
    )?;
    let admin_peer_id = libp2p::PeerId::from(operator.public()).to_bytes();

    let payload = InvitePayload {
        space_id,
        name,
        bootnodes,
        role,
        expires_at,
        admin_peer_id,
        token_pub,
        admin_sig,
        token_secret,
    };
    encode(&payload)
}

/// Parse a `vos1…` token: verify the checksum and version, then decode
/// the payload. Fails (rather than half-decoding) on a truncated,
/// mistyped, or wrong-version string.
pub fn parse(token: &str) -> anyhow::Result<InvitePayload> {
    let body58 = token
        .strip_prefix(TOKEN_HRP)
        .ok_or_else(|| anyhow!("not an invite token: expected a '{TOKEN_HRP}…' string"))?;
    let blob = bs58::decode(body58)
        .into_vec()
        .map_err(|e| anyhow!("invite token is not valid base58: {e}"))?;
    if blob.len() <= 1 + CHECKSUM_LEN {
        return Err(anyhow!("invite token is truncated"));
    }
    let (signed, checksum) = blob.split_at(blob.len() - CHECKSUM_LEN);
    let expected = vos::crypto::blake2b_hash::<32>(CHECKSUM_DOMAIN, &[signed]);
    if checksum != &expected[..CHECKSUM_LEN] {
        return Err(anyhow!("invite token checksum mismatch (corrupted or truncated)"));
    }
    if signed[0] != TOKEN_VERSION {
        return Err(anyhow!(
            "unsupported invite token version {} (this build speaks v{TOKEN_VERSION})",
            signed[0],
        ));
    }
    // The version byte offsets the rkyv payload off the archive's
    // alignment, and a bs58-decoded `Vec<u8>` is only byte-aligned
    // anyway — copy the payload into an `AlignedVec` before decoding.
    let mut aligned = vos::rkyv::util::AlignedVec::<16>::new();
    aligned.extend_from_slice(&signed[1..]);
    let payload = vos::rkyv::from_bytes::<InvitePayload, vos::rkyv::rancor::Error>(&aligned)
        .map_err(|e| anyhow!("decode invite token payload: {e}"))?;
    validate_role(payload.role)?;
    Ok(payload)
}

fn validate_role(role: u8) -> anyhow::Result<()> {
    if matches!(role, AUTH_ROLE_READONLY | AUTH_ROLE_DEVELOPER) {
        Ok(())
    } else {
        Err(anyhow!(
            "unsupported invite role {role}; expected member or developer"
        ))
    }
}

/// Produce the joiner's `redeem_sig`: the token keypair signs the
/// `redeem_invite` canonical (`[token_pub, node_peer_id]`), binding the
/// redemption to this node so the same token can't be re-pointed at a
/// different peer-id after the fact.
pub fn redeem_sig(payload: &InvitePayload, node_peer_id: &[u8]) -> anyhow::Result<[u8; OP_SIG_LEN]> {
    let token_kp = Keypair::ed25519_from_bytes(payload.token_secret)
        .map_err(|e| anyhow!("reconstruct invite token keypair: {e}"))?;
    let canon = canonical_op_bytes("redeem_invite", &[&payload.token_pub, node_peer_id]);
    sig64(
        &token_kp
            .sign(&canon)
            .map_err(|e| anyhow!("sign redeem: {e}"))?,
    )
}

/// Parse a `--expires` duration like `7d` / `24h` / `30m` / `90s` into
/// seconds. A bare number is treated as seconds.
pub fn parse_duration(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(anyhow!("empty duration"));
    }
    let (num, unit): (&str, u64) = match s.as_bytes()[s.len() - 1] {
        b'd' => (&s[..s.len() - 1], 86_400),
        b'h' => (&s[..s.len() - 1], 3_600),
        b'm' => (&s[..s.len() - 1], 60),
        b's' => (&s[..s.len() - 1], 1),
        _ => (s, 1),
    };
    let n: u64 = num
        .parse()
        .with_context(|| format!("invalid duration '{s}', expected e.g. 7d / 24h / 30m"))?;
    n.checked_mul(unit)
        .ok_or_else(|| anyhow!("duration '{s}' overflows"))
}

/// `bs58("vos1"-less blob)` where blob = `[version] ‖ rkyv ‖ checksum`.
fn encode(payload: &InvitePayload) -> anyhow::Result<String> {
    let body = vos::rkyv::to_bytes::<vos::rkyv::rancor::Error>(payload)
        .map_err(|e| anyhow!("encode invite token payload: {e}"))?;
    let mut blob = Vec::with_capacity(1 + body.len() + CHECKSUM_LEN);
    blob.push(TOKEN_VERSION);
    blob.extend_from_slice(&body);
    let checksum = vos::crypto::blake2b_hash::<32>(CHECKSUM_DOMAIN, &[&blob]);
    blob.extend_from_slice(&checksum[..CHECKSUM_LEN]);
    Ok(format!("{TOKEN_HRP}{}", bs58::encode(blob).into_string()))
}

/// The raw 32-byte ed25519 public key of a libp2p keypair — extracted
/// via the peer-id round-trip so it is byte-identical to what the
/// registry's `verify_op_sig`/`verify_raw_sig` pull out.
fn raw_ed25519_pubkey(kp: &Keypair) -> anyhow::Result<[u8; 32]> {
    let peer_bytes = libp2p::PeerId::from(kp.public()).to_bytes();
    ed25519_pubkey_from_peer_id(&peer_bytes)
        .ok_or_else(|| anyhow!("keypair is not an ed25519 identity"))
}

fn sig64(sig: &[u8]) -> anyhow::Result<[u8; OP_SIG_LEN]> {
    sig.try_into()
        .map_err(|_| anyhow!("expected a {OP_SIG_LEN}-byte ed25519 signature"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::registry::{AUTH_ROLE_ADMIN, AUTH_ROLE_READONLY};
    // The verifier lives in the actor crate (a dev-dependency), exactly
    // like the op_sign interop test — this is the make-or-break check
    // that a token minted here passes `redeem_invite`'s verification.
    use space_registry::{verify_op_sig, verify_raw_sig};

    fn sample_space_id() -> [u8; 32] {
        [0x5a; 32]
    }

    #[test]
    fn round_trips_through_parse() {
        let op = Keypair::generate_ed25519();
        let token = mint(
            &op,
            sample_space_id(),
            "demo".into(),
            vec!["/ip4/1.2.3.4/tcp/9000".into()],
            AUTH_ROLE_READONLY,
            2_000_000_000,
        )
        .unwrap();
        assert!(token.starts_with("vos1"));
        let p = parse(&token).unwrap();
        assert_eq!(p.space_id, sample_space_id());
        assert_eq!(p.name, "demo");
        assert_eq!(p.bootnodes, vec!["/ip4/1.2.3.4/tcp/9000".to_string()]);
        assert_eq!(p.role, AUTH_ROLE_READONLY);
        assert_eq!(p.expires_at, 2_000_000_000);
        assert_eq!(p.admin_peer_id, libp2p::PeerId::from(op.public()).to_bytes());
    }

    #[test]
    fn checksum_corruption_is_rejected() {
        let op = Keypair::generate_ed25519();
        let token = mint(&op, sample_space_id(), "x".into(), vec![], AUTH_ROLE_READONLY, 1).unwrap();
        // Flip a character in the middle of the base58 body.
        let mut chars: Vec<char> = token.chars().collect();
        let mid = chars.len() / 2;
        chars[mid] = if chars[mid] == 'a' { 'b' } else { 'a' };
        let corrupted: String = chars.into_iter().collect();
        assert!(parse(&corrupted).is_err());
    }

    #[test]
    fn admin_invites_are_rejected_on_mint_and_parse() {
        let op = Keypair::generate_ed25519();
        let err = mint(&op, sample_space_id(), "x".into(), vec![], AUTH_ROLE_ADMIN, 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("member or developer"), "unexpected error: {err}");

        let token = mint(&op, sample_space_id(), "x".into(), vec![], AUTH_ROLE_READONLY, 1).unwrap();
        let mut payload = parse(&token).unwrap();
        payload.role = AUTH_ROLE_ADMIN;
        let forged = encode(&payload).unwrap();
        let err = parse(&forged).unwrap_err().to_string();
        assert!(err.contains("member or developer"), "unexpected error: {err}");
    }

    #[test]
    fn wrong_version_byte_is_rejected() {
        let op = Keypair::generate_ed25519();
        let token = mint(&op, sample_space_id(), "x".into(), vec![], AUTH_ROLE_READONLY, 1).unwrap();
        // Decode, bump the version byte, re-checksum, re-encode.
        let body58 = token.strip_prefix(TOKEN_HRP).unwrap();
        let blob = bs58::decode(body58).into_vec().unwrap();
        let (signed, _) = blob.split_at(blob.len() - CHECKSUM_LEN);
        let mut tampered = signed.to_vec();
        tampered[0] = 0xFE; // unsupported version
        let checksum = vos::crypto::blake2b_hash::<32>(CHECKSUM_DOMAIN, &[&tampered]);
        tampered.extend_from_slice(&checksum[..CHECKSUM_LEN]);
        let token2 = format!("{TOKEN_HRP}{}", bs58::encode(tampered).into_string());
        let err = parse(&token2).unwrap_err().to_string();
        assert!(err.contains("version"), "expected a version error, got: {err}");
    }

    #[test]
    fn non_token_string_is_rejected() {
        assert!(parse("my-space").is_err());
        assert!(parse("vos1!!!not-base58!!!").is_err());
    }

    #[test]
    fn minted_token_verifies_under_the_registry() {
        // The interop: a token minted here must pass every signature the
        // actor's `redeem_invite` checks, byte-for-byte — admin_sig over
        // the space_id-bound invite canonical under admin_peer_id, and
        // both redeem_sig (token) and node_sig (node) over the redeem
        // canonical.
        let op = Keypair::generate_ed25519();
        let space_id = sample_space_id();
        let role = AUTH_ROLE_READONLY;
        let expires_at = 2_000_000_000u64;
        let token = mint(&op, space_id, "demo".into(), vec![], role, expires_at).unwrap();
        let p = parse(&token).unwrap();

        // admin_sig over the invite canonical (bound to space_id) verifies
        // under admin_peer_id.
        let invite_canon = canonical_op_bytes(
            "invite",
            &[&space_id, &[role], &expires_at.to_le_bytes(), &p.token_pub],
        );
        assert!(
            verify_op_sig(&p.admin_peer_id, &invite_canon, &p.admin_sig),
            "admin_sig must verify under the operator's peer-id",
        );
        // Binding space_id defeats cross-space replay: a sibling space's
        // id makes the rebuilt canonical (and signature) mismatch.
        let other_space: [u8; 32] = [0x11; 32];
        let wrong_canon = canonical_op_bytes(
            "invite",
            &[&other_space, &[role], &expires_at.to_le_bytes(), &p.token_pub],
        );
        assert!(!verify_op_sig(&p.admin_peer_id, &wrong_canon, &p.admin_sig));

        // The joining node signs the redeem canonical with BOTH the token
        // secret (redeem_sig, under token_pub) and its own node key
        // (node_sig, under the node peer-id).
        let node_kp = Keypair::generate_ed25519();
        let node = libp2p::PeerId::from(node_kp.public()).to_bytes();
        let redeem_canon = canonical_op_bytes("redeem_invite", &[&p.token_pub, &node]);

        let rsig = redeem_sig(&p, &node).unwrap();
        assert!(
            verify_raw_sig(&p.token_pub, &redeem_canon, &rsig),
            "redeem_sig must verify under the token public key",
        );

        let node_sig: [u8; 64] = node_kp
            .sign(&redeem_canon)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        assert!(
            verify_op_sig(&node, &redeem_canon, &node_sig),
            "node_sig must verify under the joining node's peer-id",
        );

        // A redeem_sig for one node must not verify for another.
        let other = libp2p::PeerId::from(Keypair::generate_ed25519().public()).to_bytes();
        let other_canon = canonical_op_bytes("redeem_invite", &[&p.token_pub, &other]);
        assert!(!verify_raw_sig(&p.token_pub, &other_canon, &rsig));
        // …and a node_sig made by a DIFFERENT key must not verify under
        // this node's peer-id (peer-id control is unforgeable).
        assert!(!verify_op_sig(&node, &redeem_canon, &{
            let s: [u8; 64] = Keypair::generate_ed25519()
                .sign(&redeem_canon)
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
            s
        }));
    }

    #[test]
    fn parse_duration_units() {
        assert_eq!(parse_duration("7d").unwrap(), 7 * 86_400);
        assert_eq!(parse_duration("24h").unwrap(), 24 * 3_600);
        assert_eq!(parse_duration("30m").unwrap(), 30 * 60);
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("42").unwrap(), 42);
        assert!(parse_duration("").is_err());
        assert!(parse_duration("xd").is_err());
    }
}
