//! Host-side reconstruction of the space-registry's signed-op canonical
//! bytes, implementing the sign-on-relay step.
//!
//! The catalog mutators (`install`/`publish`/`upgrade`/`uninstall`/
//! `unpublish`) are author-signed and re-verified on every replica's
//! replay (see `space_registry`'s `authorize_op`). A keyless PVM agent
//! (the messenger cloning a channel's actor pair via `create` →
//! `install`) and the daemon's own in-process manifest reconcile can't
//! carry a CLI signature, so the daemon signs these ops as they reach
//! the registry — at `handle_invoke_request`, the one funnel every
//! invoke converges on — with the operator key it loaded at boot,
//! before the op is recorded into the DAG.
//!
//! To sign, the daemon must reproduce the exact bytes the registry
//! verifies. `vos` can't depend on the `space-registry` actor crate
//! (that crate depends on `vos`, so it would cycle), so the canonical
//! format is mirrored here and pinned to the actor's by a cross-check
//! test (and, end-to-end, by the install round-trip). Any drift is
//! fail-closed: the reproduced bytes wouldn't match, the signature
//! wouldn't verify, and a *legitimate* catalog op would be refused —
//! a forged one is never accepted.

use crate::actors::codec::Encode;
use crate::value::{Msg, TAG_DYNAMIC, Value};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

/// Signs the canonical bytes of a registry op and returns the packed
/// `auth` blob (`signer_peer_id || sig(64)`), or `None` if signing
/// fails. Built by the daemon at boot from the operator's libp2p
/// identity (see `vosx`'s `space up`) and held by the space-registry
/// agent thread.
pub(crate) type CatalogOpSigner = Arc<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync>;

/// Mirror of `space_registry::REGISTRY_OP_DOMAIN`. Moves in lockstep —
/// the cross-check test fails if the two diverge.
const REGISTRY_OP_DOMAIN: &[u8] = b"vos-registry-op/v1";

/// Mirror of `space_registry::canonical_op_bytes`:
/// `domain || u16(op.len) || op || (u32(field.len) || field)*`.
fn canonical_op_bytes(op: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(REGISTRY_OP_DOMAIN);
    out.extend_from_slice(&(op.len() as u16).to_le_bytes());
    out.extend_from_slice(op.as_bytes());
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    out
}

/// If `msg` is one of the signed catalog mutators, rebuild the exact
/// canonical bytes its author signs — the same fields, in the same
/// order and encoding the registry handler passes to
/// `canonical_op_bytes`. `None` for any other method (the daemon
/// doesn't sign it) or if a required arg is missing or ill-typed (fail
/// closed: the op then carries no valid auth and the registry rejects
/// it). `register_remote` is deliberately absent — it is the
/// hyperspace surface with a separate trust model.
fn catalog_op_canonical(msg: &Msg) -> Option<Vec<u8>> {
    let a = &msg.args;
    let canon = match msg.name.as_str() {
        "publish" => {
            let name = a.get_str("name")?;
            let version = a.get_str("version")?;
            let hash = a.get_bytes("hash")?;
            canonical_op_bytes("publish", &[name.as_bytes(), version.as_bytes(), &hash])
        }
        "unpublish" => {
            let name = a.get_str("name")?;
            let version = a.get_str("version")?;
            canonical_op_bytes("unpublish", &[name.as_bytes(), version.as_bytes()])
        }
        "install" => {
            let instance_name = a.get_str("instance_name")?;
            let program_name = a.get_str("program_name")?;
            let program_version = a.get_str("program_version")?;
            let program_hash = a.get_bytes("program_hash")?;
            let replication_id = a.get_bytes("replication_id")?;
            let consistency = a.get_u8("consistency")?;
            let install_args = a.get_bytes("install_args")?;
            let install_payloads = a.get_bytes("install_payloads")?;
            canonical_op_bytes(
                "install",
                &[
                    instance_name.as_bytes(),
                    program_name.as_bytes(),
                    program_version.as_bytes(),
                    &program_hash,
                    &replication_id,
                    &[consistency],
                    &install_args,
                    &install_payloads,
                ],
            )
        }
        "uninstall" => {
            let instance_name = a.get_str("instance_name")?;
            canonical_op_bytes("uninstall", &[instance_name.as_bytes()])
        }
        "upgrade" => {
            let instance_name = a.get_str("instance_name")?;
            let new_program_name = a.get_str("new_program_name")?;
            let new_program_version = a.get_str("new_program_version")?;
            let new_program_hash = a.get_bytes("new_program_hash")?;
            canonical_op_bytes(
                "upgrade",
                &[
                    instance_name.as_bytes(),
                    new_program_name.as_bytes(),
                    new_program_version.as_bytes(),
                    &new_program_hash,
                ],
            )
        }
        _ => return None,
    };
    Some(canon)
}

/// Implements the sign-on-relay step: if `payload` (`[TAG_DYNAMIC][rkyv Msg]`)
/// targets a signed catalog mutator, rebuild its canonical bytes, sign
/// them with `signer`, and return a re-encoded payload carrying the
/// operator's `auth` blob (replacing any caller-supplied placeholder).
/// `None` leaves the original payload untouched — the method isn't a
/// catalog mutator, the payload isn't a dynamic `Msg`, or signing
/// failed (the registry then rejects the unsigned op).
pub(crate) fn sign_catalog_op_on_relay(payload: &[u8], signer: &CatalogOpSigner) -> Option<Vec<u8>> {
    if payload.first() != Some(&TAG_DYNAMIC) {
        return None;
    }
    let mut msg = <Msg as crate::Decode>::try_decode(&payload[1..])?;
    let canonical = catalog_op_canonical(&msg)?;
    let auth = signer(&canonical)?;
    // The registry reads the first `auth` arg; drop any caller-supplied
    // placeholder so the operator's signature is the one it sees.
    msg.args.0.retain(|(k, _)| k != "auth");
    msg.args.0.push((String::from("auth"), Value::Bytes(auth)));
    let encoded = msg.encode();
    let mut out = Vec::with_capacity(1 + encoded.len());
    out.push(TAG_DYNAMIC);
    out.extend_from_slice(&encoded);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The load-bearing pin: build each catalog op's `Msg` the way the
    /// typed wrapper / messenger does and assert our host-side canonical
    /// bytes are byte-identical to the registry actor's own
    /// `canonical_op_bytes`. Drift here means a sign-on-relay signature
    /// won't verify, so this keeps the host signer and the actor
    /// verifier locked together.
    #[test]
    fn host_canonical_matches_registry_for_every_catalog_op() {
        use space_registry::canonical_op_bytes as reg;

        let m = Msg::new("install")
            .with("instance_name", "msg-x-log")
            .with("program_name", "p")
            .with("program_version", "1")
            .with("program_hash", alloc::vec![7u8; 32])
            .with("replication_id", alloc::vec![9u8; 32])
            .with("consistency", 2u64)
            .with("install_args", alloc::vec![1u8, 2, 3])
            .with("install_payloads", Vec::<u8>::new());
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            reg(
                "install",
                &[
                    b"msg-x-log",
                    b"p",
                    b"1",
                    &[7u8; 32],
                    &[9u8; 32],
                    &[2u8],
                    &[1u8, 2, 3],
                    &[],
                ],
            ),
        );

        let m = Msg::new("publish")
            .with("name", "p")
            .with("version", "1")
            .with("hash", alloc::vec![7u8; 32]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            reg("publish", &[b"p", b"1", &[7u8; 32]]),
        );

        let m = Msg::new("unpublish").with("name", "p").with("version", "1");
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            reg("unpublish", &[b"p", b"1"]),
        );

        let m = Msg::new("uninstall").with("instance_name", "msg-x-log");
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            reg("uninstall", &[b"msg-x-log"]),
        );

        let m = Msg::new("upgrade")
            .with("instance_name", "msg-x-log")
            .with("new_program_name", "p")
            .with("new_program_version", "2")
            .with("new_program_hash", alloc::vec![5u8; 32]);
        assert_eq!(
            catalog_op_canonical(&m).unwrap(),
            reg("upgrade", &[b"msg-x-log", b"p", b"2", &[5u8; 32]]),
        );
    }

    #[test]
    fn non_catalog_method_is_not_signed() {
        assert!(catalog_op_canonical(&Msg::new("agents")).is_none());
        let grant = Msg::new("grant_role")
            .with("peer_id", alloc::vec![1u8; 38])
            .with("role", 3u8);
        assert!(catalog_op_canonical(&grant).is_none());
        // register_remote is out of scope (hyperspace trust model).
        let rr = Msg::new("register_remote")
            .with("instance_name", "x")
            .with("host_prefix", 5u32);
        assert!(catalog_op_canonical(&rr).is_none());
    }

    #[test]
    fn sign_on_relay_injects_single_auth_over_the_registry_canonical() {
        // A signer that records what it was handed and returns a fixed
        // blob. Proves the canonical the signer sees matches the
        // registry's, and that exactly one `auth` arg ends up in the
        // re-encoded Msg — replacing the caller's empty placeholder.
        let captured: Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
        let seen = captured.clone();
        let signer: CatalogOpSigner = Arc::new(move |canon: &[u8]| {
            *seen.lock().unwrap() = canon.to_vec();
            Some(alloc::vec![0xABu8; 70])
        });

        // typed-wrapper style: carries an empty `auth` placeholder.
        let m = Msg::new("uninstall")
            .with("instance_name", "x")
            .with("auth", Vec::<u8>::new());
        let mut payload = alloc::vec![TAG_DYNAMIC];
        payload.extend_from_slice(&m.encode());

        let signed = sign_catalog_op_on_relay(&payload, &signer).expect("catalog op signed");
        assert_eq!(
            *captured.lock().unwrap(),
            space_registry::canonical_op_bytes("uninstall", &[b"x"]),
        );
        let decoded = <Msg as crate::Decode>::try_decode(&signed[1..]).unwrap();
        let auths = decoded.args.0.iter().filter(|(k, _)| k == "auth").count();
        assert_eq!(auths, 1, "exactly one auth arg after signing");
        assert_eq!(decoded.args.get_bytes("auth").unwrap(), alloc::vec![0xABu8; 70]);
    }

    #[test]
    fn non_dynamic_payload_is_left_untouched() {
        let signer: CatalogOpSigner = Arc::new(|_| Some(alloc::vec![0u8; 70]));
        assert!(sign_catalog_op_on_relay(&[0x01, 0x02, 0x03], &signer).is_none());
    }
}
