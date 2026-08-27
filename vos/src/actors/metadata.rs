//! Actor message metadata — static descriptors for introspection.
//!
//! Metadata is embedded in ELF binaries in the `.vos_meta` section as a
//! self-contained binary blob (no pointers). vosx reads this section to
//! discover actor names, messages, and their argument types without running
//! the binary.
//!
//! ## Binary format
//!
//! ```text
//! [actor_name_len:u16 LE][actor_name_bytes...]
//! [msg_count:u16 LE]
//!   [name_len:u16 LE][name_bytes...]
//!   [is_query:u8]
//!   [field_count:u16 LE]
//!     [name_len:u16 LE][name_bytes...]
//!     [ty_len:u16 LE][ty_bytes...]
//!   ...
//! [ctor_count:u16 LE]
//!   [name_len:u16 LE][name_bytes...]
//!   [ty_len:u16 LE][ty_bytes...]
//!   ...
//! [cli_methods_count:u16 LE]
//!   [name_len:u16 LE][name_bytes...]
//!   ...
//! [returns_count:u16 LE]        (one entry per message, in order)
//!   [ty_len:u16 LE][ty_bytes...]
//!   ...
//! [doc_count:u16 LE]            (one entry per message, in order)
//!   [doc_len:u16 LE][doc_bytes...]
//!   ...
//! [actor_doc_len:u16 LE][actor_doc_bytes...]
//! [timeout_count:u16 LE]        (one entry per message, in order)
//!   [timeout_ms:u32 LE]
//!   ...
//! [mode_count:u16 LE]           (one entry per message, in order)
//!   [mode:u8]                   (0 = sync, 1 = job)
//!   ...
//! [crdt:u8]                     (0 = ordinary actor, 1 = CRDT actor)
//! [policy_count:u16 LE]         (one entry per message, in order)
//!   [attested:u8]               (0 = regular, 1 = proof required)
//!   [space_role:u8]             (0xff = none, otherwise `SpaceRole`)
//! [actor_role_count:u16 LE]      (one entry per message, in order)
//!   [actor_role:u8]             (0xff = none, otherwise `Actor::Role`)
//!   ...
//! [capability_count:u16 LE]      (one entry per message, in order)
//!   [name_len:u16 LE][name_bytes...] (empty = public)
//!   ...
//! [provable:u8]                 (actor-level: #[actor(task, provable)])
//! ```
//!
//! Decoding is strict and positional: every section above must be present and
//! no trailing bytes are accepted.

/// Field descriptor — name and type as strings.
pub struct FieldMeta {
    pub name: &'static str,
    pub ty: &'static str,
}

/// Message descriptor — name, query flag, and fields.
///
/// `exposed_to_cli` is set out-of-band in the binary format
/// (the encoder writes a trailing list of method names; the
/// decoder cross-references). The compile-time `ActorMeta` const
/// emitted by the `#[actor]` macro carries `false` here; the
/// macro emits the names of CLI-exposed methods as
/// `ActorMeta.cli_methods` and `encode` writes them. On decode,
/// methods named in that list flip to `true`.
pub struct MessageMeta {
    pub name: &'static str,
    pub is_query: bool,
    pub fields: &'static [FieldMeta],
    /// Declared return type, rendered whitespace-free (`u64`,
    /// `[u8;32]`, `Vec<u8>`, a custom struct name, …), with any
    /// `Result<T, E>` unwrapped to `T` — the error surfaces separately
    /// as `ClientError`. `()` for a unit / no-return handler. Emitted
    /// in `.vos_meta` (see [`encode`]).
    pub returns: &'static str,
    /// One-line handler description — the first paragraph of the
    /// handler's `///` doc, captured by the `#[msg]` macro. Empty when
    /// undocumented.
    pub doc: &'static str,
    /// Per-handler invoke timeout in milliseconds; `0` = the client's
    /// default. Set with `#[msg(timeout_ms = N)]` for handlers that
    /// legitimately run past the default (a minutes-long prove/measure).
    pub timeout_ms: u32,
    /// Dispatch mode: `0` = sync (the reply is the result), `1` = job (the
    /// handler is a `#[msg(job)]` *begin* returning a `u64` job id; the
    /// dispatcher then drives poll → stream → release).
    pub mode: u8,
    /// Whether the handler requires proof production before its transition may
    /// be accumulated. Declared with `#[msg(attested)]`.
    pub attested: bool,
    /// Direct space-wide role predicate declared with
    /// `#[msg(space_role = SpaceRole::...)]`. This is distinct from the
    /// actor-local `role = ...` hierarchy. `None` leaves the method open to
    /// any otherwise-authorized origin.
    pub space_role: Option<u8>,
    /// Actor-local role predicate declared with `#[msg(role = ...)]`.
    /// The byte is the canonical monotone `RoleByte`/`#[repr(u8)]`
    /// discriminant and is independently enforced from `space_role`.
    pub actor_role: Option<u8>,
    /// Stable space capability required by this method. Capability names are
    /// hashed into [`crate::service::CapabilityId`] when the package is built.
    pub capability: Option<&'static str>,
}

/// Actor descriptor — actor name, messages, and constructor params.
pub struct ActorMeta {
    pub actor_name: &'static str,
    pub messages: &'static [MessageMeta],
    pub constructor: &'static [FieldMeta],
    /// Names of `#[msg]` handlers that should be reachable via
    /// the `vosx <ext> <cmd>` CLI dispatcher. Subset of `messages`
    /// by name. Declared on each handler with `#[msg(cli)]` and
    /// emitted by the actor macro; the registry serves the same
    /// blob so `vosx` can extend clap from cached schemas.
    pub cli_methods: &'static [&'static str],
    /// One-line actor description — the first paragraph of the actor
    /// struct's `///` doc, threaded through `Actor::DOC` by the macro.
    /// Empty when undocumented.
    pub doc: &'static str,
    /// Whether this program was declared with `#[actor(crdt)]` and may
    /// therefore be installed with CRDT consistency.  Ordinary actors must
    /// use Ephemeral, Local, or Raft storage.
    pub crdt: bool,
    /// `#[actor(task, provable)]` — this Task is published as a
    /// provable program: a discovery/
    /// publication mark for the pin/verify tooling, not a semantic
    /// fork (record capture is the caller's `spawn_provable` opt-in
    /// either way).
    pub provable: bool,
}

// --- Binary serialization (const, used by the macro at compile time) ---

/// Encode a metadata tree into a fixed-size byte array for embedding in
/// `.vos_meta`. Called by the proc macro in a const context.
///
/// The caller provides a buffer size `N` large enough for the data.
/// Returns `(bytes, len)` where `len` is the actual number of bytes written.
pub const fn encode<const N: usize>(meta: &ActorMeta) -> ([u8; N], usize) {
    let mut buf = [0u8; N];
    let mut pos = 0;

    // actor name
    let name = meta.actor_name.as_bytes();
    let [lo, hi] = (name.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut i = 0;
    while i < name.len() {
        buf[pos + i] = name[i];
        i += 1;
    }
    pos += name.len();

    // messages
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;

    let mut m = 0;
    while m < meta.messages.len() {
        let msg = &meta.messages[m];
        // name
        let n = msg.name.as_bytes();
        let [lo, hi] = (n.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < n.len() {
            buf[pos + i] = n[i];
            i += 1;
        }
        pos += n.len();
        // is_query
        buf[pos] = msg.is_query as u8;
        pos += 1;
        // fields
        let [lo, hi] = (msg.fields.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut f = 0;
        while f < msg.fields.len() {
            let field = &msg.fields[f];
            // field name
            let fn_bytes = field.name.as_bytes();
            let [lo, hi] = (fn_bytes.len() as u16).to_le_bytes();
            buf[pos] = lo;
            buf[pos + 1] = hi;
            pos += 2;
            let mut i = 0;
            while i < fn_bytes.len() {
                buf[pos + i] = fn_bytes[i];
                i += 1;
            }
            pos += fn_bytes.len();
            // field type
            let ft_bytes = field.ty.as_bytes();
            let [lo, hi] = (ft_bytes.len() as u16).to_le_bytes();
            buf[pos] = lo;
            buf[pos + 1] = hi;
            pos += 2;
            let mut i = 0;
            while i < ft_bytes.len() {
                buf[pos + i] = ft_bytes[i];
                i += 1;
            }
            pos += ft_bytes.len();
            f += 1;
        }
        m += 1;
    }

    // constructor fields
    let [lo, hi] = (meta.constructor.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;

    let mut c = 0;
    while c < meta.constructor.len() {
        let field = &meta.constructor[c];
        // field name
        let fn_bytes = field.name.as_bytes();
        let [lo, hi] = (fn_bytes.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < fn_bytes.len() {
            buf[pos + i] = fn_bytes[i];
            i += 1;
        }
        pos += fn_bytes.len();
        // field type
        let ft_bytes = field.ty.as_bytes();
        let [lo, hi] = (ft_bytes.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < ft_bytes.len() {
            buf[pos + i] = ft_bytes[i];
            i += 1;
        }
        pos += ft_bytes.len();
        c += 1;
    }

    // CLI-exposed method names, cross-referenced by message name.
    let [lo, hi] = (meta.cli_methods.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut c = 0;
    while c < meta.cli_methods.len() {
        let cli_bytes = meta.cli_methods[c].as_bytes();
        let [lo, hi] = (cli_bytes.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < cli_bytes.len() {
            buf[pos + i] = cli_bytes[i];
            i += 1;
        }
        pos += cli_bytes.len();
        c += 1;
    }

    // Per-message return-type names in message order.
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut r = 0;
    while r < meta.messages.len() {
        let ret_bytes = meta.messages[r].returns.as_bytes();
        let [lo, hi] = (ret_bytes.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < ret_bytes.len() {
            buf[pos + i] = ret_bytes[i];
            i += 1;
        }
        pos += ret_bytes.len();
        r += 1;
    }

    // Per-message doc strings in message order.
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut d = 0;
    while d < meta.messages.len() {
        let doc_bytes = meta.messages[d].doc.as_bytes();
        let [lo, hi] = (doc_bytes.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < doc_bytes.len() {
            buf[pos + i] = doc_bytes[i];
            i += 1;
        }
        pos += doc_bytes.len();
        d += 1;
    }

    // Actor-level doc string.
    let actor_doc = meta.doc.as_bytes();
    let [lo, hi] = (actor_doc.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut i = 0;
    while i < actor_doc.len() {
        buf[pos + i] = actor_doc[i];
        i += 1;
    }
    pos += actor_doc.len();

    // Per-message invoke timeouts, u32 LE each, in message order.
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut t = 0;
    while t < meta.messages.len() {
        let [b0, b1, b2, b3] = meta.messages[t].timeout_ms.to_le_bytes();
        buf[pos] = b0;
        buf[pos + 1] = b1;
        buf[pos + 2] = b2;
        buf[pos + 3] = b3;
        pos += 4;
        t += 1;
    }

    // Per-message dispatch mode: `0` = sync, `1` = job.
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut md = 0;
    while md < meta.messages.len() {
        buf[pos] = meta.messages[md].mode;
        pos += 1;
        md += 1;
    }

    // Actor replication model.
    buf[pos] = meta.crdt as u8;
    pos += 1;

    // Per-message attestation and direct space role policy. This is the
    // original policy section and must remain byte-stable.
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut ap = 0;
    while ap < meta.messages.len() {
        buf[pos] = meta.messages[ap].attested as u8;
        buf[pos + 1] = match meta.messages[ap].space_role {
            Some(role) => role,
            None => u8::MAX,
        };
        pos += 2;
        ap += 1;
    }

    // Actor-local policy in message order.
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut ar = 0usize;
    while ar < meta.messages.len() {
        buf[pos] = match meta.messages[ar].actor_role {
            Some(role) => {
                assert!(
                    role != u8::MAX,
                    "actor role byte 255 is reserved for no role"
                );
                role
            }
            None => u8::MAX,
        };
        pos += 1;
        ar += 1;
    }

    // Stable space capability names in message order.
    let [lo, hi] = (meta.messages.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut cp = 0usize;
    while cp < meta.messages.len() {
        let name = match meta.messages[cp].capability {
            Some(name) => name.as_bytes(),
            None => &[],
        };
        let [lo, hi] = (name.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0usize;
        while i < name.len() {
            buf[pos + i] = name[i];
            i += 1;
        }
        pos += name.len();
        cp += 1;
    }

    // Actor-level provable flag.
    buf[pos] = meta.provable as u8;
    pos += 1;

    (buf, pos)
}

// --- Binary deserialization (alloc-only, re-exported unconditionally) ---

pub use decode::*;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        const META: ActorMeta = ActorMeta {
            actor_name: "Counter",
            messages: &[
                MessageMeta {
                    name: "run",
                    is_query: false,
                    fields: &[],
                    returns: "()",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                    attested: true,
                    space_role: Some(1),
                    actor_role: None,
                    capability: None,
                },
                MessageMeta {
                    name: "status",
                    is_query: true,
                    fields: &[FieldMeta {
                        name: "verbose",
                        ty: "bool",
                    }],
                    returns: "[u8;32]",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                    attested: false,
                    space_role: None,
                    actor_role: Some(2),
                    capability: Some("agent.read"),
                },
            ],
            constructor: &[FieldMeta {
                name: "start",
                ty: "u32",
            }],
            cli_methods: &[],
            doc: "",
            crdt: false,
            provable: false,
        };

        let (buf, len) = encode::<256>(&META);
        let parsed = decode(&buf[..len]).expect("decode failed");

        assert_eq!(parsed.actor_name, "Counter");
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.messages[0].name, "run");
        assert!(!parsed.messages[0].is_query);
        assert!(parsed.messages[0].fields.is_empty());
        assert_eq!(parsed.messages[0].returns, "()");
        assert!(parsed.messages[0].attested);
        assert_eq!(parsed.messages[0].space_role, Some(1));
        assert_eq!(parsed.messages[1].name, "status");
        assert!(parsed.messages[1].is_query);
        assert_eq!(parsed.messages[1].fields.len(), 1);
        assert_eq!(parsed.messages[1].fields[0].name, "verbose");
        assert_eq!(parsed.messages[1].fields[0].ty, "bool");
        assert_eq!(parsed.messages[1].returns, "[u8;32]");
        assert!(!parsed.messages[1].attested);
        assert_eq!(parsed.messages[1].space_role, None);
        assert_eq!(parsed.messages[1].actor_role, Some(2));
        assert_eq!(parsed.messages[1].capability.as_deref(), Some("agent.read"));
        assert_eq!(parsed.constructor.len(), 1);
        assert_eq!(parsed.constructor[0].name, "start");
        assert_eq!(parsed.constructor[0].ty, "u32");
        assert!(!parsed.provable);

        assert!(
            decode(&buf[..len - 1]).is_none(),
            "a truncated metadata record must be rejected"
        );
        let mut wrong_count = buf[..len].to_vec();
        let capability_count_offset = len - 1 - (2 + 2 + 2 + "agent.read".len());
        wrong_count[capability_count_offset..capability_count_offset + 2]
            .copy_from_slice(&1u16.to_le_bytes());
        assert!(
            decode(&wrong_count).is_none(),
            "capability count must match the signed message schema"
        );
        let mut trailing = buf[..len].to_vec();
        trailing.push(0);
        assert!(
            decode(&trailing).is_none(),
            "trailing metadata bytes must be rejected"
        );
        let partial_metadata = &buf[..len - 2];
        assert!(
            decode(partial_metadata).is_none(),
            "a present metadata section must contain every declared entry"
        );
    }

    #[test]
    #[should_panic(expected = "actor role byte 255 is reserved for no role")]
    fn actor_role_cannot_collide_with_the_none_sentinel() {
        const META: ActorMeta = ActorMeta {
            actor_name: "InvalidRole",
            messages: &[MessageMeta {
                name: "restricted",
                is_query: false,
                fields: &[],
                returns: "()",
                doc: "",
                timeout_ms: 0,
                mode: 0,
                attested: false,
                space_role: None,
                actor_role: Some(u8::MAX),
                capability: None,
            }],
            constructor: &[],
            cli_methods: &[],
            doc: "",
            crdt: false,
            provable: false,
        };

        let _ = encode::<128>(&META);
    }

    #[test]
    fn crdt_opt_in_roundtrips() {
        const META: ActorMeta = ActorMeta {
            actor_name: "Board",
            messages: &[],
            constructor: &[],
            cli_methods: &[],
            doc: "",
            crdt: true,
            provable: false,
        };
        let (buf, len) = encode::<128>(&META);
        assert!(decode(&buf[..len]).unwrap().crdt);
    }

    #[test]
    fn cli_methods_roundtrip_and_cross_reference() {
        const META: ActorMeta = ActorMeta {
            actor_name: "NativeWorker",
            messages: &[
                MessageMeta {
                    name: "stop",
                    is_query: false,
                    fields: &[],
                    returns: "()",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                    capability: None,
                },
                MessageMeta {
                    name: "status",
                    is_query: true,
                    fields: &[],
                    returns: "String",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                    capability: None,
                },
                MessageMeta {
                    name: "internal_only",
                    is_query: false,
                    fields: &[],
                    returns: "()",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                    capability: None,
                },
            ],
            constructor: &[],
            cli_methods: &["stop", "status"],
            doc: "",
            crdt: false,
            provable: false,
        };
        let (buf, len) = encode::<512>(&META);
        let parsed = decode(&buf[..len]).expect("decode");
        let by_name = |name: &str| {
            parsed
                .messages
                .iter()
                .find(|m| m.name == name)
                .expect("message")
        };
        assert!(by_name("stop").exposed_to_cli);
        assert!(by_name("status").exposed_to_cli);
        assert!(!by_name("internal_only").exposed_to_cli);
    }

    #[test]
    fn docs_and_timeout_roundtrip() {
        // Metadata service: per-message docs, actor doc, and per-message
        // timeout_ms survive a full encode→decode round-trip.
        const META: ActorMeta = ActorMeta {
            actor_name: "Prover",
            messages: &[
                MessageMeta {
                    name: "prove",
                    is_query: false,
                    fields: &[],
                    returns: "u64",
                    doc: "Enqueue a prove job.",
                    timeout_ms: 600_000,
                    mode: 1,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                    capability: None,
                },
                MessageMeta {
                    name: "status",
                    is_query: true,
                    fields: &[],
                    returns: "u8",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                    attested: false,
                    space_role: None,
                    actor_role: None,
                    capability: None,
                },
            ],
            constructor: &[],
            cli_methods: &["prove"],
            doc: "A pure-PVM prover/verifier.",
            crdt: false,
            provable: true,
        };
        let (buf, len) = encode::<512>(&META);
        let parsed = decode(&buf[..len]).expect("decode");
        assert_eq!(parsed.doc, "A pure-PVM prover/verifier.");
        assert_eq!(parsed.messages[0].doc, "Enqueue a prove job.");
        assert_eq!(parsed.messages[0].timeout_ms, 600_000);
        assert_eq!(parsed.messages[0].mode, 1, "job-mode handler round-trips");
        assert!(parsed.provable, "provable flag round-trips");
        assert_eq!(parsed.messages[1].doc, "");
        assert_eq!(parsed.messages[1].timeout_ms, 0);
        assert_eq!(parsed.messages[1].mode, 0, "sync handler stays mode 0");
        // All sections decode together.
        assert_eq!(parsed.messages[0].returns, "u64");
        assert!(parsed.messages[0].exposed_to_cli);
    }
}

/// Parsed metadata + the `decode` / `from_elf` / `raw_section_from_elf`
/// entry points. Self-contained against `alloc` only — no std APIs.
/// Re-exported from `vos::metadata` so it's reachable from both the
/// host (where `vosx` registers schemas) and extensions like
/// native extensions whose cdylib build runs `default-features = false`.
mod decode {
    extern crate alloc;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Parsed field from binary metadata.
    #[derive(Debug, Clone)]
    pub struct ParsedField {
        pub name: String,
        pub ty: String,
    }

    /// Parsed message from binary metadata.
    #[derive(Debug, Clone)]
    pub struct ParsedMessage {
        pub name: String,
        pub is_query: bool,
        pub fields: Vec<ParsedField>,
        /// `true` if `cli_methods` names this handler. Used by
        /// `vosx <ext> <cmd>` to filter the handler list.
        pub exposed_to_cli: bool,
        /// Declared return type (whitespace-free, `Result` unwrapped).
        /// The CLI and worker use it to label an otherwise-opaque reply.
        pub returns: String,
        /// One-line handler description. Empty when undocumented.
        pub doc: String,
        /// Per-handler invoke timeout in milliseconds; `0` = the
        /// client's default.
        pub timeout_ms: u32,
        /// Dispatch mode: `0` = sync (the reply is the result), `1` =
        /// job (the handler is a `#[msg(job)]` begin).
        pub mode: u8,
        /// True only for handlers explicitly declared `#[msg(attested)]`.
        pub attested: bool,
        /// Minimum direct space-wide role byte, if declared.
        pub space_role: Option<u8>,
        /// Minimum actor-local role byte, if declared.
        pub actor_role: Option<u8>,
        /// Stable space capability name, if declared.
        pub capability: Option<String>,
    }

    /// Parsed actor metadata from binary metadata.
    #[derive(Debug, Clone)]
    pub struct ParsedMeta {
        pub actor_name: String,
        pub messages: Vec<ParsedMessage>,
        pub constructor: Vec<ParsedField>,
        /// One-line actor description. Empty when undocumented.
        pub doc: String,
        /// True only for programs explicitly compiled with `#[actor(crdt)]`.
        pub crdt: bool,
        /// `#[actor(task, provable)]` publication mark — this Task is
        /// meant to be pinned and proved.
        pub provable: bool,
    }

    /// Decode binary metadata from a `.vos_meta` section.
    pub fn decode(data: &[u8]) -> Option<ParsedMeta> {
        decode_format(data)
    }

    fn decode_format(data: &[u8]) -> Option<ParsedMeta> {
        let mut pos = 0;

        let actor_name = read_str(data, &mut pos)?;

        let msg_count = read_u16(data, &mut pos)? as usize;
        let mut messages = Vec::with_capacity(msg_count);
        for _ in 0..msg_count {
            let name = read_str(data, &mut pos)?;
            let is_query = *data.get(pos)? != 0;
            pos += 1;
            let field_count = read_u16(data, &mut pos)? as usize;
            let mut fields = Vec::with_capacity(field_count);
            for _ in 0..field_count {
                let fname = read_str(data, &mut pos)?;
                let fty = read_str(data, &mut pos)?;
                fields.push(ParsedField {
                    name: fname,
                    ty: fty,
                });
            }
            messages.push(ParsedMessage {
                name,
                is_query,
                fields,
                // Filled in from the trailing `cli_methods` section
                // once that section parses successfully — see the
                // CLI-method block below.
                exposed_to_cli: false,
                // Filled in from the trailing `returns` section.
                returns: String::new(),
                // Filled in from the metadata doc / timeout / mode sections.
                doc: String::new(),
                timeout_ms: 0,
                mode: 0,
                attested: false,
                space_role: None,
                actor_role: None,
                capability: None,
            });
        }

        let ctor_count = read_u16(data, &mut pos)? as usize;
        let mut constructor = Vec::with_capacity(ctor_count);
        for _ in 0..ctor_count {
            constructor.push(ParsedField {
                name: read_str(data, &mut pos)?,
                ty: read_str(data, &mut pos)?,
            });
        }

        let cli_count = read_u16(data, &mut pos)? as usize;
        for _ in 0..cli_count {
            let name = read_str(data, &mut pos)?;
            let msg = messages.iter_mut().find(|message| message.name == name)?;
            msg.exposed_to_cli = true;
        }

        let ret_count = read_u16(data, &mut pos)? as usize;
        if ret_count != messages.len() {
            return None;
        }
        for message in &mut messages {
            message.returns = read_str(data, &mut pos)?;
        }

        let doc_count = read_u16(data, &mut pos)? as usize;
        if doc_count != messages.len() {
            return None;
        }
        for message in &mut messages {
            message.doc = read_str(data, &mut pos)?;
        }

        let doc = read_str(data, &mut pos)?;

        let timeout_count = read_u16(data, &mut pos)? as usize;
        if timeout_count != messages.len() {
            return None;
        }
        for message in &mut messages {
            message.timeout_ms = read_u32(data, &mut pos)?;
        }

        let mode_count = read_u16(data, &mut pos)? as usize;
        if mode_count != messages.len() {
            return None;
        }
        for message in &mut messages {
            message.mode = *data.get(pos)?;
            pos += 1;
        }

        let crdt = match *data.get(pos)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        pos += 1;

        let policy_count = read_u16(data, &mut pos)? as usize;
        if policy_count != messages.len() {
            return None;
        }
        for message in &mut messages {
            let &attested = data.get(pos)?;
            let &space_role = data.get(pos + 1)?;
            pos += 2;
            if attested > 1 || (space_role != u8::MAX && space_role > 3) {
                return None;
            }
            message.attested = attested == 1;
            message.space_role = (space_role != u8::MAX).then_some(space_role);
        }

        let actor_role_count = read_u16(data, &mut pos)? as usize;
        if actor_role_count != messages.len() {
            return None;
        }
        for message in &mut messages {
            let &actor_role = data.get(pos)?;
            pos += 1;
            message.actor_role = (actor_role != u8::MAX).then_some(actor_role);
        }

        let capability_count = read_u16(data, &mut pos)? as usize;
        if capability_count != messages.len() {
            return None;
        }
        for message in &mut messages {
            let capability = read_str(data, &mut pos)?;
            message.capability = (!capability.is_empty()).then_some(capability);
        }

        let provable = match *data.get(pos)? {
            0 => false,
            1 => true,
            _ => return None,
        };
        pos += 1;
        if pos != data.len() {
            return None;
        }

        Some(ParsedMeta {
            actor_name,
            messages,
            constructor,
            doc,
            crdt,
            provable,
        })
    }

    fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
        if *pos + 2 > data.len() {
            return None;
        }
        let val = u16::from_le_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Some(val)
    }

    fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
        if *pos + 4 > data.len() {
            return None;
        }
        let val = u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]);
        *pos += 4;
        Some(val)
    }

    fn read_str(data: &[u8], pos: &mut usize) -> Option<String> {
        let len = read_u16(data, pos)? as usize;
        if *pos + len > data.len() {
            return None;
        }
        let s = core::str::from_utf8(&data[*pos..*pos + len]).ok()?;
        *pos += len;
        Some(s.into())
    }

    /// Extract actor metadata from a RISC-V ELF binary by reading the
    /// `.vos_meta` section.
    pub fn from_elf(elf_data: &[u8]) -> Option<ParsedMeta> {
        let section_data = find_elf_section(elf_data, b".vos_meta")?;
        decode(section_data)
    }

    /// Raw bytes of the `.vos_meta` ELF section, without decoding.
    /// Used by `vosx` to forward the schema verbatim to the
    /// space-registry's `register_meta` handler, which stores it
    /// opaquely keyed by program hash. The registry validates and serves the
    /// same bytes back to consumers, which decode them into [`ParsedMeta`].
    pub fn raw_section_from_elf(elf_data: &[u8]) -> Option<Vec<u8>> {
        find_elf_section(elf_data, b".vos_meta").map(|s| s.to_vec())
    }

    /// Find a named section in a 64-bit little-endian ELF.
    fn find_elf_section<'a>(elf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
        if elf.len() < 64 {
            return None;
        }
        // Verify ELF magic
        if &elf[0..4] != b"\x7fELF" {
            return None;
        }
        // 64-bit little-endian
        if elf[4] != 2 || elf[5] != 1 {
            return None;
        }

        let shoff = u64::from_le_bytes(elf[40..48].try_into().ok()?) as usize;
        let shentsize = u16::from_le_bytes(elf[58..60].try_into().ok()?) as usize;
        let shnum = u16::from_le_bytes(elf[60..62].try_into().ok()?) as usize;
        let shstrndx = u16::from_le_bytes(elf[62..64].try_into().ok()?) as usize;

        if shoff == 0 || shentsize < 64 || shnum == 0 {
            return None;
        }
        if shstrndx >= shnum {
            return None;
        }

        // Read section header string table
        let strtab_hdr = shoff + shstrndx * shentsize;
        if strtab_hdr + 64 > elf.len() {
            return None;
        }
        let strtab_off =
            u64::from_le_bytes(elf[strtab_hdr + 24..strtab_hdr + 32].try_into().ok()?) as usize;
        let strtab_size =
            u64::from_le_bytes(elf[strtab_hdr + 32..strtab_hdr + 40].try_into().ok()?) as usize;
        if strtab_off + strtab_size > elf.len() {
            return None;
        }
        let strtab = &elf[strtab_off..strtab_off + strtab_size];

        // Scan section headers for matching name
        for i in 0..shnum {
            let hdr = shoff + i * shentsize;
            if hdr + 64 > elf.len() {
                continue;
            }
            let name_off = u32::from_le_bytes(elf[hdr..hdr + 4].try_into().ok()?) as usize;
            if name_off >= strtab.len() {
                continue;
            }

            // Compare section name
            let sec_name = &strtab[name_off..];
            if sec_name.len() >= name.len()
                && &sec_name[..name.len()] == name
                && (sec_name.len() == name.len() || sec_name[name.len()] == 0)
            {
                let off = u64::from_le_bytes(elf[hdr + 24..hdr + 32].try_into().ok()?) as usize;
                let size = u64::from_le_bytes(elf[hdr + 32..hdr + 40].try_into().ok()?) as usize;
                if off + size <= elf.len() {
                    return Some(&elf[off..off + size]);
                }
            }
        }
        None
    }
}
