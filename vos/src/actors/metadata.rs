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
//! [kind:u8]
//! [caps_count:u16 LE]
//!   [name_len:u16 LE][name_bytes...]
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
//! ```
//!
//! Each trailing section is append-only: older decoders that don't
//! know about `kind` / `caps` / `cli_methods` / `returns` / the metadata-v2
//! doc + timeout sections stop reading at the previous section and the
//! corresponding `ParsedMeta` field defaults to empty/false/0. This is how
//! the format has evolved without breaking older actor binaries. New
//! sections MUST be appended at the end, never inserted — decoding is
//! strictly positional.

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
    /// in a trailing `.vos_meta` section (see [`encode`]), so blobs
    /// that predate it decode to an empty string.
    pub returns: &'static str,
    /// One-line handler description — the first paragraph of the
    /// handler's `///` doc, captured by the `#[msg]` macro. Empty when
    /// undocumented. Trailing `.vos_meta` section; old blobs decode empty.
    pub doc: &'static str,
    /// Per-handler invoke timeout in milliseconds; `0` = the client's
    /// default. Set with `#[msg(timeout_ms = N)]` for handlers that
    /// legitimately run past the default (a minutes-long prove/measure).
    /// Trailing section; old blobs decode `0`.
    pub timeout_ms: u32,
    /// Dispatch mode: `0` = sync (the reply is the result), `1` = job (the
    /// handler is a `#[msg(job)]` *begin* returning a `u64` job id; the
    /// dispatcher then drives poll → stream → release). Trailing section;
    /// old blobs decode `0`.
    pub mode: u8,
}

/// Actor descriptor — actor name, messages, and constructor params.
pub struct ActorMeta {
    pub actor_name: &'static str,
    pub messages: &'static [MessageMeta],
    pub constructor: &'static [FieldMeta],
    /// Extension kind discriminant, encoded as a `u8`. Mirrors
    /// [`crate::extension::ExtensionKind`]: `0 = Actor`, `1 =
    /// Service`. PVM actors emit `0` — services are a host-side
    /// concept; a PVM actor running inside the deterministic
    /// universe is always `Actor`.
    pub kind: u8,
    /// Capability tokens the extension wants to use — declarative
    /// only, not enforced. Logged at load time so manifest reviewers
    /// can spot a sketchy install. Conventional strings:
    /// `net.tcp.bind`, `net.tcp.connect`, `fs.read:/etc/...`,
    /// `tokio-runtime`, `thread.spawn`. PVM actors leave this empty
    /// — they live in the deterministic universe and have no OS
    /// access by construction.
    pub caps: &'static [&'static str],
    /// Names of `#[msg]` handlers that should be reachable via
    /// the `vosx <ext> <cmd>` CLI dispatcher. Subset of `messages`
    /// by name. Declared on each handler with `#[msg(cli)]` and
    /// emitted by the actor macro; the registry serves the same
    /// blob so `vosx` can extend clap from cached schemas.
    pub cli_methods: &'static [&'static str],
    /// One-line actor description — the first paragraph of the actor
    /// struct's `///` doc, threaded through `Actor::DOC` by the macro.
    /// Empty when undocumented. Trailing section; old blobs decode empty.
    pub doc: &'static str,
    /// Whether this program was declared with `#[actor(crdt)]` and may
    /// therefore be installed with CRDT consistency.  Ordinary actors must
    /// use Ephemeral, Local, or Raft storage.
    pub crdt: bool,
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

    // Extension kind discriminant. Trailing byte so older decoders
    // that don't read it parse cleanly — they fall off the end of the
    // buffer and ParsedMeta defaults to Actor.
    buf[pos] = meta.kind;
    pos += 1;

    // Capability list. Same trailing-append discipline: older
    // decoders stop here and read an empty caps list.
    let [lo, hi] = (meta.caps.len() as u16).to_le_bytes();
    buf[pos] = lo;
    buf[pos + 1] = hi;
    pos += 2;
    let mut k = 0;
    while k < meta.caps.len() {
        let cap_bytes = meta.caps[k].as_bytes();
        let [lo, hi] = (cap_bytes.len() as u16).to_le_bytes();
        buf[pos] = lo;
        buf[pos + 1] = hi;
        pos += 2;
        let mut i = 0;
        while i < cap_bytes.len() {
            buf[pos + i] = cap_bytes[i];
            i += 1;
        }
        pos += cap_bytes.len();
        k += 1;
    }

    // CLI-exposed method names. Same trailing-append discipline:
    // older decoders stop after caps and every
    // `ParsedMessage.exposed_to_cli` stays `false`. Cross-reference
    // by name (rather than a per-message flag inline with the
    // existing record) keeps the existing per-message wire format
    // untouched — adding a byte mid-record would break every
    // older decoder.
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

    // Per-message return-type names. Same trailing-append discipline:
    // one entry per message in message order, so a decoder
    // cross-references by index. Blobs produced before this section
    // simply stop after cli_methods and every `ParsedMessage.returns`
    // defaults to the empty string.
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

    // Per-message doc strings. One entry per message in order,
    // index-crossref like `returns`. Older blobs stop after `returns`
    // and every `ParsedMessage.doc` is empty.
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

    // Actor-level doc string. A single length-prefixed string.
    // Absent → `ParsedMeta.doc` empty.
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

    // Per-message invoke timeouts, u32 LE each, one per message in
    // order. Absent → every `ParsedMessage.timeout_ms` stays 0.
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

    // Per-message dispatch mode, one u8 per message in order.
    // `0` = sync, `1` = job. Absent → every `ParsedMessage.mode` is 0 (sync).
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

    // Actor replication model. Appended so pre-v2 metadata remains readable,
    // but it defaults to `false` and therefore can never opt into CRDT mode.
    buf[pos] = meta.crdt as u8;
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
                },
            ],
            constructor: &[FieldMeta {
                name: "start",
                ty: "u32",
            }],
            kind: 0,
            caps: &[],
            cli_methods: &[],
            doc: "",
            crdt: false,
        };

        let (buf, len) = encode::<256>(&META);
        let parsed = decode(&buf[..len]).expect("decode failed");

        assert_eq!(parsed.actor_name, "Counter");
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.messages[0].name, "run");
        assert!(!parsed.messages[0].is_query);
        assert!(parsed.messages[0].fields.is_empty());
        assert_eq!(parsed.messages[0].returns, "()");
        assert_eq!(parsed.messages[1].name, "status");
        assert!(parsed.messages[1].is_query);
        assert_eq!(parsed.messages[1].fields.len(), 1);
        assert_eq!(parsed.messages[1].fields[0].name, "verbose");
        assert_eq!(parsed.messages[1].fields[0].ty, "bool");
        assert_eq!(parsed.messages[1].returns, "[u8;32]");
        assert_eq!(parsed.constructor.len(), 1);
        assert_eq!(parsed.constructor[0].name, "start");
        assert_eq!(parsed.constructor[0].ty, "u32");
        assert_eq!(parsed.kind, 0);
    }

    #[test]
    fn kind_byte_roundtrips_for_service() {
        const META: ActorMeta = ActorMeta {
            actor_name: "Gateway",
            messages: &[],
            constructor: &[],
            kind: 1, // Service
            caps: &[],
            cli_methods: &[],
            doc: "",
            crdt: false,
        };
        let (buf, len) = encode::<128>(&META);
        let parsed = decode(&buf[..len]).expect("decode");
        assert_eq!(parsed.kind, 1);
    }

    #[test]
    fn crdt_opt_in_roundtrips_and_legacy_defaults_off() {
        const META: ActorMeta = ActorMeta {
            actor_name: "Board",
            messages: &[],
            constructor: &[],
            kind: 0,
            caps: &[],
            cli_methods: &[],
            doc: "",
            crdt: true,
        };
        let (buf, len) = encode::<128>(&META);
        assert!(decode(&buf[..len]).unwrap().crdt);
        assert!(!decode(&buf[..len - 1]).unwrap().crdt);
    }

    #[test]
    fn kind_byte_defaults_to_actor_when_missing() {
        // Manually craft a meta blob without the trailing kind byte
        // (simulates an older ELF). actor_name "X", 0 messages,
        // 0 constructor fields. No kind byte.
        let blob: &[u8] = &[
            1, 0,    // actor_name_len = 1
            b'X', // actor_name
            0, 0, // msg_count = 0
            0, 0, // ctor_count = 0
               // no kind byte
        ];
        let parsed = decode(blob).expect("decode");
        assert_eq!(parsed.actor_name, "X");
        assert_eq!(parsed.kind, 0);
        assert!(parsed.caps.is_empty());
    }

    #[test]
    fn caps_roundtrip() {
        const META: ActorMeta = ActorMeta {
            actor_name: "Gateway",
            messages: &[],
            constructor: &[],
            kind: 1,
            caps: &["net.tcp.bind", "net.tcp.connect", "tokio-runtime"],
            cli_methods: &[],
            doc: "",
            crdt: false,
        };
        let (buf, len) = encode::<512>(&META);
        let parsed = decode(&buf[..len]).expect("decode");
        assert_eq!(parsed.kind, 1);
        assert_eq!(
            parsed.caps,
            vec![
                "net.tcp.bind".to_string(),
                "net.tcp.connect".to_string(),
                "tokio-runtime".to_string(),
            ],
        );
    }

    #[test]
    fn caps_empty_when_older_blob_missing_section() {
        // Older blob: name + msg_count=0 + ctor_count=0 +
        // kind=1, no trailing caps section.
        let blob: &[u8] = &[
            1, 0,    // name_len = 1
            b'Y', // name
            0, 0, // msg_count = 0
            0, 0, // ctor_count = 0
            1, // kind = Service
               // no caps section
        ];
        let parsed = decode(blob).expect("decode");
        assert_eq!(parsed.actor_name, "Y");
        assert_eq!(parsed.kind, 1);
        assert!(parsed.caps.is_empty());
    }

    #[test]
    fn cli_methods_roundtrip_and_cross_reference() {
        const META: ActorMeta = ActorMeta {
            actor_name: "Gateway",
            messages: &[
                MessageMeta {
                    name: "stop",
                    is_query: false,
                    fields: &[],
                    returns: "()",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                },
                MessageMeta {
                    name: "status",
                    is_query: true,
                    fields: &[],
                    returns: "String",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                },
                MessageMeta {
                    name: "internal_only",
                    is_query: false,
                    fields: &[],
                    returns: "()",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                },
            ],
            constructor: &[],
            kind: 1,
            caps: &[],
            cli_methods: &["stop", "status"],
            doc: "",
            crdt: false,
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
    fn cli_methods_absent_in_older_blob_defaults_false() {
        // Older blob: walks through messages, ctor,
        // kind, caps — stops cleanly without the cli_methods
        // section. Decoder must default `exposed_to_cli=false`
        // on every parsed message rather than panicking.
        let blob: &[u8] = &[
            1, 0,    // name_len = 1
            b'Z', // name
            1, 0, // msg_count = 1
            3, 0, b'r', b'u', b'n', // msg name "run"
            0,    // is_query = false
            0, 0, // field_count = 0
            0, 0, // ctor_count = 0
            0, // kind = Actor
            0, 0, // caps_count = 0
               // no cli_methods section
        ];
        let parsed = decode(blob).expect("decode");
        assert_eq!(parsed.messages.len(), 1);
        assert!(!parsed.messages[0].exposed_to_cli);
    }

    #[test]
    fn service_main_layout_with_cli_decodes() {
        // Hand-craft the exact byte layout the `service_main!` macro
        // emits for `service_main!(Gateway, caps = ["x"], cli = [stop, status])`.
        // Each CLI handler shows up as a 0-arg / !is_query message AND
        // as a `cli_methods` entry — the decoder cross-references the
        // two so `ParsedMessage.exposed_to_cli` flips on for both.
        let blob: &[u8] = &[
            // actor name "Gateway"
            7, 0, b'G', b'a', b't', b'e', b'w', b'a', b'y', // msg_count = 2
            2, 0, // msg 0: "stop", !is_query, 0 fields
            4, 0, b's', b't', b'o', b'p', 0, // is_query = false
            0, 0, // field_count = 0
            // msg 1: "status", !is_query, 0 fields
            6, 0, b's', b't', b'a', b't', b'u', b's', 0, // is_query = false
            0, 0, // field_count = 0
            // ctor_count = 0
            0, 0, // kind = 1 (Service)
            1, // caps_count = 1, "x"
            1, 0, 1, 0, b'x', // cli_methods_count = 2, "stop", "status"
            2, 0, 4, 0, b's', b't', b'o', b'p', 6, 0, b's', b't', b'a', b't', b'u', b's',
        ];
        let parsed = decode(blob).expect("decode");
        assert_eq!(parsed.actor_name, "Gateway");
        assert_eq!(parsed.kind, 1);
        assert_eq!(parsed.caps, vec!["x".to_string()]);
        assert_eq!(parsed.messages.len(), 2);
        let stop = parsed
            .messages
            .iter()
            .find(|m| m.name == "stop")
            .expect("stop");
        let status = parsed
            .messages
            .iter()
            .find(|m| m.name == "status")
            .expect("status");
        assert!(stop.exposed_to_cli);
        assert!(status.exposed_to_cli);
        assert!(stop.fields.is_empty());
        assert!(status.fields.is_empty());
    }

    #[test]
    fn docs_and_timeout_roundtrip() {
        // Metadata v2: per-message docs, actor doc, and per-message
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
                },
                MessageMeta {
                    name: "status",
                    is_query: true,
                    fields: &[],
                    returns: "u8",
                    doc: "",
                    timeout_ms: 0,
                    mode: 0,
                },
            ],
            constructor: &[],
            kind: 0,
            caps: &[],
            cli_methods: &["prove"],
            doc: "A pure-PVM prover/verifier.",
            crdt: false,
        };
        let (buf, len) = encode::<512>(&META);
        let parsed = decode(&buf[..len]).expect("decode");
        assert_eq!(parsed.doc, "A pure-PVM prover/verifier.");
        assert_eq!(parsed.messages[0].doc, "Enqueue a prove job.");
        assert_eq!(parsed.messages[0].timeout_ms, 600_000);
        assert_eq!(parsed.messages[0].mode, 1, "job-mode handler round-trips");
        assert_eq!(parsed.messages[1].doc, "");
        assert_eq!(parsed.messages[1].timeout_ms, 0);
        assert_eq!(parsed.messages[1].mode, 0, "sync handler stays mode 0");
        // Earlier sections still decode alongside the new ones.
        assert_eq!(parsed.messages[0].returns, "u64");
        assert!(parsed.messages[0].exposed_to_cli);
    }

    #[test]
    fn metadata_v2_sections_absent_default_empty_and_zero() {
        // A blob that stops after the `returns` section (pre-metadata-v2)
        // must still decode, with docs empty and timeouts 0. Layout:
        // name "W", 1 msg "run" (!query, 0 fields), 0 ctor, kind 0,
        // 0 caps, 0 cli, then a returns section [count=1]["u64"].
        let blob: &[u8] = &[
            1, 0, b'W', // actor name "W"
            1, 0, // msg_count = 1
            3, 0, b'r', b'u', b'n', // msg name "run"
            0,    // is_query = false
            0, 0, // field_count = 0
            0, 0, // ctor_count = 0
            0, // kind = Actor
            0, 0, // caps_count = 0
            0, 0, // cli_methods_count = 0
            1, 0, // returns_count = 1
            3, 0, b'u', b'6',
            b'4', // returns[0] = "u64"
                  // no doc / actor-doc / timeout sections
        ];
        let parsed = decode(blob).expect("decode");
        assert_eq!(parsed.doc, "");
        assert_eq!(parsed.messages.len(), 1);
        assert_eq!(parsed.messages[0].returns, "u64");
        assert_eq!(parsed.messages[0].doc, "");
        assert_eq!(parsed.messages[0].timeout_ms, 0);
        assert_eq!(parsed.messages[0].mode, 0);
    }
}

/// Parsed metadata + the `decode` / `from_elf` / `raw_section_from_elf`
/// entry points. Self-contained against `alloc` only — no std APIs.
/// Re-exported from `vos::metadata` so it's reachable from both the
/// host (where `vosx` registers schemas) and extensions like
/// `http-gateway` whose cdylib build runs `default-features = false`.
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
        /// `true` if the binary's trailing `cli_methods` section
        /// names this handler. Empty / absent section → `false`
        /// across the board (binary predates the CLI dispatch
        /// surface). Used by `vosx <ext> <cmd>` to filter the
        /// handler list to those exposed to the CLI.
        pub exposed_to_cli: bool,
        /// Declared return type (whitespace-free, `Result` unwrapped).
        /// Empty when the blob predates the `returns` section. The CLI
        /// and gateway use it to label an otherwise-opaque reply.
        pub returns: String,
        /// One-line handler description. Empty when the blob predates
        /// the doc section or the handler is undocumented.
        pub doc: String,
        /// Per-handler invoke timeout in milliseconds; `0` = the
        /// client's default. Empty/old blobs decode `0`.
        pub timeout_ms: u32,
        /// Dispatch mode: `0` = sync (the reply is the result), `1` =
        /// job (the handler is a `#[msg(job)]` begin). Empty/old blobs
        /// decode `0`.
        pub mode: u8,
    }

    /// Parsed actor metadata from binary metadata.
    #[derive(Debug, Clone)]
    pub struct ParsedMeta {
        pub actor_name: String,
        pub messages: Vec<ParsedMessage>,
        pub constructor: Vec<ParsedField>,
        /// Extension kind byte (0 = Actor, 1 = Service). Decoded
        /// from the trailing byte of the meta blob; absent / unknown
        /// values default to `Actor`.
        pub kind: u8,
        /// Declared capability tokens. Empty when the blob predates
        /// the field.
        pub caps: Vec<String>,
        /// One-line actor description. Empty when the blob predates
        /// the doc section or the actor is undocumented.
        pub doc: String,
        /// True only for programs explicitly compiled with `#[actor(crdt)]`.
        pub crdt: bool,
    }

    /// Decode binary metadata from a `.vos_meta` section.
    pub fn decode(data: &[u8]) -> Option<ParsedMeta> {
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
                // post-caps block below.
                exposed_to_cli: false,
                // Filled in from the trailing `returns` section.
                returns: String::new(),
                // Filled in from the metadata-v2 doc / timeout / mode sections.
                doc: String::new(),
                timeout_ms: 0,
                mode: 0,
            });
        }

        // Constructor fields (optional — backward compat with old ELFs)
        let mut constructor = Vec::new();
        if pos < data.len()
            && let Some(ctor_count) = read_u16(data, &mut pos)
        {
            for _ in 0..ctor_count as usize {
                let fname = read_str(data, &mut pos)?;
                let fty = read_str(data, &mut pos)?;
                constructor.push(ParsedField {
                    name: fname,
                    ty: fty,
                });
            }
        }

        // Extension kind byte (optional — older ELFs lack it, default
        // to Actor). Trailing position so older decoders simply stop
        // before reaching it.
        let kind = data.get(pos).copied().unwrap_or(0);
        if pos < data.len() {
            pos += 1;
        }

        // Capability list. Empty if absent.
        let mut caps: Vec<String> = Vec::new();
        if pos < data.len()
            && let Some(cap_count) = read_u16(data, &mut pos)
        {
            for _ in 0..cap_count as usize {
                if let Some(s) = read_str(data, &mut pos) {
                    caps.push(s);
                } else {
                    break;
                }
            }
        }

        // CLI-exposed method names. Trailing-append: older blobs
        // stop after caps and every `ParsedMessage.exposed_to_cli` stays
        // `false`. Cross-reference by name rather than by index so the
        // per-message wire format stays unchanged — adding a flag
        // inline would break older decoders.
        if pos < data.len()
            && let Some(cli_count) = read_u16(data, &mut pos)
        {
            for _ in 0..cli_count as usize {
                let Some(name) = read_str(data, &mut pos) else {
                    break;
                };
                if let Some(msg) = messages.iter_mut().find(|m| m.name == name) {
                    msg.exposed_to_cli = true;
                }
            }
        }

        // Per-message return-type names. Cross-referenced by
        // index — the encoder writes one entry per message in order.
        // Trailing-append: an absent section leaves every `returns` empty.
        if pos < data.len()
            && let Some(ret_count) = read_u16(data, &mut pos)
        {
            for i in 0..ret_count as usize {
                let Some(ty) = read_str(data, &mut pos) else {
                    break;
                };
                if let Some(msg) = messages.get_mut(i) {
                    msg.returns = ty;
                }
            }
        }

        // Per-message doc strings. Index-crossref like
        // `returns`. Absent → every `doc` empty.
        if pos < data.len()
            && let Some(doc_count) = read_u16(data, &mut pos)
        {
            for i in 0..doc_count as usize {
                let Some(doc) = read_str(data, &mut pos) else {
                    break;
                };
                if let Some(msg) = messages.get_mut(i) {
                    msg.doc = doc;
                }
            }
        }

        // Actor-level doc string. A single string; absent → empty.
        let mut doc = String::new();
        if pos < data.len()
            && let Some(s) = read_str(data, &mut pos)
        {
            doc = s;
        }

        // Per-message invoke timeouts, u32 LE each,
        // index-crossref. Absent → every `timeout_ms` stays 0.
        if pos < data.len()
            && let Some(to_count) = read_u16(data, &mut pos)
        {
            for i in 0..to_count as usize {
                let Some(ms) = read_u32(data, &mut pos) else {
                    break;
                };
                if let Some(msg) = messages.get_mut(i) {
                    msg.timeout_ms = ms;
                }
            }
        }

        // Per-message dispatch mode, one u8 each,
        // index-crossref. Absent → every `mode` stays 0 (sync).
        if pos < data.len()
            && let Some(mode_count) = read_u16(data, &mut pos)
        {
            for i in 0..mode_count as usize {
                let Some(&m) = data.get(pos) else {
                    break;
                };
                pos += 1;
                if let Some(msg) = messages.get_mut(i) {
                    msg.mode = m;
                }
            }
        }

        let crdt = data.get(pos).copied().unwrap_or(0) == 1;

        Some(ParsedMeta {
            actor_name,
            messages,
            constructor,
            kind,
            caps,
            doc,
            crdt,
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
    /// opaquely keyed by program hash. The registry then serves
    /// the same bytes back to consumers (the gateway, CLIs) which
    /// run `decode` to get a `ParsedMeta`. Skipping decode here
    /// keeps the registry schema-agnostic across vos versions —
    /// only the encoder and the consumer need to agree.
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
