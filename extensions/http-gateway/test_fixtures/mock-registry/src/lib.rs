//! Stand-in for the bundled space-registry, used by the
//! http-gateway dispatch tests. Implements just the handlers
//! the gateway calls during a request:
//!   - `resolve(name) -> u32`             — name → ServiceId
//!   - `meta_for_instance(name) -> Vec<u8>` — schema blob
//!
//! The actor is hardcoded against the fixture install order
//! (`counter` at id 1, `kitchen` at id 2); the schema blob for
//! `kitchen` is encoded at compile time from a verbatim
//! restatement of `kitchen-sink`'s handler signatures. We can't
//! `include_bytes!` the kitchen-sink `.so`'s ELF section because
//! host-native cdylibs don't carry `.vos_meta` (it's a PVM-side
//! convention), so we hand-keep the table here. If kitchen-sink's
//! signatures change, the test fixtures get out of sync — the
//! dispatch_e2e suite's coercion-aware tests will catch that.
//!
//! Mappings:
//!   "counter" → 1, no schema (legacy permissive path)
//!   "kitchen" → 2, full schema below
//!   _         → 0 / empty  (gateway: unknown → 404)

use vos::metadata::{ActorMeta, FieldMeta, MessageMeta, encode};
use vos::prelude::*;

/// Mirror of `kitchen-sink`'s `#[messages]` block. Hand-kept;
/// see comment above.
const KITCHEN_META: ActorMeta = ActorMeta {
    actor_name: "KitchenSink",
    messages: &[
        MessageMeta {
            name: "echo",
            is_query: false,
            fields: &[FieldMeta {
                name: "text",
                ty: "String",
            }],
            returns: "String",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "last_text",
            is_query: true,
            fields: &[],
            returns: "String",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "add",
            is_query: false,
            fields: &[
                FieldMeta {
                    name: "a",
                    ty: "u32",
                },
                FieldMeta {
                    name: "b",
                    ty: "u32",
                },
            ],
            returns: "u32",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "last_sum",
            is_query: true,
            fields: &[],
            returns: "u32",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "flip",
            is_query: false,
            fields: &[FieldMeta {
                name: "b",
                ty: "bool",
            }],
            returns: "bool",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "flip_count",
            is_query: true,
            fields: &[],
            returns: "u32",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "sum_list",
            is_query: true,
            fields: &[FieldMeta {
                name: "xs",
                ty: "Vec<u32>",
            }],
            returns: "u32",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "concat",
            is_query: true,
            fields: &[FieldMeta {
                name: "parts",
                ty: "Vec<String>",
            }],
            returns: "String",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "range",
            is_query: true,
            fields: &[FieldMeta {
                name: "n",
                ty: "u32",
            }],
            returns: "Vec<u32>",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "split",
            is_query: true,
            fields: &[FieldMeta {
                name: "s",
                ty: "String",
            }],
            returns: "Vec<String>",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "ping",
            is_query: true,
            fields: &[],
            returns: "()",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
        MessageMeta {
            name: "boom",
            is_query: true,
            fields: &[],
            returns: "u32",
            doc: "",
            timeout_ms: 0,
            mode: 0,
        },
    ],
    constructor: &[],
    kind: 0,
    caps: &[],
    cli_methods: &[],
    doc: "",
};

/// Pre-encoded meta blob — same wire bytes the bundled registry's
/// `.vos_meta` section carries on PVM actors. Generated at const
/// eval; `LEN` is the actual byte count, `BUF` holds it plus
/// trailing zeros up to the fixed-size buffer.
const KITCHEN_META_ENCODED: ([u8; 1024], usize) = encode::<1024>(&KITCHEN_META);

#[actor]
#[derive(Default)]
pub struct MockRegistry;

#[messages]
impl MockRegistry {
    fn new() -> Self {
        Self
    }

    #[msg]
    async fn resolve(&self, name: String, _ctx: &mut Context<Self>) -> u32 {
        match name.as_str() {
            "counter" => 1,
            "kitchen" => 2,
            _ => 0,
        }
    }

    /// Schema-blob lookup. Returns the same wire format the
    /// production registry serves: raw `.vos_meta` section bytes.
    /// Only `kitchen` has a schema in this fixture — `counter`
    /// is intentionally schema-less so dispatch_e2e can also
    /// exercise the gateway's legacy pre-schema fallback path
    /// when no meta is available.
    #[msg]
    async fn meta_for_instance(&self, name: String, _ctx: &mut Context<Self>) -> Vec<u8> {
        match name.as_str() {
            "kitchen" => {
                let (buf, len) = KITCHEN_META_ENCODED;
                buf[..len].to_vec()
            }
            _ => Vec::new(),
        }
    }
}
