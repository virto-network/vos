//! `space describe <agent>` — pretty-print the actor schema the
//! registry has on file. Operator-facing mirror of built-in HTTP ingress's
//! `GET /__schema/<agent>` endpoint, using the same wire path
//! (`meta_for_instance` on the registry) and rendering logic.
//!
//! Output modes:
//!   - default: aligned columns, one line per message and one
//!     "name: type" pair per arg.
//!   - `--format json`: emits the same JSON shape HTTP ingress's
//!     `/__schema/<agent>` returns, suitable for piping to `jq`
//!     or feeding into a code generator.

use crate::commands::space::client::DaemonClient;
use crate::output;
use anyhow::anyhow;
use serde::Serialize;
use vos::metadata::{ParsedMeta, decode};

#[derive(Serialize)]
struct FieldView<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    ty: &'a str,
}

#[derive(Serialize)]
struct MessageView<'a> {
    name: &'a str,
    is_query: bool,
    fields: Vec<FieldView<'a>>,
    /// `true` when the producer declared this handler via
    /// `#[msg(cli)]` (actor mode) or in `cli = [...]`
    /// (`service_main!`). Mirrors the wire-side
    /// `ParsedMessage.exposed_to_cli` so a JSON consumer
    /// (`vosx <ext> <cmd>` schema cache, IDE tooling, etc.)
    /// sees which surface is intended for the CLI.
    exposed_to_cli: bool,
}

#[derive(Serialize)]
struct MetaView<'a> {
    actor_name: &'a str,
    messages: Vec<MessageView<'a>>,
    constructor: Vec<FieldView<'a>>,
    /// Effective relay `intra_caps` (`"actor:role"` tokens) the
    /// *running daemon* loaded for this instance — distinct from
    /// `caps`. `None` when the instance isn't a service extension this
    /// daemon configured; `Some([])` means it relays everything as
    /// Unauthenticated (no relay authority).
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_caps: Option<Vec<String>>,
    /// `#[actor(task, provable)]` publication mark — this Task is
    /// meant to be pinned/proved. Omitted when false.
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    provable: bool,
}

impl<'a> From<&'a ParsedMeta> for MetaView<'a> {
    fn from(m: &'a ParsedMeta) -> Self {
        Self {
            actor_name: &m.actor_name,
            messages: m
                .messages
                .iter()
                .map(|msg| MessageView {
                    name: &msg.name,
                    is_query: msg.is_query,
                    fields: msg
                        .fields
                        .iter()
                        .map(|f| FieldView {
                            name: &f.name,
                            ty: &f.ty,
                        })
                        .collect(),
                    exposed_to_cli: msg.exposed_to_cli,
                })
                .collect(),
            constructor: m
                .constructor
                .iter()
                .map(|f| FieldView {
                    name: &f.name,
                    ty: &f.ty,
                })
                .collect(),
            // Filled in by `run` from the daemon's endpoint descriptor;
            // ParsedMeta (registry schema) doesn't carry relay caps.
            relay_caps: None,
            provable: m.provable,
        }
    }
}

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        // The registry joins agents and extension instances internally, so a
        // non-empty blob proves that an installed target owns the name.
        let blob = client.meta_for_instance(instance)?;
        if blob.is_empty() {
            if client.agent(instance)?.is_none() {
                return Err(anyhow!(
                    "no agent or extension named '{instance}' in this \
                     space (use `vosx space agents <space>` to list)"
                ));
            }
            return Err(anyhow!(
                "no schema registered for '{instance}'; reinstall or repair \
                 the target package"
            ));
        }
        let meta = decode(&blob).ok_or_else(|| {
            anyhow!("schema blob for '{instance}' failed to decode (corrupt or schema-drifted)")
        })?;

        // Effective relay caps the running daemon loaded for this
        // instance (None if it's not a service extension this daemon
        // configured). Read from the endpoint descriptor the client
        // already fetched on connect — daemon-local host policy, not
        // replicated registry state.
        let relay_caps = client
            .endpoint
            .extensions
            .iter()
            .find(|e| e.name == instance)
            .map(|e| e.caps.clone());

        if output::is_json() {
            let mut view = MetaView::from(&meta);
            view.relay_caps = relay_caps;
            output::print_json(&view);
            return Ok(());
        }

        // Text mode — one block per actor + per-method indent.
        println!("actor:  {}", meta.actor_name);
        if let Some(caps) = &relay_caps {
            let rendered = if caps.is_empty() {
                "(none — relays as Unauthenticated)".to_string()
            } else {
                caps.join(", ")
            };
            println!("relay caps: {rendered}");
        }
        if !meta.constructor.is_empty() {
            println!("constructor:");
            for f in &meta.constructor {
                println!("  {}: {}", f.name, f.ty);
            }
        }
        if meta.messages.is_empty() {
            println!("(no #[msg] handlers)");
            return Ok(());
        }
        println!("messages:");
        for msg in &meta.messages {
            // Tags are space-separated; `(query)` and `(cli)`
            // compose so a CLI-exposed query handler shows both.
            let mut tags = String::new();
            if msg.is_query {
                tags.push_str(" (query)");
            }
            if msg.exposed_to_cli {
                tags.push_str(" (cli)");
            }
            if msg.fields.is_empty() {
                println!("  {}(){tags}", msg.name);
            } else {
                let args = msg
                    .fields
                    .iter()
                    .map(|f| format!("{}: {}", f.name, f.ty))
                    .collect::<Vec<_>>()
                    .join(", ");
                println!("  {}({args}){tags}", msg.name);
            }
        }
        Ok(())
    })
}
