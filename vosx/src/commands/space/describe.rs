//! `space describe <agent>` — pretty-print the actor schema the
//! registry has on file. Operator-facing mirror of the gateway's
//! `GET /__schema/<agent>` endpoint, using the same wire path
//! (`meta_for_instance` on the registry) and rendering logic.
//!
//! Output modes:
//!   - default: aligned columns, one line per message and one
//!     "name: type" pair per arg.
//!   - `--format json`: emits the same JSON shape the gateway's
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
    /// (service-mode `service_main!`). Mirrors the wire-side
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
    kind: u8,
    caps: Vec<&'a str>,
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
            kind: m.kind,
            caps: m.caps.iter().map(String::as_str).collect(),
        }
    }
}

pub fn run(space: &str, instance: &str) -> anyhow::Result<()> {
    DaemonClient::with_connect(space, |client| {
        // Try the meta lookup first; the registry joins agents +
        // extension instances internally, so a non-empty blob
        // proves *some* installed thing owns the name (PVM agent
        // or native extension). When the lookup comes back empty,
        // fall back to the agent table to distinguish "name
        // unknown" from "name installed but no schema" — the
        // latter happens for older actor binaries that predate
        // schema forwarding.
        let blob = client.meta_for_instance(instance)?;
        if blob.is_empty() {
            if client.agent(instance)?.is_none() {
                return Err(anyhow!(
                    "no agent or extension named '{instance}' in this \
                     space (use `vosx space agents <space>` to list)"
                ));
            }
            return Err(anyhow!(
                "no schema registered for '{instance}'. The agent's \
                 program was likely installed before vosx started \
                 forwarding `.vos_meta` to the registry — \
                 re-`vosx space up --manifest` will refresh it."
            ));
        }
        let meta = decode(&blob).ok_or_else(|| {
            anyhow!("schema blob for '{instance}' failed to decode (corrupt or schema-drifted)")
        })?;

        if output::is_json() {
            output::print_json(&MetaView::from(&meta));
            return Ok(());
        }

        // Text mode — one block per actor + per-method indent.
        println!("actor:  {}", meta.actor_name);
        println!("kind:   {}", kind_label(meta.kind));
        if !meta.caps.is_empty() {
            println!("caps:   {}", meta.caps.join(", "));
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

fn kind_label(k: u8) -> &'static str {
    match k {
        0 => "actor",
        1 => "service",
        _ => "unknown",
    }
}
