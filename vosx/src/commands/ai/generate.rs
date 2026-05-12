//! `vosx ai generate` — single-prompt completion.

use serde::Serialize;
use vos::value::{Msg, Value};

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Serialize)]
struct CompletionView<'a> {
    prompt: &'a str,
    completion: &'a str,
    max_tokens: u32,
}

pub struct Args {
    pub space: String,
    pub prompt: String,
    pub max_tokens: u32,
    pub extension: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.space, |client| {
        let extension_id = client.resolve_target(&args.extension).map_err(|_| {
            anyhow::anyhow!(
                "no '{}' extension loaded in this space — \
                 add `[[extension]] name = \"{}\"` to the \
                 space's manifest and restart `vosx space up`",
                args.extension,
                args.extension,
            )
        })?;

        let reply = client.invoke_dyn(
            extension_id,
            &Msg::new("generate")
                .with("prompt", args.prompt.clone())
                .with("max_tokens", args.max_tokens),
        )?;

        let completion = match reply {
            Value::Str(s) => s,
            Value::Bytes(b) => String::from_utf8_lossy(&b).to_string(),
            other => anyhow::bail!("ai generate returned unexpected value: {other:?}"),
        };

        // The extension surfaces inference failures as a Str
        // beginning with "error: ". Detect + bail so the CLI exit
        // code reflects the failure rather than echoing the
        // message into stdout as if it were a completion.
        if let Some(rest) = completion.strip_prefix("error: ") {
            anyhow::bail!("ai generate failed: {rest}");
        }

        if output::is_json() {
            output::print_json(&CompletionView {
                prompt: &args.prompt,
                completion: &completion,
                max_tokens: args.max_tokens,
            });
        } else {
            print!("{completion}");
            if !completion.ends_with('\n') {
                println!();
            }
        }
        Ok(())
    })
}
