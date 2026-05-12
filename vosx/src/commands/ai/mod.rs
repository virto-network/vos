//! `vosx ai *` — drive the AI extension's `generate` handler.
//!
//! Three pieces of plumbing have to be in place first:
//!
//! 1. The space is `up` and reachable via its daemon endpoint.
//! 2. The manifest loaded the AI extension (`[[extension]]
//!    name = "ai" path = "…"`), optionally with `init = { … }`
//!    overrides for model_repo / model_file / etc.
//! 3. The host has network access — the first `generate` call
//!    pulls the model GGUF + tokenizer.json from HuggingFace
//!    into `$XDG_CACHE_HOME/vos-ai/hf/`. Subsequent calls reuse
//!    the cache.
//!
//! The CLI itself stays thin: argument parsing, daemon dial,
//! single invoke, decoded text to stdout. All the model-loading
//! and inference logic lives in the extension.

use clap::Subcommand;

pub mod actor;
pub mod generate;

#[derive(Subcommand, Debug)]
pub enum AiCommand {
    /// Run a prompt through the AI extension's loaded model and
    /// print the completion to stdout. The model loads on first
    /// use; subsequent calls are warm.
    ///
    /// By default the CLI streams tokens as the model emits them
    /// (visible incremental output, polling the extension at
    /// ~100ms). Pass `--no-stream` for the one-shot blocking
    /// shape — useful for `--format json` consumers that want a
    /// single well-formed JSON object on stdout.
    Generate {
        /// Space id (full hex) or name.
        #[arg(long)]
        space: String,
        /// The prompt text. Pass via shell quoting — multi-word
        /// prompts work as long as they're one argv element.
        prompt: String,
        /// Cap on tokens generated. Defaults match the extension
        /// (256 — enough for a few lines of code).
        #[arg(long, default_value_t = 256)]
        max_tokens: u32,
        /// Override the extension instance name. Useful when the
        /// operator loaded the same extension twice under
        /// different configs.
        #[arg(long, default_value = "ai")]
        extension: String,
        /// Skip the streaming path: send one blocking `generate`
        /// invoke and print the full completion at once. Default
        /// streams via `begin_generate` + `poll_generation`.
        /// `--format json` implies `--no-stream` because the
        /// single-object reply is what JSON consumers expect.
        #[arg(long)]
        no_stream: bool,
    },
    /// Ask the AI extension to write or modify a VOS actor's
    /// source. Pulls the project's current files out of the
    /// dev-project actor's commit DAG, stuffs them into the
    /// prompt as context, then streams the completion to stdout.
    ///
    /// Requires both the AI extension and the dev extension
    /// loaded in the space (the dev extension owns the
    /// dev-project actor instances). Provision the project with
    /// `vosx dev new` first.
    ///
    /// Default mode is read-only — the model's reply lands on
    /// stdout for inspection. Pass `--apply` to parse the
    /// fenced code blocks out of the reply and commit them back
    /// to the project's `main` branch as a new commit.
    Actor {
        /// Space id (full hex) or name.
        #[arg(long)]
        space: String,
        /// Project instance name (the one passed to `vosx dev new`).
        #[arg(long)]
        project: String,
        /// Description of what to add, change, or write. Quote
        /// it so the shell hands the whole sentence as one argv.
        prompt: String,
        /// Cap on tokens generated. Higher than `generate`'s
        /// default because a full actor file is often 100-300
        /// tokens before the model gets to anything new.
        #[arg(long, default_value_t = 512)]
        max_tokens: u32,
        /// Override the AI extension instance name.
        #[arg(long, default_value = "ai")]
        extension: String,
        /// Source commit hash (64 hex). Defaults to the project's
        /// current `main` branch head.
        #[arg(long, value_name = "HEX")]
        commit: Option<String>,
        /// Parse the model's response and write each detected
        /// file back to the project's `main` branch as a new
        /// commit. The parser looks for `path:` (or `## path`,
        /// `**path:**`) followed by a fenced code block.
        /// Without this flag the response is print-only.
        #[arg(long)]
        apply: bool,
    },
}

pub fn run(cmd: AiCommand) -> anyhow::Result<()> {
    match cmd {
        AiCommand::Generate {
            space,
            prompt,
            max_tokens,
            extension,
            no_stream,
        } => generate::run(generate::Args {
            space,
            prompt,
            max_tokens,
            extension,
            no_stream,
        }),
        AiCommand::Actor {
            space,
            project,
            prompt,
            max_tokens,
            extension,
            commit,
            apply,
        } => actor::run(actor::Args {
            space,
            project,
            prompt,
            max_tokens,
            extension,
            commit,
            apply,
        }),
    }
}
