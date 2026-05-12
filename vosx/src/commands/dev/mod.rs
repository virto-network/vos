//! `vosx dev *` — develop, compile, and publish PVM actors from
//! source held in a dev-project actor's commit DAG.
//!
//! Three pieces of plumbing have to be in place before these
//! commands work end-to-end:
//!
//! 1. The space is `up` and reachable via its daemon endpoint.
//! 2. The space's manifest loaded the dev extension (`[[extension]]
//!    name = "dev" path = "…"`). The extension provides the
//!    compile/publish dispatch handlers `dev compile`/`dev publish`
//!    call into.
//! 3. A dev-project actor instance exists under each project name.
//!    `vosx dev new <name>` provisions it by auto-publishing the
//!    bundled `dev-project` program and installing an instance.
//!
//! Once those are set up, the agent (or a human) writes source via
//! `put_blob` + `commit` on the project actor, drives `dev compile`
//! to produce a PVM blob, and `dev publish` to register it with
//! the space-registry. `dev log` shows the commit graph.

use clap::Subcommand;

pub mod compile;
pub mod log;
pub mod merge;
pub mod new;
pub mod publish;
pub mod show;

#[derive(Subcommand, Debug)]
pub enum DevCommand {
    /// Provision a new dev-project actor instance.
    /// Auto-publishes the bundled `dev-project` program if it
    /// isn't already in the catalog, then installs an instance
    /// under `<name>`.
    New {
        /// Space id (full hex) or name.
        #[arg(long)]
        space: String,
        /// Local name for the project instance. Used by every
        /// subsequent `dev *` command.
        name: String,
        /// Override the per-space replication id (64 hex).
        /// Defaults to auto-derived from instance_name +
        /// program_hash, matching `vosx space install`.
        #[arg(long, value_name = "HEX")]
        replication_id: Option<String>,
    },
    /// Compile the named project's tree at `--commit` (or its
    /// current `main` branch head if `--commit` is omitted) into
    /// a PVM blob. Records the result as a commit on the
    /// project's `builds` branch and prints the build commit's
    /// hash.
    Compile {
        /// Space id (full hex) or name.
        #[arg(long)]
        space: String,
        /// Project instance name (the one passed to `dev new`).
        name: String,
        /// Source commit hash (64 hex). Defaults to the project's
        /// current `main` branch head.
        #[arg(long, value_name = "HEX")]
        commit: Option<String>,
    },
    /// Publish the project's latest successful build under
    /// `(program_name, version)` in the space-registry. Records
    /// the result as a commit on the project's `publishes`
    /// branch and prints the publish commit's hash.
    Publish {
        /// Space id (full hex) or name.
        #[arg(long)]
        space: String,
        /// Project instance name.
        name: String,
        /// Program name to register (e.g. `counter`).
        program_name: String,
        /// Program version (e.g. `0.1.0`).
        version: String,
        /// Optional explicit build commit hash to publish. By
        /// default we use the head of the project's `builds`
        /// branch — i.e. the most recent build attempt. Use this
        /// to publish an older build deliberately.
        #[arg(long, value_name = "HEX")]
        build_commit: Option<String>,
    },
    /// Walk the project's commit graph along `--branch` (default
    /// `main`) and print the hashes newest-first. Same shape as
    /// `git log --oneline`, capped at `--limit` entries.
    Log {
        /// Space id (full hex) or name.
        #[arg(long)]
        space: String,
        /// Project instance name.
        name: String,
        /// Branch to walk. Common choices: `main` (source edits),
        /// `builds` (compile attempts), `publishes` (catalog
        /// publishes).
        #[arg(long, default_value = "main")]
        branch: String,
        /// Maximum number of commits to surface.
        #[arg(long, default_value_t = 16)]
        limit: u32,
    },
    /// Promote a side branch into another branch by invoking
    /// the dev-project actor's `merge` handler. Defaults match
    /// the side-branch AI workflow: pull commits from
    /// `ai-suggested` into `main`.
    ///
    /// Fast-forward is preferred when the source branch is a
    /// descendant of the target; otherwise the actor runs a
    /// true three-way merge and records per-path conflicts on
    /// the resulting commit. Conflicts don't fail the merge —
    /// `ours`'s blob is the tentative pick and the operator
    /// resolves by committing the chosen content at the same
    /// path.
    Merge {
        /// Space id (full hex) or name.
        #[arg(long)]
        space: String,
        /// Project instance name.
        #[arg(long)]
        project: String,
        /// Source branch to merge from.
        #[arg(long, default_value = "ai-suggested")]
        from: String,
        /// Target branch to advance.
        #[arg(long, default_value = "main")]
        into: String,
    },
    /// Inspect a project's tree at a commit.
    ///
    /// Without `<PATH>` prints the file list (path, size, blob
    /// hash prefix) on the chosen branch's head. With `<PATH>`
    /// dumps that file's bytes to stdout so `vosx dev show
    /// --project P src/lib.rs > local.rs` works for local edits.
    ///
    /// `--commit` overrides the branch lookup when you want to
    /// inspect a specific historical commit.
    Show {
        /// Space id (full hex) or name.
        #[arg(long)]
        space: String,
        /// Project instance name.
        #[arg(long)]
        project: String,
        /// Optional path within the tree. Omit to list the whole
        /// tree.
        path: Option<String>,
        /// Branch to read from. Default `main`.
        #[arg(long, default_value = "main")]
        branch: String,
        /// Specific commit hex to inspect. Overrides `--branch`.
        #[arg(long, value_name = "HEX")]
        commit: Option<String>,
    },
}

pub fn run(cmd: DevCommand) -> anyhow::Result<()> {
    match cmd {
        DevCommand::New {
            space,
            name,
            replication_id,
        } => new::run(new::Args {
            space,
            name,
            replication_id,
        }),
        DevCommand::Compile {
            space,
            name,
            commit,
        } => compile::run(compile::Args {
            space,
            name,
            commit,
        }),
        DevCommand::Publish {
            space,
            name,
            program_name,
            version,
            build_commit,
        } => publish::run(publish::Args {
            space,
            name,
            program_name,
            version,
            build_commit,
        }),
        DevCommand::Log {
            space,
            name,
            branch,
            limit,
        } => log::run(log::Args {
            space,
            name,
            branch,
            limit,
        }),
        DevCommand::Show {
            space,
            project,
            path,
            branch,
            commit,
        } => show::run(show::Args {
            space,
            project,
            path,
            branch,
            commit,
        }),
        DevCommand::Merge {
            space,
            project,
            from,
            into,
        } => merge::run(merge::Args {
            space,
            project,
            from,
            into,
        }),
    }
}
