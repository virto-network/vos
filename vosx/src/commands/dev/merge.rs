//! `vosx dev merge` — promote a side branch into another
//! branch (default `--into main`). The default `--from` matches
//! the per-identity branch `vosx ai actor` mints,
//! `ai/<your-node-prefix>/suggested`, so the common case
//! "merge what I just suggested" is one command with no flags.
//!
//! Wraps the dev-project actor's `merge(into_branch, theirs,
//! author, ts_ms)` handler. The actor does the merge logic —
//! fast-forward / already-merged short-circuits + true three-way
//! merge with first-class conflicts on the resulting commit. The
//! CLI just resolves the source branch's head, drives the call,
//! and pretty-prints the outcome.
//!
//! Conflicts don't fail the call: the actor records them on the
//! merge commit's `conflicts` field, leaving `ours`'s blobs as
//! tentative picks. The CLI surfaces the count + each conflicting
//! path so the operator knows there's resolution work; a
//! subsequent plain commit at the same path clears the conflict.

use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

use vos::Decode;
use vos::abi::service::ServiceId;
use vos::value::{Msg, Value};

use crate::commands::space::client::DaemonClient;
use crate::output;

#[derive(Serialize)]
struct MergeView<'a> {
    project: &'a str,
    from: &'a str,
    into: &'a str,
    result_commit: String,
    conflicts: Vec<ConflictView>,
    /// Whether the source branch was equal to / a descendant of
    /// the target ("FF" or no-op), so the result_commit equals
    /// either ours or theirs and no merge commit was minted.
    fast_forward: bool,
}

#[derive(Serialize)]
struct ConflictView {
    path: String,
    base: String,
    ours: String,
    theirs: String,
}

pub struct Args {
    pub space: String,
    pub project: String,
    /// When `None`, defaults to `ai/<your-node-prefix>/suggested`
    /// — matching the per-identity branch `vosx ai actor` mints
    /// by default. Pass an explicit `--from NAME` to merge a
    /// different branch (e.g. another node's `ai/06b7/suggested`
    /// in a multi-peer setup).
    pub from: Option<String>,
    pub into: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.space, |client| {
        let project_id = client.resolve_target(&args.project)?;

        // Per-identity default mirrors the ai actor command so
        // the common case "merge what I just suggested" is a
        // one-liner.
        let from = args
            .from
            .clone()
            .unwrap_or_else(|| default_ai_branch(client.daemon_prefix()));

        // Resolve the source branch's head — that's `theirs`.
        let theirs = fetch_branch_head(client, project_id, &from)?.ok_or_else(|| {
            anyhow::anyhow!(
                "source branch '{}' has no commits yet on project '{}'",
                from,
                args.project,
            )
        })?;

        // The actor's `merge` handler returns STATUS_NOT_FOUND
        // when the target branch doesn't exist — translate to a
        // clear CLI error rather than the opaque status code.
        // Also snapshots `into`'s head before the merge for the
        // FF detection below.
        let into_before = fetch_branch_head(client, project_id, &args.into)?.ok_or_else(|| {
            anyhow::anyhow!(
                "target branch '{}' doesn't exist on project '{}' — \
                 the actor's merge handler requires the target to already \
                 have at least one commit. Pick a different --into.",
                args.into,
                args.project,
            )
        })?;

        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let reply = client.invoke_dyn(
            project_id,
            &Msg::new("merge")
                .with("into_branch", args.into.clone())
                .with("theirs", theirs.clone())
                .with("author", Vec::<u8>::new())
                .with("ts_ms", ts_ms),
        )?;
        let bytes = match reply {
            Value::Bytes(b) if !b.is_empty() => b,
            Value::Bytes(_) => anyhow::bail!("merge returned empty bytes"),
            other => anyhow::bail!("merge returned {other:?}, expected Bytes"),
        };
        let result = <dev_project::HashResult as Decode>::try_decode(&bytes)
            .ok_or_else(|| anyhow::anyhow!("merge reply isn't a valid HashResult"))?;
        if result.status != dev_project::STATUS_OK {
            anyhow::bail!(
                "merge rejected: status={} (actor-side; see dev_project::STATUS_*)",
                result.status,
            );
        }
        if result.hash.len() != 32 {
            anyhow::bail!("merge returned hash of wrong length: {}", result.hash.len());
        }

        // FF detection via the *actual* signal the actor uses:
        // a real merge commit has `extras = [theirs]`, while FF
        // and already-merged short-circuit paths skip minting a
        // new commit. We fetch the result commit's `extras` (and
        // `conflicts` if it IS a merge) in one round-trip.
        let result_commit = fetch_commit(client, project_id, &result.hash)?;
        let fast_forward = result_commit.extras.is_empty();
        let conflicts = if fast_forward {
            // Sanity check: on FF/no-op the result hash should
            // equal either theirs (FF advance) or into_before
            // (no-op already-merged).
            debug_assert!(
                result.hash == theirs || result.hash == into_before,
                "FF result hash didn't match theirs or into_before"
            );
            Vec::new()
        } else {
            result_commit.conflicts
        };

        emit(&args, &from, &result.hash, fast_forward, conflicts)?;
        Ok(())
    })
}

/// Print the merge result to stdout in either text or JSON mode.
fn emit(
    args: &Args,
    from: &str,
    result_hash: &[u8],
    fast_forward: bool,
    conflicts: Vec<dev_project::ConflictEntry>,
) -> anyhow::Result<()> {
    let result_hex = hex::encode(result_hash);
    let conflict_views: Vec<ConflictView> = conflicts
        .iter()
        .map(|c| ConflictView {
            path: c.path.clone(),
            base: hex::encode(c.base),
            ours: hex::encode(c.ours),
            theirs: hex::encode(c.theirs),
        })
        .collect();

    if output::is_json() {
        output::print_json(&MergeView {
            project: &args.project,
            from,
            into: &args.into,
            result_commit: result_hex.clone(),
            conflicts: conflict_views,
            fast_forward,
        });
        return Ok(());
    }

    if fast_forward {
        println!(
            "fast-forwarded '{}' to {} (from '{}')",
            args.into,
            &result_hex[..16],
            from,
        );
    } else if conflicts.is_empty() {
        println!(
            "merged '{}' into '{}'\n  result_commit = {}",
            from, args.into, result_hex,
        );
    } else {
        println!(
            "merged '{}' into '{}' with {} conflict(s)\n  result_commit = {}",
            from,
            args.into,
            conflicts.len(),
            result_hex,
        );
        println!("  conflicts (ours' blob kept as tentative pick):");
        for c in &conflicts {
            println!(
                "    {}\n      base={}\n      ours={}\n      theirs={}",
                c.path,
                short_hex(&c.base),
                short_hex(&c.ours),
                short_hex(&c.theirs),
            );
        }
        println!(
            "  resolve each conflicting path with a plain put_blob + commit on '{}'",
            args.into,
        );
    }
    Ok(())
}

fn short_hex(h: &[u8; 32]) -> String {
    let s = hex::encode(h);
    s[..16].to_string()
}

fn fetch_branch_head(
    client: &DaemonClient,
    project_id: ServiceId,
    branch: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("head").with("branch", branch.to_string()),
    )?;
    let bytes = match reply {
        Value::Bytes(b) => b,
        other => anyhow::bail!("head('{branch}') returned non-bytes: {other:?}"),
    };
    if bytes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

fn fetch_commit(
    client: &DaemonClient,
    project_id: ServiceId,
    commit_hash: &[u8],
) -> anyhow::Result<dev_project::CommitNode> {
    let reply = client.invoke_dyn(
        project_id,
        &Msg::new("get_commit").with("hash", commit_hash.to_vec()),
    )?;
    let bytes = match reply {
        Value::Bytes(b) if !b.is_empty() => b,
        Value::Unit => anyhow::bail!("get_commit returned Unit — merge commit missing?"),
        other => anyhow::bail!("get_commit returned {other:?}, expected Bytes"),
    };
    <dev_project::CommitNode as Decode>::try_decode(&bytes)
        .ok_or_else(|| anyhow::anyhow!("get_commit reply isn't a valid CommitNode"))
}

/// Per-identity default branch the ai suggestion flow writes to (and `merge`
/// reads from when `--from` is omitted): `ai/<node-prefix hex>/suggested`. The
/// node prefix keeps two nodes' defaults distinct; the 4-hex zero-pad keeps the
/// name predictable.
fn default_ai_branch(daemon_prefix: u16) -> String {
    format!("ai/{daemon_prefix:04x}/suggested")
}

#[cfg(test)]
mod tests {
    use super::default_ai_branch;

    #[test]
    fn default_ai_branch_is_per_identity() {
        assert_eq!(default_ai_branch(0x06b7), "ai/06b7/suggested");
        assert_eq!(default_ai_branch(0x0001), "ai/0001/suggested");
        assert_eq!(default_ai_branch(0xffff), "ai/ffff/suggested");
    }

    #[test]
    fn default_ai_branch_zero_pads_to_four_hex_chars() {
        assert_eq!(default_ai_branch(0x0042), "ai/0042/suggested");
        assert_eq!(default_ai_branch(0), "ai/0000/suggested");
    }
}
