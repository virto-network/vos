//! `space publish` — add a program to the catalog.

use space_registry::{STATUS_OK, STATUS_TAG_CONFLICT};

use crate::blob_store::{self, BlobSource};
use crate::commands::space::client::DaemonClient;

pub struct Args {
    pub space: String,
    pub program_ref: String, // "name" or "name:version"
    pub source: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let (name, version) = parse_program_ref(&args.program_ref)?;

    // Resolve and cache the blob bytes locally.
    let source = BlobSource::parse(&args.source);
    let (hash, _bytes) = blob_store::resolve(&source)
        .map_err(|e| anyhow::anyhow!("blob: {e}"))?;

    let client = DaemonClient::connect(&args.space)?;

    let reg = client.registry();
    let status = vos::block_on(reg.publish(
        &mut &*client.node(),
        name.clone(),
        version.clone(),
        hash.0.to_vec(),
    ))
    .map_err(|e| anyhow::anyhow!("publish() failed: {e}"))?;

    match status {
        STATUS_OK => {
            println!("published {name}:{version}");
            println!("  hash = {hash}");
        }
        STATUS_TAG_CONFLICT => anyhow::bail!(
            "{name}:{version} already exists in the catalog with a different hash; \
             tags are immutable",
        ),
        other => anyhow::bail!("publish returned status {other}"),
    }

    client.shutdown()
}

/// Parse `name` or `name:version`. When version is omitted,
/// defaults to `"latest"`.
fn parse_program_ref(s: &str) -> anyhow::Result<(String, String)> {
    if let Some((n, v)) = s.split_once(':') {
        if n.is_empty() || v.is_empty() {
            anyhow::bail!("program ref '{s}' must be 'name' or 'name:version'");
        }
        Ok((n.to_string(), v.to_string()))
    } else {
        Ok((s.to_string(), "latest".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_versioned_ref() {
        assert_eq!(
            parse_program_ref("counter:1.0").unwrap(),
            ("counter".into(), "1.0".into()),
        );
    }

    #[test]
    fn parses_bare_name_to_latest() {
        assert_eq!(
            parse_program_ref("counter").unwrap(),
            ("counter".into(), "latest".into()),
        );
    }

    #[test]
    fn rejects_empty_halves() {
        assert!(parse_program_ref(":1.0").is_err());
        assert!(parse_program_ref("counter:").is_err());
    }
}
