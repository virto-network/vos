//! `jamt`, which creates services, provides preimages and submits work
//! items.

use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use vos_tree::Hash;

use super::{Node, failed};
use crate::Error;

/// How long a `jamt` command may take.
const JAMT_TIMEOUT: Duration = Duration::from_secs(300);

impl Node {
    /// Run `jamt` with `args`, for at most [`JAMT_TIMEOUT`]: what it
    /// printed, on its output and on its errors.
    fn jamt(&self, args: impl IntoIterator<Item: AsRef<OsStr>>) -> Result<(String, String), Error> {
        let args: Vec<OsString> = args
            .into_iter()
            .map(|arg| arg.as_ref().to_owned())
            .collect();
        let command = args[0].to_string_lossy().into_owned();
        let mut child = Command::new(&self.jamt)
            .arg("--rpc")
            .arg(format!("ws://{}", self.rpc))
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(failed)?;
        let until = Instant::now() + JAMT_TIMEOUT;
        while child.try_wait().map_err(failed)?.is_none() {
            if Instant::now() > until {
                let _ = child.kill();
                let _ = child.wait();
                return Err(failed(format!("jamt {command} timed out")));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let output = child.wait_with_output().map_err(failed)?;
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !output.status.success() {
            return Err(failed(format!(
                "jamt {command}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Ok((stdout, stderr))
    }

    /// Create a service of `code`, a service blob, endowed with `amount`:
    /// its id.
    pub fn create_service(&self, code: &Path, amount: u64) -> Result<u64, Error> {
        let amount = amount.to_string();
        let (printed, _) = self.jamt([
            OsStr::new("create-service"),
            OsStr::new("--raw"),
            code.as_os_str(),
            OsStr::new(&amount),
        ])?;
        service_id(&printed)
    }

    /// Provide `preimage`, a file, which `service` solicited.
    pub fn provide(&self, service: u64, preimage: &Path) -> Result<(), Error> {
        let service = format!("{service:08x}");
        self.jamt([
            OsStr::new("provide"),
            OsStr::new(&service),
            preimage.as_os_str(),
        ])
        .map(drop)
    }

    /// Submit a work package of one item to `service`: `payload`, which
    /// exports `exports` segments and imports `imports`, by segment root.
    /// What `jamt` said of it, its lines joined: the package's hash, cut
    /// short, and its anchor among them.
    pub fn item(
        &self,
        service: u64,
        payload: &[u8],
        exports: u32,
        imports: &[(Hash, u32)],
    ) -> Result<String, Error> {
        std::fs::create_dir_all(&self.files).map_err(failed)?;
        let file = self.files.join("payload.bin");
        std::fs::write(&file, payload).map_err(failed)?;
        let mut args: Vec<OsString> = vec!["item".into(), "-e".into(), exports.to_string().into()];
        for (root, index) in imports {
            args.push("-i".into());
            args.push(format!("sr:{}:{index}", hex::encode(root)).into());
        }
        args.push(format!("{service:08x}").into());
        args.push(file.into_os_string());
        let (stdout, stderr) = self.jamt(args)?;
        let lines: Vec<&str> = stdout.lines().chain(stderr.lines()).collect();
        Ok(lines.join("; "))
    }
}

/// The service id `jamt create-service --raw` printed, in hex.
fn service_id(printed: &str) -> Result<u64, Error> {
    u64::from_str_radix(printed.trim(), 16)
        .map_err(|_| failed(format!("a service id: {printed:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_id_reads_as_jamt_prints_it() {
        assert_eq!(service_id("0000002a\n").unwrap(), 42);
        assert!(service_id("Created service").is_err());
    }
}
