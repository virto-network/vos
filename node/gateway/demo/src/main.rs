//! `vos-gateway-demo --data DIR --ssh ADDRESS`: the demo's local space and
//! its gateway, for a phone that reaches the SSH port (through `adb reverse`)
//! as `anonymous@ADDRESS`. The operator's commands come on standard input:
//!
//! - `invite MEMBER ACCOUNT OWNER`: invite the member digest into the
//!   credential actor's tree and the account `ACCOUNT` for the owner
//!   digest, both as the phone's Enroll screen shows them;
//! - `mint ACCOUNT AMOUNT`; `balance ACCOUNT`; `quit`.
//!
//! The space starts with an account `shop` of another owner, to pay to. The
//! node's and the gateway's logs go to standard error.

use std::path::PathBuf;

use tokio::io::AsyncBufReadExt as _;
use vos_gateway_demo::{LocalSpace, random};

fn digest(text: &str) -> Result<[u8; 32], String> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{text}: not 32 bytes in hex"))
}

fn command(space: &LocalSpace, line: &str) -> Result<String, String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["invite", member, account, owner] => {
            space.invite(digest(member)?, account, digest(owner)?)?;
            Ok(format!("invited the member and the account {account}"))
        }
        ["mint", account, amount] => {
            let amount = amount.parse().map_err(|_| "the amount is a number")?;
            space.mint(account, amount)?;
            Ok(format!("minted {amount} to {account}"))
        }
        ["balance", account] => Ok(match space.balance(account)? {
            Some(balance) => format!("{account}: {balance}"),
            None => format!("no account {account}"),
        }),
        [] => Ok(String::new()),
        _ => {
            Err("invite MEMBER ACCOUNT OWNER | mint ACCOUNT AMOUNT | balance ACCOUNT | quit".into())
        }
    }
}

/// The host key whose seed is kept at `path`, made there on the first run so
/// that a phone which trusted it keeps recognising the gateway.
fn kept_host_key(path: &std::path::Path) -> Result<russh::keys::PrivateKey, String> {
    let seed: [u8; 32] = match std::fs::read(path) {
        Ok(bytes) => bytes
            .try_into()
            .map_err(|_| format!("{}: not a 32-byte seed", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let seed = random();
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .and_then(|mut file| file.write_all(&seed))
                .map_err(|error| format!("{}: {error}", path.display()))?;
            seed
        }
        Err(error) => return Err(error.to_string()),
    };
    Ok(russh::keys::PrivateKey::from(
        russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed),
    ))
}

fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let mut arguments = std::env::args().skip(1);
    let (mut data, mut ssh) = (None, "127.0.0.1:2222".to_owned());
    while let Some(flag) = arguments.next() {
        match (flag.as_str(), arguments.next()) {
            ("--data", Some(value)) => data = Some(PathBuf::from(value)),
            ("--ssh", Some(value)) => ssh = value,
            _ => return Err("vos-gateway-demo --data DIR [--ssh ADDRESS]".into()),
        }
    }
    let data = data.ok_or("--data DIR, an empty directory")?;
    std::fs::create_dir_all(&data).map_err(|error| error.to_string())?;
    let space = LocalSpace::found(&data, random(), random())?;
    space.open_account("shop", random::<32>().map(|byte| byte & 0x3f), 0)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(&ssh)
            .await
            .map_err(|error| format!("{ssh}: {error}"))?;
        let host_key = kept_host_key(&data.join("host_key"))?;
        let fingerprint = host_key
            .public_key()
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256);
        let _gateway = space.gateway(listener, host_key, random());
        println!("ssh anonymous@{ssh}  (host key {fingerprint})");
        println!("agent {}", space.agent().0);
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim() == "quit" {
                break;
            }
            match tokio::task::block_in_place(|| command(&space, &line)) {
                Ok(done) if done.is_empty() => {}
                Ok(done) => println!("{done}"),
                Err(error) => println!("error: {error}"),
            }
        }
        Ok::<(), String>(())
    })?;
    space.shutdown();
    Ok(())
}
