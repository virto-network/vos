//! `vos-gateway-demo --data DIR [--ssh ADDRESS]`: the demo's local space
//! and its gateway as `vos-gateway` serves it: the SSH port on `ADDRESS`
//! (`127.0.0.1:2222` by default) and the onion arti hosts for it over the
//! live Tor network, its key and state kept under `DIR`, both serving the
//! demo's screens. A phone reaches the SSH port (through `adb reverse`) as
//! `anonymous@ADDRESS` to enroll; the enrollment pins the onion, which then
//! carries its proofs and its screens. The operator's commands come on
//! standard input:
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
    let ssh = ssh
        .parse()
        .map_err(|_| format!("{ssh}: not an address and port"))?;
    std::fs::create_dir_all(&data).map_err(|error| error.to_string())?;
    let space = LocalSpace::found(&data.join("space"), random(), random())?;
    space.open_account("shop", random::<32>().map(|byte| byte & 0x3f), 0)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let hosted = space.host(&data, ssh).await?;
        println!("ssh anonymous@{ssh}  (host key {})", hosted.fingerprint);
        println!("onion {}", hosted.onion);
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
        drop(hosted);
        Ok::<(), String>(())
    })?;
    space.shutdown();
    Ok(())
}
