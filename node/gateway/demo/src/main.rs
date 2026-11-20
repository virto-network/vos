//! `vos-gateway-demo --data DIR [--ssh ADDRESS] [--homes N] [--pool N]`:
//! the demo's local space and its gateway as `vos-gateway` serves it: the
//! SSH port on `ADDRESS` (`127.0.0.1:2222` by default) and the onion arti
//! hosts for it over the live Tor network, its key and state kept under
//! `DIR`, both serving the demo's screens. A phone reaches the SSH port
//! (through `adb reverse`) as `anonymous@ADDRESS` to enroll; the enrollment
//! pins the onion, which then carries its proofs and its screens.
//!
//! With `--homes N` (1 or 2), as many test homes on the same node, in the
//! demo's space, behind an onion of their own, its own SSH host key and no
//! clearnet port ([`vos_gateway_demo::home`], in Virto's home's shape,
//! E20): each a home agent with
//! a pool of `--pool` personal agents (6 by default), the delays and the
//! lease of [`vos_gateway_demo::home::SESSION`], its open claim at a low
//! difficulty; each printed as the code the app scans or pastes
//! (`home N VOSHOME1:…`), and as a QR code for its Scan. Two homes let a
//! phone move home.
//!
//! The space is founded anew at each start (`DIR/space`, removed first): a
//! phone enrolled or claimed at an earlier run clears the app's data. The
//! gateway's keys and arti's state under `DIR` stay, so the onion's address
//! and the host key do. The operator's commands come on standard input:
//!
//! - `invite CODE ACCOUNT`: the phone's enrollment code (`VOSENROLL1:…`,
//!   the QR code its own window shows after an enrollment, scanned and
//!   pasted here): its six-digit check is printed, and `yes`, once the
//!   phone shows the same six, invites the member digest into the
//!   credential actor's tree and the account `ACCOUNT` for the owner
//!   digest, claiming both at once for a device that enrolled through the
//!   screens; any other line invites nothing;
//! - `invite MEMBER ACCOUNT OWNER`: the same with the two digests typed
//!   whole, their check printed and asked as well;
//! - `mint ACCOUNT AMOUNT`; `balance ACCOUNT`;
//! - `members N`: N members of random digests enrolled, so a device's
//!   first read of the tree's feed is a catch-up of about 77 bytes each;
//! - `homes`: each home's code again, its QR code, and its pool's counts;
//! - `quit`.
//!
//! The space starts with an account `shop` of another owner, to pay to. The
//! node's and the gateway's logs go to standard error.

use std::path::PathBuf;

use tokio::io::AsyncBufReadExt as _;
use vos_gateway_demo::home::{Home, SESSION};
use vos_gateway_demo::{LocalSpace, random};
use vos_wire::credentials::Onion;

/// An invitation asked, waiting for the operator's `yes` to its check.
struct Asked {
    member: [u8; 32],
    account: String,
    owner: [u8; 32],
}

/// `text` as a QR code in the terminal: two modules a character, dark on
/// light whatever the terminal's colours, its quiet zone around it.
fn qr(text: &str) -> String {
    const QUIET: usize = 2;
    let Ok(code) = qrcode::QrCode::new(text.as_bytes()) else {
        return String::new();
    };
    let (width, colors) = (code.width(), code.to_colors());
    let dark = |x: usize, y: usize| {
        let inside = (QUIET..QUIET + width).contains(&x) && (QUIET..QUIET + width).contains(&y);
        inside && colors[(y - QUIET) * width + (x - QUIET)] == qrcode::Color::Dark
    };
    let side = width + 2 * QUIET;
    let mut out = String::new();
    for y in (0..side).step_by(2) {
        out.push_str("\x1b[30;47m");
        for x in 0..side {
            out.push(match (dark(x, y), dark(x, y + 1)) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push_str("\x1b[0m\n");
    }
    out
}

fn digest(text: &str) -> Result<[u8; 32], String> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{text}: not 32 bytes in hex"))
}

/// Each home's code and its pool's counts.
fn homes(space: &LocalSpace, homes: &[Home], onion: &Onion) -> Result<String, String> {
    let mut lines = Vec::new();
    for (n, home) in homes.iter().enumerate() {
        let counts = space.tally(home)?;
        let code = space.home_code(home, std::slice::from_ref(onion));
        lines.push(format!(
            "home {} {code}\n{}home {} handle {} agent {}: {} pooled, {} claimed, {} assigned",
            n + 1,
            qr(&code),
            n + 1,
            hex::encode(home.handle),
            home.agent.0,
            counts.pooled,
            counts.claimed,
            counts.assigned,
        ));
    }
    Ok(lines.join("\n"))
}

/// The invitation `asked`, its check printed, waiting for `yes`.
fn ask(asked: &mut Option<Asked>, member: [u8; 32], account: &str, owner: [u8; 32]) -> String {
    let check = vos_api::enrollment_check(&member, &owner);
    *asked = Some(Asked {
        member,
        account: account.to_owned(),
        owner,
    });
    format!(
        "check {check}: does the phone show the same six digits? `yes` invites the member and \
         the account {account}; any other line does not"
    )
}

fn command(space: &LocalSpace, line: &str, asked: &mut Option<Asked>) -> Result<String, String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    if let Some(Asked {
        member,
        account,
        owner,
    }) = asked.take()
    {
        if words.as_slice() != ["yes"] {
            // Not a yes: nothing invited, and the line is a command of its own.
            let then = command(space, line, asked)?;
            return Ok(format!("not invited: {account}\n{then}")
                .trim_end()
                .to_owned());
        }
        let claimed = space.invite(member, &account, owner)?;
        return Ok(match claimed {
            true => format!("invited and claimed the member and the account {account}"),
            false => format!("invited the member and the account {account}"),
        });
    }
    match words.as_slice() {
        ["invite", code, account] => {
            let (member, owner) = vos_api::read_enrollment_code(code).ok_or_else(|| {
                format!(
                    "not an enrollment code (the phone's starts with {})",
                    vos_api::ENROLLMENT_CODE
                )
            })?;
            Ok(ask(asked, member, account, owner))
        }
        ["invite", member, account, owner] => {
            Ok(ask(asked, digest(member)?, account, digest(owner)?))
        }
        ["mint", account, amount] => {
            let amount = amount.parse().map_err(|_| "the amount is a number")?;
            space.mint(account, amount)?;
            Ok(format!("minted {amount} to {account}"))
        }
        ["members", count] => {
            let count = count.parse().map_err(|_| "the count is a number")?;
            space.members(count)?;
            Ok(format!("enrolled {count} members"))
        }
        ["balance", account] => Ok(match space.balance(account)? {
            Some(balance) => format!("{account}: {balance}"),
            None => format!("no account {account}"),
        }),
        [] => Ok(String::new()),
        _ => Err(
            "invite CODE ACCOUNT | invite MEMBER ACCOUNT OWNER | mint ACCOUNT AMOUNT | balance \
                 ACCOUNT | members N | homes | quit"
                .into(),
        ),
    }
}

fn main() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let mut arguments = std::env::args().skip(1);
    let usage = "vos-gateway-demo --data DIR [--ssh ADDRESS] [--homes 0|1|2] [--pool N]";
    let (mut data, mut ssh, mut count, mut pool) = (None, "127.0.0.1:2222".to_owned(), 0, 6);
    while let Some(flag) = arguments.next() {
        let number = |value: &str| value.parse::<u32>().map_err(|_| usage.to_owned());
        match (flag.as_str(), arguments.next()) {
            ("--data", Some(value)) => data = Some(PathBuf::from(value)),
            ("--ssh", Some(value)) => ssh = value,
            ("--homes", Some(value)) => count = number(&value)?,
            ("--pool", Some(value)) => pool = number(&value)?,
            _ => return Err(usage.into()),
        }
    }
    if count > 2 || pool == 0 {
        return Err(usage.into());
    }
    let data = data.ok_or("--data DIR, an empty directory")?;
    let ssh = ssh
        .parse()
        .map_err(|_| format!("{ssh}: not an address and port"))?;
    std::fs::create_dir_all(&data).map_err(|error| error.to_string())?;
    let founded = data.join("space");
    if founded.exists() {
        eprintln!("founding the space anew: {} removed", founded.display());
        std::fs::remove_dir_all(&founded).map_err(|error| error.to_string())?;
    }
    let space = LocalSpace::found(&founded, random(), random())?;
    space.open_account("shop", random::<32>().map(|byte| byte & 0x3f), 0)?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    runtime.block_on(async {
        let hosted = space.host(&data, ssh, count > 0).await?;
        println!("ssh anonymous@{ssh}  (host key {})", hosted.fingerprint);
        println!("onion {}", hosted.onion.address);
        println!(
            "onion host key {}",
            hex::encode(hosted.onion.pinned.ssh_host_key)
        );
        if let Some(homes) = &hosted.homes {
            println!("homes onion {}", homes.address);
            println!(
                "homes onion host key {}",
                hex::encode(homes.pinned.ssh_host_key)
            );
        }
        println!("agent {}", space.agent().0);
        let mut founded = Vec::new();
        for _ in 0..count {
            let home = tokio::task::block_in_place(|| {
                let home = space.found_home(random(), SESSION, pool)?;
                let onion = &hosted.homes.as_ref().expect("the homes' onion").pinned;
                space.set_onions(&home, std::slice::from_ref(onion))?;
                Ok::<_, String>(home)
            })?;
            founded.push(home);
        }
        let pinned = hosted.homes.as_ref().map(|homes| homes.pinned);
        if let Some(onion) = &pinned {
            println!(
                "{}",
                tokio::task::block_in_place(|| homes(&space, &founded, onion))?
            );
        }
        let mut asked = None;
        let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim() == "quit" {
                break;
            }
            let done = tokio::task::block_in_place(|| match line.trim() {
                "homes" if asked.is_none() => match &pinned {
                    Some(onion) => homes(&space, &founded, onion),
                    None => Ok("no homes: start with --homes N".into()),
                },
                _ => command(&space, &line, &mut asked),
            });
            match done {
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
