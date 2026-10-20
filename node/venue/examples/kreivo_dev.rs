//! The Kreivo client's chain transport against a Kreivo dev chain, whose
//! runtime need not hold the spaces pallet: a stock call
//! (`System::remark_with_event`, `[0, 7] ++ SCALE(remark)`) sent through
//! the same [`Transport`] and [`Sender`] the spaces calls go through,
//! checking the envelope (Kreivo's ten extensions, `PassAuthenticate`
//! pinned to `None`), the nonce, inclusion and the event read by the
//! extrinsic's index; the same nonce sent again refused as stale; a
//! failed dispatch's error read; an unfunded signer's call refused for its
//! fee; and raw storage reads.
//!
//! `cargo run -p vos-venue --features kreivo --example kreivo_dev -- ws://127.0.0.1:9944`

use std::process::ExitCode;
use std::time::Duration;

use parity_scale_codec::Encode;
use subxt_signer::SecretUri;
use subxt_signer::sr25519::Keypair;
use vos_venue::kreivo::Sender;
use vos_venue::kreivo::calls::{self, AccountInfo, keys};
use vos_venue::kreivo::chain::{self, ChainTransport};
use vos_venue::kreivo::transport::{Invalid, SendError, Sent, Transport, Unsent};

fn dev(uri: &str) -> Keypair {
    Keypair::from_uri(&uri.parse::<SecretUri>().expect("a dev URI")).expect("a dev key")
}

fn check(what: &str, ok: bool) -> Result<(), String> {
    println!("{} {what}", if ok { "ok  " } else { "FAIL" });
    ok.then_some(()).ok_or_else(|| what.to_string())
}

fn run(url: &str) -> Result<(), String> {
    let alice = dev("//Alice");
    let account = chain::account(&alice);
    let transport = std::sync::Arc::new(
        ChainTransport::connect(url, alice)
            .map_err(|lost| lost.0)?
            .events_of(0),
    );
    println!(
        "genesis 0x{}",
        hex(&transport.genesis().map_err(|lost| lost.0)?)
    );
    let before = transport.nonce().map_err(|lost| lost.0)?;
    let remark = format!("vos 6.17b {}", std::process::id()).into_bytes();
    let call = [&[0u8, 7][..], &remark.encode()].concat();
    let sender = Sender::new(transport.clone(), Duration::from_secs(1));
    let Ok(Sent::Included(outcome)) = sender.call(&call) else {
        return Err("the remark was not included".into());
    };
    println!("included at #{}: {:?}", outcome.block, outcome);
    check("dispatched Ok", outcome.failure.is_none())?;
    let remarked = outcome
        .unread
        .iter()
        .find(|event| event.first() == Some(&5))
        .ok_or("no System::Remarked by the extrinsic's index")?;
    let hash = blake2b_256(&remark);
    check(
        "System::Remarked names Alice and the remark's hash",
        remarked[1..] == [&account[..], &hash[..]].concat(),
    )?;
    let after = transport.nonce().map_err(|lost| lost.0)?;
    check("the nonce went up by one", after == before + 1)?;

    let signed = transport
        .sign(&call, before)
        .map_err(|error| format!("{error:?}"))?;
    let again = transport.send(&signed);
    println!("the same nonce again: {again:?}");
    check(
        "the same nonce again is stale",
        again == Err(SendError::Invalid(Invalid::Stale)),
    )?;

    let bob = chain::account(&dev("//Bob"));
    let transfer = calls::RuntimeCall::Balances(calls::BalancesCall::TransferKeepAlive {
        dest: calls::MultiAddress::Id(bob),
        value: 100_000_000_000_000_000_000,
    })
    .encode();
    let Ok(Sent::Included(failed)) = sender.call(&transfer) else {
        return Err("the transfer was not included".into());
    };
    println!("a transfer past Alice's balance: {:?}", failed.failure);
    check(
        "a failed dispatch's error is read from ExtrinsicFailed",
        failed.failure.is_some() && failed.events.is_empty(),
    )?;

    let poor = std::sync::Arc::new(
        ChainTransport::connect(url, chain::keypair(&[0x5e; 32])?).map_err(|lost| lost.0)?,
    );
    let unpaid = Sender::new(poor, Duration::from_secs(1)).call(&call);
    println!("an unfunded signer: {unpaid:?}");
    check(
        "an unfunded signer's call is refused for its fee",
        unpaid == Err(Unsent::Invalid(Invalid::Payment)),
    )?;

    let now = transport.storage(&keys::now()).map_err(|lost| lost.0)?;
    let now = now.as_deref().and_then(calls::read::<u64>);
    println!("Timestamp.Now {now:?}");
    check("Timestamp.Now reads", now.is_some())?;
    let info = transport
        .storage(&keys::account(&account))
        .map_err(|lost| lost.0)?;
    let info = info.as_deref().and_then(calls::read::<AccountInfo>);
    println!("System.Account[Alice] {info:?}");
    check(
        "System.Account reads Alice's nonce",
        info.is_some_and(|info| Ok(u64::from(info.nonce)) == transport.nonce()),
    )?;
    let accounts = transport
        .keys(&keys::plain("System", "Account"))
        .map_err(|lost| lost.0)?;
    check(
        "the accounts' keys list",
        accounts.contains(&keys::account(&account)),
    )?;
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn blake2b_256(data: &[u8]) -> [u8; 32] {
    vos_anchor::blake2b_256(&[data])
}

fn main() -> ExitCode {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws://127.0.0.1:9944".into());
    match run(&url) {
        Ok(()) => {
            println!("the client's envelope, nonce, inclusion and events: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("kreivo_dev: {error}");
            ExitCode::FAILURE
        }
    }
}
