//! `vos jam statements`: the JAM statements service deployed on a running
//! PolkaJam testnet and driven through its items, each a work package of
//! its own submitted by RPC with its extrinsics, its outcome read back from
//! the service's storage:
//! - a 256 KiB extrinsic first, `MAX_PROOF_BYTES` of a proof, read by
//!   refine and refused by the verifier;
//! - a space registered, a window's root anchored, an anchor by a key the
//!   space does not list refused;
//! - the golden fixtures' masked statements: the rootless one accepted (its
//!   program pinned, not venue-bound), then refused as a repeat; the rooted
//!   one, venue-bound to the fixtures' venue, refused as another venue's;
//! - the space migrated away, then a second root for its window, its
//!   evidence kept and the space suspended.
//!
//! Each statement's refine gas, by the service's own count, is compared
//! with the JAM-only host's for the same item; the record lists every
//! outcome and the gas, and is written whatever the outcome.

use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_jam::live::PolkaJam;
use vos_jam::live::statements::Statements;
use vos_pvm::refine_host::{JamItem, JamRefine, RefineContext};
use vos_pvm_compiler::{ServiceMetadata, service_blob};
use vos_statement::fixtures::{self, Fixture};
use vos_statement::vos_anchor::{
    Anchor, Migrate, RootKind, SpaceGenesis, VenueId, WindowClock, space_id,
};
use vos_statement::vos_pvm_final_verifier::MAX_PROOF_BYTES;
use vos_statement::{Pin, blake2b_256};
use vos_statement_service::config::{Config, configure};
use vos_statement_service::item::Item;
use vos_statement_service::state::Outcome;
use vos_venue::VenueClient;
use vos_venue::jam::{JamVenue, register_code};
use vos_wire::jam::RefineArgs;
use vos_wire::package::EPOCH_MS;
use vos_wire::result::digest;

use crate::{at, link};

#[derive(clap::Args)]
pub struct StatementsArgs {
    /// The directory of PolkaJam's binaries, `jamt` among them.
    #[arg(long, env = "POLKAJAM")]
    pub polkajam: PathBuf,
    /// The node's JSON-RPC, `host:port`.
    #[arg(long, default_value = "localhost:19800")]
    pub rpc: String,
    /// The service's program, as `just check-no-std` builds it
    /// (`statement-service.elf`).
    #[arg(long)]
    pub service: PathBuf,
    /// The golden fixtures (`pvm/proof/fixtures`).
    #[arg(long)]
    pub fixtures: PathBuf,
    /// The run's directory: the service's blob, the files `jamt` reads and
    /// the record.
    #[arg(long)]
    pub data: PathBuf,
}

/// The service's endowment: its storage deposits.
const ENDOWMENT: u64 = 10_000_000_000;
/// How long the service's code may take to become available.
const PREIMAGE_TIMEOUT: Duration = Duration::from_secs(180);
/// The space's window length: the shortest a venue registers.
const LENGTH_MS: u64 = 120_000;

const METADATA: ServiceMetadata<'static> = ServiceMetadata {
    name: "vos-statements",
    version: env!("CARGO_PKG_VERSION"),
    license: "Apache-2.0",
    authors: &["VOS"],
};

type Failed = Box<dyn std::error::Error>;

/// Run the service on the testnet and write the run's record.
pub fn run(args: StatementsArgs) -> Result<(), String> {
    let mut record = Record::default();
    let outcome = drive(&args, &mut record).map_err(|error| error.to_string());
    if let Err(error) = &outcome {
        record.note(format!("the run fails: {error}"));
    }
    std::fs::create_dir_all(&args.data).map_err(at(&args.data))?;
    let file = args.data.join("record.txt");
    std::fs::write(&file, &record.0).map_err(at(&file))?;
    println!("its record: {}", file.display());
    outcome
}

#[derive(Default)]
struct Record(String);

impl Record {
    fn note(&mut self, line: impl AsRef<str>) {
        println!("{}", line.as_ref());
        self.0.push_str(line.as_ref());
        self.0.push('\n');
    }

    fn outcome(&mut self, what: &str, outcome: &Outcome) {
        self.note(format!(
            "{what}: code {:#x}, at {} ms, of {}, refine {} gas by the service's count",
            outcome.code,
            outcome.time,
            hex::encode(&outcome.subject[..8]),
            outcome.refine_gas
        ));
    }
}

fn fixture(fixtures: &[Fixture], name: &str) -> Result<Fixture, Failed> {
    fixtures
        .iter()
        .find(|fixture| fixture.name == name)
        .cloned()
        .ok_or_else(|| format!("no fixture {name:?}").into())
}

/// The gas `program`'s refine of `payload` with `extrinsics`, as service
/// `service`, takes on the JAM-only host by the service's own count.
fn jam_only_gas(
    program: &[u8],
    service: u64,
    payload: &[u8],
    extrinsics: &[Vec<u8>],
) -> Result<u64, Failed> {
    let args = RefineArgs::new(service, payload.to_vec(), [0; 32]).encode();
    let jam = JamRefine {
        service,
        items: vec![JamItem {
            payload: payload.to_vec(),
            extrinsics: extrinsics.to_vec(),
            ..JamItem::default()
        }],
        ..JamRefine::default()
    };
    let context =
        RefineContext::load(program, &args, 1_000_000_000).map_err(|e| format!("{e:?}"))?;
    let run = context.try_run_jam(jam).map_err(|e| format!("{e:?}"))?;
    let output = run
        .invocation
        .output_bounded(1 << 20)
        .ok_or("the JAM-only host's refine gave no output")?;
    let gas = output
        .get(output.len().saturating_sub(8)..)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_le_bytes)
        .ok_or("an output too short")?;
    Ok(gas)
}

fn drive(args: &StatementsArgs, record: &mut Record) -> Result<(), Failed> {
    std::fs::create_dir_all(&args.data).map_err(at(&args.data))?;
    let node = PolkaJam {
        rpc: args.rpc.clone(),
        jamt: args.polkajam.join("jamt"),
        files: args.data.join("files"),
    };
    let parameters = node.parameters()?;
    record.note(format!("testnet: {parameters:?}"));
    let genesis = node.genesis()?;
    record.note(format!("the chain's genesis hash {}", hex::encode(genesis)));

    let fixtures = fixtures::load(&args.fixtures);
    let rooted = fixture(&fixtures, "valid")?;
    let rootless = fixture(&fixtures, "rootless")?;
    let config = Config {
        genesis,
        genesis_ms: EPOCH_MS,
        pins: vec![
            Pin {
                venue_bound: true,
                ..rooted.input.pin
            },
            Pin {
                venue_bound: false,
                ..rootless.input.pin
            },
        ],
    };
    let mut program = link(&args.service)?;
    configure(&mut program, &config).map_err(|error| format!("{error:?}"))?;
    let blob = service_blob(&program, &METADATA);
    let file = args.data.join("statements.jam");
    std::fs::write(&file, &blob).map_err(at(&file))?;
    let service = node.create_service(&file, ENDOWMENT)?;
    record.note(format!(
        "service {service}: the statements service, program {} B, blob {} B, code hash {}",
        program.len(),
        blob.len(),
        hex::encode(digest(&blob))
    ));
    let since =
        node.await_preimage(service, &digest(&blob), blob.len() as u64, PREIMAGE_TIMEOUT)?;
    record.note(format!("its code available since slot {since}"));
    let statements = Statements::new(node, service, parameters.max_refine_gas)?;
    let venue = JamVenue::new(statements, genesis);
    record.note(format!("the venue {}", hex::encode(venue.id().0)));

    // A proof of `MAX_PROOF_BYTES` as an extrinsic: the package past CE
    // 133's bound but for it, read whole by refine.
    let submit = |statement: &vos_statement::Statement| Item::Submit(statement.encode()).encode();
    let lone = submit(&rootless.input.statement);
    let large = vec![0x5a; MAX_PROOF_BYTES];
    let outcome = venue.land(lone.clone(), vec![large.clone()])?;
    record.outcome(
        &format!("a {MAX_PROOF_BYTES} B extrinsic as the proof"),
        &outcome,
    );
    compare(record, &program, service, &lone, &[large], &outcome)?;
    if outcome.code >> 8 != 1 {
        return Err("the 256 KiB proof was not refused by the verifier".into());
    }

    // A space of one founder, its windows the shortest, registered from
    // the window before the venue's open one.
    let now = venue.statements.now()?;
    let founder = SigningKey::from_bytes(&blake2b_256(&[b"vos/jam/statements/founder"]));
    let controller = SigningKey::from_bytes(&blake2b_256(&[b"vos/jam/statements/controller"]));
    let clock = WindowClock {
        origin_ms: now - now % LENGTH_MS - 4 * LENGTH_MS,
        length_ms: LENGTH_MS,
    };
    let genesis_space = SpaceGenesis {
        version: 1,
        nodes: vec![(0, founder.verifying_key().to_bytes())],
        clock,
        time: now,
        nonce: blake2b_256(&[&now.to_le_bytes()])[..16].try_into()?,
    };
    let space = space_id(&genesis_space);
    let open = clock
        .window(now)
        .ok_or("the venue's time before the clock")?;
    let start = open - 1;
    let code = venue.register(
        &genesis_space,
        controller.verifying_key().to_bytes(),
        start,
        &founder,
    )?;
    record.note(format!(
        "register {} from window {start}: {code} ({})",
        hex::encode(&space.0[..8]),
        register_code(code)
    ));
    let anchor = |window: u64, root: u8, key: &SigningKey| {
        let mut anchor = Anchor {
            space,
            window,
            kind: RootKind::Space,
            root: [root; 32],
            signer: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = ed25519_dalek::Signer::sign(key, &anchor.digest(&venue.id())).to_bytes();
        anchor
    };
    let stranger = SigningKey::from_bytes(&[0x99; 32]);
    record.note(format!(
        "anchor window {start} by a key the space does not list: {:?}",
        venue.anchor(&anchor(start, 1, &stranger))
    ));
    record.note(format!(
        "anchor window {start}: {:?}",
        venue.anchor(&anchor(start, 1, &founder))
    ));
    record.note(format!(
        "its anchor keys at the venue: {}",
        venue.anchor_keys(&space).len()
    ));

    // The fixtures' masked statements.
    let landed = venue.land(lone.clone(), vec![rootless.proof.clone()])?;
    record.outcome("the rootless masked statement", &landed);
    compare(
        record,
        &program,
        service,
        &lone,
        std::slice::from_ref(&rootless.proof),
        &landed,
    )?;
    record.note(format!(
        "accumulate: {:?} gas by its own count",
        venue.statements.accumulate_gas()?
    ));
    let replayed = venue.land(lone, vec![rootless.proof.clone()])?;
    record.outcome("the rootless masked statement again", &replayed);
    let bound = submit(&rooted.input.statement);
    let other = venue.land(bound, vec![rooted.proof.clone()])?;
    record.outcome(
        "the rooted masked statement, bound to the fixtures' venue",
        &other,
    );

    // The space migrated away from the venue's next window, then a second
    // root for its anchored window.
    let next = venue
        .statements
        .now()
        .map(|now| clock.window(now).unwrap_or(0) + 1)?;
    let migrate = Migrate {
        space,
        from: venue.id(),
        to: VenueId([0xee; 32]),
        from_window: next,
    };
    record.note(format!(
        "migrate from window {next}: {:?}",
        venue.migrate(&migrate, &controller)
    ));
    record.note(format!(
        "a second root for window {start}: {:?}; the space suspended: {:?}",
        venue.anchor(&anchor(start, 2, &founder)),
        venue.space(&space)?.map(|space| space.suspended)
    ));

    let expected = [
        (landed.code, 0, "the rootless statement accepted"),
        (replayed.code, 6, "its replay refused as repeated"),
        (other.code, 7, "the rooted one refused as another venue's"),
    ];
    for (code, expected, what) in expected {
        if code != expected {
            return Err(format!("{what}: code {code:#x}").into());
        }
    }
    record.note("every verdict as expected");
    Ok(())
}

/// The outcome's refine gas against the JAM-only host's for the same item.
fn compare(
    record: &mut Record,
    program: &[u8],
    service: u64,
    payload: &[u8],
    extrinsics: &[Vec<u8>],
    outcome: &Outcome,
) -> Result<(), Failed> {
    let local = jam_only_gas(program, service, payload, extrinsics)?;
    record.note(format!(
        "  its refine on the JAM-only host: {local} gas; PolkaJam's {}: {}",
        outcome.refine_gas,
        if local == outcome.refine_gas {
            "equal".to_string()
        } else {
            format!("{} apart", outcome.refine_gas as i128 - local as i128)
        }
    ));
    Ok(())
}
