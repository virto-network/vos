//! `vos-jam-dev statements`: the JAM statements service deployed on a running
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
//! - a second root for its window, its evidence kept and the space
//!   suspended; the controller's controls: the founder's key removed, a
//!   rotated key added (its control replayed, refused), the space resumed,
//!   the rotated key anchoring; then the space migrated away.
//!
//! Each statement's refine gas, by the service's own count, is compared
//! with the JAM-only host's for the same item; the record lists every
//! outcome and the gas, and is written whatever the outcome.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use vos_jam_dev::live::statements::{Deployed, deploy};
use vos_jam_dev::live::{PolkaJam, Watch};
use vos_jam_dev::venue::{JamVenue, anchor_code, register_code};
use vos_pvm::refine_host::{JamItem, JamRefine, RefineContext};
use vos_statement::fixtures::{self, Fixture};
use vos_statement::vos_anchor::{
    Anchor, Migrate, RootKind, SpaceGenesis, SpaceId, VenueId, WindowClock, space_id,
};
use vos_statement::vos_pvm_final_verifier::MAX_PROOF_BYTES;
use vos_statement::{Pin, Refusal, blake2b_256};
use vos_statement_service::config::Config;
use vos_statement_service::item::{Item, Op};
use vos_statement_service::state::Outcome;
use vos_statement_service::verdict::{AnchorCode, ControlCode};
use vos_venue::{MigrateRefusal, VenueClient};
use vos_wire::jam::RefineArgs;
use vos_wire::package::EPOCH_MS;
use vos_wire::result::digest;

use crate::at;

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

/// The space's window length: the shortest a venue registers.
const LENGTH_MS: u64 = 120_000;

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
    // Every package the run sends, as it goes: the service's storage is
    // accounted for against them at the end.
    let sent: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let (mut run, rooted, rootless) = deployed(args, record, &sent)?;
    let baseline = run.venue.statements.entries(0)?;

    let lone = submit(&rootless.input.statement);
    run.large_proof(&lone)?;
    let space = run.register()?;
    let [landed, replayed, other] = run.fixture_statements(&lone, &rootless, &rooted)?;
    let controlled = run.controls(&space)?;
    let migrated = run.migrate(&space)?;

    check(&[landed, replayed, other], &controlled, migrated)?;
    run.record.note("every verdict as expected");
    let accounting = run
        .venue
        .statements
        .account(baseline, || lock(&sent).clone())?;
    run.record.note(format!(
        "the service's storage: {} entries, {} named from the {} packages sent, {} outcomes \
         among them",
        accounting.held,
        accounting.named,
        lock(&sent).len(),
        accounting.outcomes
    ));
    if accounting.held != accounting.named {
        return Err("the service holds entries no package the run sent names".into());
    }
    Ok(())
}

/// The service deployed on the node at `args`, configured for the golden
/// fixtures' pins, every package sent noted in `sent`; with the fixtures'
/// rooted and rootless statements.
fn deployed<'a>(
    args: &StatementsArgs,
    record: &'a mut Record,
    sent: &Arc<Mutex<Vec<Vec<u8>>>>,
) -> Result<(Run<'a>, Fixture, Fixture), Failed> {
    let sending = Arc::clone(sent);
    let node = PolkaJam {
        rpc: args.rpc.clone(),
        jamt: args.polkajam.join("jamt"),
        files: args.data.join("files"),
        watch: Some(Watch(Arc::new(
            move |package: &[u8], _: &[Vec<u8>], answered: Option<bool>| {
                if answered.is_none() {
                    lock(&sending).push(package.to_vec());
                }
            },
        ))),
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
    let file = args.data.join("statements.jam");
    let Deployed {
        program,
        blob,
        service,
        since,
        venue,
    } = deploy(
        node,
        &args.service,
        &config,
        &file,
        parameters.max_refine_gas,
    )?;
    record.note(format!(
        "service {service}: the statements service, program {} B, blob {} B, code hash {}",
        program.len(),
        blob.len(),
        hex::encode(digest(&blob))
    ));
    record.note(format!("its code available since slot {since}"));
    record.note(format!("the venue {}", hex::encode(venue.id().0)));
    let run = Run {
        record,
        program,
        service,
        venue,
    };
    Ok((run, rooted, rootless))
}

/// The item submitting `statement`.
fn submit(statement: &vos_statement::Statement) -> Vec<u8> {
    Item::Submit(statement.encode()).encode()
}

/// The deployed service the run drives, and its record.
struct Run<'a> {
    record: &'a mut Record,
    program: Vec<u8>,
    service: u64,
    venue: JamVenue,
}

/// The run's space, registered.
struct Space {
    id: SpaceId,
    clock: WindowClock,
    /// The window it anchors from.
    start: u64,
    founder: SigningKey,
    controller: SigningKey,
}

impl Space {
    /// `key`'s anchor of `root` (each byte) for `window` at `venue`.
    fn anchor(&self, venue: VenueId, window: u64, root: u8, key: &SigningKey) -> Anchor {
        let mut anchor = Anchor {
            space: self.id,
            window,
            kind: RootKind::Space,
            root: [root; 32],
            signer: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        anchor.signature = key.sign(&anchor.digest(&venue)).to_bytes();
        anchor
    }
}

/// The controller's controls: each one's code, the add's replay's code and
/// the rotated key's anchor once the space is resumed.
struct Controlled {
    codes: Vec<u32>,
    replayed_add: u32,
    resumed: Result<u32, vos_jam::Error>,
}

impl Run<'_> {
    /// A proof of `MAX_PROOF_BYTES` as an extrinsic: the package past CE
    /// 133's bound but for it, read whole by refine, and refused by the
    /// verifier.
    fn large_proof(&mut self, lone: &[u8]) -> Result<(), Failed> {
        let large = vec![0x5a; MAX_PROOF_BYTES];
        let outcome = self.venue.land(lone.to_vec(), vec![large.clone()])?;
        self.record.outcome(
            &format!("a {MAX_PROOF_BYTES} B extrinsic as the proof"),
            &outcome,
        );
        self.compare(lone, &[large], &outcome)?;
        if !vos_venue::proof_refused(outcome.code) {
            return Err("the 256 KiB proof was not refused by the verifier".into());
        }
        Ok(())
    }

    /// A space of one founder, its windows the shortest, registered from
    /// the window before the venue's open one; an anchor of that window by
    /// a key the space does not list, then by the founder.
    fn register(&mut self) -> Result<Space, Failed> {
        let venue = &self.venue;
        let now = venue.statements.now()?;
        let founder = SigningKey::from_bytes(&blake2b_256(&[b"vos/jam/statements/founder"]));
        let controller = SigningKey::from_bytes(&blake2b_256(&[b"vos/jam/statements/controller"]));
        let clock = WindowClock {
            origin_ms: now - now % LENGTH_MS - 4 * LENGTH_MS,
            length_ms: LENGTH_MS,
        };
        let genesis = SpaceGenesis {
            version: 1,
            nodes: vec![(0, founder.verifying_key().to_bytes())],
            clock,
            time: now,
            nonce: blake2b_256(&[&now.to_le_bytes()])[..16].try_into()?,
        };
        let id = space_id(&genesis);
        let open = clock
            .window(now)
            .ok_or("the venue's time before the clock")?;
        let start = open - 1;
        let code = venue.register(
            &genesis,
            controller.verifying_key().to_bytes(),
            start,
            &founder,
        )?;
        self.record.note(format!(
            "register {} from window {start}: {code} ({})",
            hex::encode(&id.0[..8]),
            register_code(code)
        ));
        let space = Space {
            id,
            clock,
            start,
            founder,
            controller,
        };
        let stranger = SigningKey::from_bytes(&[0x99; 32]);
        self.record.note(format!(
            "anchor window {start} by a key the space does not list: {:?}",
            venue.anchor_now(&space.anchor(venue.id(), start, 1, &stranger))
        ));
        self.record.note(format!(
            "anchor window {start}: {:?}",
            venue.anchor_now(&space.anchor(venue.id(), start, 1, &space.founder))
        ));
        self.record.note(format!(
            "its anchor keys at the venue: {}",
            venue.anchor_keys(&space.id).len()
        ));
        Ok(space)
    }

    /// The fixtures' masked statements: the rootless one (`lone`), again,
    /// and the rooted one, bound to the fixtures' venue. Their codes.
    fn fixture_statements(
        &mut self,
        lone: &[u8],
        rootless: &Fixture,
        rooted: &Fixture,
    ) -> Result<[u32; 3], Failed> {
        let landed = self
            .venue
            .land(lone.to_vec(), vec![rootless.proof.clone()])?;
        self.record
            .outcome("the rootless masked statement", &landed);
        self.compare(lone, std::slice::from_ref(&rootless.proof), &landed)?;
        self.record.note(format!(
            "accumulate: {:?} gas by its own count",
            self.venue.statements.accumulate_gas()?
        ));
        let replayed = self
            .venue
            .land(lone.to_vec(), vec![rootless.proof.clone()])?;
        self.record
            .outcome("the rootless masked statement again", &replayed);
        let bound = submit(&rooted.input.statement);
        let other = self.venue.land(bound, vec![rooted.proof.clone()])?;
        self.record.outcome(
            "the rooted masked statement, bound to the fixtures' venue",
            &other,
        );
        Ok([landed.code, replayed.code, other.code])
    }

    /// A second root for the space's anchored window: the space suspended.
    /// Its controller delists the founder, lists a rotated key (a replay of
    /// which is refused) and resumes it; the rotated key anchors.
    fn controls(&mut self, space: &Space) -> Result<Controlled, Failed> {
        let venue = &self.venue;
        let start = space.start;
        self.record.note(format!(
            "a second root for window {start}: {:?}; {:?}",
            venue.anchor_now(&space.anchor(venue.id(), start, 2, &space.founder)),
            venue.status(&space.id)
        ));
        let rotated = SigningKey::from_bytes(&blake2b_256(&[b"vos/jam/statements/rotated"]));
        let add = Op::AddKey(rotated.verifying_key().to_bytes());
        let controls = [
            (
                "remove the founder's key",
                Op::RemoveKey(space.founder.verifying_key().to_bytes()),
            ),
            ("add a rotated key", add),
            ("resume", Op::Resume),
        ];
        let mut codes = Vec::new();
        for (what, op) in controls {
            let code = venue.control(&space.id, op, &space.controller)?;
            self.record.note(format!("control, {what}: {code}"));
            codes.push(code);
        }
        let replayed_add = venue.control_at(&space.id, 1, add, &space.controller)?;
        self.record.note(format!(
            "the add's control replayed: {replayed_add}; {:?}",
            venue.status(&space.id)
        ));
        let later = loop {
            let open = space.clock.window(venue.statements.now()?).unwrap_or(0);
            if open >= start + 2 {
                break open - 1;
            }
            std::thread::sleep(Duration::from_secs(6));
        };
        let resumed = venue.anchor_now(&space.anchor(venue.id(), later, 3, &rotated));
        self.record.note(format!(
            "anchor window {later} by the rotated key: {resumed:?}"
        ));
        Ok(Controlled {
            codes,
            replayed_add,
            resumed,
        })
    }

    /// The space migrated away from a window past the venue's next by the
    /// time its item lands.
    fn migrate(&mut self, space: &Space) -> Result<Result<(), MigrateRefusal>, Failed> {
        let next = self
            .venue
            .statements
            .now()
            .map(|now| space.clock.window(now).unwrap_or(0) + 2)?;
        let migrate = Migrate {
            space: space.id,
            from: self.venue.id(),
            to: VenueId([0xee; 32]),
            from_window: next,
        };
        let migrated = self.venue.migrate(&migrate, &space.controller);
        self.record
            .note(format!("migrate from window {next}: {migrated:?}"));
        Ok(migrated)
    }

    /// The outcome's refine gas against the JAM-only host's for the same
    /// item.
    fn compare(
        &mut self,
        payload: &[u8],
        extrinsics: &[Vec<u8>],
        outcome: &Outcome,
    ) -> Result<(), Failed> {
        let local = jam_only_gas(&self.program, self.service, payload, extrinsics)?;
        self.record.note(format!(
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
}

/// Every verdict the expected one: the fixtures' statements' codes (the
/// rootless one, its replay, the rooted one), the controls', the rotated
/// key's anchor and the migration.
fn check(
    [landed, replayed, other]: &[u32; 3],
    controlled: &Controlled,
    migrated: Result<(), MigrateRefusal>,
) -> Result<(), Failed> {
    let expected = [
        (*landed, 0, "the rootless statement accepted"),
        (
            *replayed,
            Refusal::Repeated.code(),
            "its replay refused as repeated",
        ),
        (
            *other,
            Refusal::Venue.code(),
            "the rooted one refused as another venue's",
        ),
    ];
    for (code, expected, what) in expected {
        if code != expected {
            return Err(format!("{what}: code {code:#x}").into());
        }
    }
    let Controlled {
        codes,
        replayed_add,
        resumed,
    } = controlled;
    if codes != &[0, 0, 0] || *replayed_add != ControlCode::Nonce as u32 {
        return Err(format!("the controls: {codes:?}, the replay {replayed_add}").into());
    }
    if resumed.as_ref().ok().copied().and_then(anchor_code) != Some(AnchorCode::New) {
        return Err(format!("the rotated key's anchor: {resumed:?}").into());
    }
    migrated.map_err(|refusal| format!("the migration refused: {refusal:?}"))?;
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
