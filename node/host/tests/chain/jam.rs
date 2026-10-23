//! The PolkaJam testnet `just e2e-chain` starts, as its environment names
//! it, and the JAM statements service deployed on it: its program
//! configured with the chain's genesis and the run's pins, created and
//! made available, then wrapped as a venue.
//!
//! The testnet's clock is the host's shifted by the milliseconds a file
//! holds (`tools/jam-dev/clock-shift.c`, preloaded into its nodes): the run
//! moves the chain's time, the venue's, past `MaxRootAge` by writing them.

use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use vos_jam_dev::JamVenue;
use vos_jam_dev::live::PolkaJam;
use vos_jam_dev::live::statements::{MIN_ITEM_GAS, Statements};
use vos_pvm_compiler::{ServiceMetadata, service_blob};
use vos_statement_service::config::{Config, configure};
use vos_venue::vos_statement::Pin;
use vos_wire::package::EPOCH_MS;
use vos_wire::result::digest;

use crate::venues::Wire;

/// A service's endowment: its storage deposits.
const ENDOWMENT: u64 = 10_000_000_000;
/// How long a service's code may take to become available.
const PREIMAGE_TIMEOUT: Duration = Duration::from_secs(180);

const METADATA: ServiceMetadata<'static> = ServiceMetadata {
    name: "vos-statements",
    version: env!("CARGO_PKG_VERSION"),
    license: "Apache-2.0",
    authors: &["VOS"],
};

/// The testnet and the run's files.
pub struct Testnet {
    pub node: PolkaJam,
    /// The statements service's program (`statement-service.elf`).
    service: PathBuf,
    /// The file whose eight bytes shift the testnet's clock.
    shift: PathBuf,
    /// The testnet's log: its nodes' output.
    pub log: PathBuf,
    /// The run's directory: its record, the services' blobs and `jamt`'s
    /// files.
    pub run: PathBuf,
}

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set: the test runs against the testnet `just e2e-chain` starts")
    })
}

impl Testnet {
    /// The testnet the environment names.
    pub fn from_env() -> Self {
        let run = PathBuf::from(var("VOS_E2E_RUN"));
        Self {
            node: PolkaJam {
                rpc: var("VOS_E2E_RPC"),
                jamt: PathBuf::from(var("POLKAJAM")).join("jamt"),
                files: run.join("files"),
                watch: None,
            },
            service: PathBuf::from(var("VOS_E2E_SERVICE")),
            shift: PathBuf::from(var("VOS_CLOCK_SHIFT")),
            log: PathBuf::from(var("VOS_E2E_TESTNET_LOG")),
            run,
        }
    }

    /// The statements service, deployed as `name` and pinning `pins`, as a
    /// venue checked to run its code, every package its client sends kept
    /// by `wire`.
    pub fn deploy(&self, name: &str, pins: Vec<Pin>, wire: &Arc<Wire>) -> JamVenue {
        let parameters = self.node.parameters().expect("the testnet's parameters");
        let config = Config {
            genesis: self.node.genesis().expect("the chain's genesis"),
            genesis_ms: EPOCH_MS,
            pins,
        };
        let elf = std::fs::read(&self.service).expect("the service's program");
        let mut program = vos_pvm_compiler::link_elf_spi(&elf).expect("the service links");
        configure(&mut program, &config).expect("the service's configuration");
        let blob = service_blob(&program, &METADATA);
        let file = self.run.join(format!("statements-{name}.jam"));
        std::fs::write(&file, &blob).expect("the service's blob written");
        let service = self
            .node
            .create_service(&file, ENDOWMENT, Some(MIN_ITEM_GAS))
            .expect("the service created");
        self.node
            .await_preimage(service, &digest(&blob), blob.len() as u64, PREIMAGE_TIMEOUT)
            .expect("the service's code available");
        let mut node = self.node.clone();
        node.watch = Some(wire.watch(&self.node));
        let statements = Statements::new(node, service, parameters.max_refine_gas, EPOCH_MS)
            .expect("the service's code hash");
        JamVenue::new(statements, config, &blob)
            .unwrap_or_else(|mismatch| panic!("the service's code: {mismatch:?}"))
    }

    /// The testnet's clock set `ms` ahead of the host's.
    pub fn shift(&self, ms: i64) {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.shift)
            .expect("the clock's shift file");
        file.write_all_at(&ms.to_le_bytes(), 0)
            .expect("the clock's shift written");
    }

    /// The testnet's chain directory, as its log names it.
    pub fn chain(&self) -> PathBuf {
        let log = std::fs::read_to_string(&self.log).expect("the testnet's log");
        log.lines()
            .find_map(|line| line.strip_prefix("testnet: Working directory: "))
            .map(PathBuf::from)
            .expect("the testnet's log names its chain directory")
    }
}
