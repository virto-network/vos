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

use vos_jam_dev::JamVenue;
use vos_jam_dev::live::PolkaJam;
use vos_jam_dev::live::statements;
use vos_statement_service::config::Config;
use vos_venue::vos_statement::ProgramId;
use vos_wire::package::EPOCH_MS;

use crate::venues::Wire;

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
    pub fn deploy(&self, name: &str, pins: Vec<ProgramId>, wire: &Arc<Wire>) -> JamVenue {
        let parameters = self.node.parameters().expect("the testnet's parameters");
        let config = Config {
            genesis: self.node.genesis().expect("the chain's genesis"),
            genesis_ms: EPOCH_MS,
            pins,
        };
        let mut node = self.node.clone();
        node.watch = Some(wire.watch(&self.node));
        let file = self.run.join(format!("statements-{name}.jam"));
        statements::deploy(
            node,
            &self.service,
            &config,
            &file,
            parameters.max_refine_gas,
        )
        .unwrap_or_else(|error| panic!("the statements service deployed: {error}"))
        .venue
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
