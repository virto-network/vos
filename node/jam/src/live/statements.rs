//! A JAM statements service (`vos-statement-service`) on a PolkaJam node:
//! its items submitted as work packages with their extrinsics, each item's
//! outcome read back from the service's storage at the finalized block.

use std::time::{Duration, Instant};

use vos_statement_service::state::{Outcome, keys};
use vos_tree::Hash;
use vos_wire::package::{EPOCH_MS, SLOT_MS};
use vos_wire::result::digest;

use super::package::WorkItem;
use super::{PolkaJam, failed};
use crate::Error;

/// A package's accumulate gas an item: the service's accumulate takes about
/// 0.1M a statement on the JAM-only host [6.19].
const ACCUMULATE_GAS: u64 = 10_000_000;
/// The RPC errors in a row a wait takes before it stops.
const TRANSIENT: u32 = 10;

/// The statements service `service` on `node`.
#[derive(Clone, Debug)]
pub struct Statements {
    pub node: PolkaJam,
    pub service: u64,
    /// Its code hash, which each work item names.
    pub code_hash: Hash,
    /// A work package's refine gas, which its items share.
    pub refine_gas: u64,
}

/// An item to submit: its payload and its extrinsics.
pub type Item = (Vec<u8>, Vec<Vec<u8>>);

impl Statements {
    /// Service `service` of `node`, its code hash read at the finalized
    /// block, its packages' refine gas `refine_gas`.
    pub fn new(node: PolkaJam, service: u64, refine_gas: u64) -> Result<Self, Error> {
        let code_hash = node.code_hash(service)?;
        Ok(Self {
            node,
            service,
            code_hash,
            refine_gas,
        })
    }

    /// The venue's time at the finalized block: its slot's start.
    pub fn now(&self) -> Result<u64, Error> {
        let (_, slot) = self.node.finalized()?;
        Ok(EPOCH_MS + slot * SLOT_MS)
    }

    /// Submit `items` as one work package to `core`, sharing its refine gas.
    pub fn submit(&self, core: u16, items: &[Item]) -> Result<(), Error> {
        let service = u32::try_from(self.service).map_err(failed)?;
        let refine_gas = self.refine_gas / items.len().max(1) as u64;
        let items: Vec<WorkItem> = items
            .iter()
            .map(|(payload, extrinsics)| WorkItem {
                service,
                code_hash: self.code_hash,
                refine_gas,
                accumulate_gas: ACCUMULATE_GAS,
                payload: payload.clone(),
                extrinsics: extrinsics.clone(),
            })
            .collect();
        self.node.submit_package(core, &items).map(drop)
    }

    /// A value of the service's storage at the finalized block.
    pub fn value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let (head, _) = self.node.finalized()?;
        self.node.value(&head, self.service, key)
    }

    /// The outcome of the item whose payload is `payload`, as the finalized
    /// block holds it.
    pub fn outcome(&self, payload: &[u8]) -> Result<Option<Outcome>, Error> {
        self.value(&keys::outcome(&digest(payload)))?
            .map(|bytes| Outcome::decode(&bytes).map_err(|error| failed(format!("{error:?}"))))
            .transpose()
    }

    /// The gas the service's last accumulate took, by its own count.
    pub fn accumulate_gas(&self) -> Result<Option<u64>, Error> {
        Ok(self
            .value(keys::GAS)?
            .and_then(|bytes| Some(u64::from_le_bytes(bytes.try_into().ok()?))))
    }

    /// Submit `items` as one package, and wait until each one's outcome
    /// lands, timed past the venue's time at submission: each outcome. The
    /// package goes to core 0, and again to core 1 if nothing lands within
    /// half of `timeout`.
    pub fn land(&self, items: &[Item], timeout: Duration) -> Result<Vec<Outcome>, Error> {
        let since = self.now()?;
        let until = Instant::now() + timeout;
        let mut retried = false;
        self.submit(0, items)?;
        let resubmit = Instant::now() + timeout / 2;
        let mut errors = 0;
        loop {
            match self.landed(items, since) {
                Ok(Some(outcomes)) => return Ok(outcomes),
                Ok(None) => errors = 0,
                Err(error) if errors == TRANSIENT => return Err(error),
                Err(_) => errors += 1,
            }
            if !retried && Instant::now() > resubmit {
                retried = true;
                self.submit(1, items)?;
            }
            if Instant::now() > until {
                return Err(failed("the package's outcomes never landed"));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Each item's outcome, if every one landed past `since`.
    fn landed(&self, items: &[Item], since: u64) -> Result<Option<Vec<Outcome>>, Error> {
        let mut outcomes = Vec::with_capacity(items.len());
        for (payload, _) in items {
            match self.outcome(payload)? {
                Some(outcome) if outcome.time > since => outcomes.push(outcome),
                _ => return Ok(None),
            }
        }
        Ok(Some(outcomes))
    }
}
