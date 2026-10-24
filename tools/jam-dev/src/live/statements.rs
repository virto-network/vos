//! A JAM statements service (`vos-statement-service`) on a PolkaJam node:
//! its items submitted as work packages with their extrinsics, each item's
//! outcome read back from the service's storage at the finalized block, by
//! its package's and its payload's hashes.

use std::time::{Duration, Instant};

use std::collections::BTreeSet;

use vos_statement::MAX_ROOT_AGE_MS;
use vos_statement::vos_anchor::{RootKind, SpaceId};
use vos_statement_service::MAX_ITEMS;
use vos_statement_service::accumulate::BUCKET_MS;
use vos_statement_service::state::{Outcome, SpaceRecord, keys, outcome_id};
use vos_tree::Hash;
use vos_wire::package::SLOT_MS;
use vos_wire::result::digest;

use super::package::{WorkItem, payloads};
use super::{PolkaJam, failed};
use vos_jam::Error;

/// A package's accumulate gas an item: the service's accumulate takes about
/// 0.1M a statement on the JAM-only host and on PolkaJam.
pub const ACCUMULATE_GAS: u64 = 10_000_000;
/// The least accumulate gas a work item to the service may declare, set at
/// its creation: above its worst item's, a statement of `MAX_ROOTS` roots,
/// two reads a root at the Gray Paper's prices beside the 0.1M of any item
/// (an estimate), so no item declaring less starves a report's accumulate.
pub const MIN_ITEM_GAS: u64 = 2_000_000;
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
    /// The chain's genesis time, ms since the Unix epoch, the service's
    /// configured one: slot t starts at `genesis_ms + t × 6 s`.
    pub genesis_ms: u64,
}

/// The service's storage, accounted for at one block: the entries its
/// account counts, and those named from the packages a client sent, the
/// items' outcomes among them. Equal when every outcome it holds is of a
/// package the client sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accounting {
    /// The storage entries the account counts.
    pub held: u32,
    /// The outcomes found of the packages' items.
    pub outcomes: u32,
    /// Every entry found: the outcomes, the spaces and statements they
    /// are of, the spaces' anchors and evidence, the pruning's queue, its
    /// cursor and the gas key.
    pub named: u32,
    /// Every entry found, its key and its value, in the order read: the
    /// service's storage as a carrier audit searches it.
    pub rows: Vec<(Vec<u8>, Vec<u8>)>,
}

/// An item to submit: its payload and its extrinsics.
pub type Item = (Vec<u8>, Vec<Vec<u8>>);

impl Statements {
    /// Service `service` of `node`, its code hash read at the finalized
    /// block, its packages' refine gas `refine_gas`, its chain's genesis
    /// time `genesis_ms`.
    pub fn new(
        node: PolkaJam,
        service: u64,
        refine_gas: u64,
        genesis_ms: u64,
    ) -> Result<Self, Error> {
        let code_hash = node.code_hash(service)?;
        Ok(Self {
            node,
            service,
            code_hash,
            refine_gas,
            genesis_ms,
        })
    }

    /// The venue's time at the finalized block: its slot's start.
    pub fn now(&self) -> Result<u64, Error> {
        let (_, slot) = self.node.finalized()?;
        Ok(self.genesis_ms + slot * SLOT_MS)
    }

    /// Submit `items` as one work package to `core`, sharing its refine gas:
    /// the package's hash. At most [`MAX_ITEMS`], so their verdicts fit the
    /// report.
    pub fn submit(&self, core: u16, items: &[Item]) -> Result<Hash, Error> {
        if items.is_empty() || items.len() > MAX_ITEMS {
            return Err(failed(format!(
                "{} items: a package holds 1 to {MAX_ITEMS}",
                items.len()
            )));
        }
        // An item's outcome is kept by its package and payload: two of one
        // payload would share it.
        let payloads: std::collections::BTreeSet<&Vec<u8>> =
            items.iter().map(|(payload, _)| payload).collect();
        if payloads.len() < items.len() {
            return Err(failed("two items of one payload in a package"));
        }
        let service = u32::try_from(self.service).map_err(failed)?;
        let refine_gas = self.refine_gas / items.len() as u64;
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
        self.node
            .submit_package(core, &items)
            .map(|package| digest(&package))
    }

    /// A value of the service's storage at the finalized block.
    pub fn value(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let (head, _) = self.node.finalized()?;
        self.node.value(&head, self.service, key)
    }

    /// The outcome of the item `payload` in the package `package`, as the
    /// finalized block holds it.
    pub fn outcome(&self, package: &Hash, payload: &[u8]) -> Result<Option<Outcome>, Error> {
        self.value(&keys::outcome(&outcome_id(package, &digest(payload))))?
            .map(|bytes| Outcome::decode(&bytes).map_err(|error| failed(format!("{error:?}"))))
            .transpose()
    }

    /// The storage entries the service's account counts at the finalized
    /// block, past the `baseline` it counted with none (its preimage
    /// lookups, at its deployment).
    pub fn entries(&self, baseline: u32) -> Result<u32, Error> {
        let (head, _) = self.node.finalized()?;
        Ok(self
            .node
            .service_items(&head, self.service)?
            .saturating_sub(baseline))
    }

    /// The service's storage accounted for at the finalized block, against
    /// `packages`, the packages a client sent, read once that block is
    /// chosen (`sent`, called after it): every outcome found of their
    /// items, every space and statement those are of, each space's anchors
    /// and evidence over its windows anchored, the pruning's queue from its
    /// cursor to the latest hour a row can expire in, the cursor, and the
    /// gas key. `baseline` is the account's count with no storage.
    pub fn account(
        &self,
        baseline: u32,
        sent: impl FnOnce() -> Vec<Vec<u8>>,
    ) -> Result<Accounting, Error> {
        let (head, slot) = self.node.finalized()?;
        let held = self
            .node
            .service_items(&head, self.service)?
            .saturating_sub(baseline);
        let packages = sent();
        let value = |key: &[u8]| self.node.value(&head, self.service, key);
        let mut rows = Vec::new();
        let mut found = |key: &[u8]| -> Result<Option<Vec<u8>>, Error> {
            let value = value(key)?;
            if let Some(value) = &value {
                rows.push((key.to_vec(), value.clone()));
            }
            Ok(value)
        };
        let mut outcomes = 0u32;
        let mut subjects = BTreeSet::new();
        for package in &packages {
            let hash = digest(package);
            for payload in payloads(package).ok_or_else(|| failed("a package not ours"))? {
                let key = keys::outcome(&outcome_id(&hash, &digest(&payload)));
                if let Some(bytes) = found(&key)? {
                    outcomes += 1;
                    let outcome = Outcome::decode(&bytes).map_err(|e| failed(format!("{e:?}")))?;
                    subjects.insert(outcome.subject);
                }
            }
        }
        let mut spaces = Vec::new();
        for subject in &subjects {
            if let Some(bytes) = found(&keys::space(&SpaceId(*subject)))? {
                let record = SpaceRecord::decode(&bytes).map_err(|e| failed(format!("{e:?}")))?;
                spaces.push((SpaceId(*subject), record));
            }
            found(&keys::seen(&vos_statement::StatementId(*subject)))?;
        }
        for (space, record) in &spaces {
            let Some(last) = record.last else { continue };
            for window in record.range.from..=last {
                found(&keys::anchor(space, RootKind::Space, window))?;
                found(&keys::evidence(space, RootKind::Space, window))?;
            }
        }
        if let Some(cursor) = found(keys::CURSOR)? {
            let from = cursor
                .get(..8)
                .and_then(|bucket| Some(u64::from_le_bytes(bucket.try_into().ok()?)))
                .ok_or_else(|| failed("a cursor cut short"))?;
            let now = self.genesis_ms + slot * SLOT_MS;
            let until = (now + MAX_ROOT_AGE_MS) / BUCKET_MS + 1;
            for bucket in from..=until {
                let Some(count) = found(&keys::bucket(bucket))? else {
                    continue;
                };
                let count = count
                    .try_into()
                    .map(u32::from_le_bytes)
                    .map_err(|_| failed("a bucket's count"))?;
                for index in 0..count {
                    found(&keys::queued(bucket, index))?;
                }
            }
        }
        found(keys::GAS)?;
        Ok(Accounting {
            held,
            outcomes,
            named: rows.len() as u32,
            rows,
        })
    }

    /// The gas the service's last accumulate took, by its own count.
    pub fn accumulate_gas(&self) -> Result<Option<u64>, Error> {
        Ok(self
            .value(keys::GAS)?
            .and_then(|bytes| Some(u64::from_le_bytes(bytes.try_into().ok()?))))
    }

    /// Submit `items` as one package, and wait until each one's outcome
    /// lands: each outcome. The package goes to core 0, and again to core 1
    /// if nothing lands within half of `timeout`; the outcomes are the
    /// package's that lands, each item's taken from the other package
    /// instead where that one landed too and applied it (code 0): a
    /// control the first applied is the second's `Nonce`.
    pub fn land(&self, items: &[Item], timeout: Duration) -> Result<Vec<Outcome>, Error> {
        let until = Instant::now() + timeout;
        let mut packages = vec![self.submit(0, items)?];
        let resubmit = Instant::now() + timeout / 2;
        let mut errors = 0;
        loop {
            let mut landed: Vec<Vec<Outcome>> = Vec::new();
            for package in &packages {
                match self.landed(package, items) {
                    Ok(Some(outcomes)) => landed.push(outcomes),
                    Ok(None) => errors = 0,
                    Err(error) if errors == TRANSIENT => return Err(error),
                    Err(_) => errors += 1,
                }
            }
            if let Some(first) = landed.first() {
                let applied = (0..first.len())
                    .map(|at| {
                        landed
                            .iter()
                            .map(|outcomes| outcomes[at])
                            .find(|outcome| outcome.code == 0)
                            .unwrap_or(first[at])
                    })
                    .collect();
                return Ok(applied);
            }
            if packages.len() == 1 && Instant::now() > resubmit {
                packages.push(self.submit(1, items)?);
            }
            if Instant::now() > until {
                return Err(failed("the package's outcomes never landed"));
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    /// Each item's outcome in `package`, if every one landed.
    fn landed(&self, package: &Hash, items: &[Item]) -> Result<Option<Vec<Outcome>>, Error> {
        let mut outcomes = Vec::with_capacity(items.len());
        for (payload, _) in items {
            match self.outcome(package, payload)? {
                Some(outcome) => outcomes.push(outcome),
                None => return Ok(None),
            }
        }
        Ok(Some(outcomes))
    }
}
