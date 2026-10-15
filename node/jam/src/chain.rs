//! The chain an agent's packages go to: a JAM node ([`crate::live`]), or
//! one emulated in process here, which refines a package on the JAM-only
//! host, keeps its exports in emulated DA, and accumulates its output
//! against the service's storage.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::{AccumulateContext, ServiceStorage};
use vos_pvm::refine::MemoryModel;
use vos_pvm::refine_host::RefineContext;
use vos_tree::{Blake2b, Hash, Hasher};
use vos_wire::batch::Work;
use vos_wire::jam::{AccumulateInput, Operand};
use vos_wire::package::{EPOCH_MS, EXPORTS, Exports, JamOutput, Package, ROOT, SLOT_MS};
use vos_wire::{Decode, Encode};

use crate::Error;
use crate::builder::Prepared;
use crate::da::{Da, Segments};
use crate::simulate::Runner;

/// What the chain holds of an agent: its root, and the last package it
/// took's exports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Landed {
    pub root: Hash,
    pub exports: Option<Exports>,
}

impl Landed {
    /// What the service's storage holds, by its two keys' values.
    pub fn read(root: Option<&[u8]>, exports: Option<&[u8]>) -> Result<Self, Error> {
        let root = match root {
            Some(bytes) => bytes.try_into().map_err(|_| Error::Corrupt("the root"))?,
            None => vos_tree::empty_root(&Blake2b),
        };
        let exports = exports
            .map(|bytes| match Exports::decode(bytes) {
                Ok((exports, used)) if used == bytes.len() => Ok(exports),
                _ => Err(Error::Corrupt("the last exports")),
            })
            .transpose()?;
        Ok(Self { root, exports })
    }
}

/// Where an agent's packages go.
pub trait Chain {
    /// Where its exported segments are read from.
    fn segments(&self) -> Arc<dyn Segments>;
    /// Submit `prepared`'s package: what the chain said of it.
    fn submit(&mut self, runner: &Runner, prepared: &Prepared) -> Result<String, Error>;
    /// What the chain holds once `prepared`'s package was taken, or once
    /// it has waited long enough to take it for refused.
    fn wait(&mut self, prepared: &Prepared) -> Result<Landed, Error>;
    /// What the chain holds now.
    fn landed(&self) -> Result<Landed, Error>;
}

/// The slot a time falls in.
pub fn slot_of(time: u64) -> u64 {
    time.saturating_sub(EPOCH_MS) / SLOT_MS
}

/// The most a work report's outputs take, the Gray Paper's `W_R`
/// (48 KiB, as PolkaJam's parameters give it): what refine may return.
pub const MAX_REFINE_OUTPUT: usize = 48 << 10;

/// Accumulate's gas: it swaps a root and solicits a few preimages.
const ACCUMULATE_GAS: u64 = 10_000_000;

/// A fault the emulated chain puts in a package it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Accumulated three minutes past its time: refused.
    Late,
    /// Refined with a tenth of its gas: out of gas.
    Starved,
}

/// A JAM node emulated in process for one agent: its service's storage,
/// DA, and the faults to put in the packages it takes next.
#[derive(Default)]
pub struct Emulated {
    /// The service's storage, which accumulate reads and writes.
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    pub da: Da,
    /// The preimages accumulate solicited, by hash and length.
    pub solicited: BTreeSet<(Hash, u64)>,
    pub faults: Vec<Fault>,
}

/// A package refined: its output, as refine returned it and decoded, the
/// segment root of its exports, and the refine's gas.
#[derive(Clone, Debug)]
pub struct Refined {
    pub package_hash: Hash,
    pub bytes: Vec<u8>,
    pub output: JamOutput,
    pub segment_root: Hash,
    pub gas_used: u64,
}

impl Emulated {
    /// Refine `package` on the JAM-only host with `gas`, its imports'
    /// segments `imports`, as a guarantor does; its exports kept in DA.
    pub fn refine(
        &mut self,
        runner: &Runner,
        package: &Package,
        imports: Vec<Vec<u8>>,
        gas: u64,
    ) -> Result<Refined, Error> {
        let payload = Work::Package(package.clone()).encode();
        let package_hash = Blake2b.hash(b"vos/jam/package", &[&payload]);
        let arguments = runner.arguments(&payload, package_hash);
        let run = RefineContext::load_prepared(&runner.program, &arguments, gas, MemoryModel::Auto)
            .map_err(Error::Load)?
            .try_run_jam(runner.jam(payload, imports))
            .map_err(Error::Load)?;
        let invocation = run.invocation;
        if invocation.exit != ExitReason::Halt {
            return Err(Error::Refine(invocation.exit));
        }
        let bytes = invocation
            .output_bounded(MAX_REFINE_OUTPUT)
            .ok_or(Error::Output)?;
        let (output, used) = JamOutput::decode(&bytes).map_err(|_| Error::Output)?;
        if used != bytes.len() || output.exports as usize != run.exports.len() {
            return Err(Error::Output);
        }
        let segment_root = self.da.put(run.exports);
        Ok(Refined {
            package_hash,
            bytes,
            output,
            segment_root,
            gas_used: invocation.gas_used,
        })
    }

    /// Accumulate `refined` at `slot`: the root the service stores after.
    pub fn accumulate(
        &mut self,
        runner: &Runner,
        refined: &Refined,
        slot: u64,
    ) -> Result<Option<Hash>, Error> {
        let input = AccumulateInput::Operand(Operand {
            package_hash: refined.package_hash,
            segment_root: refined.segment_root,
            ..Operand::new(refined.bytes.clone())
        })
        .encode();
        let inputs = [input];
        let mut storage = Storage {
            values: &mut self.storage,
            solicited: &mut self.solicited,
        };
        let invocation = AccumulateContext::load(
            &runner.program,
            slot,
            runner.service,
            &inputs,
            ACCUMULATE_GAS,
            &mut storage,
        )
        .map_err(Error::Load)?
        .try_run()
        .map_err(Error::Load)?;
        if invocation.exit != ExitReason::Halt {
            return Err(Error::Accumulate(invocation.exit));
        }
        Ok(self.root())
    }

    /// The root the service stores.
    pub fn root(&self) -> Option<Hash> {
        self.storage
            .get(ROOT)
            .and_then(|root| root.as_slice().try_into().ok())
    }
}

impl Chain for Emulated {
    fn segments(&self) -> Arc<dyn Segments> {
        Arc::new(self.da.clone())
    }

    /// Refine the package with the gas it asks, its imports from DA, then
    /// accumulate it in the slot after its time's, unless a fault says
    /// otherwise. A refine that fails leaves the chain as it was.
    fn submit(&mut self, runner: &Runner, prepared: &Prepared) -> Result<String, Error> {
        let fault = (!self.faults.is_empty()).then(|| self.faults.remove(0));
        let imports = prepared
            .segments
            .iter()
            .map(|(root, at)| self.da.segment(root, *at).ok_or(Error::Exports))
            .collect::<Result<_, _>>()?;
        let gas = match fault {
            Some(Fault::Starved) => prepared.gas / 10,
            _ => prepared.gas,
        };
        let refined = match self.refine(runner, &prepared.package, imports, gas) {
            Ok(refined) => refined,
            Err(Error::Refine(exit)) => return Ok(format!("refine stopped: {exit:?}")),
            Err(error) => return Err(error),
        };
        let mut slot = slot_of(prepared.package.batch.time) + 1;
        if fault == Some(Fault::Late) {
            slot += 30;
        }
        self.accumulate(runner, &refined, slot)?;
        Ok(format!("refined, accumulated at slot {slot}"))
    }

    fn wait(&mut self, _: &Prepared) -> Result<Landed, Error> {
        self.landed()
    }

    fn landed(&self) -> Result<Landed, Error> {
        Landed::read(
            self.storage.get(ROOT).map(Vec::as_slice),
            self.storage.get(EXPORTS).map(Vec::as_slice),
        )
    }
}

struct Storage<'a> {
    values: &'a mut BTreeMap<Vec<u8>, Vec<u8>>,
    solicited: &'a mut BTreeSet<(Hash, u64)>,
}

impl ServiceStorage for Storage<'_> {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.values.get(key).cloned()
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
        let previous = match value {
            Some(value) if !value.is_empty() => self.values.insert(key.to_vec(), value.to_vec()),
            _ => self.values.remove(key),
        };
        previous.map(|value| value.len())
    }

    fn solicit(&mut self, hash: &[u8; 32], len: u64) -> Option<bool> {
        Some(self.solicited.insert((*hash, len)))
    }
}
