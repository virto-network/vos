//! A JAM node, emulated in process for one agent: a package refined on the
//! JAM-only host, its exports kept in emulated DA, and its output
//! accumulated against the service's storage, where the agent keeps only
//! its root.

use std::collections::BTreeMap;

use vos_pvm::ExitReason;
use vos_pvm::accumulate_host::{AccumulateContext, ServiceStorage};
use vos_pvm::refine::MemoryModel;
use vos_pvm::refine_host::RefineContext;
use vos_tree::{Blake2b, Hash, Hasher};
use vos_wire::batch::Work;
use vos_wire::jam::{AccumulateInput, Operand};
use vos_wire::package::{JamOutput, Package, ROOT};
use vos_wire::{Decode, Encode};

use crate::Error;
use crate::da::Da;
use crate::simulate::Runner;

/// The most a work report's outputs take, the Gray Paper's `W_R`
/// (48 KiB): what refine may return.
const MAX_REFINE_OUTPUT: usize = 48 << 10;

/// Accumulate's gas: it swaps a root.
const ACCUMULATE_GAS: u64 = 10_000_000;

/// The chain's side of an agent: its service's storage and DA.
#[derive(Default)]
pub struct Chain {
    /// The service's storage, which accumulate reads and writes.
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    pub da: Da,
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

impl Chain {
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
            authorizer: [0; 32],
            payload_hash: [0; 32],
            gas_limit: 0,
            result: Ok(refined.bytes.clone()),
            auth_trace: Vec::new(),
        })
        .encode();
        let inputs = [input];
        let invocation = AccumulateContext::load(
            &runner.program,
            slot,
            runner.service,
            &inputs,
            ACCUMULATE_GAS,
            &mut Storage(&mut self.storage),
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

struct Storage<'a>(&'a mut BTreeMap<Vec<u8>, Vec<u8>>);

impl ServiceStorage for Storage<'_> {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key).cloned()
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
        let previous = match value {
            Some(value) if !value.is_empty() => self.0.insert(key.to_vec(), value.to_vec()),
            _ => self.0.remove(key),
        };
        previous.map(|value| value.len())
    }
}
