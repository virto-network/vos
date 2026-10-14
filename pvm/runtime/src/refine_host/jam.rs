//! The JAM-only host: refine as a JAM node runs it, which serves the Gray
//! Paper's refine calls and no VOS extension, at PolkaJam's prices.

use alloc::vec::Vec;

use super::{RefineContext, result};
use crate::refine::{Invocation, Machine, RefineError};
use crate::{ExitReason, Gas};

/// What the JAM-only host charges where PolkaJam's prices differ from the
/// Gray Paper's base, as the probe in `spikes/sj-jam-b` measured them on
/// PolkaJam 0.1.29, Gray Paper 0.8.0.
pub mod jam_gas {
    use crate::Gas;

    /// `gas`.
    pub const GAS: Gas = 48;
    /// `log`, which PolkaJam answers `WHAT`, as a call it does not serve.
    pub const LOG: Gas = 1_000;
    /// A call PolkaJam does not serve, which answers `WHAT`.
    pub const UNSERVED: Gas = 1_000;
    /// `fetch`, by the length asked for, fitted to the one length the probe
    /// asked, a segment's 4,104 bytes: 171, served or answering `NONE`.
    /// Other lengths are unmeasured.
    pub const FETCH_BASE: Gas = 10;
    pub const FETCH_PER_KIB: Gas = 40;
    /// `export`, a segment, measured at 4,096 bytes.
    pub const EXPORT: Gas = 3_521;
    /// `historical_lookup`: not measured on PolkaJam, so the Gray Paper's
    /// base.
    pub const HISTORICAL_LOOKUP: Gas = 10;

    /// `fetch` of `len` bytes.
    pub const fn fetch(len: u64) -> Gas {
        FETCH_BASE.saturating_add(crate::inner::gas::memory(FETCH_PER_KIB, len))
    }
}

/// A segment: what one `export` puts out and one import brings in, its
/// bytes zero-padded to this length.
pub const SEGMENT: usize = 4104;
/// The most segments a work package exports.
pub const MAX_EXPORTS: u64 = 3072;

/// `fetch` kinds the JAM-only host serves in refine.
pub mod fetch_kind {
    /// The protocol's parameters, encoded.
    pub const PARAMETERS: u64 = 0;
    /// Import φ12 of work item φ11.
    pub const ANY_IMPORT: u64 = 5;
    /// Import φ11 of the running work item.
    pub const OUR_IMPORT: u64 = 6;
    /// Work item φ11's payload.
    pub const PAYLOAD: u64 = 13;
}

/// A service's preimages, as `historical_lookup` reads them at a work
/// package's lookup anchor.
pub trait Preimages: Send + Sync {
    fn preimage(&self, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>>;
}

/// What a JAM node gives a work item's refine beyond its arguments, for
/// the JAM-only host to serve.
#[derive(Clone, Default)]
pub struct JamRefine {
    /// The running service: `historical_lookup` of service `u64::MAX`
    /// reads its preimages.
    pub service: u64,
    /// The protocol's parameters, encoded.
    pub parameters: Vec<u8>,
    /// The package's work items.
    pub items: Vec<JamItem>,
    /// The running item's index among them.
    pub item: usize,
    /// The segments the package's earlier items export: `export` numbers
    /// this item's from it.
    pub export_offset: u64,
    pub preimages: Option<alloc::sync::Arc<dyn Preimages>>,
}

/// A work item of a package: its payload and the segments it imports.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JamItem {
    pub payload: Vec<u8>,
    pub imports: Vec<Vec<u8>>,
}

/// A JAM-only run: the invocation and the segments it exported, each
/// [`SEGMENT`] bytes.
#[derive(Debug)]
pub struct JamRun {
    pub invocation: Invocation,
    pub exports: Vec<Vec<u8>>,
}

impl RefineContext {
    /// Run as a JAM node would, serving what `jam` gives, at PolkaJam's
    /// prices ([`jam_gas`]): `fetch`, `export` and `historical_lookup`; no
    /// precompile computed; and every call this host does not serve, every
    /// VOS extension when no pool or state reader is set among them,
    /// answering `WHAT` while execution continues.
    pub fn try_run_jam(mut self, jam: JamRefine) -> Result<JamRun, RefineError> {
        self.precompiles = false;
        self.jam = true;
        let mut exports = Vec::new();
        let invocation =
            self.try_run_with_host(|id, machine| serve_jam(&jam, &mut exports, id, machine))?;
        Ok(JamRun {
            invocation,
            exports,
        })
    }
}

/// A call the JAM-only host serves past [`RefineContext::dispatch`]:
/// `fetch`, `export` and `historical_lookup` from `jam`; `log` and every
/// other call answer `WHAT`, as PolkaJam does.
fn serve_jam(
    jam: &JamRefine,
    exports: &mut Vec<Vec<u8>>,
    id: u64,
    machine: &mut Machine,
) -> Result<(), ExitReason> {
    use crate::inner::gp_call;
    let r = *machine.registers();
    let charge = |machine: &mut Machine, gas: Gas| {
        machine
            .charge(gas)
            .then_some(())
            .ok_or(ExitReason::OutOfGas)
    };
    let answer = match u32::try_from(id) {
        Ok(gp_call::FETCH) => {
            charge(machine, jam_gas::fetch(r[9]))?;
            let index = |register: u64| usize::try_from(register).unwrap_or(usize::MAX);
            let item = |at: usize| jam.items.get(at);
            let value = match r[10] {
                fetch_kind::PARAMETERS => Some(jam.parameters.as_slice()),
                fetch_kind::ANY_IMPORT => item(index(r[11]))
                    .and_then(|item| item.imports.get(index(r[12])))
                    .map(Vec::as_slice),
                fetch_kind::OUR_IMPORT => item(jam.item)
                    .and_then(|item| item.imports.get(index(r[11])))
                    .map(Vec::as_slice),
                fetch_kind::PAYLOAD => item(index(r[11])).map(|item| item.payload.as_slice()),
                _ => None,
            };
            copy_out(machine, value, r[7], r[8], r[9])?
        }
        Ok(gp_call::EXPORT) => {
            charge(machine, jam_gas::EXPORT)?;
            let len = r[8].min(SEGMENT as u64) as usize;
            let mut segment = alloc::vec![0u8; SEGMENT];
            let readable = len == 0
                || u32::try_from(r[7]).is_ok_and(|address| {
                    machine
                        .memory()
                        .read_bytes_checked(address, &mut segment[..len])
                });
            if !readable {
                return Err(ExitReason::Panic);
            }
            let index = jam.export_offset + exports.len() as u64;
            if index >= MAX_EXPORTS {
                result::FULL
            } else {
                exports.push(segment);
                index
            }
        }
        Ok(gp_call::HISTORICAL_LOOKUP) => {
            charge(machine, jam_gas::HISTORICAL_LOOKUP)?;
            let mut hash = [0u8; 32];
            let readable = u32::try_from(r[8])
                .is_ok_and(|address| machine.memory().read_bytes_checked(address, &mut hash));
            if !readable {
                return Err(ExitReason::Panic);
            }
            let service = match r[7] {
                u64::MAX => jam.service,
                service => service,
            };
            let preimage = jam
                .preimages
                .as_ref()
                .and_then(|preimages| preimages.preimage(service, &hash));
            copy_out(machine, preimage.as_deref(), r[9], r[10], r[11])?
        }
        Ok(gp_call::LOG) => {
            charge(machine, jam_gas::LOG)?;
            result::WHAT
        }
        _ => {
            charge(machine, jam_gas::UNSERVED)?;
            result::WHAT
        }
    };
    machine.registers_mut()[7] = answer;
    Ok(())
}

/// The Gray Paper's copy of a value out to the guest: `value`'s bytes from
/// `offset`, at most `len` of them, written at `address`; the value's
/// whole length, or `NONE` without one. A panic when the output is not
/// writable.
fn copy_out(
    machine: &mut Machine,
    value: Option<&[u8]>,
    address: u64,
    offset: u64,
    len: u64,
) -> Result<u64, ExitReason> {
    let Some(value) = value else {
        return Ok(result::NONE);
    };
    let offset = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(value.len());
    let len = usize::try_from(len)
        .unwrap_or(usize::MAX)
        .min(value.len() - offset);
    let written = len == 0
        || u32::try_from(address).is_ok_and(|address| {
            machine
                .memory_mut()
                .write_bytes_checked(address, &value[offset..offset + len])
        });
    written
        .then_some(value.len() as u64)
        .ok_or(ExitReason::Panic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refine_host::BASE_CALL_GAS;
    use crate::refine_host::tests::standard_program_with_rw;

    /// Loads φ7 to φ11 as `registers` gives them, makes call `id`, and
    /// halts; an 8 KiB read-write window at 0x2_0000 holds a page of 0x5a.
    fn calling_program(id: u8, registers: [u32; 5]) -> Vec<u8> {
        let mut code = Vec::new();
        let mut starts = Vec::new();
        for (register, value) in (7u8..).zip(registers) {
            starts.push(code.len());
            code.extend_from_slice(&[51, register]);
            code.extend_from_slice(&value.to_le_bytes());
        }
        starts.extend([code.len(), code.len() + 2]);
        code.extend_from_slice(&[10, id, 50, 0]);
        let mut rw = alloc::vec![0x5au8; 4096];
        rw.resize(8192, 0);
        standard_program_with_rw(&code, &starts, &rw)
    }

    const WINDOW: u32 = 0x2_0000;

    /// What a call costs on the JAM-only host beyond a `gas` call made
    /// alike, with `jam` given.
    fn jam_price(id: u8, registers: [u32; 5], jam: JamRefine) -> (u64, JamRun) {
        let run = |id| {
            RefineContext::load(&calling_program(id, registers), &[], 1_000_000)
                .unwrap()
                .try_run_jam(jam.clone())
                .unwrap()
        };
        let calibration = run(0);
        let called = run(id);
        assert_eq!(called.invocation.exit, ExitReason::Halt);
        let price = called.invocation.gas_used + jam_gas::GAS - calibration.invocation.gas_used;
        (price, called)
    }

    #[test]
    fn the_jam_only_host_charges_polkajams_prices() {
        assert_eq!(
            (jam_gas::GAS, jam_gas::LOG, jam_gas::UNSERVED),
            (48, 1_000, 1_000)
        );
        assert_eq!(jam_gas::fetch(SEGMENT as u64), 171, "a segment's fetch");
        assert_eq!(jam_gas::EXPORT, 3_521);
        let program = calling_program(0, [0; 5]);
        let jam = RefineContext::load(&program, &[], 1_000_000)
            .unwrap()
            .try_run_jam(JamRefine::default())
            .unwrap()
            .invocation;
        let node = RefineContext::load(&program, &[], 1_000_000).unwrap().run();
        assert_eq!(jam.gas_used - node.gas_used, jam_gas::GAS - BASE_CALL_GAS);
        for (id, price) in [(100, jam_gas::LOG), (0x47, jam_gas::UNSERVED)] {
            let (charged, run) = jam_price(id, [0; 5], JamRefine::default());
            assert_eq!(charged, price, "call {id}");
            assert_eq!(run.invocation.registers[7], result::WHAT, "call {id}");
        }
    }

    #[test]
    fn the_jam_only_host_exports_segments_from_its_offset() {
        let jam = JamRefine {
            export_offset: 5,
            ..JamRefine::default()
        };
        let (price, run) = jam_price(8, [WINDOW, 4096, 0, 0, 0], jam);
        assert_eq!(price, jam_gas::EXPORT);
        assert_eq!(run.invocation.registers[7], 5, "numbered from the offset");
        let mut segment = alloc::vec![0x5a; 4096];
        segment.resize(SEGMENT, 0);
        assert_eq!(run.exports, [segment], "the page, then zeros");
        // An empty export reads nothing, wherever it points: φ7 sign-extends
        // to past every 32-bit address.
        let (_, run) = jam_price(8, [u32::MAX, 0, 0, 0, 0], JamRefine::default());
        assert_eq!(run.invocation.registers[7], 0);
        assert_eq!(run.exports, [alloc::vec![0u8; SEGMENT]]);
        let full = JamRefine {
            export_offset: MAX_EXPORTS,
            ..JamRefine::default()
        };
        let (_, run) = jam_price(8, [WINDOW, 4096, 0, 0, 0], full);
        assert_eq!(run.invocation.registers[7], result::FULL);
        assert!(run.exports.is_empty());
    }

    #[test]
    fn the_jam_only_host_fetches_imports_payloads_and_parameters() {
        let segment = |byte: u8| alloc::vec![byte; SEGMENT];
        let jam = JamRefine {
            parameters: alloc::vec![9; 12],
            items: alloc::vec![
                JamItem {
                    payload: alloc::vec![1, 2, 3],
                    imports: alloc::vec![segment(7)],
                },
                JamItem {
                    payload: Vec::new(),
                    imports: alloc::vec![segment(8), segment(9)],
                },
            ],
            item: 1,
            ..JamRefine::default()
        };
        let fetch = |registers| jam_price(2, registers, jam.clone());
        let len = SEGMENT as u32;
        let (price, run) = fetch([WINDOW, 0, len, fetch_kind::OUR_IMPORT as u32, 1]);
        assert_eq!(price, 171, "a segment");
        assert_eq!(run.invocation.registers[7], SEGMENT as u64);
        let mut fetched = alloc::vec![0u8; SEGMENT];
        run.invocation.memory().read_bytes(WINDOW, &mut fetched);
        assert_eq!(fetched, segment(9), "the running item's second import");
        let (price, run) = fetch([WINDOW, 0, len, fetch_kind::OUR_IMPORT as u32, 2]);
        assert_eq!(
            (price, run.invocation.registers[7]),
            (171, result::NONE),
            "past the imports, at the same price"
        );
        let (_, run) = fetch([WINDOW, 1, 8, fetch_kind::ANY_IMPORT as u32, 0]);
        assert_eq!(run.invocation.registers[7], SEGMENT as u64);
        let (_, run) = fetch([WINDOW, 1, 8, fetch_kind::PAYLOAD as u32, 0]);
        assert_eq!(run.invocation.registers[7], 3);
        let mut bytes = [0u8; 3];
        run.invocation.memory().read_bytes(WINDOW, &mut bytes);
        assert_eq!(bytes, [2, 3, 0x5a], "copied from the offset");
        let (_, run) = fetch([WINDOW, 0, 64, fetch_kind::PARAMETERS as u32, 0]);
        assert_eq!(run.invocation.registers[7], 12);
    }

    #[test]
    fn the_jam_only_host_looks_up_its_services_preimages() {
        struct Own;
        impl Preimages for Own {
            fn preimage(&self, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>> {
                (service == 7 && *hash == [0x5a; 32]).then(|| alloc::vec![4; 10])
            }
        }
        let jam = JamRefine {
            service: 7,
            preimages: Some(alloc::sync::Arc::new(Own)),
            ..JamRefine::default()
        };
        // φ7 the service, φ8 the hash, φ9 the output, φ10 the offset, φ11
        // the length.
        let own = u32::MAX;
        let (price, run) = jam_price(7, [own, WINDOW, WINDOW + 4096, 0, 64], jam.clone());
        assert_eq!(price, jam_gas::HISTORICAL_LOOKUP);
        assert_eq!(run.invocation.registers[7], 10);
        let (_, other) = jam_price(7, [8, WINDOW, WINDOW + 4096, 0, 64], jam);
        assert_eq!(other.invocation.registers[7], result::NONE, "another's");
    }
}
