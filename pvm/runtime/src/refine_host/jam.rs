//! The JAM-only host: refine as a JAM node runs it (Gray Paper v0.8.0's
//! Ψ_R, `pvm_invocations.tex`), which serves the text's refine calls,
//! `gas`, `grow_heap`, `fetch`, `historical_lookup`, `export` and the inner
//! machines', at its tariff (`definitions.tex`), and no VOS extension
//! whatever the context holds: every other call is unknown, `WHAT` at
//! `C_unknown`. Its state stand-in
//! (`RefineContext::try_run_jam_with_state_stand_in`) also serves
//! `state_read` and `state_scan` from the context's state reader, in place
//! of the witness a package carries: the builder's recording simulation
//! and tests run on it, and no JAM node does.

use alloc::borrow::Cow;
use alloc::vec::Vec;

use super::{Host, RefineContext, result};
use crate::refine::{Invocation, Machine, RefineError};
use crate::{ExitReason, Gas};

/// The JAM-only host's prices past the inner machines' (`crate::inner::gas`):
/// Gray Paper 0.8.0's host-call tariff (`definitions.tex`). Those measured
/// on PolkaJam 0.1.29 (Gray Paper 0.8.0) say so; it charged each to the
/// unit.
pub mod jam_gas {
    use super::FetchKind;
    use crate::Gas;

    /// `gas`, `C_G`; measured on PolkaJam.
    pub const GAS: Gas = 48;
    /// `grow_heap`'s base, `C_{Γ,c}`: all a call that grows nothing costs.
    /// The text's, not measured on PolkaJam.
    pub const GROW_HEAP_BASE: Gas = 275;
    /// `grow_heap`'s price a page grown, `C_{Γ,l}`; the text's.
    pub const GROW_HEAP_PER_PAGE: Gas = 121;
    /// `log`, no call of the text's: an unknown call's; measured on
    /// PolkaJam, which answers it `WHAT`.
    pub const LOG: Gas = UNSERVED;
    /// An unknown call, `C_unknown`, which answers `WHAT`; measured on
    /// PolkaJam.
    pub const UNSERVED: Gas = 1_000;
    /// `fetch` of kind `kind` and `len` bytes asked for: Gray Paper 0.8.0's
    /// per-kind table (`definitions.tex`, C_Y), a base and a price a KiB
    /// asked for by kind, served or answering `NONE`; a kind past the
    /// table's at its "otherwise" price. Measured on PolkaJam for an
    /// import (171) and a payload (95 and 96 a KiB); the other kinds are
    /// the text's. `None` past u64 ([`crate::inner::gas::memory`]).
    pub const fn fetch(kind: u64, len: u64) -> Option<Gas> {
        use FetchKind::*;
        let (base, per_kib): (Gas, Gas) = match FetchKind::from_u64(kind) {
            Some(Parameters) => (390, 0),
            Some(Entropy) => (103, 0),
            Some(AuthorizerTrace) => (80, 96),
            Some(AnyExtrinsic | OurExtrinsic) => (85, 96),
            Some(AnyImport | OurImport) => (171, 0),
            Some(Package) => (85, 96),
            Some(AuthorizerConfig) => (84, 0),
            Some(AuthorizerToken) => (88, 0),
            Some(Context) => (111, 0),
            Some(Items) => (317, 0),
            Some(Item) => (250, 0),
            Some(Payload) => (95, 96),
            Some(Inputs) => (287, 400),
            Some(Input) => (355, 344),
            None => (80, 0),
        };
        crate::inner::gas::memory(base, per_kib, len)
    }
    /// `export`, `C_E`; measured on PolkaJam at 4,096 bytes.
    pub const EXPORT: Gas = 3_521;
    /// `historical_lookup`, `C_{H,c}` and `C_{H,l}` a KiB by the length asked
    /// for: 1,125 for none, 1,203 for 300 bytes, 2,181 for 4 KiB, served or
    /// answering `NONE`, as measured on PolkaJam.
    pub const HISTORICAL_LOOKUP_BASE: Gas = 1_125;
    pub const HISTORICAL_LOOKUP_PER_KIB: Gas = 264;

    /// `historical_lookup` of `len` bytes; `None` past u64.
    pub const fn historical_lookup(len: u64) -> Option<Gas> {
        crate::inner::gas::memory(HISTORICAL_LOOKUP_BASE, HISTORICAL_LOOKUP_PER_KIB, len)
    }
}

/// A segment: what one `export` puts out and one import brings in, its
/// bytes zero-padded to this length.
pub const SEGMENT: usize = 4104;
/// The most segments a work package exports.
pub const MAX_EXPORTS: u64 = 3072;

/// `fetch`'s kinds (φ10), Gray Paper 0.8.0's: what each asks for, φ11 and
/// φ12 its indices where it takes them. The JAM-only host serves every
/// kind refine has, 0 to 13; accumulate's inputs answer `NONE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum FetchKind {
    /// The protocol's parameters, encoded.
    Parameters = 0,
    /// The entropy.
    Entropy = 1,
    /// The authorizer's trace.
    AuthorizerTrace = 2,
    /// Extrinsic φ12 of work item φ11.
    AnyExtrinsic = 3,
    /// Extrinsic φ11 of the running work item.
    OurExtrinsic = 4,
    /// Import φ12 of work item φ11.
    AnyImport = 5,
    /// Import φ11 of the running work item.
    OurImport = 6,
    /// The work package, encoded.
    Package = 7,
    /// The authorizer's configuration.
    AuthorizerConfig = 8,
    /// The authorization token.
    AuthorizerToken = 9,
    /// The refinement context, encoded.
    Context = 10,
    /// Every work item's summary.
    Items = 11,
    /// Work item φ11's summary.
    Item = 12,
    /// Work item φ11's payload.
    Payload = 13,
    /// Accumulate's inputs, all of them.
    Inputs = 14,
    /// Accumulate's input φ11.
    Input = 15,
}

impl FetchKind {
    /// The kind φ10 names; none past the table.
    pub const fn from_u64(kind: u64) -> Option<Self> {
        use FetchKind::*;
        Some(match kind {
            0 => Parameters,
            1 => Entropy,
            2 => AuthorizerTrace,
            3 => AnyExtrinsic,
            4 => OurExtrinsic,
            5 => AnyImport,
            6 => OurImport,
            7 => Package,
            8 => AuthorizerConfig,
            9 => AuthorizerToken,
            10 => Context,
            11 => Items,
            12 => Item,
            13 => Payload,
            14 => Inputs,
            15 => Input,
            _ => return None,
        })
    }
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
    /// The protocol's parameters, encoded (`fetch` kind 0).
    pub parameters: Vec<u8>,
    /// The authorizer's trace (kind 2).
    pub authorizer_trace: Vec<u8>,
    /// The work package, encoded (kind 7): given whole, as the fixture
    /// does not encode a package, so it is the caller's to keep it the
    /// encoding of the package [`Self::items`] and the fields below are
    /// from.
    pub package: Vec<u8>,
    /// The package's authorizer configuration (kind 8).
    pub authorizer_config: Vec<u8>,
    /// The package's authorization token (kind 9).
    pub authorizer_token: Vec<u8>,
    /// The package's refinement context, encoded (kind 10).
    pub context: Vec<u8>,
    /// The package's work items (kinds 3 to 6, 11 to 13).
    pub items: Vec<JamItem>,
    /// The running item's index among them.
    pub item: usize,
    /// The segments the package's earlier items export: `export` numbers
    /// this item's from it.
    pub export_offset: u64,
    pub preimages: Option<alloc::sync::Arc<dyn Preimages>>,
}

/// A work item of a package: its payload, the segments it imports and its
/// extrinsics' data, and what its summary (`fetch` kinds 11 and 12) holds
/// besides their counts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JamItem {
    pub payload: Vec<u8>,
    pub imports: Vec<Vec<u8>>,
    pub extrinsics: Vec<Vec<u8>>,
    /// The item's service.
    pub service: u32,
    /// The hash of its service's code.
    pub code_hash: [u8; 32],
    /// Its refine and accumulate gas limits.
    pub refine_gas: u64,
    pub accumulate_gas: u64,
    /// The segments it exports.
    pub export_count: u16,
}

impl JamItem {
    /// Its summary, Gray Paper `S(w)`: `E_4(service) ⌢ code_hash ⌢
    /// E_8(refine_gas, accumulate_gas) ⌢ E_2(export_count, |imports|,
    /// |extrinsics|) ⌢ E_4(|payload|)`. A package's counts are within the
    /// fixed widths (at most 3,072 imports, 128 extrinsics); one past them
    /// is written at the width's largest.
    pub fn summary(&self) -> Vec<u8> {
        let count = |n: usize| u16::try_from(n).unwrap_or(u16::MAX).to_le_bytes();
        let mut summary = Vec::with_capacity(4 + 32 + 16 + 6 + 4);
        summary.extend_from_slice(&self.service.to_le_bytes());
        summary.extend_from_slice(&self.code_hash);
        summary.extend_from_slice(&self.refine_gas.to_le_bytes());
        summary.extend_from_slice(&self.accumulate_gas.to_le_bytes());
        summary.extend_from_slice(&self.export_count.to_le_bytes());
        summary.extend_from_slice(&count(self.imports.len()));
        summary.extend_from_slice(&count(self.extrinsics.len()));
        let payload = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
        summary.extend_from_slice(&payload.to_le_bytes());
        summary
    }
}

/// A JAM-only run: the invocation and the segments it exported, each
/// [`SEGMENT`] bytes.
#[derive(Debug)]
pub struct JamRun {
    pub invocation: Invocation,
    pub exports: Vec<Vec<u8>>,
}

impl RefineContext {
    /// Run as a JAM node would, serving what `jam` gives: Gray Paper
    /// v0.8.0's refine calls at its tariff ([`jam_gas`] and the inner
    /// machines' `crate::inner::gas`), no precompile computed and no VOS
    /// extension served, whatever pool or state reader the context holds;
    /// every other call answers `WHAT` at `C_unknown` while execution
    /// continues.
    pub fn try_run_jam(mut self, jam: JamRefine) -> Result<JamRun, RefineError> {
        self.host = Host::Jam { state: false };
        self.run_jam(jam)
    }

    /// [`Self::try_run_jam`], and `state_read` and `state_scan` served from
    /// the context's state reader at the VOS node's prices: a stand-in for
    /// the witness a package carries, which the builder's recording
    /// simulation and tests run a batch's refine on. It is no JAM host: a
    /// JAM node serves no state. `INSTANTIATE` and every other VOS call
    /// still answer `WHAT`. [`RefineError::NoStateReader`] when the
    /// context holds no state reader.
    pub fn try_run_jam_with_state_stand_in(
        mut self,
        jam: JamRefine,
    ) -> Result<JamRun, RefineError> {
        if self.state.is_none() {
            return Err(RefineError::NoStateReader);
        }
        self.host = Host::Jam { state: true };
        self.run_jam(jam)
    }

    fn run_jam(self, jam: JamRefine) -> Result<JamRun, RefineError> {
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
/// `grow_heap`, `fetch`, `export` and `historical_lookup` from `jam`; `log`
/// and every other call answer `WHAT`.
fn serve_jam(
    jam: &JamRefine,
    exports: &mut Vec<Vec<u8>>,
    id: u64,
    machine: &mut Machine,
) -> Result<(), ExitReason> {
    use crate::inner::gp_call;
    let r = *machine.registers();
    // A whole price past u64 (`None`) is more than the machine holds.
    let charge = |machine: &mut Machine, gas: Option<Gas>| match gas {
        Some(gas) if machine.charge(gas) => Ok(()),
        _ => {
            machine.charge(Gas::MAX);
            Err(ExitReason::OutOfGas)
        }
    };
    let answer = match u32::try_from(id) {
        Ok(gp_call::GROW_HEAP) => grow_heap(machine, r[7])?,
        Ok(gp_call::FETCH) => {
            charge(machine, jam_gas::fetch(r[10], r[9]))?;
            let value = fetch(jam, r[10], r[11], r[12]);
            copy_out(machine, value.as_deref(), r[7], r[8], r[9])?
        }
        Ok(gp_call::EXPORT) => {
            charge(machine, Some(jam_gas::EXPORT))?;
            let mut segment = machine
                .read_range(r[7], r[8].min(SEGMENT as u64))
                .ok_or(ExitReason::Panic)?;
            segment.resize(SEGMENT, 0);
            let index = jam.export_offset + exports.len() as u64;
            if index >= MAX_EXPORTS {
                result::FULL
            } else {
                exports.push(segment);
                index
            }
        }
        Ok(gp_call::HISTORICAL_LOOKUP) => {
            charge(machine, jam_gas::historical_lookup(r[11]))?;
            let hash: [u8; 32] = machine
                .read_range(r[8], 32)
                .ok_or(ExitReason::Panic)?
                .try_into()
                .expect("32 bytes read");
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
            charge(machine, Some(jam_gas::LOG))?;
            result::WHAT
        }
        _ => {
            charge(machine, Some(jam_gas::UNSERVED))?;
            result::WHAT
        }
    };
    machine.registers_mut()[7] = answer;
    Ok(())
}

/// Refine's `fetch` value of `kind` with indices `first` and `second` (φ10
/// to φ12), Gray Paper Ω_Y's under Ψ_R: the zero hash for the entropy, the
/// package's fields, and none for accumulate's inputs or a kind past the
/// table.
fn fetch<'a>(jam: &'a JamRefine, kind: u64, first: u64, second: u64) -> Option<Cow<'a, [u8]>> {
    let index = |register: u64| usize::try_from(register).unwrap_or(usize::MAX);
    let item = |at: usize| jam.items.get(at);
    let ours = || item(jam.item);
    let bytes = |bytes: &'a [u8]| Some(Cow::Borrowed(bytes));
    match FetchKind::from_u64(kind)? {
        FetchKind::Parameters => bytes(&jam.parameters),
        FetchKind::Entropy => Some(Cow::Borrowed(&[0; 32])),
        FetchKind::AuthorizerTrace => bytes(&jam.authorizer_trace),
        FetchKind::AnyExtrinsic => bytes(item(index(first))?.extrinsics.get(index(second))?),
        FetchKind::OurExtrinsic => bytes(ours()?.extrinsics.get(index(first))?),
        FetchKind::AnyImport => bytes(item(index(first))?.imports.get(index(second))?),
        FetchKind::OurImport => bytes(ours()?.imports.get(index(first))?),
        FetchKind::Package => bytes(&jam.package),
        FetchKind::AuthorizerConfig => bytes(&jam.authorizer_config),
        FetchKind::AuthorizerToken => bytes(&jam.authorizer_token),
        FetchKind::Context => bytes(&jam.context),
        FetchKind::Items => {
            let mut encoded = Vec::new();
            vos_pvm_program::encode_nat(jam.items.len() as u64, &mut encoded);
            for item in &jam.items {
                encoded.extend_from_slice(&item.summary());
            }
            Some(Cow::Owned(encoded))
        }
        FetchKind::Item => Some(Cow::Owned(item(index(first))?.summary())),
        FetchKind::Payload => bytes(&item(index(first))?.payload),
        FetchKind::Inputs | FetchKind::Input => None,
    }
}

/// Gray Paper v0.8.0's `grow_heap` (Ω_Γ, `pvm_invocations.tex`): the
/// read-write data's writable pages `[a, h)` grown to `[a, φ7)` when
/// `h < φ7 <= b`, at `C_{Γ,c} + (φ7 - h) · C_{Γ,l}`, out of gas with the
/// gas left untouched when that is more than the machine holds; otherwise
/// nothing grown, at `C_{Γ,c}`. φ7 becomes the heap's end page after the
/// call, `h` or the new φ7. A machine of a bare code blob has no heap:
/// the call is unknown there.
fn grow_heap(machine: &mut Machine, requested: u64) -> Result<u64, ExitReason> {
    use jam_gas::{GROW_HEAP_BASE, GROW_HEAP_PER_PAGE, UNSERVED};
    let Some(heap) = machine.heap_pages() else {
        return if machine.charge(UNSERVED) {
            Ok(result::WHAT)
        } else {
            Err(ExitReason::OutOfGas)
        };
    };
    let (start, stop) = (heap.start as usize, heap.end as usize);
    let writable: usize = machine
        .memory()
        .permission_runs()
        .into_iter()
        .filter(|&(_, _, permission)| permission == crate::interpreter::PERM_RW)
        .map(|(first, count, _)| (first + count).min(stop).saturating_sub(first.max(start)))
        .sum();
    let writable = writable as u64;
    let end = u64::from(heap.start) + writable;
    if requested <= end || requested > u64::from(heap.end) {
        return if machine.charge(GROW_HEAP_BASE) {
            Ok(end)
        } else {
            Err(ExitReason::OutOfGas)
        };
    }
    let price = GROW_HEAP_BASE + (requested - end) * GROW_HEAP_PER_PAGE;
    if machine.gas_remaining() < price {
        return Err(ExitReason::OutOfGas);
    }
    machine.charge(price);
    let grown = machine.memory_mut().set_page_range(
        start,
        requested as usize - start,
        crate::interpreter::PERM_RW,
    );
    assert!(
        grown,
        "a standard layout's heap lies in its machine's memory"
    );
    Ok(requested)
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
    let window = crate::refine::window(value.len(), offset, len);
    let (address, len) = machine
        .writable_range(address, window.len() as u64)
        .ok_or(ExitReason::Panic)?;
    if len > 0
        && !machine
            .memory_mut()
            .write_bytes_checked(address, &value[window])
    {
        return Err(ExitReason::Panic);
    }
    Ok(value.len() as u64)
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
    fn the_jam_only_host_charges_the_gray_papers_tariff() {
        assert_eq!(
            (jam_gas::GAS, jam_gas::LOG, jam_gas::UNSERVED),
            (48, 1_000, 1_000)
        );
        // Gray Paper 0.8.0's `fetch` table, by kind: an import flat, a
        // payload or an extrinsic by the KiB asked for; the payload's
        // prices PolkaJam 0.1.29 charged a 186 KiB fetch to the unit.
        assert_eq!(
            jam_gas::fetch(FetchKind::OurImport as u64, SEGMENT as u64),
            Some(171),
            "a segment's fetch"
        );
        assert_eq!(
            jam_gas::fetch(FetchKind::AnyImport as u64, 1 << 20),
            Some(171)
        );
        assert_eq!(
            jam_gas::fetch(FetchKind::Payload as u64, 186 << 10),
            Some(95 + 96 * 186)
        );
        assert_eq!(
            jam_gas::fetch(FetchKind::OurExtrinsic as u64, 1),
            Some(85 + 1)
        );
        assert_eq!(jam_gas::fetch(FetchKind::Parameters as u64, 64), Some(390));
        assert_eq!(jam_gas::fetch(16, 1 << 20), Some(80), "past the table");
        // The whole length asked for, priced exactly: ceil(96 · (2^64 - 1)
        // / 1024) = 1,729,382,256,910,270,464, plus the base.
        assert_eq!(
            jam_gas::fetch(FetchKind::Payload as u64, u64::MAX),
            Some(95 + 1_729_382_256_910_270_464)
        );
        assert_eq!(jam_gas::EXPORT, 3_521);
        assert_eq!(
            [0, 300, 4096].map(jam_gas::historical_lookup),
            [Some(1_125), Some(1_203), Some(2_181)]
        );
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
                    ..JamItem::default()
                },
                JamItem {
                    imports: alloc::vec![segment(8), segment(9)],
                    ..JamItem::default()
                },
            ],
            item: 1,
            ..JamRefine::default()
        };
        let fetch = |registers| jam_price(2, registers, jam.clone());
        let len = SEGMENT as u32;
        let (price, run) = fetch([WINDOW, 0, len, FetchKind::OurImport as u32, 1]);
        assert_eq!(price, 171, "a segment");
        assert_eq!(run.invocation.registers[7], SEGMENT as u64);
        let mut fetched = alloc::vec![0u8; SEGMENT];
        run.invocation.memory().read_bytes(WINDOW, &mut fetched);
        assert_eq!(fetched, segment(9), "the running item's second import");
        let (price, run) = fetch([WINDOW, 0, len, FetchKind::OurImport as u32, 2]);
        assert_eq!(
            (price, run.invocation.registers[7]),
            (171, result::NONE),
            "past the imports, at the same price"
        );
        let (_, run) = fetch([WINDOW, 1, 8, FetchKind::AnyImport as u32, 0]);
        assert_eq!(run.invocation.registers[7], SEGMENT as u64);
        let (_, run) = fetch([WINDOW, 1, 8, FetchKind::Payload as u32, 0]);
        assert_eq!(run.invocation.registers[7], 3);
        let mut bytes = [0u8; 3];
        run.invocation.memory().read_bytes(WINDOW, &mut bytes);
        assert_eq!(bytes, [2, 3, 0x5a], "copied from the offset");
        let (_, run) = fetch([WINDOW, 0, 64, FetchKind::Parameters as u32, 0]);
        assert_eq!(run.invocation.registers[7], 12);
        let (price, _) = fetch([WINDOW, 0, 64, FetchKind::Parameters as u32, 0]);
        assert_eq!(price, 390);
        let (price, _) = fetch([WINDOW, 0, 2048, FetchKind::Payload as u32, 0]);
        assert_eq!(price, 95 + 192, "by the length asked for");
    }

    #[test]
    fn the_jam_only_host_fetches_extrinsics() {
        let jam = JamRefine {
            items: alloc::vec![
                JamItem {
                    extrinsics: alloc::vec![alloc::vec![1; 5]],
                    ..JamItem::default()
                },
                JamItem {
                    extrinsics: alloc::vec![alloc::vec![2; 3], alloc::vec![3; 4]],
                    ..JamItem::default()
                },
            ],
            item: 1,
            ..JamRefine::default()
        };
        let fetch = |registers| jam_price(2, registers, jam.clone());
        let (price, run) = fetch([WINDOW, 0, 1024, FetchKind::OurExtrinsic as u32, 1]);
        assert_eq!(price, 85 + 96, "a KiB asked for");
        assert_eq!(run.invocation.registers[7], 4);
        let mut bytes = [0u8; 5];
        run.invocation.memory().read_bytes(WINDOW, &mut bytes);
        assert_eq!(bytes, [3, 3, 3, 3, 0x5a], "the running item's second");
        let (_, run) = fetch([WINDOW, 0, 8, FetchKind::OurExtrinsic as u32, 2]);
        assert_eq!(run.invocation.registers[7], result::NONE, "past them");
        let (_, run) = fetch([WINDOW, 0, 8, FetchKind::AnyExtrinsic as u32, 0]);
        assert_eq!(run.invocation.registers[7], 5, "the first item's first");
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
        assert_eq!(Some(price), jam_gas::historical_lookup(64));
        assert_eq!(run.invocation.registers[7], 10);
        let (_, other) = jam_price(7, [8, WINDOW, WINDOW + 4096, 0, 64], jam);
        assert_eq!(other.invocation.registers[7], result::NONE, "another's");
    }

    /// `calling_program`'s heap: read-write data from page 32, two pages
    /// of it; `grow_heap`'s bound a zone below its one stack page.
    const HEAP_START: u64 = 0x2_0000 / 4096;
    const HEAP_END: u64 = HEAP_START + 2;
    const HEAP_BOUND: u64 = ((1 << 32) - 3 * (1 << 16) - (1 << 24) - 4096) / 4096;

    /// `grow_heap` grows the read-write data's writable pages to φ7 at
    /// `C_{Γ,c}` and `C_{Γ,l}` a page grown, and answers the heap's end.
    #[test]
    fn grow_heap_grows_the_writable_pages_at_the_tariff() {
        let grown = HEAP_END + 2;
        let (price, run) = jam_price(1, [grown as u32, 0, 0, 0, 0], JamRefine::default());
        assert_eq!(price, 275 + 2 * 121);
        assert_eq!(run.invocation.registers[7], grown);
        let memory = run.invocation.memory();
        for page in HEAP_START..grown {
            assert_eq!(
                memory.page_perm(page as usize),
                Some(crate::interpreter::PERM_RW),
                "page {page}"
            );
        }
        assert_eq!(
            memory.page_perm(grown as usize),
            Some(crate::interpreter::PERM_NONE)
        );
    }

    /// Asking for no more than the heap holds, or past its bound, grows
    /// nothing at the base price and answers the heap's end; asking for
    /// more than the gas pays is out of gas with the gas left untouched.
    #[test]
    fn grow_heap_grows_nothing_out_of_its_bounds() {
        for requested in [0, HEAP_START, HEAP_END, HEAP_BOUND + 1, u64::from(u32::MAX)] {
            let (price, run) = jam_price(1, [requested as u32, 0, 0, 0, 0], JamRefine::default());
            assert_eq!(
                (price, run.invocation.registers[7]),
                (275, HEAP_END),
                "{requested}"
            );
        }
        let program = calling_program(1, [HEAP_BOUND as u32, 0, 0, 0, 0]);
        let calibration = RefineContext::load(&calling_program(0, [0; 5]), &[], 1_000_000)
            .unwrap()
            .try_run_jam(JamRefine::default())
            .unwrap()
            .invocation;
        let starved = RefineContext::load(&program, &[], 1_000_000)
            .unwrap()
            .try_run_jam(JamRefine::default())
            .unwrap()
            .invocation;
        assert_eq!(starved.exit, ExitReason::OutOfGas);
        assert_eq!(
            starved.gas_used,
            calibration.gas_used - jam_gas::GAS,
            "the instructions before the call alone"
        );
        assert_eq!(
            starved.memory().page_perm(HEAP_END as usize),
            Some(crate::interpreter::PERM_NONE)
        );
    }

    /// Refine's `fetch` serves the zero hash as its entropy and the
    /// package's fields, each at its kind's price.
    #[test]
    fn the_jam_only_host_fetches_the_entropy_and_the_package() {
        let item = |service: u32, payload: Vec<u8>| JamItem {
            payload,
            imports: alloc::vec![alloc::vec![0; SEGMENT]],
            extrinsics: alloc::vec![alloc::vec![1], alloc::vec![2, 3]],
            service,
            code_hash: [service as u8; 32],
            refine_gas: 1_000 + u64::from(service),
            accumulate_gas: 2_000,
            export_count: 4,
        };
        let jam = JamRefine {
            authorizer_trace: alloc::vec![0xa1; 5],
            package: alloc::vec![0xb2; 40],
            authorizer_config: alloc::vec![0xc3; 3],
            authorizer_token: alloc::vec![0xd4; 2],
            context: alloc::vec![0xe5; 7],
            items: alloc::vec![item(9, alloc::vec![7; 6]), item(10, Vec::new())],
            ..JamRefine::default()
        };
        let fetch = |kind: FetchKind, index: u32| {
            let (price, run) = jam_price(2, [WINDOW, 0, 4096, kind as u32, index], jam.clone());
            let len = run.invocation.registers[7];
            let mut bytes = alloc::vec![0u8; len.min(4096) as usize];
            run.invocation.memory().read_bytes(WINDOW, &mut bytes);
            (price, len, bytes)
        };
        let per_kib = (96 * 4096u64).div_ceil(1024);
        assert_eq!(fetch(FetchKind::Entropy, 0), (103, 32, alloc::vec![0; 32]));
        assert_eq!(
            fetch(FetchKind::AuthorizerTrace, 0),
            (80 + per_kib, 5, jam.authorizer_trace.clone())
        );
        assert_eq!(
            fetch(FetchKind::Package, 0),
            (85 + per_kib, 40, jam.package.clone())
        );
        assert_eq!(
            fetch(FetchKind::AuthorizerConfig, 0),
            (84, 3, jam.authorizer_config.clone())
        );
        assert_eq!(
            fetch(FetchKind::AuthorizerToken, 0),
            (88, 2, jam.authorizer_token.clone())
        );
        assert_eq!(fetch(FetchKind::Context, 0), (111, 7, jam.context.clone()));
        // S(w): E_4(9), the code hash, E_8(1,009, 2,000), E_2(4, 1, 2),
        // E_4(6), written out.
        let mut summary = alloc::vec![9, 0, 0, 0];
        summary.extend_from_slice(&[9; 32]);
        summary.extend_from_slice(&[0xf1, 3, 0, 0, 0, 0, 0, 0]);
        summary.extend_from_slice(&[0xd0, 7, 0, 0, 0, 0, 0, 0]);
        summary.extend_from_slice(&[4, 0, 1, 0, 2, 0, 6, 0, 0, 0]);
        assert_eq!(summary.len(), 62);
        assert_eq!(fetch(FetchKind::Item, 0), (250, 62, summary.clone()));
        let (price, len, items) = fetch(FetchKind::Items, 0);
        assert_eq!((price, len), (317, 1 + 2 * 62));
        assert_eq!(items[0], 2, "a length-prefixed sequence");
        assert_eq!(&items[1..63], &summary[..]);
        assert_eq!(items[63..67], [10, 0, 0, 0]);
        assert_eq!(fetch(FetchKind::Item, 2).1, result::NONE, "past the items");
        for kind in [FetchKind::Inputs, FetchKind::Input] {
            assert_eq!(fetch(kind, 0).1, result::NONE, "accumulate's alone");
        }
    }

    /// A grown page is the guest's to write, on every backend: `grow_heap`
    /// to φ7 = 35, a byte stored on page 34, a halt; without the growth the
    /// store faults.
    #[test]
    fn a_grown_page_is_written_on_every_backend() {
        let program = |requested: u8| {
            let (code, starts) = crate::test_support::code(&[
                &[51, 7, requested],        // load_imm φ7, requested
                &[10, 1],                   // ecalli grow_heap
                &[59, 7, 0x00, 0x20, 0x02], // store_u8 φ7 at 0x2_2000
                &[50, 0],                   // jump_ind φ0 (halt)
            ]);
            crate::refine_host::tests::standard_program_with_rw(&code, &starts, &[0; 8192])
        };
        let mut backends = alloc::vec![crate::PvmBackend::ForceInterpreter];
        if cfg!(all(
            feature = "std",
            target_os = "linux",
            target_arch = "x86_64"
        )) {
            backends.push(crate::PvmBackend::ForceRecompiler);
        }
        for backend in backends {
            let run = |requested| {
                RefineContext::load_with_backend(
                    &program(requested),
                    &[],
                    1_000_000,
                    crate::refine::MemoryModel::Auto,
                    backend,
                )
                .unwrap()
                .try_run_jam(JamRefine::default())
                .unwrap()
                .invocation
            };
            let grown = run(35);
            assert_eq!(grown.exit, ExitReason::Halt, "{backend:?}");
            let mut byte = [0u8];
            grown.memory().read_bytes(0x2_2000, &mut byte);
            assert_eq!(byte, [35], "{backend:?}");
            let ungrown = run(34);
            assert_eq!(
                ungrown.exit,
                ExitReason::PageFault(0x2_2000),
                "{backend:?}: the heap's end already"
            );
        }
    }

    /// A fetch prices the whole length asked for, exactly: φ9 = 2^64 - 1
    /// at a payload's 96 a KiB costs 95 + 1,729,382,256,910,270,464, which
    /// a machine holding that gas pays, and one holding a unit less does
    /// not.
    #[test]
    fn a_fetch_of_the_whole_length_is_priced_exactly() {
        const PRICE: u64 = 95 + 1_729_382_256_910_270_464;
        let jam = JamRefine {
            items: alloc::vec![JamItem {
                payload: alloc::vec![1, 2, 3],
                ..JamItem::default()
            }],
            ..JamRefine::default()
        };
        // φ9 = u32::MAX, sign-extended by load_imm to 2^64 - 1.
        let registers = [WINDOW, 0, u32::MAX, FetchKind::Payload as u32, 0];
        let instructions = RefineContext::load(&calling_program(0, registers), &[], 1_000)
            .unwrap()
            .try_run_jam(JamRefine::default())
            .unwrap()
            .invocation
            .gas_used
            - jam_gas::GAS;
        let run = |gas| {
            RefineContext::load(&calling_program(2, registers), &[], gas)
                .unwrap()
                .try_run_jam(jam.clone())
                .unwrap()
                .invocation
        };
        let paid = run(instructions + PRICE);
        assert_eq!(paid.exit, ExitReason::Halt);
        assert_eq!(paid.registers[7], 3);
        assert_eq!(paid.gas_used, instructions + PRICE);
        let short = run(instructions + PRICE - 1);
        assert_eq!(short.exit, ExitReason::OutOfGas);
    }
}
