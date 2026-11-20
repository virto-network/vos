//! Merge fields' rows (`vos_abi::merge`): a merge handler's writes, its
//! operation's entries, each kept against its author's stored one; and a
//! query's reads, each element's latest entry among the authors not cut
//! off. A query writes nothing, so it reads applied state.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use vos_abi::abi::{Failure, Keep, Kind, MergeRows, Op, cap, code, price};
use vos_abi::ids::InstanceId;
use vos_abi::keys::{self, AUTHOR, Transform};
use vos_abi::merge::{self, Cutoff, Entry};
use vos_abi::{Decode, Encode};

use super::Invocation;
use super::memory::{copy_out, read, read_key, write};
use crate::machines::Machine;
use crate::refine::base::Corrupt;

/// An element's entries, each its author and its entry's bytes.
type Entries = Vec<([u8; 32], Vec<u8>)>;

impl From<merge::Malformed> for Corrupt {
    fn from(_: merge::Malformed) -> Corrupt {
        Corrupt
    }
}

impl Invocation<'_> {
    /// A row operation of a merge step, or on a merge field's rows: a merge
    /// handler writes its merge fields alone; a query reads merge fields,
    /// filtered; nothing else reaches them. Apart, so the operations every
    /// other step makes keep their frames.
    #[cold]
    #[inline(never)]
    pub(super) fn merge_operation(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        op: Op,
    ) -> Result<(), Failure> {
        let r = machine.registers();
        let field = MergeRows::from_register(r[7]).ok_or(Failure::Trapped)?;
        let element = |machine: &mut Machine| {
            let key = read_key(machine, r[8], r[9])?;
            keys::merge_element(instance, field, &key)
        };
        let merging = self.entry == Kind::Merge;
        let querying = self.entry == Kind::Query;
        match op {
            Op::Get if querying => {
                if !machine.charge(price::SCAN) {
                    return Err(Failure::OutOfGas);
                }
                let element = element(machine)?;
                let value = self.merge_read(machine, instance, &element)?;
                self.copy_value(machine, value.as_deref())
            }
            Op::Put | Op::Delete if merging => {
                if !machine.charge(price::GET) {
                    return Err(Failure::OutOfGas);
                }
                let element = element(machine)?;
                let value = match op {
                    Op::Put => Some(read(machine, r[10], r[11], cap::VALUE)?),
                    _ => None,
                };
                if let Some((key, entry)) = self.merge_entry(element, field.keep, value)? {
                    self.write_bytes += key.len() + entry.len();
                    self.rows_written += 1;
                    if self.write_bytes > self.limits.step_writes
                        || self.rows_written > self.limits.step_rows
                    {
                        return Err(Failure::Cap);
                    }
                    self.frames
                        .last_mut()
                        .expect("a frame")
                        .insert(key, Some(entry));
                }
                machine.set_register(7, code::OK);
                Ok(())
            }
            Op::Scan if querying => {
                let after = match r[12] {
                    0 => None,
                    1 => Some(element(machine)?),
                    _ => return Err(Failure::Trapped),
                };
                let prefix = keys::merge_rows(instance, field);
                let capacity = (r[11] as usize).min(cap::SCAN);
                let (out, full) =
                    self.merge_scan(machine, instance, &prefix, after, capacity, field.transform)?;
                write(machine, r[10], &out)?;
                machine.set_register(7, if full { code::FULL } else { out.len() as u64 });
                Ok(())
            }
            _ => Err(Failure::Trapped),
        }
    }

    /// A read's value copied out as `Op::Get` copies it, or `NONE`.
    fn copy_value(&mut self, machine: &mut Machine, value: Option<&[u8]>) -> Result<(), Failure> {
        let r = machine.registers();
        match value {
            Some(value) => {
                copy_out(machine, value, r[10], r[11], r[12])?;
                machine.set_register(7, value.len() as u64);
            }
            None => machine.set_register(7, code::NONE),
        }
        Ok(())
    }

    /// A merge handler's write of `value` (`None`: a removal) to the
    /// element whose row is `element`: its operation's entry under its
    /// author, and the entry's bytes, when it replaces the author's stored
    /// one as `keep` says; `None` when it does not.
    fn merge_entry(
        &mut self,
        element: Vec<u8>,
        keep: Keep,
        value: Option<Vec<u8>>,
    ) -> Result<Option<(Vec<u8>, Vec<u8>)>, Failure> {
        let origin = self.origin.ok_or(Failure::Trapped)?;
        let entry = Entry::new(&origin, self.merge_writes, value.as_deref()).encode();
        self.merge_writes += 1;
        let key = keys::merge_entry(&element, &origin.author);
        let stored = self.read_state(&key)?;
        Ok(merge::replaces(&entry, stored.as_deref(), keep).then_some((key, entry)))
    }

    /// The value of the element whose row is `element`: its latest entry's
    /// among the authors `instance`'s cutoffs admit, `None` when that is a
    /// removal or none is admitted.
    fn merge_read(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        element: &[u8],
    ) -> Result<Option<Vec<u8>>, Failure> {
        let mut entries = Entries::new();
        let mut after = Vec::new();
        loop {
            let page = self.base.applied_rows(element, &after)?;
            let Some((last, _)) = page.last() else {
                break;
            };
            after = last.clone();
            for (key, value) in page {
                pay(machine, &key, &value)?;
                entries.push((author(element, &key)?, value));
            }
        }
        self.latest(machine, instance, &entries)
    }

    /// A query's scan of a merge field's rows under `prefix`, after the
    /// element whose row is `after` when given: each element whose latest
    /// admitted entry holds a value, its raw key and the value as a
    /// table's scan packs them (`Op::Scan`), until `capacity`; and whether
    /// the first alone did not fit. Each row walked is paid as it is read,
    /// so a field of removals stops where the gas does.
    fn merge_scan(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        prefix: &[u8],
        after: Option<Vec<u8>>,
        capacity: usize,
        transform: Transform,
    ) -> Result<(Vec<u8>, bool), Failure> {
        // After an element: past every entry of it.
        let mut after = match after {
            Some(element) => keys::merge_entry(&element, &[0xff; AUTHOR]),
            None => Vec::new(),
        };
        let mut out = Vec::new();
        let mut element: Option<Vec<u8>> = None;
        let mut entries = Entries::new();
        loop {
            let page = self.base.applied_rows(prefix, &after)?;
            let done = page.is_empty();
            if let Some((last, _)) = page.last() {
                after = last.clone();
            }
            // An empty element closes the last group.
            let rows = page.into_iter().map(Some).chain(done.then_some(None));
            for row in rows {
                let next = match &row {
                    Some((key, value)) => {
                        pay(machine, key, value)?;
                        let split = key.len().checked_sub(AUTHOR).ok_or(Corrupt)?;
                        Some(&key[..split])
                    }
                    None => None,
                };
                if element.is_some() && element.as_deref() != next {
                    let closed = element.take().expect("an element");
                    if let Some(value) = self.latest(machine, instance, &entries)? {
                        let raw = transform.raw(&closed[prefix.len()..]).ok_or(Corrupt)?;
                        if out.len() + 8 + raw.len() + value.len() > capacity {
                            let full = out.is_empty();
                            return Ok((out, full));
                        }
                        (raw.len() as u32).encode_to(&mut out);
                        out.extend_from_slice(&raw);
                        (value.len() as u32).encode_to(&mut out);
                        out.extend_from_slice(&value);
                    }
                    entries.clear();
                }
                if let Some((key, value)) = row {
                    let at = key.len() - AUTHOR;
                    if element.is_none() {
                        element = Some(key[..at].to_vec());
                    }
                    let author: [u8; 32] = key[at..].try_into().expect("an author's bytes");
                    entries.push((author, value));
                }
            }
            if done {
                return Ok((out, false));
            }
        }
    }

    /// The value of the latest of `entries` that `instance`'s cutoffs
    /// admit, if it holds one.
    fn latest(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        entries: &Entries,
    ) -> Result<Option<Vec<u8>>, Failure> {
        let mut cutoffs = BTreeMap::new();
        for (author, _) in entries {
            cutoffs.insert(*author, self.cutoff(machine, instance, author)?);
        }
        let entries = entries
            .iter()
            .map(|(author, bytes)| (*author, bytes.as_slice()));
        let latest = merge::latest(entries, |author| cutoffs.get(author).copied().flatten())
            .map_err(Corrupt::from)?;
        Ok(latest.and_then(|entry| entry.value).map(<[u8]>::to_vec))
    }

    /// `author`'s cutoff in `instance`'s scope, read, and paid, once a
    /// step.
    fn cutoff(
        &mut self,
        machine: &mut Machine,
        instance: InstanceId,
        author: &[u8; 32],
    ) -> Result<Option<Cutoff>, Failure> {
        if let Some(cutoff) = self.cutoffs.get(&(instance, *author)) {
            return Ok(*cutoff);
        }
        if !machine.charge(price::GET) {
            return Err(Failure::OutOfGas);
        }
        let cutoff = match self.read_state(&keys::cutoff(instance, author))? {
            Some(bytes) => Some(Cutoff::decode_exact(&bytes).ok_or(Corrupt)?),
            None => None,
        };
        self.cutoffs.insert((instance, *author), cutoff);
        Ok(cutoff)
    }
}

/// Pay for a merge field's row a read walks: its key's bytes as a scan's
/// are, and its value's as a copy's.
fn pay(machine: &mut Machine, key: &[u8], value: &[u8]) -> Result<(), Failure> {
    let cost = key.len() as u64 * price::KEY_BYTE + value.len() as u64 * price::PER_BYTE;
    if machine.charge(cost) {
        Ok(())
    } else {
        Err(Failure::OutOfGas)
    }
}

/// The author of an entry of the element whose row is `element`, from the
/// entry's key: the element's row, then the author's 32 bytes.
fn author(element: &[u8], key: &[u8]) -> Result<[u8; 32], Corrupt> {
    key.strip_prefix(element)
        .and_then(|author| author.try_into().ok())
        .ok_or(Corrupt)
}
