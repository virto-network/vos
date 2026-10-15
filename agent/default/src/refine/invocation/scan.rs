//! An invocation's reads: a value, and a table's rows, through every
//! overlay.

use alloc::vec::Vec;

use vos_wire::Encode;
use vos_wire::keys::Transform;

use super::Invocation;
use crate::refine::base::Corrupt;

impl Invocation<'_> {
    /// A value through the call frames, the refine's earlier steps and
    /// applied state.
    pub(crate) fn read_state(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        for frame in self.frames.iter().rev() {
            if let Some(value) = frame.get(key) {
                return Ok(value.clone());
            }
        }
        self.base.read(key)
    }

    /// The rows of the table at `prefix`, after `after` when given, merged
    /// through every overlay and packed until `capacity`, each with the
    /// key its `transform` was given; whether the first row alone did not
    /// fit; and the bytes of the keys returned. The sources are walked in
    /// key order and the walk stops
    /// when the buffer is full, so a scan costs the rows it returns, not
    /// the overlays' size.
    pub(crate) fn scan(
        &self,
        prefix: &[u8],
        mut after: Option<Vec<u8>>,
        capacity: usize,
        transform: Transform,
    ) -> Result<(Vec<u8>, bool, usize), Corrupt> {
        use core::ops::Bound;
        let mut out = Vec::new();
        let mut returned = 0;
        loop {
            // A page of applied rows bounds which overlay rows join it; an
            // empty page means no applied rows remain, so all of them do.
            let page = self
                .base
                .applied_rows(prefix, after.as_deref().unwrap_or(&[]))?;
            let bound = page.last().map(|(key, _)| key.as_slice());
            // A cursor below the prefix starts the scan at the prefix, as
            // the node's applied rows do; one above it leaves no row.
            let lower = match &after {
                Some(after) if after.as_slice() >= prefix => Bound::Excluded(after.as_slice()),
                _ => Bound::Included(prefix),
            };
            let joins =
                |key: &[u8]| key.starts_with(prefix) && bound.is_none_or(|bound| key <= bound);
            // Lowest precedence first: the refine's earlier steps' writes,
            // then each frame up the stack.
            let mut overlays: Vec<_> = core::iter::once(&self.base.earlier)
                .chain(self.frames.iter())
                .map(|overlay| {
                    overlay
                        .range::<[u8], _>((lower, Bound::Unbounded))
                        .take_while(|(key, _)| joins(key))
                        .peekable()
                })
                .collect();
            let mut applied = page.iter().peekable();
            loop {
                let mut next = applied.peek().copied().map(|(key, _)| key.as_slice());
                for overlay in &mut overlays {
                    if let Some(&(key, _)) = overlay.peek()
                        && next.is_none_or(|next| key.as_slice() < next)
                    {
                        next = Some(key.as_slice());
                    }
                }
                let Some(key) = next else {
                    break;
                };
                // The source the key came from holds it without a compare:
                // keys here run to kilobytes.
                let holds = |head: &[u8]| core::ptr::eq(head, key) || head == key;
                // The highest source holding the key decides its value.
                let mut value: Option<Option<&[u8]>> = None;
                for overlay in overlays.iter_mut().rev() {
                    if overlay.peek().is_some_and(|&(head, _)| holds(head)) {
                        let (_, held) = overlay.next().expect("peeked");
                        value.get_or_insert(held.as_deref());
                    }
                }
                if applied.peek().is_some_and(|(head, _)| holds(head)) {
                    let (_, held) = applied.next().expect("peeked");
                    value.get_or_insert(Some(held));
                }
                let Some(Some(value)) = value else { continue };
                let raw = transform.raw(&key[prefix.len()..]).ok_or(Corrupt)?;
                if out.len() + 8 + raw.len() + value.len() > capacity {
                    let full = out.is_empty();
                    return Ok((out, full, returned));
                }
                returned += raw.len();
                (raw.len() as u32).encode_to(&mut out);
                out.extend_from_slice(&raw);
                (value.len() as u32).encode_to(&mut out);
                out.extend_from_slice(value);
            }
            match bound {
                Some(bound) => after = Some(bound.to_vec()),
                None => return Ok((out, false, returned)),
            }
        }
    }
}
