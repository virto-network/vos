//! Proof-owned canonical sparse memory images.
//!
//! This type is deliberately independent of `vos-pvm`: verifier-only users
//! build `vos-pvm-proof` without the optional interpreter dependency. The
//! prover feature supplies the one-way conversion from an interpreter
//! snapshot at the tracing boundary.

use alloc::vec::Vec;

pub const SPARSE_MEMORY_PAGE_SIZE: usize = 4096;

/// One non-zero page in a canonical sparse proof image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMemoryPage {
    pub page_index: u32,
    pub bytes: [u8; SPARSE_MEMORY_PAGE_SIZE],
}

/// Sorted non-zero pages plus the logical byte span they inhabit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMemoryImage {
    span: u64,
    pages: Vec<SparseMemoryPage>,
}

impl SparseMemoryImage {
    /// Construct a canonical image. Invalid spans, duplicate/unordered or
    /// out-of-range pages, and explicitly listed zero pages are rejected.
    pub fn new(span: u64, pages: Vec<SparseMemoryPage>) -> Option<Self> {
        if span > 1u64 << 32 || !span.is_multiple_of(SPARSE_MEMORY_PAGE_SIZE as u64) {
            return None;
        }
        let page_count = span / SPARSE_MEMORY_PAGE_SIZE as u64;
        let mut previous = None;
        for page in &pages {
            if u64::from(page.page_index) >= page_count
                || previous.is_some_and(|index| index >= page.page_index)
                || page.bytes.iter().all(|&byte| byte == 0)
            {
                return None;
            }
            previous = Some(page.page_index);
        }
        Some(Self { span, pages })
    }

    pub fn span(&self) -> u64 {
        self.span
    }

    pub fn pages(&self) -> &[SparseMemoryPage] {
        &self.pages
    }

    /// Return a page by index, or an all-zero page if it is absent.
    pub fn page(&self, page_index: u32) -> [u8; SPARSE_MEMORY_PAGE_SIZE] {
        self.pages
            .binary_search_by_key(&page_index, |page| page.page_index)
            .ok()
            .map_or([0; SPARSE_MEMORY_PAGE_SIZE], |index| {
                self.pages[index].bytes
            })
    }

    pub fn byte(&self, address: u32) -> u8 {
        if u64::from(address) >= self.span {
            return 0;
        }
        let page_index = address / SPARSE_MEMORY_PAGE_SIZE as u32;
        let offset = address as usize % SPARSE_MEMORY_PAGE_SIZE;
        self.pages
            .binary_search_by_key(&page_index, |page| page.page_index)
            .ok()
            .map_or(0, |index| self.pages[index].bytes[offset])
    }

    /// Apply bytes while retaining sorted/non-zero canonical form.
    pub fn write(&mut self, address: u32, mut bytes: &[u8]) -> bool {
        let Some(end) = u64::from(address).checked_add(bytes.len() as u64) else {
            return false;
        };
        if end > self.span {
            return false;
        }
        let mut cursor = u64::from(address);
        while !bytes.is_empty() {
            let page_index = (cursor / SPARSE_MEMORY_PAGE_SIZE as u64) as u32;
            let offset = cursor as usize % SPARSE_MEMORY_PAGE_SIZE;
            let len = (SPARSE_MEMORY_PAGE_SIZE - offset).min(bytes.len());
            let search = self
                .pages
                .binary_search_by_key(&page_index, |page| page.page_index);
            let index = match search {
                Ok(index) => index,
                Err(index) => {
                    if bytes[..len].iter().all(|&byte| byte == 0) {
                        cursor += len as u64;
                        bytes = &bytes[len..];
                        continue;
                    }
                    self.pages.insert(
                        index,
                        SparseMemoryPage {
                            page_index,
                            bytes: [0; SPARSE_MEMORY_PAGE_SIZE],
                        },
                    );
                    index
                }
            };
            self.pages[index].bytes[offset..offset + len].copy_from_slice(&bytes[..len]);
            if self.pages[index].bytes.iter().all(|&byte| byte == 0) {
                self.pages.remove(index);
            }
            cursor += len as u64;
            bytes = &bytes[len..];
        }
        true
    }
}

#[cfg(feature = "prover")]
impl From<vos_pvm::interpreter::SparseMemoryImage> for SparseMemoryImage {
    fn from(image: vos_pvm::interpreter::SparseMemoryImage) -> Self {
        debug_assert_eq!(SPARSE_MEMORY_PAGE_SIZE, vos_pvm::PVM_PAGE_SIZE as usize);
        let pages = image
            .pages()
            .iter()
            .map(|page| SparseMemoryPage {
                page_index: page.page_index,
                bytes: page.bytes,
            })
            .collect();
        Self::new(image.span(), pages).expect("interpreter sparse image is canonical")
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn canonical_high_page_image_updates_without_dense_allocation() {
        let address = u32::MAX - 31;
        let mut page = SparseMemoryPage {
            page_index: address / SPARSE_MEMORY_PAGE_SIZE as u32,
            bytes: [0; SPARSE_MEMORY_PAGE_SIZE],
        };
        page.bytes[address as usize % SPARSE_MEMORY_PAGE_SIZE] = 7;
        let mut image = SparseMemoryImage::new(1u64 << 32, vec![page]).unwrap();
        assert_eq!(image.byte(address), 7);
        assert!(image.write(address, &[0]));
        assert!(image.pages().is_empty());
    }
}
