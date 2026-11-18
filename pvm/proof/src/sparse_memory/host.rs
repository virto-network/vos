//! The image from the interpreter's, the prover's half.

use super::*;

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
