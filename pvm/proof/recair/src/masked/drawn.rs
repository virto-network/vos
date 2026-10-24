//! The masking's randomness as it is drawn, shown to a carrier audit under
//! the `watch` feature ([`drawn_in`]): each attempt's operating-system
//! bytes and seed, the witness digest it is hedged with, the blinding
//! values, and the seeds that fix every mask, salt and `R` column. None of
//! it may leave the prover role. Without `watch`, nothing is kept.

/// One value of the masking's randomness: what it is and its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drawn {
    pub what: &'static str,
    pub bytes: Vec<u8>,
}

#[cfg(feature = "watch")]
std::thread_local! {
    static DRAWN: std::cell::RefCell<Option<Vec<Drawn>>> = const { std::cell::RefCell::new(None) };
}

/// Keeps `bytes`, drawn as `what`, when this thread runs in [`drawn_in`].
#[inline]
pub(crate) fn note(what: &'static str, bytes: &[u8]) {
    #[cfg(feature = "watch")]
    DRAWN.with(|drawn| {
        if let Some(drawn) = drawn.borrow_mut().as_mut() {
            drawn.push(Drawn {
                what,
                bytes: bytes.to_vec(),
            });
        }
    });
    #[cfg(not(feature = "watch"))]
    let _ = (what, bytes);
}

/// `prove` run, and the randomness its masked proofs drew on this thread,
/// in order: none without `watch`.
pub fn drawn_in<T>(prove: impl FnOnce() -> T) -> (T, Vec<Drawn>) {
    #[cfg(feature = "watch")]
    {
        let outer = DRAWN.with(|drawn| drawn.replace(Some(Vec::new())));
        let proved = prove();
        let drawn = DRAWN.with(|drawn| drawn.replace(outer)).unwrap_or_default();
        (proved, drawn)
    }
    #[cfg(not(feature = "watch"))]
    (prove(), Vec::new())
}
