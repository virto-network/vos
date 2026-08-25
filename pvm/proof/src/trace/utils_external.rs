// Adapted from stwo's coset_order_to_circle_domain_order.
// Copyright 2024 StarkWare Industries Ltd. / Nexus Laboratories, Ltd.
// Licensed under Apache-2.0.

use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use stwo::core::fields::Field;

pub fn coset_order_to_circle_domain_order<F: Field>(values: &[F]) -> Vec<F> {
    let mut ret = Vec::with_capacity(values.len());
    let n = values.len();
    let half_len = n / 2;

    (0..half_len)
        .into_par_iter()
        .map(|i| values[i << 1])
        .chain(
            (0..half_len)
                .into_par_iter()
                .map(|i| values[n - 1 - (i << 1)]),
        )
        .collect_into_vec(&mut ret);
    ret
}
