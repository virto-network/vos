use crate::defaults::{SESSION_BUCKET_MS, SESSION_EXPIRY_MS};

/// The bucket a time falls in.
pub const fn bucket(time: u64) -> u64 {
    time / SESSION_BUCKET_MS
}

/// The batch time from which every session whose mark lies in
/// `bucket` has expired.
pub const fn due(bucket: u64) -> u64 {
    (bucket + 1)
        .saturating_mul(SESSION_BUCKET_MS)
        .saturating_add(SESSION_EXPIRY_MS)
}

/// Where a session last active at `time` lies in the due index.
pub const fn at(time: u64) -> u64 {
    due(bucket(time))
}
