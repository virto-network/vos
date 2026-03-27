//! JAR error/result codes returned by hostcalls.

pub const HOST_OK: u64 = 0;
pub const HOST_NONE: u64 = u64::MAX;
pub const HOST_WHAT: u64 = u64::MAX - 1;
pub const HOST_OOB: u64 = u64::MAX - 2;
pub const HOST_WHO: u64 = u64::MAX - 3;
pub const HOST_FULL: u64 = u64::MAX - 4;
pub const HOST_CORE: u64 = u64::MAX - 5;
pub const HOST_CASH: u64 = u64::MAX - 6;
pub const HOST_LOW: u64 = u64::MAX - 7;
pub const HOST_HUH: u64 = u64::MAX - 8;
