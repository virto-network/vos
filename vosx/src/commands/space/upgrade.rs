//! `space upgrade` — reject the retired legacy service-upgrade path and direct
//! operators to the Agent lifecycle.

use crate::commands::space::common::{parse_instance_name, parse_program_name};

pub struct Args {
    pub space: String,
    pub instance: String,
    pub program_ref: String,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let program_name = parse_program_name(&args.program_ref)?;
    let instance_name = parse_instance_name(&args.instance)?;

    // The former two-phase path could commit the guest upgrade and crash
    // before moving the registry row. Clean cutover refuses before dialing or
    // reading either side; the Agent lifecycle owns the atomic transition.
    let _ = (args.space, program_name, instance_name);
    Err(super::client::legacy_service_upgrade_cutover_error())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upgrade_rejects_noncanonical_instance_before_connecting() {
        let error = run(Args {
            space: "does-not-exist".into(),
            instance: "bad/instance".into(),
            program_ref: "worker-program".into(),
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("instance name"), "{error}");
        assert!(error.contains("canonical registry slug"), "{error}");
    }

    #[test]
    fn legacy_upgrade_refuses_at_clean_cutover_before_connecting() {
        let error = run(Args {
            space: "does-not-exist".into(),
            instance: "worker".into(),
            program_ref: "worker-v2".into(),
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("clean cutover"), "{error}");
        assert!(error.contains("Agent lifecycle"), "{error}");
        assert!(error.contains("no guest mutation"), "{error}");
    }
}
