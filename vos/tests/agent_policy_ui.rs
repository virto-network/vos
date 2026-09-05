#![cfg(feature = "macros")]

#[test]
fn agent_role_policy_ids_fail_closed_at_compile_time() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/agent_policy_*.rs");
}
