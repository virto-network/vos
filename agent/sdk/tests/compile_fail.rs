//! What the macros and the context types refuse to compile.

#[test]
fn restrictions() {
    trybuild::TestCases::new().compile_fail("tests/compile_fail/*.rs");
}
