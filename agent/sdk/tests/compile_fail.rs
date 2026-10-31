//! What the macros and the context types refuse to compile, and what they
//! take.

#[test]
fn restrictions() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/compile_fail/*.rs");
    cases.pass("tests/compile_pass/*.rs");
}
