#[test]
fn compile_time_security_boundaries_hold() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/cannot_impl_permission.rs");
    t.compile_fail("tests/ui/cannot_construct_capability.rs");
    t.compile_fail("tests/ui/cannot_create_new_agentstate.rs");
    t.compile_fail("tests/ui/coerce_requires_implies.rs");
}
