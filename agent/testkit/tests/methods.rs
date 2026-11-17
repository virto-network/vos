//! The stock actors' method ids host code names (`vos_wire::*::method`),
//! each resolved by its name in the built actor's schema: a handler
//! renamed, or one host code names and the actor lacks, fails here.

use vos_abi::ids::MethodId;
use vos_testkit::programs::{program, schema};

fn resolves(name: &str, all: &[(&str, MethodId)]) {
    let schema = schema(&program(name));
    for (method, id) in all {
        assert_eq!(
            schema.method_id(method),
            Some(*id),
            "{name} has no handler `{method}` of that id"
        );
    }
}

#[test]
fn every_method_id_host_code_names_is_a_handler_of_its_actor() {
    resolves("vos-personal", vos_wire::personal::method::ALL);
    resolves("vos-homes", vos_wire::homes::method::ALL);
    resolves("vos-credentials", vos_wire::credentials::method::ALL);
    resolves("vos-credential-book", vos_wire::books::credential_book::ALL);
    resolves("vos-device-book", vos_wire::books::device_book::ALL);
}
