use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, ProgramHash};
use vos_wire::result::Attest;
use vos_wire::served::Served;

use super::*;

fn audit(reach: Reach, bytes: &[u8], needle: Needle) -> Vec<Finding> {
    let mut audit = Audit::default();
    audit.carrier("carrier", reach, bytes.to_vec());
    audit.needles.0.push(needle);
    audit.findings()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn a_needle_is_found_in_each_of_its_forms() {
    let secret: Vec<u8> = (1..=16).collect();
    let needle = || Needle::bytes(Kind::ServedRow, "secret", &secret).unwrap();
    for carrier in [
        [b"x".as_slice(), &secret, b"y"].concat(),
        format!("value={}", hex(&secret)).into_bytes(),
        format!("value={}", hex(&secret).to_uppercase()).into_bytes(),
        format!("value={}…", &hex(&secret)[..16]).into_bytes(),
        format!("value={secret:?}").into_bytes(),
    ] {
        assert_eq!(audit(Reach::Leaves, &carrier, needle()).len(), 1);
    }
    assert!(audit(Reach::Leaves, &secret[1..], needle()).is_empty());
}

#[test]
fn a_field_hash_is_found_as_its_limbs() {
    let limbs: [u32; 8] = [5, 1 << 20, 77, 3_000_000, 9, 1 << 30, 12, 400];
    let mut bytes = [0u8; 32];
    for (at, limb) in limbs.iter().enumerate() {
        bytes[at * 4..at * 4 + 4].copy_from_slice(&limb.to_le_bytes());
    }
    let needle = || Needle::field(Kind::NodeProof, "root", &bytes).unwrap();
    let listed = limbs.map(|limb| limb.to_string()).join(", ");
    let wrapped = limbs.map(|limb| format!("M31({limb})")).join(", ");
    let postcard = postcard::to_allocvec(&limbs).unwrap();
    for carrier in [
        format!("root=P2Hash([{listed}])").into_bytes(),
        format!("root=P2Hash([{wrapped}])").into_bytes(),
        [b"x".as_slice(), &postcard].concat(),
    ] {
        assert_eq!(audit(Reach::Role, &carrier, needle()).len(), 1);
    }
}

#[test]
fn a_number_is_found_whole_in_the_carriers_that_leave() {
    let steps = || Needle::number(Kind::StepCount, "steps", 123_457);
    for carrier in [
        b"took 123457 steps".to_vec(),
        123_457u32.to_le_bytes().to_vec(),
        123_457u64.to_be_bytes().to_vec(),
        b"steps=0x1e241".to_vec(),
    ] {
        assert_eq!(audit(Reach::Leaves, &carrier, steps()).len(), 1);
    }
    assert!(audit(Reach::Leaves, b"took 1234570 steps", steps()).is_empty());
    assert!(audit(Reach::Role, b"took 123457 steps", steps()).is_empty());
}

#[test]
fn a_venues_record_is_searched_in_full_forms_alone() {
    let secret: Vec<u8> = (1..=16).collect();
    let needle = || Needle::bytes(Kind::ServedRow, "secret", &secret).unwrap();
    assert_eq!(audit(Reach::Recorded, &secret, needle()).len(), 1);
    let prefix = format!("hash={}…", &hex(&secret)[..16]).into_bytes();
    assert!(audit(Reach::Recorded, &prefix, needle()).is_empty());
    let steps = || Needle::number(Kind::StepCount, "steps", 123_457);
    assert!(audit(Reach::Recorded, b"conn_id=123457", steps()).is_empty());
    assert!(audit(Reach::Recorded, &123_457u64.to_le_bytes(), steps()).is_empty());
    let root: Vec<u8> = (100..132).collect();
    let proof = Needle::bytes(Kind::NodeProof, "root", &root).unwrap();
    assert_eq!(
        audit(Reach::Recorded, &hex(&root).into_bytes(), proof).len(),
        1
    );
}

#[test]
fn proofs_and_registers_are_searched_within_the_role_too() {
    let root: Vec<u8> = (100..132).collect();
    let proof = Needle::bytes(Kind::NodeProof, "root", &root).unwrap();
    assert_eq!(audit(Reach::Role, &root, proof).len(), 1);
    let row = Needle::bytes(Kind::ServedRow, "row", &root).unwrap();
    assert!(audit(Reach::Role, &root, row).is_empty());
    let file = [1u64 << 40, 7, 9];
    let bytes: Vec<u8> = file.iter().flat_map(|value| value.to_le_bytes()).collect();
    assert_eq!(
        audit(Reach::Role, &bytes, Needle::registers("file", &file)).len(),
        1
    );
    let debug = format!("{:?}", [1u64 << 40, 7, 9, 3]).into_bytes();
    assert_eq!(
        audit(Reach::Leaves, &debug, Needle::registers("file", &file)).len(),
        1
    );
}

#[test]
fn a_short_or_constant_value_is_no_needle() {
    assert!(Needle::bytes(Kind::ServedRow, "short", &[1, 2, 3]).is_none());
    assert!(Needle::bytes(Kind::ServedRow, "zeros", &[0; 32]).is_none());
    assert!(Needle::bytes(Kind::ServedRow, "a small integer", &21u64.to_le_bytes()).is_none());
}

/// A read's record: its arguments, a public one among them, then its rows.
fn attest(value: u64) -> (Attest, usize) {
    let served = Served {
        space: vos_wire::SpaceId([3; 32]),
        window: 4,
        agent: AgentId(5),
        instance: InstanceId(6),
        agent_root: core::array::from_fn(|at| at as u8),
        rep_root: core::array::from_fn(|at| 40 + at as u8),
        rep_salt: core::array::from_fn(|at| 80 + at as u8),
        space_path: (1..=24).collect(),
        rows: vec![(
            vec![1],
            Some((
                [4, 8, 15, 16, 23, 42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                value.encode(),
            )),
        )],
        rows_proof: (100..140).collect(),
    };
    let public: Vec<u8> = (200..220).collect();
    let private: Vec<u8> = (10..30).collect();
    let arguments = [public.clone(), private].concat();
    let attest = Attest {
        program: ProgramHash([0; 32]),
        window: Some(4),
        witness_input: [arguments.clone(), served.encode()].concat(),
        output: Vec::new(),
        public_args: public,
        roots: Vec::new(),
    };
    (attest, arguments.len())
}

#[test]
fn a_records_rows_and_private_arguments_are_needles() {
    let (attest, arguments) = attest(0x1234_5678_9abc);
    let mut needles = Needles::default();
    needles.attest("read", &attest, arguments);
    assert_eq!(needles.named(Kind::ServedRow, "row 0's value").count(), 2);
    assert_eq!(needles.named(Kind::ServedRow, "argument part").count(), 1);
    let private: Vec<u8> = (10..30).collect();
    let public: Vec<u8> = (200..220).collect();
    for (carrier, found) in [(private, 1), (public, 0)] {
        let mut audit = Audit {
            needles: needles.clone(),
            ..Audit::default()
        };
        audit.carrier("carrier", Reach::Leaves, carrier);
        assert_eq!(
            audit
                .findings()
                .iter()
                .filter(|finding| finding.needle.contains("argument part"))
                .count(),
            found
        );
    }
    let domain = vos_wire::vos_anchor::blake2b_256(&[b"vos/io/v1", &(10..30).collect::<Vec<u8>>()]);
    assert_eq!(
        audit(
            Reach::Leaves,
            &domain,
            needles
                .named(Kind::PrivateHash, "vos/io/v1 of argument part 0")
                .next()
                .unwrap()
                .clone()
        )
        .len(),
        1
    );
}

#[test]
fn a_rootless_records_private_arguments_are_needles() {
    let public: Vec<u8> = (200..220).collect();
    let secret: Vec<u8> = (10..30).collect();
    let attest = Attest {
        program: ProgramHash([0; 32]),
        window: None,
        witness_input: [public.clone(), secret.clone()].concat(),
        output: Vec::new(),
        public_args: public,
        roots: Vec::new(),
    };
    let mut needles = Needles::default();
    needles.attest("rootless", &attest, attest.witness_input.len());
    assert_eq!(needles.named(Kind::ServedRow, "argument part").count(), 1);
    assert_eq!(needles.named(Kind::ServedRow, "row").count(), 0);
    let mut audit = Audit {
        needles,
        ..Audit::default()
    };
    audit.carrier("carrier", Reach::Leaves, secret);
    assert_eq!(audit.findings().len(), 1);
}

#[test]
#[should_panic(expected = "no rows served after its arguments")]
fn a_record_whose_rows_are_not_after_its_arguments_fails() {
    let (attest, arguments) = attest(7);
    Needles::default().attest("read", &attest, arguments - 1);
}
