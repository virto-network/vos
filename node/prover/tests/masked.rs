//! The masked prover's checks before it proves, on the `kernels` test
//! actor's live run (`just build-test-actors`): a kernel's record and
//! program recomputed from its blob alone; a record whose re-run is its
//! statement accepted, and one whose output, public arguments or witness
//! is not refused; and `vos program-id`'s ids, the repository's constants.

use vos_node_prover::masked::{MaskedProver, kernel_record};
use vos_node_prover::program::program_id;
use vos_node_prover::{ProveError, Prover};
use vos_pvm_proof::constants;
use vos_testkit::Testkit;
use vos_testkit::programs::{actor_elf, derivation, derived, method, package};
use vos_wire::Encode;
use vos_wire::abi::cap::Target;
use vos_wire::ids::{AgentId, InstanceId, Principal, ProgramHash};
use vos_wire::result::Attest;

/// The `kernels` actor's `check` run live on `values`: each kernel's blob
/// and the attest it recorded.
fn attests(values: &[u64]) -> Vec<(Vec<u8>, Attest)> {
    let derived = derived("kernels");
    let mut kit = Testkit::new(AgentId(7));
    kit.install_derived(Target::Vos, InstanceId(9), &derived, &[])
        .expect("installs");
    let step = kit.command(
        Principal::Client([1; 32]),
        InstanceId(9),
        method(&derived.actor, "check"),
        &values.to_vec().encode(),
    );
    step.attests
        .into_iter()
        .map(|attest| {
            let blob = derived
                .kernels
                .iter()
                .map(|(_, kernel)| kernel)
                .find(|kernel| ProgramHash::of(kernel) == attest.program)
                .expect("a derived kernel")
                .clone();
            (blob, attest)
        })
        .collect()
}

/// A kernel's record recomputed from its blob is its install's, the method
/// aside, and its program is the one the install's record makes.
#[test]
fn a_kernel_is_read_from_its_blob_alone() {
    let derived = derived("kernels");
    let install = derivation(&package("kernels"), &derived);
    let prover = MaskedProver::new();
    for (_, blob) in &derived.kernels {
        let mut record = kernel_record(blob).unwrap();
        let installed = install
            .kernels
            .iter()
            .find(|kernel| kernel.program == record.program)
            .unwrap();
        record.method = installed.method;
        assert_eq!(&record, installed);
        let (program, _) = vos_pvm_recair::leaf::kernel_program(
            blob,
            installed,
            vos_pvm_compiler::TRANSPILER_VERSION,
            &vos_pvm_proof::format::SEGMENT,
        )
        .unwrap();
        assert_eq!(prover.program(blob).unwrap().0, program.id().words());
    }
    assert!(matches!(
        prover.program(b"not a kernel"),
        Err(ProveError::Kernel(_))
    ));
}

/// Each record re-runs as its statement; a record of another output,
/// other public arguments or another witness is refused before anything
/// is proved.
#[test]
fn a_record_whose_rerun_is_not_its_statement_is_refused() {
    let prover = MaskedProver::new();
    let runs = attests(&(0..40).collect::<Vec<_>>());
    assert_eq!(runs.len(), 3);
    for (blob, attest) in &runs {
        prover.rerun(blob, attest).expect("the record re-runs");
        let tampered: [fn(&mut Attest); 3] = [
            |attest| attest.output[0] ^= 1,
            |attest| attest.public_args.push(0),
            |attest| {
                let last = attest.witness_input.len() - 1;
                attest.witness_input[last] ^= 1;
            },
        ];
        for (n, tamper) in tampered.iter().enumerate() {
            let mut attest = attest.clone();
            tamper(&mut attest);
            assert!(
                matches!(prover.rerun(blob, &attest), Err(ProveError::Rerun(_))),
                "change {n}"
            );
            assert!(matches!(
                prover.prove(blob, &attest),
                Err(ProveError::Rerun(_))
            ));
        }
    }
}

/// `vos program-id`'s id of each known kernel, from its actor's ELF, is
/// the repository's constant.
#[test]
fn the_program_ids_are_the_repositorys() {
    for (actor, name, pinned) in [
        ("window", "settle", constants::WINDOW_PROGRAM),
        ("balance", "at_least", constants::BALANCE_PROGRAM),
        ("kernels", "areas", constants::PREDICATE_PROGRAM),
    ] {
        let elf = std::fs::read(actor_elf(actor)).unwrap();
        assert_eq!(program_id(&elf, name).unwrap(), pinned, "{actor}'s {name}");
    }
    let elf = std::fs::read(actor_elf("kernels")).unwrap();
    assert!(program_id(&elf, "check").is_err(), "not attestable");
    assert!(program_id(&elf, "nothing").is_err());
}
