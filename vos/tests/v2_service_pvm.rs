//! Physical generic-service PVM integration gate.
//!
//! Build the guest first with:
//! `cd services/vos-service && cargo +nightly actor`.

use std::path::PathBuf;

use javm::kernel::InvocationKernel;
use vos::v2::{
    AccumulateProtocolHostV2, AccumulateTransactionV2, ActorId, AuthorizationEvidenceV2,
    ConsistencyBaseV2, ConsistencyModeV2, DeploymentId, GasAccountingV2, Hash, InvocationId,
    NoRefineProtocolHostV2, Origin, ProgramId, RefineProtocolHostV2, RootServiceId,
    ServiceIdentityV2, ServicePvmErrorV2, ServicePvmV2, TransitionV2, V2Wire, WorkEnvelopeV2,
};

fn service_elf() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../services/vos-service/target/riscv64em-javm/release/vos_service.elf");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: build the generic guest first with `cd services/vos-service && cargo +nightly actor` ({})",
                path.display()
            );
            None
        }
    }
}

fn work() -> WorkEnvelopeV2 {
    WorkEnvelopeV2 {
        service: ServiceIdentityV2 {
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: vos::v2::ABI_VERSION,
            execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
        },
        invocation: InvocationId([4; 32]),
        target: ActorId([5; 32]),
        target_program: ProgramId([6; 32]),
        method: "increment".into(),
        arguments: vec![7],
        origin: Origin::Anonymous,
        authorization: AuthorizationEvidenceV2::Public,
        causal_parent: None,
        parent_call: None,
        consistency: ConsistencyModeV2::Local,
        base: ConsistencyBaseV2::Linear {
            revision: 0,
            state_root: Hash([8; 32]),
        },
        imported_actors: vec![],
        imported_blobs: vec![],
        proof_requested: false,
    }
}

struct NestedActorHost;

struct FailClosedAccumulateHost {
    committed: bool,
}

struct EmptyTransaction;

impl AccumulateTransactionV2 for EmptyTransaction {
    fn handle(
        &mut self,
        slot: u8,
        _registers: &[u64; 13],
        _kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        Err(ServicePvmErrorV2::AccumulateHostRejected(slot))
    }
}

impl AccumulateProtocolHostV2 for FailClosedAccumulateHost {
    type Transaction = EmptyTransaction;

    fn begin(&mut self) -> Result<Self::Transaction, ServicePvmErrorV2> {
        Ok(EmptyTransaction)
    }

    fn commit(&mut self, _transaction: Self::Transaction) -> Result<(), ServicePvmErrorV2> {
        self.committed = true;
        Ok(())
    }
}

impl RefineProtocolHostV2 for NestedActorHost {
    fn handle(
        &self,
        slot: u8,
        registers: &[u64; 13],
        kernel: &mut InvocationKernel,
    ) -> Result<[u64; 2], ServicePvmErrorV2> {
        if slot == vos::abi::hostcall::GAS as u8 {
            return Ok([kernel.active_gas(), 0]);
        }
        if slot != vos::abi::hostcall::INVOKE as u8 {
            return NoRefineProtocolHostV2.handle(slot, registers, kernel);
        }

        let program = kernel
            .read_data_cap_window(registers[7] as u32, 32)
            .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
        let input = kernel
            .read_data_cap_window(registers[8] as u32, registers[9] as u32)
            .ok_or(ServicePvmErrorV2::RefineHostRejected(slot))?;
        let work = WorkEnvelopeV2::decode(&input)
            .map_err(|_| ServicePvmErrorV2::RefineHostRejected(slot))?;
        assert_eq!(program, work.target_program.0);

        let transition = TransitionV2 {
            service: work.service.clone(),
            consumed_input: work.invocation,
            target_program: work.target_program,
            base: work.base.clone(),
            writes: vec![],
            crdt_operations: vec![],
            resulting_crdt_heads: vec![],
            continuations: vec![],
            inbox: vec![],
            outbox: vec![],
            reply: None,
            exported_blobs: vec![],
            gas: GasAccountingV2 {
                refine_used: 10,
                proof_used: 0,
                accumulate_used: 0,
            },
            proof: None,
        };
        let output = transition.encode();
        let output_packed = registers[11];
        let output_address = output_packed as u32;
        let output_capacity = (output_packed >> 32) as usize;
        if output.len() > output_capacity || !kernel.write_data_cap_window(output_address, &output)
        {
            return Err(ServicePvmErrorV2::RefineHostRejected(slot));
        }
        Ok([output.len() as u64, 0])
    }
}

#[test]
fn canonical_guest_refine_runs_at_ic0_and_returns_nested_transition() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm))
        .expect("generic service has the GP IC0/IC5 entries");
    let work = work();

    let output = service
        .refine(&work.encode(), 10_000_000, &NestedActorHost)
        .expect("generic Refine completes");
    let transition = TransitionV2::decode(&output.bytes).expect("Refine returns TransitionV2");
    assert_eq!(transition.service, work.service);
    assert_eq!(transition.consumed_input, work.invocation);
    assert_eq!(transition.target_program, work.target_program);
    assert_eq!(transition.base, work.base);
}

#[test]
fn unfinished_guest_accumulate_traps_without_committing() {
    let Some(elf) = service_elf() else {
        return;
    };
    let pvm = grey_transpiler::link_elf(&elf).expect("generic service ELF transpiles");
    let service = ServicePvmV2::new(pvm.clone(), ProgramId::of_pvm(&pvm)).unwrap();
    let mut host = FailClosedAccumulateHost { committed: false };

    assert_eq!(
        service.accumulate(&[], 10_000_000, &mut host),
        Err(ServicePvmErrorV2::Panic)
    );
    assert!(!host.committed);
}
