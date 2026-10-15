//! What a VOS node serves the default agent beyond the runtime's host, for
//! the tests and benches that run the agent as a node does.

use vos_pvm::ExitReason;
use vos_pvm::inner::gp_call::HISTORICAL_LOOKUP;
use vos_pvm::refine::Machine;
use vos_pvm::refine_host::serve_lookup;
use vos_wire::abi::code;
use vos_wire::abi::surface::LOST;
use vos_wire::ids::AgentId;

/// Serve `agent`'s host call `id` as a VOS node does beyond the runtime:
/// `historical_lookup` from the programs `find` gives ([`serve_lookup`]),
/// and the agent's report of lost state, which stops the refine. Every
/// other call answers `WHAT`.
pub fn serve<P: AsRef<[u8]>>(
    id: u64,
    machine: &mut Machine,
    agent: AgentId,
    find: impl FnOnce(&[u8; 32]) -> Option<P>,
) -> Result<(), ExitReason> {
    match id {
        LOST => Err(ExitReason::HostCall(LOST)),
        id if id == u64::from(HISTORICAL_LOOKUP) => serve_lookup(machine, u64::from(agent.0), find),
        _ => {
            machine.registers_mut()[7] = code::WHAT;
            Ok(())
        }
    }
}
