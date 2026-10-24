//! The kernels the run's statements are of, each by its blob and the
//! program id recomputed from it, and the statement a record makes.

use vos_node_prover::Prover;
use vos_venue::vos_statement::{Pin, ProgramId, Statement};
use vos_wire::ids::ProgramHash;
use vos_wire::result::Attest;

use crate::venues::Serial;

pub struct Kernel {
    pub blob: Vec<u8>,
    pub program: ProgramId,
}

impl Kernel {
    fn load(prover: &Serial, actor: &str, method: &str) -> Self {
        let blob = vos_testkit::programs::kernel(actor, method);
        let program = prover.program(&blob).expect("the kernel's program id");
        Self { blob, program }
    }

    pub fn pin(&self, venue_bound: bool) -> Pin {
        Pin {
            program: self.program,
            venue_bound,
        }
    }

    /// The statement `attest` makes, as the worker makes it.
    pub fn statement(&self, attest: &Attest) -> Statement {
        vos_node_prover::statement(attest, self.program)
    }
}

/// `balance`'s and the window actor's kernels at a cut, and the reader's
/// rootless `stamped` (venue-bound) and `ordered`.
pub struct Kernels {
    pub balance: Kernel,
    pub window: Kernel,
    pub stamped: Kernel,
    pub ordered: Kernel,
}

impl Kernels {
    pub fn load(prover: &Serial) -> Self {
        Self {
            balance: Kernel::load(prover, "balance", "at_least"),
            window: Kernel::load(prover, "window", "settle"),
            stamped: Kernel::load(prover, "reader", "stamped"),
            ordered: Kernel::load(prover, "reader", "ordered"),
        }
    }

    /// The pins each JAM deployment takes.
    pub fn pins(&self) -> Vec<Pin> {
        vec![
            self.balance.pin(false),
            self.window.pin(false),
            self.stamped.pin(true),
            self.ordered.pin(false),
        ]
    }

    /// The kernel `attest` names.
    pub fn of(&self, attest: &Attest) -> &Kernel {
        [&self.balance, &self.window, &self.stamped, &self.ordered]
            .into_iter()
            .find(|kernel| ProgramHash::of(&kernel.blob) == attest.program)
            .expect("a kernel of the run")
    }
}
