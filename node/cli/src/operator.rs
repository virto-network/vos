//! The operator's commands, with a node's admin token: agents, installs
//! and roles.

use vos_node::client::Operator;
use vos_node::{ADMIN_TOKEN, NODE_KEY};
use vos_wire::Decode;
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{Install, Response};
use vos_wire::records::Derivation;
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;

use crate::args::{AgentCommand, InstallArgs, OperatorArgs, RoleArgs};
use crate::call::{print_admin_answer, said};
use crate::{at, failed, key_bytes};

impl AgentCommand {
    pub fn run(self) -> Result<(), String> {
        match self {
            AgentCommand::Create { operator, replicas } => match operator_of(&operator)?
                .create_agent(replicas)
                .map_err(failed)?
            {
                Response::Created(agent) => {
                    println!("{}", agent.0);
                    Ok(())
                }
                Response::Unconfirmed(agent) => {
                    println!("{}", agent.0);
                    eprintln!("vos: a majority of its replicas does not hold it yet");
                    Ok(())
                }
                other => {
                    let (Ok(text) | Err(text)) = said(&other);
                    Err(text)
                }
            },
            AgentCommand::Replace {
                operator,
                agent,
                remove,
                add,
            } => match operator_of(&operator)?
                .replace(AgentId(agent), remove, add)
                .map_err(failed)?
            {
                Response::Placed(replicas) => {
                    let replicas: Vec<String> = replicas.iter().map(u8::to_string).collect();
                    println!("{}", replicas.join(","));
                    Ok(())
                }
                Response::TimedOut => {
                    Err("not committed in time: the agent's leader goes on with the change".into())
                }
                other => Err(format!("{other:?}")),
            },
        }
    }
}

impl InstallArgs {
    pub fn run(self) -> Result<(), String> {
        let elf = std::fs::read(&self.elf).map_err(at(&self.elf))?;
        // Derived here too, to refuse a package before it is sent and to
        // name its kernels' methods.
        let derived = vos_pvm_compiler::derive(&elf).map_err(at(&self.elf))?;
        let schema = Schema::read(&derived.schema)
            .map_err(|error| format!("{}: its schema: {error:?}", self.elf.display()))?;
        let local = Derivation::new(
            &elf,
            &derived.actor,
            &derived.kernels,
            &derived.shapes,
            derived.transpiler_version,
            derived.heap,
        );
        let install = Install {
            instance: InstanceId(self.instance),
            elf,
            roles: self.roles,
        };
        let answer = operator_of(&self.operator)?
            .install(AgentId(self.agent), &install)
            .map_err(failed)?;
        let Response::Ran {
            outcome: Outcome::Done(reply),
            ..
        } = &answer
        else {
            return print_admin_answer(&answer);
        };
        let derivation = Derivation::decode(reply)
            .map(|(derivation, _)| derivation)
            .map_err(|_| format!("an install answered {}", hex::encode(reply)))?;
        if local != derivation {
            eprintln!(
                "warning: the node derived other programs than this vos, with transpiler {} \
                 against {}: the node's are installed",
                derivation.transpiler, local.transpiler
            );
        }
        print!("{}", derived_lines(&derivation, &schema));
        Ok(())
    }
}

/// The programs an install derived, a line each: `done`, then the actor's
/// program, each kernel by its method's name, the ELF and the transpiler
/// version.
fn derived_lines(derivation: &Derivation, schema: &Schema) -> String {
    let mut lines = format!("done\nprogram {}\n", hex::encode(derivation.program.0));
    for kernel in &derivation.kernels {
        let name = schema.method(kernel.method).map_or_else(
            || format!("{:#010x}", kernel.method.0),
            |method| String::from_utf8_lossy(&method.name).into_owned(),
        );
        lines += &format!("kernel {name} {}\n", hex::encode(kernel.program.0));
    }
    lines += &format!(
        "elf {}\ntranspiler {}\n",
        hex::encode(derivation.elf),
        derivation.transpiler
    );
    lines
}

impl RoleArgs {
    pub fn run(self) -> Result<(), String> {
        let key = key_bytes(&self.principal)?;
        let answer = operator_of(&self.operator)?
            .grant(AgentId(self.agent), Principal::Client(key), self.role.0)
            .map_err(failed)?;
        print_admin_answer(&answer)
    }
}

fn operator_of(args: &OperatorArgs) -> Result<Operator, String> {
    let path = args.data.join(ADMIN_TOKEN);
    let token = std::fs::read_to_string(&path).map_err(at(&path))?;
    // On the node's host, its data directory holds its key.
    let target = args.node.target_or(Some(&args.data.join(NODE_KEY)))?;
    Ok(Operator::new(&target, &token))
}
