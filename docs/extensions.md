# Extensions

Extensions are native host integrations for capabilities that should not run
inside an actor, such as HTTP ingress or proof production. They are dynamic
libraries loaded by the node and communicate through typed VOS messages.

An extension must:

- declare its methods and capabilities;
- bound every request, response, queue, and external wait;
- preserve authenticated caller identity when forwarding;
- keep host-local secrets out of actor replies and replicated effects;
- shut down when the node revokes its route.

The supported implementations are:

- `extensions/http-gateway`: schema-aware HTTP ingress;
- `extensions/prover`: proof creation and verification.

Small transport fixtures under `tests/fixtures/extensions` exercise the plugin
boundary; they are not application examples.
