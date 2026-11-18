# PVM specification pin

The portable runtime and compiler implement Gray Paper **v0.8.0**, pinned to
commit `07f041dabd073f9018b418e9ee72e79dd2185401`.

The standard-program container, instruction semantics, gas model, and Refine
inner-machine calls are consensus-facing contracts. Updating the pin requires:

- interpreter and recompiler conformance;
- standard-program and inner-machine vectors;
- proof-format review and, when semantics change, a proof-format bump;
- rebuilding every canonical PVM artifact.

VOS-specific actor behavior belongs above this boundary. It must not add host
instructions or change standard PVM execution.
