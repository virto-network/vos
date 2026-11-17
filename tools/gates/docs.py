#!/usr/bin/env python3
"""The proof docs' tripwire, run by `just doc-check`.

    python3 -I tools/gates/docs.py

It fails when
- a design doc (a slice's plan, a record of its steps, aside) or a doc
  under `pvm/` names deleted code as built: the retired device format's
  chip and configuration names;
- a path `pvm/proof/AUDIT.md` names (in backticks, braces expanded) is no
  file or directory: under `pvm/proof/` or the repository's root, or, for
  a path the map gives relative to its parent's (`cut/pin.rs` beside
  `src/chips/cpu/cut.rs`), the end of one under `pvm/proof/`;
- a fuzz target of the justfile's `proof_fuzz_targets` goes unnamed in
  `pvm/proof/SECURITY.md`.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Names of code deleted with format 46, each a sign a doc describes it as
# built.
STALE = ["DeviceMemoryChip", "Cpu::PerProgram", "Memory::Word", "while its code lives"]

PATH = re.compile(r"`([A-Za-z0-9_.{},/-]+\.(?:rs|md|toml|py|sh)|[A-Za-z0-9_.{},/-]+/)`")


def expand(token: str) -> list[str]:
    """`a/{b,c}.rs` as `a/b.rs` and `a/c.rs`."""
    match = re.search(r"\{([^{}]*)\}", token)
    if not match:
        return [token]
    head, tail = token[: match.start()], token[match.end() :]
    return [path for part in match.group(1).split(",") for path in expand(head + part + tail)]


def stale() -> list[str]:
    docs = [
        path for path in (ROOT / "docs/design").glob("*.md") if not re.match(r"slice-\d+-plan\.md$", path.name)
    ] + [
        path for path in (ROOT / "pvm").rglob("*.md") if "target" not in path.parts
    ]
    return [
        f"{doc.relative_to(ROOT)}:{number}: names {name}"
        for doc in docs
        for number, line in enumerate(doc.read_text().splitlines(), 1)
        for name in STALE
        if name in line
    ]


def audit_paths() -> list[str]:
    audit = ROOT / "pvm/proof/AUDIT.md"
    proof = ROOT / "pvm/proof"
    under = {
        str(path.relative_to(proof)) + ("/" if path.is_dir() else "")
        for path in proof.rglob("*")
        if "target" not in path.relative_to(proof).parts
    }
    missing = []
    for token in PATH.findall(audit.read_text()):
        if "/" not in token:
            continue
        for path in expand(token):
            if any((base / path).exists() for base in (proof, ROOT)):
                continue
            if any(known.endswith("/" + path) for known in under):
                continue
            missing.append(f"pvm/proof/AUDIT.md names {path}, which does not exist")
    return missing


def fuzz_targets() -> list[str]:
    justfile = (ROOT / "justfile").read_text()
    targets = re.search(r'^proof_fuzz_targets := "([^"]*)"', justfile, re.M)
    if not targets:
        return ["the justfile holds no proof_fuzz_targets"]
    security = (ROOT / "pvm/proof/SECURITY.md").read_text()
    return [
        f"pvm/proof/SECURITY.md names no fuzz target {target}"
        for target in targets.group(1).split()
        if f"`{target}`" not in security
    ]


def main() -> int:
    failures = stale() + audit_paths() + fuzz_targets()
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print("the proof docs name no deleted code, AUDIT.md's paths exist, SECURITY.md names every fuzz target")
    return 0


if __name__ == "__main__":
    sys.exit(main())
