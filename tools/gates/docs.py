#!/usr/bin/env python3
"""The proof docs' tripwire, run by `just doc-check`.

    python3 -I tools/gates/docs.py

It fails when
- a design doc or a doc under `pvm/` names deleted code as built: the retired device format's
  chip and configuration names, and `javm`, the interpreter `vos-pvm`
  replaced;
- a path `pvm/proof/AUDIT.md` names (in backticks, braces expanded) is no
  file or directory: under `pvm/proof/` or the repository's root, or, for
  a path the map gives relative to its parent's (`cut/pin.rs` beside
  `src/chips/cpu/cut.rs`), the end of one under `pvm/proof/`;
- a Rust source on a production check path (`AUDITED`) is named by
  `pvm/proof/AUDIT.md` neither by its path, nor by a directory of its
  crate, nor is it a test's, a vector's or a harness's (`UNAUDITED`);
- a fuzz target of the justfile's `proof_fuzz_targets` goes unnamed in
  `pvm/proof/SECURITY.md`;
- a link of a tracked Markdown doc (`[text](path)`, its `#anchor` aside;
  a leading `/` from the repository's root) names no tracked file or
  directory, or a doc `pvm/` and the root share (`SHARED`) names in
  backticks a `*.md` that is no tracked file and not one of the node
  side's (`NODE_DOCS`);
- a doc gives `pvm/proof/fixtures/wrap.proof` a length that is not the
  file's: a line naming `wrap.proof` with a byte count, or the phrase
  "`wrap.proof` is N bytes", of which at least one doc holds one;
- an `olanod/stwo` revision a tracked file names (a manifest's or lock
  file's `rev`, a URL's `/blob/`, a doc's "olanod/stwo at" or "pin") is
  not the root `Cargo.toml`'s, or `pvm/proof/SECURITY.md` does not
  record that revision as the one its Stwo table was audited at.
"""

import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Names of code deleted with format 46, each a sign a doc describes it as
# built.
STALE = ["DeviceMemoryChip", "Cpu::PerProgram", "Memory::Word", "while its code lives", "javm"]

# The Rust sources on a production check path, which AUDIT.md must name:
# the verifier kit's five crates, the JAM statements service and the
# venue guests, the device verifier, the segment's native verifier and the
# column derives.
AUDITED = [
    "anchor/src",
    "statement/src",
    "final-verifier/src",
    "recair-air/src",
    "poseidon2/src",
    "statement/service/src",
    "device/src",
    "verifier/src",
    "derive/src",
]

# Of those, the tests', the vectors' and the harnesses' files, compiled
# into no production build.
UNAUDITED = [
    "anchor/src/suite.rs",
    "anchor/src/tests.rs",
    "anchor/src/vectors.rs",
    "statement/src/fixtures.rs",
]

# The docs `pvm/` and the repository's root share, on every tree that
# holds `pvm/`: whatever they name must be there, or the node side's.
SHARED = ["pvm/", "docs/design/proving.md", "docs/design/recursion-air.md", "docs/design/spaces-pallet.md", "docs/design/open.md"]

# The node side's docs, which a tree of `pvm/` alone does not hold: the
# design docs by name (under `docs/design/`), the rest by path.
NODE_DOCS = {
    "core-model.md",
    "identity-and-authority.md",
    "light-node.md",
    "node-api.md",
    "clerk-across-spaces.md",
    "node/SECURITY.md",
    "node/light/SECURITY.md",
}

PATH = re.compile(r"`([A-Za-z0-9_.{},/-]+\.(?:rs|md|toml|py|sh)|[A-Za-z0-9_.{},/-]+/)`")


def expand(token: str) -> list[str]:
    """`a/{b,c}.rs` as `a/b.rs` and `a/c.rs`."""
    match = re.search(r"\{([^{}]*)\}", token)
    if not match:
        return [token]
    head, tail = token[: match.start()], token[match.end() :]
    return [path for part in match.group(1).split(",") for path in expand(head + part + tail)]


def stale() -> list[str]:
    docs = list((ROOT / "docs/design").glob("*.md")) + [
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


def audit_converse() -> list[str]:
    """Every production check path's Rust source named by the map."""
    proof = ROOT / "pvm/proof"
    files = sorted(
        str(path.relative_to(proof))
        for directory in AUDITED
        for path in (proof / directory).rglob("*.rs")
        if "target" not in path.relative_to(proof).parts
    )
    every = [path for path in proof.rglob("*") if path.is_file() and "target" not in path.relative_to(proof).parts]

    def crate(path: str) -> pathlib.Path:
        directory = (proof / path).parent
        while not (directory / "Cargo.toml").exists():
            directory = directory.parent
        return directory

    named = set(UNAUDITED)
    for token in PATH.findall((proof / "AUDIT.md").read_text()):
        for path in expand(token):
            if path.endswith("/"):
                # A directory names what it holds of its own crate only, never a crate under it.
                for base in (proof, ROOT):
                    directory = (base / path).resolve()
                    named |= {
                        file
                        for file in files
                        if directory.is_dir()
                        and (proof / file).is_relative_to(directory)
                        and directory.is_relative_to(crate(file))
                    }
            elif "/" in path:
                named |= {file for file in files if file == path or f"pvm/proof/{file}" == path or file.endswith("/" + path)}
            else:
                # A bare name counts where one file of `pvm/proof/` has it.
                holders = [str(candidate.relative_to(proof)) for candidate in every if candidate.name == path]
                if len(holders) == 1:
                    named.add(holders[0])
    if not files:
        return ["no Rust source on the production check paths: AUDITED names none"]
    return [f"pvm/proof/AUDIT.md does not name pvm/proof/{file}, on a production check path" for file in files if file not in named]


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


MD = re.compile(r"`([A-Za-z0-9_./-]+\.md)`")


def tracked() -> set[str]:
    return set(
        filter(
            None,
            subprocess.run(
                ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True, text=True
            ).stdout.split("\0"),
        )
    )


def shared_docs(files: set[str]) -> list[str]:
    return sorted(
        file
        for file in files
        if file.endswith(".md") and any(file == doc or (doc.endswith("/") and file.startswith(doc)) for doc in SHARED)
    )


def md_names() -> list[str]:
    """Each `*.md` a shared doc names in backticks: a tracked file (from the
    doc's directory, the root or `docs/design/`, or the end of a tracked
    path), or one of the node side's docs."""
    files = tracked()
    missing = []
    for name in shared_docs(files):
        for token in MD.findall((ROOT / name).read_text()):
            candidates = {
                os.path.normpath(os.path.join(os.path.dirname(name), token)),
                token.lstrip("/"),
                f"docs/design/{token}",
            }
            if candidates & files or any(file.endswith("/" + token) for file in files):
                continue
            if token.removeprefix("docs/design/") in NODE_DOCS:
                continue
            missing.append(f"{name}: names {token}, which is no tracked file")
    return missing


WRAP = "pvm/proof/fixtures/wrap.proof"
WRAP_IS = re.compile(r"`wrap\.proof`\s+is\s+(\d{1,3}(?:,\d{3})*)\s+bytes")
BYTES = re.compile(r"\b(\d{1,3}(?:,\d{3})+|\d{4,}) ?(?:bytes|B)\b")


def wrap_length() -> list[str]:
    """Every length a doc gives the committed wrap is the file's."""
    length = (ROOT / WRAP).stat().st_size
    files = tracked()
    stale, phrased = [], 0
    for name in sorted(file for file in files if file.endswith(".md")):
        text = (ROOT / name).read_text()
        for value in WRAP_IS.findall(text):
            phrased += 1
            if int(value.replace(",", "")) != length:
                stale.append(f"{name}: says `wrap.proof` is {value} bytes, the file has {length:,}")
        for number, line in enumerate(text.splitlines(), 1):
            if "wrap.proof" not in line:
                continue
            for value in BYTES.findall(line):
                if int(value.replace(",", "")) != length:
                    stale.append(f"{name}:{number}: gives wrap.proof {value} bytes, the file has {length:,}")
    if not phrased:
        stale.append(f"no doc says \"`wrap.proof` is {length:,} bytes\": the tripwire holds nothing")
    return stale


STWO = re.compile(r"(?:rev ?= ?\"?|\?rev=|/blob/|olanod/stwo at `|pin `)([0-9a-f]{7,40})")
AUDITED_AT = re.compile(r"audited at the fork's revision `([0-9a-f]{8,40})`")


def stwo_pin() -> list[str]:
    """Every copy of the Stwo pin is the root manifest's, and the audit of
    Stwo's verify path names it."""
    manifest = (ROOT / "Cargo.toml").read_text()
    pin = re.search(r'^stwo = \{ git = "https://github.com/olanod/stwo", rev = "([0-9a-f]{40})"', manifest, re.M)
    if not pin:
        return ["the root Cargo.toml pins no olanod/stwo revision"]
    pin = pin.group(1)
    moved = []
    for name in sorted(tracked()):
        path = ROOT / name
        if not path.is_file() or path.stat().st_size > 1 << 22:
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if "olanod/stwo" not in text:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if "olanod/stwo" in line:
                moved += [
                    f"{name}:{number}: names olanod/stwo at {revision}, the pin is {pin}"
                    for revision in STWO.findall(line)
                    if not pin.startswith(revision)
                ]
    audited = AUDITED_AT.findall((ROOT / "pvm/proof/SECURITY.md").read_text())
    if not audited or any(not pin.startswith(revision) for revision in audited):
        moved.append(f"pvm/proof/SECURITY.md records no audit of Stwo's verify path at the pin {pin[:8]}")
    return moved


LINK = re.compile(r"\[[^\]]*\]\(([^()\s]+)(?:\s+\"[^\"]*\")?\)")


def links() -> list[str]:
    files = tracked()
    known = files | {str(parent) for file in files for parent in pathlib.PurePosixPath(file).parents}
    broken = []
    for name in sorted(file for file in files if file.endswith(".md")):
        doc = ROOT / name
        text = re.sub(r"```.*?```", "", doc.read_text(), flags=re.S)
        for line in text.splitlines():
            for target in LINK.findall(re.sub(r"`[^`]*`", "", line)):
                if re.match(r"[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
                    continue
                path = target.split("#", 1)[0]
                if not path:
                    continue
                resolved = os.path.normpath(
                    path.lstrip("/") if path.startswith("/") else os.path.join(os.path.dirname(name), path)
                )
                if resolved not in known:
                    broken.append(f"{name}: links {target}, which is no tracked path")
    return broken


def main() -> int:
    failures = stale() + audit_paths() + audit_converse() + fuzz_targets() + links() + md_names() + wrap_length() + stwo_pin()
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(
        "the proof docs name no deleted code, AUDIT.md's paths exist and it names every production check "
        "path's source, SECURITY.md names every fuzz target, every relative link of a tracked doc and every "
        "doc a shared doc names resolves, the docs give wrap.proof its length, and every copy of the Stwo "
        "pin is the root manifest's"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
