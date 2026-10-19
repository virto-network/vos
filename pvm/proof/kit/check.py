#!/usr/bin/env python3
"""The sync check's own test (`just check-kit`), on a scratch clone of VOS
with a test tag at `--rev`:
- a kit vendored at the tag syncs, by `vos_kit.py` and by the consumer's
  bootstrap `vos-sync.sh`;
- one byte changed in any vendored file is refused, whether `VENDOR`'s hash
  is left as it was or recomputed over the change; so is a file added or
  removed;
- a kit whose own script is replaced by one that accepts anything passes
  that script and is refused by the bootstrap, which runs the tag's;
- `VENDOR` naming no tag, a malformed commit or tag, or a tag of another
  commit is refused.

    python3 -I pvm/proof/kit/check.py --rev <commit> --scratch <dir>
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

KIT = Path(__file__).resolve().parent / "vos_kit.py"
BOOTSTRAP = KIT.parent / "vos-sync.sh"
REPO = KIT.parents[3]
TAG = "kit-check"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(KIT), *args], capture_output=True, text=True, check=False
    )


def git(*args: str) -> str:
    done = subprocess.run(["git", *args], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        sys.exit(f"git {' '.join(args)}: {done.stderr}")
    return done.stdout.strip()


class Check:
    def __init__(self, scratch: Path, clone: Path):
        self.scratch = scratch
        self.clone = clone

    def sync(self, kit: Path) -> subprocess.CompletedProcess:
        return run("sync", str(kit), "--vos", str(self.clone), "--scratch", str(self.scratch / "work"))

    def bootstrap(self, kit: Path) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(BOOTSTRAP), str(kit), str(self.clone)],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "VOS_SYNC_SCRATCH": str(self.scratch / "work")},
        )

    def refused(self, done: subprocess.CompletedProcess, why: str, case: str) -> None:
        if done.returncode == 0 or why not in done.stderr:
            sys.exit(f"{case}: not refused ({why!r}):\n{done.stdout}{done.stderr}")

    def accepted(self, done: subprocess.CompletedProcess, case: str) -> None:
        if done.returncode != 0:
            sys.exit(f"{case}: refused:\n{done.stdout}{done.stderr}")

    def copy(self, kit: Path) -> Path:
        tampered = self.scratch / "tampered"
        shutil.rmtree(tampered, ignore_errors=True)
        shutil.copytree(kit, tampered)
        return tampered


def vendor_line(kit: Path, key: str, value: str | None) -> None:
    """`VENDOR`'s `key` set to `value` (a TOML string), or removed."""
    vendor = kit / "VENDOR"
    lines = [line for line in vendor.read_text().splitlines() if not line.startswith(f"{key} = ")]
    if value is not None:
        lines.append(f'{key} = "{value}"')
    vendor.write_text("\n".join(lines) + "\n")


def rehash(kit: Path) -> None:
    """`VENDOR`'s tree hash recomputed over the kit as it now is."""
    done = run("hash", str(kit))
    if done.returncode != 0:
        sys.exit(done.stderr)
    vendor_line(kit, "tree", done.stdout.strip())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rev", default="HEAD")
    parser.add_argument("--scratch", required=True)
    arguments = parser.parse_args()
    scratch = Path(arguments.scratch).resolve()
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)

    commit = git("-C", str(REPO), "rev-parse", "--verify", f"{arguments.rev}^{{commit}}")
    clone = scratch / "vos.git"
    common = git("-C", str(REPO), "rev-parse", "--path-format=absolute", "--git-common-dir")
    git("clone", "--quiet", "--bare", "--shared", "--no-tags", common, str(clone))
    git("-C", str(clone), "tag", TAG, commit)
    git("-C", str(clone), "tag", f"{TAG}-other", f"{commit}^")
    check = Check(scratch, clone)

    kit = scratch / "kit"
    done = run("vendor", str(kit), "--repo", str(clone), "--rev", TAG)
    check.accepted(done, "vendoring at the test tag")
    check.accepted(check.sync(kit), "a kit vendored at a tag")
    check.accepted(check.bootstrap(kit), "a kit vendored at a tag, by the bootstrap")

    victims = [
        "vos-statement/src/lib.rs",
        "vos-pvm-final-verifier/Cargo.toml",
        "fixtures/wrap.proof",
        "vos_kit.py",
        ".gitattributes",
    ]
    for victim in victims:
        tampered = check.copy(kit)
        path = tampered / victim
        content = bytearray(path.read_bytes())
        content[len(content) // 2] ^= 0x01
        path.write_bytes(bytes(content))
        check.refused(check.sync(tampered), "differ from VENDOR's hash", f"{victim}, a byte flipped")
        rehash(tampered)
        check.refused(check.sync(tampered), f"differs {victim}", f"{victim}, a byte flipped and rehashed")

    for case, change, why in [
        ("a file added", lambda kit: (kit / "vos-anchor/src/extra.rs").write_text(""), "not VOS's vos-anchor/src/extra.rs"),
        ("a file removed", lambda kit: (kit / "fixtures/statements.cases").unlink(), "missing fixtures/statements.cases"),
    ]:
        tampered = check.copy(kit)
        change(tampered)
        check.refused(check.sync(tampered), "differ from VENDOR's hash", case)
        rehash(tampered)
        check.refused(check.sync(tampered), why, f"{case}, rehashed")

    # The kit's own script replaced by one that accepts anything, beside a
    # change: it passes itself; the bootstrap runs the tag's and refuses.
    tampered = check.copy(kit)
    (tampered / "vos-statement/src/lib.rs").write_text("// not VOS's\n")
    (tampered / "vos_kit.py").write_text("print(\"the kit is VOS's\")\n")
    rehash(tampered)
    lying = subprocess.run(
        [sys.executable, "-I", str(tampered / "vos_kit.py"), "sync", str(tampered)],
        capture_output=True, text=True, check=False,
    )
    check.accepted(lying, "the tampered kit's own script")
    check.refused(check.bootstrap(tampered), "differs vos-statement/src/lib.rs", "a tampered kit, by the bootstrap")

    # `VENDOR`'s names, outside the hash, each refused.
    for case, key, value, why in [
        ("no tag", "tag", None, "names no tag"),
        ("a short commit", "commit", commit[:12], "is not 40 hex digits"),
        ("a tag read as an option", "tag", "-x", "is not a tag name"),
        ("a tag of another commit", "tag", f"{TAG}-other", "VENDOR says"),
        ("a tag VOS lacks", "tag", f"{TAG}-none", "holds no tag"),
    ]:
        tampered = check.copy(kit)
        vendor_line(tampered, key, value)
        check.refused(check.sync(tampered), why, f"VENDOR with {case}")
    tampered = check.copy(kit)
    vendor_line(tampered, "tag", None)
    check.refused(check.bootstrap(tampered), "names no tag", "VENDOR with no tag, by the bootstrap")

    shutil.rmtree(scratch, ignore_errors=True)
    print(
        f"the sync check refuses a one-byte change in each of {len(victims)} vendored files, a file "
        "added and one removed, a kit's own script, and VENDOR's untagged, malformed or moved names"
    )


if __name__ == "__main__":
    main()
