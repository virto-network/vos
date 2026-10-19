#!/usr/bin/env python3
"""The sync check's own test (`just check-kit`): a kit vendored at a commit
syncs, and one byte changed in any vendored file is refused, whether
`VENDOR`'s hash is left as it was or recomputed over the change; so is a
file added or removed.

    python3 -I pvm/proof/kit/check.py --rev <commit> --scratch <dir>
"""

import argparse
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

KIT = Path(__file__).resolve().parent / "vos_kit.py"
REPO = KIT.parents[3]


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(KIT), *args], capture_output=True, text=True, check=False
    )


def sync(kit: Path, scratch: Path) -> subprocess.CompletedProcess:
    return run("sync", str(kit), "--vos", str(REPO), "--scratch", str(scratch / "work"))


def refused(kit: Path, scratch: Path, why: str, case: str) -> None:
    done = sync(kit, scratch)
    if done.returncode == 0 or why not in done.stderr:
        sys.exit(f"{case}: the sync did not refuse it ({why!r}):\n{done.stdout}{done.stderr}")


def rehash(kit: Path) -> None:
    """`VENDOR`'s tree hash recomputed over the kit as it now is."""
    vendor = kit / "VENDOR"
    lines = vendor.read_text().splitlines()
    done = run("hash", str(kit))
    if done.returncode != 0:
        sys.exit(done.stderr)
    lines = [f'tree = "{done.stdout.strip()}"' if line.startswith("tree = ") else line for line in lines]
    vendor.write_text("\n".join(lines) + "\n")
    tomllib.loads(vendor.read_text())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rev", default="HEAD")
    parser.add_argument("--scratch", required=True)
    arguments = parser.parse_args()
    scratch = Path(arguments.scratch).resolve()
    shutil.rmtree(scratch, ignore_errors=True)
    kit = scratch / "kit"
    done = run("vendor", str(kit), "--rev", arguments.rev)
    if done.returncode != 0:
        sys.exit(done.stderr)
    done = sync(kit, scratch)
    if done.returncode != 0:
        sys.exit(f"a kit vendored at {arguments.rev} does not sync:\n{done.stderr}")

    victims = [
        "vos-statement/src/lib.rs",
        "vos-pvm-final-verifier/Cargo.toml",
        "fixtures/wrap.proof",
        "vos_kit.py",
    ]
    for victim in victims:
        tampered = scratch / "tampered"
        shutil.rmtree(tampered, ignore_errors=True)
        shutil.copytree(kit, tampered)
        path = tampered / victim
        content = bytearray(path.read_bytes())
        content[len(content) // 2] ^= 0x01
        path.write_bytes(bytes(content))
        refused(tampered, scratch, "differ from VENDOR's hash", f"{victim}, a byte flipped")
        rehash(tampered)
        refused(tampered, scratch, f"differs {victim}", f"{victim}, a byte flipped and rehashed")

    for case, change, why in [
        ("a file added", lambda kit: (kit / "vos-anchor/src/extra.rs").write_text(""), "not VOS's vos-anchor/src/extra.rs"),
        ("a file removed", lambda kit: (kit / "fixtures/statements.cases").unlink(), "missing fixtures/statements.cases"),
    ]:
        tampered = scratch / "tampered"
        shutil.rmtree(tampered, ignore_errors=True)
        shutil.copytree(kit, tampered)
        change(tampered)
        refused(tampered, scratch, "differ from VENDOR's hash", case)
        rehash(tampered)
        refused(tampered, scratch, why, f"{case}, rehashed")

    shutil.rmtree(scratch, ignore_errors=True)
    print(f"the sync check refuses a one-byte change in each of {len(victims)} vendored files, a file added and one removed")


if __name__ == "__main__":
    main()
