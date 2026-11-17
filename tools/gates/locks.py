#!/usr/bin/env python3
"""The side workspaces' lock files held to the root's (`just check-locks`).

    python3 -I tools/gates/locks.py check [--root <Cargo.lock>]

The verifier's dependencies are resolved once, in the root `Cargo.lock`.
A workspace built apart from the root's that links the verifier keeps a
lock of its own, written from the root's (`just locks`: the root's copied
in, cargo left to prune it to what the workspace links, the result kept),
and builds `--locked` on it. `check` fails unless every package of each
side lock, its name, version and source, is a package of the root lock
(or of `--root`'s) too, but the side workspace's own package and the
tools only that workspace links (`SIDES`' names): no package of the
verifier's graph resolves to another version there than in the root's.

The side workspaces (`SIDES`): the final verifier's Wasm blob, whose
bytes `blobs.lock` pins, and the prover's fuzz targets. The blob's runner
(`pvm/proof/final-verifier/wasm/run`) keeps a lock of its own: it links
wasmtime, a tool that measures the blob and is no part of it.
"""

import pathlib
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Each side workspace, and the packages only it links (by name, at any
# version): its tools, and their own dependencies the root's graph does not
# hold.
SIDES = {
    "pvm/proof/final-verifier/wasm/blob": set(),
    "pvm/proof/fuzz": {"libfuzzer-sys", "arbitrary", "derive_arbitrary"},
}


def packages(lock: pathlib.Path) -> set[tuple[str, str, str]]:
    """Each package of `lock`: its name, version and source (empty for a
    path package)."""
    with lock.open("rb") as file:
        data = tomllib.load(file)
    return {(package["name"], package["version"], package.get("source", ""))
            for package in data.get("package", [])}


def own(side: pathlib.Path) -> set[str]:
    """The packages of the workspace at `side` (its manifest's package and
    members)."""
    with (side / "Cargo.toml").open("rb") as file:
        manifest = tomllib.load(file)
    names = set()
    if "package" in manifest:
        names.add(manifest["package"]["name"])
    for member in manifest.get("workspace", {}).get("members", []):
        for path in side.glob(member):
            with (path / "Cargo.toml").open("rb") as file:
                names.add(tomllib.load(file)["package"]["name"])
    return names


def check(root: pathlib.Path, sides: dict[str, set[str]]) -> int:
    held = packages(root)
    failed = 0
    for directory, tools in sides.items():
        side = ROOT / directory
        lock = side / "Cargo.lock"
        if not lock.exists():
            print(f"{directory}: no Cargo.lock: `just locks` writes it", file=sys.stderr)
            failed += 1
            continue
        allowed = own(side) | tools
        off = sorted(package for package in packages(lock)
                     if package not in held and package[0] not in allowed)
        for name, version, source in off:
            print(f"{directory}/Cargo.lock: {name} {version} {source or '(path)'} is not the root lock's",
                  file=sys.stderr)
        if off:
            failed += 1
        else:
            print(f"{directory}/Cargo.lock: every package the root lock's, but {', '.join(sorted(allowed))}")
    if failed:
        print("a side lock is off the root's: `just locks` writes them from it", file=sys.stderr)
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv == ["check"]:
        return check(ROOT / "Cargo.lock", SIDES)
    if len(argv) == 3 and argv[:2] == ["check", "--root"]:
        return check(pathlib.Path(argv[2]), SIDES)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
