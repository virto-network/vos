#!/usr/bin/env python3
"""The side workspaces' lock files held to the root's (`just check-locks`).

    python3 -I tools/gates/locks.py check [--root <Cargo.lock>]

The verifier's dependencies are resolved once, in the root `Cargo.lock`.
A workspace built apart from the root's that links the verifier keeps a
lock of its own, written from the root's (`just locks`: the root's copied
in, cargo left to prune it to what the workspace links, the result kept),
and builds `--locked` on it. `check` fails unless every package of each
side lock that the root lock (or `--root`'s) holds at another version is
at the root's, and each dependency a package names in both locks resolves
to the same version in both, but for the side workspace's own packages,
the tools only that workspace links (`SIDES`' names) and the edges
`DRIFT` names, with what they alone reach: no package of the verifier's
graph resolves to another version there than in the root's. A package the
root's graph lacks altogether (a dependency of a feature only the side
enables) is `deny`'s to check, over the side's manifest.

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


# The edges a side lock resolves otherwise than the root's, each a
# dependency (by name) of a package (by name), kept visible here: cargo
# re-resolves a workspace whose graph differs from the root's and takes
# the highest version a lock holds within an open requirement. Stwo asks
# for `hashbrown >=0.15.2`; the fuzz targets' graph holds `indexmap`'s
# `hashbrown 0.17.1`, so Stwo resolves onto it there (and onto its
# `foldhash 0.2`), where the root, the kit and the Wasm blob resolve
# `0.15.5`. Bounding the requirement is the fork's.
DRIFT = {
    "pvm/proof/fuzz": {("stwo", "hashbrown"), ("stwo-constraint-framework", "hashbrown")},
}

Key = tuple[str, str, str]


def graph(lock: pathlib.Path) -> dict[Key, set[Key]]:
    """Each package of `lock`, its name, version and source (empty for a
    path package), and the packages it depends on."""
    with lock.open("rb") as file:
        data = tomllib.load(file)
    listed = [package for package in data.get("package", [])]
    keys = [(package["name"], package["version"], package.get("source", "")) for package in listed]
    by_name: dict[str, list[Key]] = {}
    for key in keys:
        by_name.setdefault(key[0], []).append(key)

    def resolve(dependency: str) -> Key:
        name, *rest = dependency.split(" ")
        candidates = by_name[name]
        if rest:
            candidates = [key for key in candidates if key[1] == rest[0]]
        return candidates[0]

    return {key: {resolve(dependency) for dependency in package.get("dependencies", [])}
            for key, package in zip(keys, listed)}


def reach(edges: dict[Key, set[Key]], starts: set[Key]) -> set[Key]:
    """`starts` and everything they depend on, transitively."""
    seen, todo = set(), list(starts)
    while todo:
        key = todo.pop()
        if key not in seen:
            seen.add(key)
            todo.extend(edges[key])
    return seen


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
    held = graph(root)
    versions: dict[str, set[str]] = {}
    for name, version, _ in held:
        versions.setdefault(name, set()).add(version)
    failed = 0
    for directory, tools in sides.items():
        side = ROOT / directory
        lock = side / "Cargo.lock"
        if not lock.exists():
            print(f"{directory}: no Cargo.lock: `just locks` writes it", file=sys.stderr)
            failed += 1
            continue
        edges = graph(lock)
        names = own(side) | tools
        drift = DRIFT.get(directory, set())
        drifted = {target for key, targets in edges.items() for target in targets
                   if (key[0], target[0]) in drift}
        # What the side's own packages reach on edges that are neither a
        # tool's nor a drifted one's: the graph held to the root's.
        shared, todo = set(), [key for key in edges if key[0] in own(side)]
        while todo:
            key = todo.pop()
            if key in shared:
                continue
            shared.add(key)
            if key in drifted:
                continue
            todo.extend(target for target in edges[key]
                        if target[0] not in tools and (key[0], target[0]) not in drift)
        off = []
        for key in sorted(shared):
            if key[0] in names:
                continue
            if key not in held:
                if key[0] in versions:
                    off.append(f"{key[0]} {key[1]} {key[2] or '(path)'}: the root lock's is "
                               f"{', '.join(sorted(versions[key[0]]))}")
                continue
            ours = {target[0]: target[1] for target in edges[key] if (key[0], target[0]) not in drift}
            theirs = {target[0]: target[1] for target in held[key]}
            for name in sorted(ours.keys() & theirs.keys()):
                if ours[name] != theirs[name] and name not in tools:
                    off.append(f"{key[0]} {key[1]} depends on {name} {ours[name]}, "
                               f"the root lock's on {theirs[name]}")
        for line in off:
            print(f"{directory}/Cargo.lock: {line}", file=sys.stderr)
        if off:
            failed += 1
        else:
            named = sorted(names) + [f"{a}'s {b}" for a, b in sorted(drift)]
            print(f"{directory}/Cargo.lock: every package at the root lock's versions, on its "
                  f"dependencies' versions, but {', '.join(named)} and what they alone reach")
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
