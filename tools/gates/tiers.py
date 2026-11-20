#!/usr/bin/env python3
"""The gate tiers' tool: which test targets are fast and which heavy, the
tripwire that holds the tiers to that, and the tests a change touches.

    python3 -I tools/gates/tiers.py check
    python3 -I tools/gates/tiers.py fast  -p <package>...
    python3 -I tools/gates/tiers.py heavy -p <package>...
    python3 -I tools/gates/tiers.py changed <base> [--heavy]

The tiers nest, `check` within `gate` within `ci` within `ci-full` within
`slice-gate`. `check` runs every test target of the packages it names but
the heavy ones, `tools/gates/heavy.toml`'s; `gate` runs those.

`fast` and `heavy` print the target flags of a `cargo test` over the
packages given (other arguments are skipped, so a recipe passes its whole
package list): `--lib --bins` and a `--test` for each fast test target, or
a `--test` for each heavy one.

`check`, the tripwire, reads `just --dump`: each recipe's body and
dependencies, followed through the `just <recipe>` lines of a body, the
justfile's variables and this tool's own flags expanded. It fails when
- a test target of the workspace is run by no tier;
- a test target is neither run by `check` nor listed heavy and run by
  `gate` (but one that requires a feature, which a recipe enables in a
  build of its own, and those of the packages whose suites prove, `UPPER`,
  which the tiers above `gate` run), or a heavy one is run by `check`, or
  is no target, or is run by no gate;
- a workspace outside the root's is named by no command a tier reaches
  (`--manifest-path`, `cd`, `_at-fixed-path`);
- the agent's guest workspace (`agent/programs`) and `programs.toml` name
  different programs;
- the justfile does not unexport `VOS_PINS`, the pinning tests' write
  mode, or a recipe a tier reaches sets it, so that a gate holds its pins
  and never writes them.

`changed` runs `cargo test` for the workspace packages the diff against
`base` touches and those that depend on them, the fast targets alone
unless `--heavy`.
"""

import json
import pathlib
import re
import shlex
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[2]
TIERS = ["check", "gate", "ci", "ci-full", "slice-gate"]

# The guests the testkit loads: a change under one is a change of the
# tests that run them.
GUEST_LOADER = "vos-testkit"

# Test targets in no tier, on purpose: each needs what no gate has.
UNTIERED = {
    # A PolkaJam testnet: `just e2e-chain`.
    ("vos-node", "chain"),
}

# The pinning tests' write mode, which only the re-pin recipes set.
PIN_MODE = "VOS_PINS"

# The packages no light or step tier runs whole: their suites prove, and
# belong to `ci` and above (`test-bench`, `test-proof`, `test-carriers`).
UPPER = {"vos-pvm-proof", "vos-kernel-tests", "vos-pvm-bench", "vos-phone"}


def run(*command):
    return subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True).stdout


def workspace():
    """Each workspace package's test targets, `(name, kind, features)` with
    the features the target requires beyond the package's defaults, its
    manifest and its directory."""
    metadata = json.loads(run("cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"))
    members, manifests, directories = {}, {}, {}
    for package in metadata["packages"]:
        manifest = pathlib.Path(package["manifest_path"]).relative_to(ROOT)
        manifests[str(manifest)] = package["name"]
        directories[package["name"]] = str(manifest.parent)
        defaults, queue = set(), ["default"]
        while queue:
            for feature in package["features"].get(queue.pop(), []):
                if feature not in defaults:
                    defaults.add(feature)
                    queue.append(feature)
        members[package["name"]] = [
            (t["name"], "lib" if t["kind"][0] in ("lib", "proc-macro", "rlib") else t["kind"][0],
             [feature for feature in t.get("required-features", []) if feature not in defaults])
            for t in package["targets"]
            if t.get("test") and t["kind"][0] in ("lib", "proc-macro", "rlib", "bin", "test")
        ]
    return members, manifests, directories


def heavy_list():
    """`heavy.toml`'s entries: `(package, target)` to its seconds."""
    listed = tomllib.loads((ROOT / "tools/gates/heavy.toml").read_text())["heavy"]
    return {(entry["package"], entry["target"]): entry["seconds"] for entry in listed}


def packages_of(arguments):
    return [arguments[i + 1] for i, argument in enumerate(arguments[:-1]) if argument == "-p"]


def features_of(arguments):
    """The features a `cargo test`'s arguments enable, by their bare names."""
    return {feature.split("/")[-1]
            for i, argument in enumerate(arguments[:-1]) if argument == "--features"
            for feature in arguments[i + 1].split(",")}


def flags(tier, arguments, members=None):
    """The target flags for `tier` of a `cargo test` with `arguments`, its
    packages and features. A target that requires a feature they do not
    enable is named by neither tier: the recipe that enables it runs it."""
    packages, features = packages_of(arguments), features_of(arguments)
    members = members or workspace()[0]
    heavy = heavy_list()
    fast, slow = set(), set()
    for package in packages:
        for name, kind, required in members[package]:
            if kind == "test" and set(required) <= features:
                (slow if (package, name) in heavy else fast).add(name)
    both = fast & slow
    if both:
        sys.exit(f"{sorted(both)}: a heavy test target and a fast one of one name in one "
                 f"invocation ({' '.join(packages)}): run the packages apart")
    if tier == "heavy":
        if not slow:
            # No flag at all would run every target again.
            sys.exit(f"no heavy test target in {' '.join(packages)}: drop the recipe's line")
        return [flag for name in sorted(slow) for flag in ("--test", name)]
    # `--lib` where no package has a library is cargo's error, not an empty set.
    lib = ["--lib"] if any(kind == "lib" for package in packages
                           for _, kind, _ in members[package]) else []
    return lib + ["--bins"] + [flag for name in sorted(fast) for flag in ("--test", name)]


# ===== The tripwire =====

def text(fragments, variables):
    """A body line's text, its interpolations expanded."""
    out = []
    for fragment in fragments:
        if isinstance(fragment, str):
            out.append(fragment)
        elif fragment and fragment[0] and fragment[0][0] == "variable":
            out.append(variables.get(fragment[0][1], "ARG"))
        else:
            # An expression: a placeholder no flag reads.
            out.append("ARG")
    return "".join(out)


def reached(dump, top, members):
    """Every recipe `top` reaches, and every body line of theirs, this
    tool's flags expanded."""
    variables = {name: a["value"] if isinstance(a["value"], str) else ""
                 for name, a in dump["assignments"].items()}
    recipes = dump["recipes"]
    seen, lines, stack = set(), [], [top]
    own = re.compile(r"\.\.\.\(python3 -I tools/gates/tiers\.py (fast|heavy) ([^|)]*)\| split row ' '\)")
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        recipe = recipes[name]
        stack.extend(d["recipe"] for d in recipe["dependencies"])
        for fragments in recipe["body"]:
            line = text(fragments, variables)
            line = own.sub(
                lambda m: " ".join(flags(m.group(1), m.group(2).split(), members)), line)
            lines.append(line)
            # A recipe named in backticks, as a message's `just repin`, is
            # no call.
            for called in re.findall(r"(?<!`)\bjust\s+([A-Za-z_][\w-]*)", line):
                if called in recipes:
                    stack.append(called)
    return seen, lines


def commands(line):
    """The cargo invocations of a nushell or bash line, as token lists."""
    for part in re.split(r";|\|\||&&|\{|\}|\(|\)", line):
        try:
            tokens = shlex.split(part, posix=True)
        except ValueError:
            tokens = part.split()
        if "cargo" in tokens:
            yield tokens[tokens.index("cargo"):]


def covered(lines, members, manifests):
    """The (package, target) pairs the `cargo test` lines run."""
    runs = set()
    for line in lines:
        for tokens in commands(line):
            if len(tokens) < 2 or tokens[1] != "test":
                continue
            arguments = tokens[2:tokens.index("--")] if "--" in tokens else tokens[2:]
            packages, targets, features, everything = [], [], set(), False
            i = 0
            while i < len(arguments):
                flag = arguments[i]
                value = arguments[i + 1] if i + 1 < len(arguments) else None
                if flag == "-p":
                    packages.append(value)
                    i += 1
                elif flag == "--manifest-path":
                    packages.append(manifests.get(value, value))
                    i += 1
                elif flag == "--features":
                    features |= features_of([flag, value])
                    i += 1
                elif flag in ("--test", "--bin"):
                    targets.append(value)
                    i += 1
                elif flag in ("--lib", "--bins", "--tests"):
                    targets.append(flag)
                elif flag == "--all-targets":
                    everything = True
                elif flag == "--workspace":
                    packages = list(members)
                elif flag == "--doc":
                    targets.append(flag)
                i += 1
            for package in packages:
                for name, kind, required in members.get(package, []):
                    if not set(required) <= features:
                        continue
                    if (everything or not targets or (kind == "test" and name in targets)
                            or (kind == "bin" and name in targets)
                            or ("--lib" in targets and kind == "lib")
                            or ("--bins" in targets and kind == "bin")
                            or ("--tests" in targets and kind == "test")):
                        runs.add((package, name))
    return runs


def listed_programs():
    """`programs.toml`'s programs: none in a tree without the agent's guest
    workspace (`agent/programs`)."""
    if not (ROOT / "agent/programs/Cargo.toml").exists():
        return []
    return tomllib.loads((ROOT / "programs.toml").read_text())["program"]


def programs():
    """Where `programs.toml` and the agent's guest workspace differ."""
    listed = listed_programs()
    if not listed:
        return []
    guests = json.loads(run("cargo", "metadata", "--no-deps", "--format-version", "1", "--offline",
                            "--manifest-path", "agent/programs/Cargo.toml"))
    built = {package["name"]: str(pathlib.Path(package["manifest_path"]).parent.relative_to(ROOT))
             for package in guests["packages"]}
    named = {program["name"]: program["crate"] for program in listed}
    failures = [f"programs.toml names {name} at {crate}, agent/programs builds {built.get(name)}"
                for name, crate in named.items() if built.get(name) != crate]
    failures += [f"agent/programs builds {name}, which programs.toml does not name"
                 for name in built if name not in named]
    return failures


def workspace_root(directory):
    """The directory of the workspace `directory`'s manifest belongs to."""
    path = ROOT / directory
    for parent in [path, *path.parents]:
        if parent == ROOT:
            break
        manifest = parent / "Cargo.toml"
        if manifest.exists() and "[workspace]" in manifest.read_text():
            return str(parent.relative_to(ROOT))
    # A package naming its workspace by `package.workspace`.
    named = re.search(r'^workspace\s*=\s*"([^"]+)"', (path / "Cargo.toml").read_text(), re.M)
    if named:
        return str((path / named.group(1)).resolve().relative_to(ROOT))
    return directory


def check():
    dump = json.loads(run("just", "--dump", "--dump-format", "json"))
    members, manifests, directories = workspace()
    heavy = heavy_list()
    failures = []

    runs, lines, recipes = {}, {}, {}
    for tier in TIERS:
        recipes[tier], lines[tier] = reached(dump, tier, members)
        runs[tier] = covered(lines[tier], members, manifests)
    for inner, outer in zip(TIERS, TIERS[1:]):
        for recipe in sorted(recipes[inner] - recipes[outer] - {inner}):
            failures.append(f"`{inner}` reaches `{recipe}`, which `{outer}` does not: the tiers nest")
    top = TIERS[-1]

    targets = {(package, name): kind
               for package, listed in members.items() for name, kind, _ in listed}
    gated = {(package, name)
             for package, listed in members.items() for name, _, required in listed if required}
    for (package, name), kind in sorted(targets.items()):
        if (package, name) in UNTIERED:
            if (package, name) in runs[top]:
                failures.append(f"{package}'s `{name}` is run by a tier, and named untiered")
        elif (package, name) not in runs[top]:
            failures.append(f"{package}'s {kind} target `{name}` is run by no tier")
        elif (package, name) in gated or (package, name) in runs["check"]:
            continue
        elif (package, name) not in runs["gate"]:
            if package not in UPPER:
                failures.append(f"{package}'s {kind} target `{name}` is run above `gate` alone: "
                                f"it belongs to `check`, or to tools/gates/heavy.toml and `gate`")
        elif (package, name) not in heavy:
            failures.append(f"{package}'s {kind} target `{name}` is run by `gate`, not by `check`, "
                            f"and tools/gates/heavy.toml does not list it")
    for package, name in sorted(heavy):
        if (package, name) not in targets:
            failures.append(f"heavy.toml lists {package}'s `{name}`, which is no test target")
        elif (package, name) in runs["check"]:
            failures.append(f"heavy.toml lists {package}'s `{name}`, which `check` runs")
        elif (package, name) not in runs["gate"]:
            failures.append(f"heavy.toml lists {package}'s `{name}`, which `gate` does not run")

    # Workspaces outside the root's: each named by a command a tier reaches.
    tracked = run("git", "ls-files", "*Cargo.toml").split()
    outside = set()
    for manifest in tracked:
        directory = str(pathlib.Path(manifest).parent)
        if directory != "." and directory not in directories.values():
            outside.add(workspace_root(directory))
    # A line that only formats builds and tests nothing.
    joined = "\n".join(line for line in lines[top] if "cargo fmt" not in line)
    for directory in sorted(outside):
        if not re.search(rf"(^|[\s/'\"\[(]){re.escape(directory)}([/\s'\"\]);]|$)", joined, re.M):
            failures.append(f"the workspace at {directory} is built or tested by no tier")

    # The pins' write mode: never inherited, never set within a tier.
    if PIN_MODE not in dump.get("unexports", []):
        failures.append(f"the justfile does not unexport {PIN_MODE}: an inherited write mode "
                        f"would turn a gate's pin checks into rewrites")
    for tier in TIERS:
        for line in lines[tier]:
            if re.search(rf"\b{PIN_MODE}\b", line):
                failures.append(f"`{tier}` reaches a line setting {PIN_MODE}: {line.strip()}")

    failures.extend(programs())
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        sys.exit(f"{len(failures)} failures of the gate tiers")
    print(f"the tiers nest ({' ⊆ '.join(TIERS)}); every test target is in one "
          f"({len(runs['check'])} in `check`, {len(heavy)} heavy, {len(runs[top])} in all), "
          f"and every workspace outside the root's ({len(outside)})")


# ===== The tests a change touches =====

def changed(base, with_heavy):
    members, _, directories = workspace()
    files = run("git", "diff", "--name-only", base, "--").split("\n")
    files += run("git", "ls-files", "--others", "--exclude-standard").split("\n")
    files = [file for file in files if file]
    guests = [program["crate"] for program in listed_programs()] + ["agent/test-actors"]
    touched, everything = set(), False
    for file in files:
        owner = max((directory for directory in directories.values()
                     if file.startswith(directory + "/")), key=len, default=None)
        if owner:
            touched.add(next(name for name, directory in directories.items() if directory == owner))
        elif (any(file.startswith(guest + "/") for guest in guests)
              or file == "programs.toml" or file.startswith(("agent/programs/", "pvm/guest/"))):
            if GUEST_LOADER in members:
                touched.add(GUEST_LOADER)
        elif file in ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml") or file.startswith(".cargo/"):
            everything = True
    if everything:
        touched = set(members)
    # Whoever depends on a touched package, dev-dependencies among them.
    graph = json.loads(run("cargo", "metadata", "--format-version", "1", "--offline"))
    names = {package["id"]: package["name"] for package in graph["packages"]}
    dependents = {}
    for node in graph["resolve"]["nodes"]:
        if names[node["id"]] in members:
            for dependency in node["dependencies"]:
                dependents.setdefault(names[dependency], set()).add(names[node["id"]])
    selected, queue = set(), list(touched)
    while queue:
        package = queue.pop()
        if package not in selected:
            selected.add(package)
            queue.extend(dependents.get(package, ()))
    if not selected:
        print(f"no workspace package differs from {base}")
        return
    upper = sorted(selected & UPPER)
    if upper:
        print(f"left to `ci` and above: {' '.join(upper)}")
    selected -= UPPER
    features = [f"{package}/{feature}" for package, feature in
                (("vos-anchor", "vectors"), ("vos-statement", "fixtures")) if package in selected]
    # The masked prover's suites (the recursion AIR's and the device
    # profile's) run four tests at a time, under the gates' memory limit:
    # apart from the rest.
    masked = {"vos-pvm-recair", "vos-pvm-device"}
    for packages, threads in ((sorted(selected - masked), []),
                              (sorted(selected & masked), ["--", "--test-threads=4"])):
        if not packages:
            continue
        command = ["cargo", "test"] + [argument for package in packages for argument in ("-p", package)]
        if features and not threads:
            command += ["--features", ",".join(features)]
        if not with_heavy:
            command += flags("fast", command, members)
        command += threads
        print(" ".join(command), flush=True)
        status = subprocess.run(command, cwd=ROOT).returncode
        if status:
            sys.exit(status)


def main():
    arguments = sys.argv[1:]
    match arguments[:1]:
        case ["check"]:
            check()
        case ["fast" | "heavy" as tier]:
            print(" ".join(flags(tier, arguments[1:])))
        case ["changed"]:
            rest = [argument for argument in arguments[1:] if argument != "--heavy"]
            if len(rest) != 1:
                sys.exit("changed takes the base to compare with: the justfile's `test-changed` passes its own")
            changed(rest[0], "--heavy" in arguments)
        case _:
            sys.exit(__doc__)


if __name__ == "__main__":
    main()
