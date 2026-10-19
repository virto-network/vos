#!/usr/bin/env python3
"""VOS's verifier kit: the crates a venue links to judge VOS statements,
vendored for a chain's runtime (Kreivo's `vendor/vos-verifier/`), and the
check that a vendored kit is exactly VOS's at the commit it names.

The kit holds:
- `vos-anchor`, `vos-statement`, `vos-pvm-final-verifier`,
  `vos-pvm-recair-air` and `vos-pvm-poseidon2`: their sources, and
  manifests made concrete (no workspace inheritance; each other by path;
  Stwo a git dependency at VOS's pin, without default features; no
  dev-dependencies, tests or bins, which stay in VOS);
- `fixtures/`: the golden fixtures `vos-statement`'s `fixtures` feature
  reads (`../fixtures` from its manifest);
- `conformance/`: the conformance vectors, once VOS ships them;
- this script, `vos_kit.py`;
- `VENDOR`: the repository (for information), the commit, the tag, the
  Stwo pin and the tree's hash;
- `.gitattributes`, so a checkout keeps the kit's bytes.

Usage, in a VOS checkout (`just vendor-verifier`, `just vos-sync`):

    python3 -I pvm/proof/kit/vos_kit.py vendor <dir> [--rev <tag or commit>]

writes the kit into `<dir>`: from the working tree, or from `--rev`'s
commit. A kit vendored from uncommitted sources says so in `VENDOR`, and no
sync accepts it; a release vendors from a tag, and a sync refuses a kit
that names none (`--allow-untagged`, against a local clone alone, for
VOS's own checks).

    python3 -I vos_kit.py sync <dir> [--vos <local clone or https:// URL>] [--scratch <dir>]

recomputes the tree's hash against `VENDOR`'s, checks that the tag
`VENDOR` names is the commit it names (fetching nothing the clone lacks),
then vendors the kit anew from that tag, by the tag's own copy of this
script, and refuses any difference, file by file: the sources, the
manifests, the fixtures, the conformance vectors and `VENDOR` itself.
`--vos` defaults to VOS's canonical repository, cloned bare without blobs;
`VENDOR`'s repository is never used. `--scratch` is where the clone and
the reference kit go (default: the system's temporary directory); the
sync removes what it wrote there. Python 3.11 or later and git, nothing of
Rust.

A consumer never runs the kit's own copy of this script, which the kit's
changes could replace: `vos-sync.sh`, kept outside the kit, takes the
script from the tag in VOS's canonical repository and runs that.
"""

import argparse
import fnmatch
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path

# The script's own path in VOS, which a sync runs at the vendored commit.
SCRIPT = "pvm/proof/kit/vos_kit.py"

# The vendored crates, by package, and their directories in VOS.
CRATES = [
    ("vos-anchor", "pvm/proof/anchor"),
    ("vos-statement", "pvm/proof/statement"),
    ("vos-pvm-final-verifier", "pvm/proof/final-verifier"),
    ("vos-pvm-recair-air", "pvm/proof/recair-air"),
    ("vos-pvm-poseidon2", "pvm/proof/poseidon2"),
]

# Features left in VOS: `vos-statement`'s `pvm-guest` builds the JAM refine
# program, a bin; `test-formats` links format 28, the unmasked wrap, which no
# production venue accepts. Their code compiles out of the kit, and an
# optional dependency only they enabled goes with them.
DROPPED_FEATURES = {
    "vos-statement": ["pvm-guest", "test-formats"],
    "vos-pvm-final-verifier": ["test-formats"],
}

# The golden fixtures `vos-statement`'s `fixtures` reader takes: the final
# proofs and the cases.
FIXTURES = "pvm/proof/fixtures"
FIXTURE_FILES = ["statements.cases", "wrap*.proof"]

# The conformance vectors, each its path in VOS and its name under
# `conformance/`. The generator that writes them adds each file here; the
# vendor and the sync then carry and check it as every other file.
CONFORMANCE: list[tuple[str, str]] = []

# The kit's own files, beside the crates.
VENDOR = "VENDOR"
KIT_SCRIPT = "vos_kit.py"

# VOS's canonical repository, which a sync clones unless `--vos` names
# another: never the kit's `VENDOR`, which the kit's own changes could
# rewrite.
CANONICAL = "https://codeberg.org/Virto/VOS.git"

# A tag's name in `VENDOR`.
TAG = r"[A-Za-z0-9._/][A-Za-z0-9._/-]*"

# The tree hash's domain.
TREE_DOMAIN = b"vos/kit/tree/v1"

PACKAGE_KEYS = {
    "name",
    "version",
    "edition",
    "rust-version",
    "license",
    "description",
}
DEPENDENCY_KEYS = {
    "version",
    "path",
    "git",
    "rev",
    "tag",
    "package",
    "default-features",
    "features",
    "optional",
}
DROPPED = {"dev-dependencies", "bin", "test", "bench", "example"}


class KitError(Exception):
    pass


def git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=False
    )
    if done.returncode != 0:
        raise KitError(
            f"git {' '.join(args)}: {done.stderr.decode(errors='replace').strip()}"
        )
    return done.stdout


def git_ok(repo: Path, *args: str) -> bool:
    return (
        subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, check=False
        ).returncode
        == 0
    )


def sources() -> list[str]:
    """The VOS paths a kit is made from."""
    return (
        ["Cargo.toml", SCRIPT, FIXTURES]
        + [directory for _, directory in CRATES]
        + [path for path, _ in CONFORMANCE]
    )


class Tree:
    """VOS's files a kit is made from, by path, and where they come from."""

    def __init__(self, files, repository, commit, tag, dirty):
        self.files: dict[str, bytes] = files
        self.repository: str = repository
        self.commit: str = commit
        self.tag: str | None = tag
        self.dirty: bool = dirty

    def read(self, path: str) -> bytes:
        if path not in self.files:
            raise KitError(f"{path} is not in VOS at {self.commit}")
        return self.files[path]

    def under(self, directory: str) -> list[str]:
        prefix = directory.rstrip("/") + "/"
        return sorted(path for path in self.files if path.startswith(prefix))


def worktree(repo: Path) -> Tree:
    """The working tree's tracked files."""
    commit = git(repo, "rev-parse", "HEAD").decode().strip()
    listed = git(repo, "ls-files", "-z", "--", *sources()).decode()
    files = {}
    for path in filter(None, listed.split("\0")):
        try:
            files[path] = (repo / path).read_bytes()
        except FileNotFoundError:
            raise KitError(f"{path} is tracked but missing from the working tree")
    dirty = not git_ok(repo, "diff", "--quiet", "HEAD", "--", *sources())
    return Tree(files, repository(files), commit, None, dirty)


def at(repo: Path, rev: str) -> Tree:
    """The files of commit `rev`, a tag or a commit."""
    tag = rev if git_ok(repo, "rev-parse", "--verify", "--quiet", f"refs/tags/{rev}") else None
    name = f"refs/tags/{rev}" if tag else rev
    commit = git(repo, "rev-parse", "--verify", f"{name}^{{commit}}").decode().strip()
    archive = git(repo, "archive", "--format=tar", commit, "--", *sources())
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        for member in tar:
            if member.isfile():
                files[member.name] = tar.extractfile(member).read()
    return Tree(files, repository(files), commit, tag, False)


def repository(files: dict[str, bytes]) -> str:
    workspace = tomllib.loads(files["Cargo.toml"].decode())["workspace"]
    return workspace.get("package", {}).get("repository", "")


def toml_key(key: str) -> str:
    return key if re.fullmatch(r"[A-Za-z0-9_-]+", key) else json.dumps(key)


def toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        fields = ", ".join(f"{toml_key(k)} = {toml_value(v)}" for k, v in value.items())
        return "{ " + fields + " }"
    raise KitError(f"no TOML for {value!r}")


def table(name: str, entries: dict) -> list[str]:
    lines = [f"[{name}]"]
    lines += [f"{toml_key(key)} = {toml_value(value)}" for key, value in entries.items()]
    return lines + [""]


class Manifests:
    """The vendored crates' manifests, made concrete from VOS's workspace."""

    def __init__(self, tree: Tree):
        self.tree = tree
        workspace = tomllib.loads(tree.read("Cargo.toml").decode())["workspace"]
        self.package = workspace.get("package", {})
        self.dependencies = workspace.get("dependencies", {})
        self.lints = workspace.get("lints")
        self.vendored = {directory: package for package, directory in CRATES}

    def stwo(self) -> str:
        stwo = self.dependencies.get("stwo")
        if not isinstance(stwo, dict) or "rev" not in stwo:
            raise KitError("the workspace pins no Stwo revision")
        return stwo["rev"]

    def dependency(self, crate: str, name: str, spec, workspace_relative: bool) -> dict:
        spec = {"version": spec} if isinstance(spec, str) else dict(spec)
        if spec.pop("workspace", False):
            base = self.dependencies.get(name)
            if base is None:
                raise KitError(f"{crate}: {name} is not a workspace dependency")
            base = {"version": base} if isinstance(base, str) else dict(base)
            features = base.get("features", []) + spec.pop("features", [])
            base.update(spec)
            if features:
                base["features"] = features
            spec, workspace_relative = base, True
        unknown = set(spec) - DEPENDENCY_KEYS
        if unknown:
            raise KitError(f"{crate}: {name} has keys the kit does not vendor: {sorted(unknown)}")
        if "git" in spec and "rev" not in spec and "tag" not in spec:
            raise KitError(f"{crate}: {name} is a git dependency at no revision")
        if "path" in spec:
            base = "" if workspace_relative else self.directory(crate) + "/"
            target = normalize(base + spec["path"])
            if target not in self.vendored:
                raise KitError(f"{crate}: {name} ({target}) is not a vendored crate")
            spec["path"] = f"../{self.vendored[target]}"
        order = ["package", "version", "path", "git", "rev", "tag", "default-features", "features", "optional"]
        return {key: spec[key] for key in order if key in spec}

    def directory(self, crate: str) -> str:
        return next(directory for package, directory in CRATES if package == crate)

    def write(self, crate: str) -> bytes:
        directory = self.directory(crate)
        manifest = tomllib.loads(self.tree.read(f"{directory}/Cargo.toml").decode())
        unknown = set(manifest) - DROPPED - {"package", "lib", "features", "dependencies", "build-dependencies", "lints"}
        if unknown:
            raise KitError(f"{crate}: sections the kit does not vendor: {sorted(unknown)}")

        package = {}
        for key, value in manifest["package"].items():
            if key not in PACKAGE_KEYS:
                raise KitError(f"{crate}: package.{key} is not vendored")
            if isinstance(value, dict) and value.get("workspace"):
                if key not in self.package:
                    raise KitError(f"{crate}: package.{key} inherits no workspace value")
                value = self.package[key]
            package[key] = value
        if package.get("name") != crate:
            raise KitError(f"{directory} is {package.get('name')}, not {crate}")
        package.update(
            {
                "publish": False,
                "build": False,
                "autobins": False,
                "autoexamples": False,
                "autotests": False,
                "autobenches": False,
            }
        )

        lib = dict(manifest.get("lib", {}))
        lib.update({"test": False, "doctest": False, "bench": False})

        sections = {}
        for kind in ("dependencies", "build-dependencies"):
            entries = manifest.get(kind, {})
            if entries:
                sections[kind] = {
                    name: self.dependency(crate, name, spec, False)
                    for name, spec in entries.items()
                }
        features = dict(manifest.get("features", {}))
        # A dropped feature's code compiles out: it stays an expected cfg
        # value, so a source that reads it builds without a warning.
        expected = []
        for feature in DROPPED_FEATURES.get(crate, []):
            if features.pop(feature, None) is None:
                raise KitError(f"{crate}: no feature {feature} to leave in VOS")
            if any(
                f'feature = "{feature}"'.encode() in self.tree.files[path]
                for path in self.tree.under(f"{directory}/src")
                if not path.startswith(f"{directory}/src/bin/")
            ):
                expected.append(feature)
        for feature, enables in features.items():
            for item in enables:
                target, _, enabled = item.partition("/")
                if enabled in DROPPED_FEATURES.get(target.rstrip("?"), []):
                    raise KitError(f"{crate}: feature {feature} enables {item}, which the kit leaves in VOS")
        referenced = {
            item.removeprefix("dep:").split("/")[0].rstrip("?")
            for enables in features.values()
            for item in enables
        }
        for entries in sections.values():
            for name in [name for name, spec in entries.items() if spec.get("optional")]:
                if name not in referenced:
                    del entries[name]
        names = {name for entries in sections.values() for name in entries}
        for feature, enables in features.items():
            for item in enables:
                dependency = item.removeprefix("dep:").split("/")[0].rstrip("?")
                if dependency not in names and dependency not in features:
                    raise KitError(f"{crate}: feature {feature} names {item}, not vendored")

        lines = [
            f"# Vendored from VOS's `{directory}/Cargo.toml` by `vos_kit.py`: the",
            "# workspace's fields and dependencies made concrete; the tests,",
            "# dev-dependencies and bins left in VOS. Change it there and vendor",
            "# again.",
            "",
        ]
        lines += table("package", package)
        lines += table("lib", lib)
        if features:
            lines += table("features", features)
        for kind, entries in sections.items():
            lines += table(kind, entries)
        lints = manifest.get("lints")
        if isinstance(lints, dict) and lints.get("workspace"):
            if self.lints is None:
                raise KitError(f"{crate}: lints inherit no workspace lints")
            lints = self.lints
        lints = {tool: dict(entries) for tool, entries in (lints or {}).items()}
        if expected:
            rust = lints.setdefault("rust", {})
            if "unexpected_cfgs" in rust:
                raise KitError(f"{crate}: its own unexpected_cfgs lint and dropped features")
            values = ", ".join(f'"{feature}"' for feature in expected)
            rust["unexpected_cfgs"] = {
                "level": "warn",
                "check-cfg": [f"cfg(feature, values({values}))"],
            }
        for tool, entries in lints.items():
            lines += table(f"lints.{tool}", entries)
        return ("\n".join(lines).rstrip("\n") + "\n").encode()


def normalize(path: str) -> str:
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise KitError(f"{path} leaves the repository")
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def kit(tree: Tree) -> dict[str, bytes]:
    """The kit's files, by path in it, `VENDOR` last."""
    manifests = Manifests(tree)
    files: dict[str, bytes] = {}
    for crate, directory in CRATES:
        files[f"{crate}/Cargo.toml"] = manifests.write(crate)
        for path in tree.under(f"{directory}/src"):
            if not path.startswith(f"{directory}/src/bin/"):
                files[f"{crate}/{path.removeprefix(directory + '/')}"] = tree.files[path]
    fixtures = [
        path
        for path in tree.under(FIXTURES)
        if "/" not in path.removeprefix(FIXTURES + "/")
        and any(fnmatch.fnmatchcase(Path(path).name, pattern) for pattern in FIXTURE_FILES)
    ]
    if not fixtures:
        raise KitError(f"no fixtures under {FIXTURES}")
    for path in fixtures:
        files[f"fixtures/{Path(path).name}"] = tree.files[path]
    for path, name in CONFORMANCE:
        files[f"conformance/{name}"] = tree.read(path)
    files[KIT_SCRIPT] = tree.read(SCRIPT)
    # A checkout that converts line endings would change the kit's bytes.
    files[".gitattributes"] = b"* -text\n"

    lines = [
        "# The VOS verifier kit: the crates a venue links to judge VOS",
        "# statements, the golden fixtures and the conformance vectors, vendored",
        "# by `vos_kit.py vendor`. Every file here is generated: change it in VOS",
        "# and vendor again. `python3 -I vos_kit.py sync <this directory>` checks",
        "# it against the commit below.",
        f"repository = {toml_value(tree.repository)}",
        f"commit = {toml_value(tree.commit)}",
    ]
    if tree.tag:
        lines.append(f"tag = {toml_value(tree.tag)}")
    if tree.dirty:
        lines.append("dirty = true")
    lines += [
        f"stwo = {toml_value(manifests.stwo())}",
        f"tree = {toml_value(tree_hash(files))}",
    ]
    files[VENDOR] = ("\n".join(lines) + "\n").encode()
    return files


def tree_hash(files: dict[str, bytes]) -> str:
    """BLAKE2b-256 over every file but `VENDOR`, by path: each its path's
    length (4, LE), its path, its length (8, LE) and its bytes."""
    hasher = hashlib.blake2b(digest_size=32)
    hasher.update(TREE_DOMAIN)
    for path in sorted((path for path in files if path != VENDOR), key=str.encode):
        name = path.encode()
        hasher.update(len(name).to_bytes(4, "little"))
        hasher.update(name)
        hasher.update(len(files[path]).to_bytes(8, "little"))
        hasher.update(files[path])
    return "blake2b-256:" + hasher.hexdigest()


def read_kit(directory: Path) -> dict[str, bytes]:
    """Every file under `directory`, by its path there."""
    if not directory.is_dir():
        raise KitError(f"{directory} is not a directory")
    files = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if path.is_symlink():
            raise KitError(f"{relative} is a link: a kit holds files alone")
        if path.is_file():
            files[relative] = path.read_bytes()
        elif not path.is_dir():
            raise KitError(f"{relative} is not a file")
    return files


def write_kit(directory: Path, files: dict[str, bytes]) -> None:
    if directory.exists():
        if any(directory.iterdir()):
            if not (directory / VENDOR).is_file():
                raise KitError(f"{directory} holds files and no kit: refusing to replace it")
            shutil.rmtree(directory)
    for path, content in files.items():
        target = directory / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)


def vendor(arguments) -> None:
    script_repo = Path(__file__).resolve().parent
    repo = Path(arguments.repo) if arguments.repo else Path(
        git(script_repo, "rev-parse", "--show-toplevel").decode().strip()
    )
    if arguments.rev:
        tree = at(repo, arguments.rev)
    else:
        if not (repo / SCRIPT).is_file():
            raise KitError(f"{repo} is not a VOS checkout")
        tree = worktree(repo)
    files = kit(tree)
    write_kit(Path(arguments.dir), files)
    note = " (uncommitted sources: no sync accepts it)" if tree.dirty else ""
    print(f"vendored VOS {tree.tag or tree.commit} into {arguments.dir}: {tree_hash(files)}{note}")


def vos_repository(spec: str, scratch: Path) -> tuple[Path, bool]:
    """The VOS repository to sync against, and whether it is local: an
    `https://` URL, cloned bare without blobs, or a local clone, which only
    `--vos` names."""
    if spec.startswith("https://"):
        clone = scratch / "vos.git"
        done = subprocess.run(
            ["git", "clone", "--quiet", "--bare", "--filter=blob:none", "--", spec, str(clone)],
            capture_output=True,
            check=False,
        )
        if done.returncode != 0:
            raise KitError(f"cloning {spec}: {done.stderr.decode(errors='replace').strip()}")
        return clone, False
    path = Path(spec)
    if not path.is_dir() or not git_ok(path, "rev-parse", "--git-dir"):
        raise KitError(f"{spec} is neither an https:// URL nor a local git repository")
    return path.resolve(), True


def no_lazy_fetch(repo: Path, *args: str) -> subprocess.CompletedProcess:
    """`git args` in `repo`, fetching no missing object: a partial clone
    otherwise asks the server for any commit by its hash."""
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        check=False,
        env={**os.environ, "GIT_NO_LAZY_FETCH": "1"},
    )


def sync(arguments) -> None:
    directory = Path(arguments.dir)
    files = read_kit(directory)
    if VENDOR not in files:
        raise KitError(f"{directory} has no VENDOR file")
    vendored = tomllib.loads(files[VENDOR].decode())
    if vendored.get("dirty"):
        raise KitError("the kit was vendored from uncommitted sources: vendor it from a tag")
    commit = vendored.get("commit", "")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise KitError(f"VENDOR's commit {commit!r} is not 40 hex digits")
    tag = vendored.get("tag")
    if tag is not None and (not isinstance(tag, str) or not re.fullmatch(TAG, tag)):
        raise KitError(f"VENDOR's tag {tag!r} is not a tag name")
    if tag is None and not arguments.allow_untagged:
        raise KitError("VENDOR names no tag: a kit is vendored from a VOS tag")
    computed = tree_hash(files)
    if computed != vendored.get("tree"):
        raise KitError(
            f"the kit's files differ from VENDOR's hash (a file edited, added or removed): "
            f"{computed}, VENDOR says {vendored.get('tree')}"
        )

    if arguments.scratch:
        Path(arguments.scratch).mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="vos-sync-", dir=arguments.scratch))
    try:
        repo, local = vos_repository(arguments.vos or CANONICAL, scratch)
        if tag is None and not local:
            raise KitError("an untagged kit syncs against a local clone alone")
        if tag is not None:
            tagged = no_lazy_fetch(repo, "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}^{{commit}}")
            if tagged.returncode != 0:
                raise KitError(f"{repo} holds no tag {tag}")
            if tagged.stdout.decode().strip() != commit:
                raise KitError(
                    f"tag {tag} is {tagged.stdout.decode().strip()} in {repo}, VENDOR says {commit}"
                )
        elif no_lazy_fetch(repo, "cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
            raise KitError(f"{repo} holds no commit {commit}: fetch it")
        tool = scratch / "tool" / KIT_SCRIPT
        tool.parent.mkdir()
        tool.write_bytes(git(repo, "show", f"{commit}:{SCRIPT}"))
        reference = scratch / "reference"
        done = subprocess.run(
            [sys.executable, "-I", str(tool), "vendor", str(reference),
             "--repo", str(repo), "--rev", tag or commit],
            capture_output=True,
            check=False,
        )
        if done.returncode != 0:
            raise KitError(
                f"vendoring VOS {tag or commit} anew: {done.stderr.decode(errors='replace').strip()}"
            )
        expected = read_kit(reference)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    missing = sorted(set(expected) - set(files))
    extra = sorted(set(files) - set(expected))
    changed = sorted(path for path in set(files) & set(expected) if files[path] != expected[path])
    if missing or extra or changed:
        report = [f"missing {path}" for path in missing]
        report += [f"not VOS's {path}" for path in extra]
        report += [f"differs {path}" for path in changed]
        raise KitError(
            f"the kit is not VOS's at {tag or commit}:\n  " + "\n  ".join(report)
        )
    print(f"the kit is VOS's at {tag or commit}: {computed}")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="vos_kit.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    commands = parser.add_subparsers(dest="command", required=True)
    vendoring = commands.add_parser("vendor", help="write the kit into a directory")
    vendoring.add_argument("dir")
    vendoring.add_argument("--repo", help="the VOS repository (default: this script's)")
    vendoring.add_argument("--rev", help="a tag or commit (default: the working tree)")
    syncing = commands.add_parser("sync", help="check a kit against the commit VENDOR names")
    syncing.add_argument("dir")
    syncing.add_argument("--vos", help=f"a local VOS clone, or an https:// URL (default: {CANONICAL})")
    syncing.add_argument(
        "--allow-untagged", action="store_true", help="accept a kit vendored at a commit (a local clone only)"
    )
    syncing.add_argument("--scratch", help="where the clone and the reference kit go")
    hashing = commands.add_parser("hash", help="print a kit's tree hash")
    hashing.add_argument("dir")
    arguments = parser.parse_args()
    try:
        if arguments.command == "vendor":
            vendor(arguments)
        elif arguments.command == "sync":
            sync(arguments)
        else:
            print(tree_hash(read_kit(Path(arguments.dir))))
    except KitError as error:
        print(f"vos_kit.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
