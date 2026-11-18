#!/usr/bin/env python3
"""The fuzz targets' replay corpora, each one archive (`replay/<target>.tar`
of a fuzz workspace), and their inputs unpacked where the recipes run them.

    python3 -I corpus.py unpack <archives> <directory>
    python3 -I corpus.py pack <inputs> <archive>

`unpack` empties `<directory>`, then writes each archive `<target>.tar` of
`<archives>` into `<directory>/<target>/`, one file an input (`just
fuzz-replay`, `fuzz-reach`, `fuzz`). `pack` writes the inputs of
`<inputs>`, a directory of files alone, into `<archive>` (`just
fuzz-refresh`).

An archive is a plain POSIX ustar archive of regular files, by name in
byte order, each of mode 0644, owner and group 0 with no names, and time
0: the same inputs make the same bytes, so a refresh that finds no new
input leaves the archive as it was. An archive holds at most `MAX_INPUTS`
inputs and `MAX_BYTES` bytes in all, each a plain name (no directory, no
link) of at most `MAX_INPUT` bytes. `unpack` reads every archive whole
before it writes anything, and refuses one that is not the bytes `pack`
writes for its inputs: each member is checked to be a regular file within
those bounds before it is read, then the archive is rebuilt from the
inputs and compared. `unpack`'s `<directory>` is left empty on a refusal.
`test_corpus.py` holds it to that.

A corpus is pruned by its unpacked inputs (`cargo run --example paths --
--each` lists what each reaches): remove the inputs from
`target/replay/<target>/`, then `pack` it into `replay/<target>.tar`.
"""

import io
import shutil
import sys
import tarfile
from pathlib import Path

# The largest input a target takes: a device input, an io-hash and a whole
# device proof (`vos_pvm_device::MAX_PROOF_BYTES`), the justfile's largest
# `-max_len`.
MAX_INPUT = 32 + (1536 << 10)
# The most inputs an archive holds, and the most bytes its inputs hold in
# all.
MAX_INPUTS = 4096
MAX_BYTES = 64 << 20


class CorpusError(Exception):
    pass


def plain(name: str) -> bool:
    return name not in ("", ".", "..") and "/" not in name and "\\" not in name and "\0" not in name


def packed(inputs: list[tuple[str, bytes]]) -> bytes:
    """The archive of `inputs`, each a name and its bytes, by name in byte
    order: the bytes `pack` writes."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in sorted(inputs, key=lambda input: input[0].encode()):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def checked(where: str, inputs: list[tuple[str, bytes]]) -> None:
    """Refuses `inputs` unless an archive may hold them: at least one, at
    most `MAX_INPUTS` and `MAX_BYTES` in all, each a plain name of at most
    ustar's 100 bytes, no name twice, each at most `MAX_INPUT` bytes."""
    if not inputs:
        raise CorpusError(f"{where} holds no input")
    if len(inputs) > MAX_INPUTS:
        raise CorpusError(f"{where}: more than {MAX_INPUTS} inputs")
    names = set()
    for name, data in inputs:
        if not plain(name) or len(name.encode()) > 100:
            raise CorpusError(f"{where}: {name!r} is not a plain name of at most ustar's 100 bytes")
        if name in names:
            raise CorpusError(f"{where}: {name} repeats")
        if len(data) > MAX_INPUT:
            raise CorpusError(f"{where}: {name} is past {MAX_INPUT} bytes")
        names.add(name)
    if sum(len(data) for _, data in inputs) > MAX_BYTES:
        raise CorpusError(f"{where}: its inputs are past {MAX_BYTES} bytes in all")


def pack(inputs: Path, archive: Path) -> None:
    found = []
    for path in sorted(inputs.iterdir()):
        if not path.is_file() or path.is_symlink():
            raise CorpusError(f"{path} is no input: a corpus is a directory of files")
        found.append((path.name, path.read_bytes()))
    checked(str(inputs), found)
    data = packed(found)
    archive.parent.mkdir(parents=True, exist_ok=True)
    partial = archive.with_name(archive.name + ".partial")
    partial.write_bytes(data)
    partial.replace(archive)
    print(f"{archive}: {len(found)} inputs")


def read(archive: Path) -> list[tuple[str, bytes]]:
    """The inputs of `archive`, refused unless it is the bytes `pack`
    writes for them. Each member is checked before it is read: a regular
    file (no link, directory, device or sparse file), a plain name, at most
    `MAX_INPUT` bytes; then the archive is rebuilt from the inputs and
    compared byte for byte, which refuses anything else `pack` would not
    write: names out of order, another mode, owner, time or format, a GNU
    or pax header, a link name, device numbers, data past the end."""
    if archive.stat().st_size > MAX_BYTES + (MAX_INPUTS + 1) * 1024 + tarfile.RECORDSIZE:
        raise CorpusError(f"{archive} is larger than an archive of the most inputs")
    raw = archive.read_bytes()
    inputs = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tar:
            for member in tar:
                if member.type != tarfile.REGTYPE or member.issparse() or member.pax_headers:
                    raise CorpusError(f"{archive}: {member.name!r} is not a regular file as `pack` writes one")
                if not plain(member.name) or member.size > MAX_INPUT or len(inputs) >= MAX_INPUTS:
                    raise CorpusError(f"{archive}: {member.name!r} is no input, or past an archive's bounds")
                inputs.append((member.name, tar.extractfile(member).read()))
    except tarfile.TarError as error:
        raise CorpusError(f"{archive}: {error}") from error
    checked(str(archive), inputs)
    if packed(inputs) != raw:
        raise CorpusError(f"{archive} is not as `pack` writes it")
    return inputs


def unpack(archives: Path, directory: Path) -> None:
    found = sorted(archives.glob("*.tar"))
    if not found:
        raise CorpusError(f"no archive under {archives}")
    shutil.rmtree(directory, ignore_errors=True)
    corpora = [(archive.stem, read(archive)) for archive in found]
    for target, inputs in corpora:
        destination = directory / target
        destination.mkdir(parents=True)
        for name, data in inputs:
            (destination / name).write_bytes(data)
        print(f"{destination}: {len(inputs)} inputs")


def main(argv: list[str]) -> int:
    commands = {"pack": pack, "unpack": unpack}
    if len(argv) != 3 or argv[0] not in commands:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        commands[argv[0]](Path(argv[1]), Path(argv[2]))
    except CorpusError as error:
        print(f"corpus: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
