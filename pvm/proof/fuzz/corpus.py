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
input leaves the archive as it was. `unpack` takes nothing but such files,
each a plain name (no directory, no link), and refuses an archive that is
not in that form: names out of order, another mode, owner, time or
format.

A corpus is pruned by its unpacked inputs (`cargo run --example paths --
--each` lists what each reaches): remove the inputs from
`target/replay/<target>/`, then `pack` it into `replay/<target>.tar`.
"""

import io
import shutil
import sys
import tarfile
from pathlib import Path


class CorpusError(Exception):
    pass


def plain(name: str) -> bool:
    return name not in ("", ".", "..") and "/" not in name and "\\" not in name and "\0" not in name


def archived(inputs: Path) -> tuple[bytes, int]:
    """The archive of `inputs`' files, and their count."""
    files = sorted(inputs.iterdir(), key=lambda path: path.name.encode())
    if not files:
        raise CorpusError(f"{inputs} holds no input")
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path in files:
            if not path.is_file() or path.is_symlink() or not plain(path.name):
                raise CorpusError(f"{path} is no input: a corpus is a directory of files")
            data = path.read_bytes()
            if len(path.name.encode()) > 100:
                raise CorpusError(f"{path}: a name past ustar's 100 bytes")
            info = tarfile.TarInfo(path.name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue(), len(files)


def pack(inputs: Path, archive: Path) -> None:
    data, count = archived(inputs)
    archive.parent.mkdir(parents=True, exist_ok=True)
    partial = archive.with_name(archive.name + ".partial")
    partial.write_bytes(data)
    partial.replace(archive)
    print(f"{archive}: {count} inputs")


def unpack(archives: Path, directory: Path) -> None:
    found = sorted(archives.glob("*.tar"))
    if not found:
        raise CorpusError(f"no archive under {archives}")
    shutil.rmtree(directory, ignore_errors=True)
    for archive in found:
        target = directory / archive.stem
        target.mkdir(parents=True)
        names = []
        try:
            with tarfile.open(archive, mode="r:", format=tarfile.USTAR_FORMAT) as tar:
                for member in tar:
                    if not member.isreg() or not plain(member.name):
                        raise CorpusError(f"{archive}: {member.name!r} is no input")
                    canonical = (member.mode, member.uid, member.gid, member.uname, member.gname, member.mtime)
                    if canonical != (0o644, 0, 0, "", "", 0) or member.pax_headers:
                        raise CorpusError(f"{archive}: {member.name} is not as `pack` writes it")
                    (target / member.name).write_bytes(tar.extractfile(member).read())
                    names.append(member.name)
        except tarfile.TarError as error:
            raise CorpusError(f"{archive}: {error}") from error
        if not names:
            raise CorpusError(f"{archive} holds no input")
        if names != sorted(set(names), key=str.encode):
            raise CorpusError(f"{archive}: its inputs are not in order, or repeat")
        print(f"{target}: {len(names)} inputs")


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
