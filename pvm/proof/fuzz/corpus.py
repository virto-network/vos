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
each a plain name (no directory, no link), and refuses an archive that
`pack` would not write byte for byte from the inputs it holds.
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
        count = 0
        with tarfile.open(archive, mode="r:") as tar:
            for member in tar:
                if not member.isreg() or not plain(member.name):
                    raise CorpusError(f"{archive}: {member.name!r} is no input")
                source = tar.extractfile(member)
                (target / member.name).write_bytes(source.read())
                count += 1
        if count == 0:
            raise CorpusError(f"{archive} holds no input")
        if archived(target)[0] != archive.read_bytes():
            raise CorpusError(f"{archive} is not its inputs' archive as `pack` writes it")
        print(f"{target}: {count} inputs")


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
