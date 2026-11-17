#!/usr/bin/env python3
"""`corpus.py`'s refusals (`just check`): an archive as `pack` writes it
unpacks to its inputs; a sparse member, a GNU long name, a pax header, a
link, a member past `MAX_INPUT`, a repeated name, names out of order, a
member of another mode and data past the archive's end are each refused,
and `unpack`'s directory is left empty.

    python3 -I pvm/proof/fuzz/test_corpus.py
"""

import importlib.util
import sys
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("corpus", Path(__file__).resolve().parent / "corpus.py")
corpus = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(corpus)


def member(name: str, data: bytes, **fields) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    for field, value in fields.items():
        setattr(info, field, value)
    return info, data


def archive(members, format=tarfile.USTAR_FORMAT) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=format) as tar:
        for info, data in members:
            tar.addfile(info, io.BytesIO(data) if info.isreg() else None)
    return buffer.getvalue()


class Unpack(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        root = Path(self.scratch.name)
        self.archives = root / "replay"
        self.archives.mkdir()
        self.directory = root / "unpacked"

    def tearDown(self):
        self.scratch.cleanup()

    def write(self, name: str, raw: bytes) -> None:
        (self.archives / f"{name}.tar").write_bytes(raw)

    def refused(self, raw: bytes) -> None:
        self.write("good", corpus.packed([("a", b"1")]))
        self.write("target", raw)
        self.directory.mkdir()
        (self.directory / "stale").write_bytes(b"left from an earlier unpack")
        with self.assertRaises(corpus.CorpusError):
            corpus.unpack(self.archives, self.directory)
        self.assertFalse(self.directory.exists() and any(self.directory.iterdir()), "the directory is left empty")

    def test_an_archive_as_pack_writes_it_unpacks(self):
        inputs = Path(self.scratch.name) / "inputs"
        inputs.mkdir()
        (inputs / "b").write_bytes(b"\x00\x01")
        (inputs / "a").write_bytes(b"")
        corpus.pack(inputs, self.archives / "target.tar")
        self.assertEqual((self.archives / "target.tar").read_bytes(), corpus.packed([("a", b""), ("b", b"\x00\x01")]))
        corpus.unpack(self.archives, self.directory)
        self.assertEqual(sorted(path.name for path in (self.directory / "target").iterdir()), ["a", "b"])
        self.assertEqual((self.directory / "target" / "b").read_bytes(), b"\x00\x01")

    def test_a_sparse_member_is_refused(self):
        # An old GNU sparse header: no data stored, one region of a byte at
        # the end of a file of 8 GiB, which reads as 8 GiB of zeros.
        info, _ = member("a", b"")
        info.type = tarfile.GNUTYPE_SPARSE
        header = bytearray(info.tobuf(tarfile.GNU_FORMAT))
        logical = 8 << 30
        header[386:398] = b"%011o\0" % (logical - 1)
        header[398:410] = b"%011o\0" % 1
        header[483:495] = b"%011o\0" % logical
        header[148:156] = b" " * 8
        header[148:156] = b"%06o\0 " % sum(header)
        self.refused(bytes(header) + bytes(tarfile.RECORDSIZE))

    def test_a_gnu_long_name_is_refused(self):
        self.refused(archive([member("n" * 120, b"1")], tarfile.GNU_FORMAT))

    def test_a_pax_header_is_refused(self):
        self.refused(archive([member("a", b"1", pax_headers={"comment": "x"})], tarfile.PAX_FORMAT))

    def test_a_link_is_refused(self):
        info, _ = member("a", b"")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        self.refused(archive([(info, b"")]))

    def test_a_member_past_the_cap_is_refused(self):
        self.refused(archive([member("a", bytes(corpus.MAX_INPUT + 1))]))

    def test_a_repeated_name_is_refused(self):
        self.refused(archive([member("a", b"1"), member("a", b"2")]))

    def test_names_out_of_order_are_refused(self):
        self.refused(archive([member("b", b"1"), member("a", b"2")]))

    def test_another_mode_is_refused(self):
        self.refused(archive([member("a", b"1", mode=0o755)]))

    def test_trailing_data_is_refused(self):
        self.refused(corpus.packed([("a", b"1")]) + b"\x00" * 511 + b"x")

    def test_a_member_past_the_end_marker_is_refused(self):
        raw = corpus.packed([("a", b"1")])
        self.refused(raw + archive([member("b", b"2")]))

    def test_an_empty_archive_is_refused(self):
        self.refused(bytes(tarfile.RECORDSIZE))


if __name__ == "__main__":
    unittest.main()
