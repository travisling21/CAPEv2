# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Tests for the end-of-analysis dropped-file sweep."""

import hashlib
import os
import sys
import time

import pytest

if sys.platform == "linux":
    from lib.core import dropped


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux")
class TestIterCandidateFiles:
    def test_finds_files_newer_than_cutoff(self, tmp_path):
        cutoff = time.time()
        time.sleep(0.05)
        new = tmp_path / "new.bin"
        new.write_bytes(b"abc")

        old = tmp_path / "old.bin"
        old.write_bytes(b"xyz")
        # Force mtime to before the cutoff.
        os.utime(old, (cutoff - 60, cutoff - 60))

        found = list(
            dropped.iter_candidate_files(
                since_mtime=cutoff,
                roots=[str(tmp_path)],
                exclude_prefixes=(),
            )
        )
        assert str(new) in found
        assert str(old) not in found

    def test_skips_symlinks(self, tmp_path):
        target = tmp_path / "target"
        target.write_bytes(b"hi")
        link = tmp_path / "link"
        link.symlink_to(target)

        found = list(
            dropped.iter_candidate_files(
                since_mtime=0,
                roots=[str(tmp_path)],
                exclude_prefixes=(),
            )
        )
        assert str(target) in found
        assert str(link) not in found

    def test_respects_exclude_prefixes(self, tmp_path):
        good = tmp_path / "good.bin"
        good.write_bytes(b"a")
        sub = tmp_path / "excluded"
        sub.mkdir()
        bad = sub / "bad.bin"
        bad.write_bytes(b"a")

        found = list(
            dropped.iter_candidate_files(
                since_mtime=0,
                roots=[str(tmp_path)],
                exclude_prefixes=(str(sub),),
            )
        )
        assert str(good) in found
        assert str(bad) not in found

    def test_caps_at_max_files(self, tmp_path):
        for i in range(5):
            (tmp_path / f"f{i}").write_bytes(b"x")

        found = list(
            dropped.iter_candidate_files(
                since_mtime=0,
                roots=[str(tmp_path)],
                exclude_prefixes=(),
                max_files=3,
            )
        )
        assert len(found) == 3

    def test_skips_oversized(self, tmp_path):
        small = tmp_path / "small"
        small.write_bytes(b"x" * 16)
        big = tmp_path / "big"
        big.write_bytes(b"x" * 1024)

        found = list(
            dropped.iter_candidate_files(
                since_mtime=0,
                roots=[str(tmp_path)],
                exclude_prefixes=(),
                max_bytes=64,
            )
        )
        assert str(small) in found
        assert str(big) not in found

    def test_missing_root_doesnt_crash(self, tmp_path):
        ghost = tmp_path / "does-not-exist"
        found = list(
            dropped.iter_candidate_files(
                since_mtime=0,
                roots=[str(ghost)],
                exclude_prefixes=(),
            )
        )
        assert found == []

    def test_fifo_not_yielded(self, tmp_path):
        fifo = tmp_path / "myfifo"
        os.mkfifo(str(fifo))
        good = tmp_path / "good"
        good.write_bytes(b"a")

        found = list(
            dropped.iter_candidate_files(
                since_mtime=0,
                roots=[str(tmp_path)],
                exclude_prefixes=(),
            )
        )
        assert str(good) in found
        assert str(fifo) not in found


@pytest.mark.skipif(sys.platform != "linux", reason="Requires Linux")
class TestSweepAndUpload:
    def _sha256(self, path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def test_uploads_each_new_file_once(self, tmp_path):
        f1 = tmp_path / "a"
        f1.write_bytes(b"hello-a")
        f2 = tmp_path / "b"
        f2.write_bytes(b"hello-b")

        calls = []

        def uploader(path, dump_path):
            calls.append((path, dump_path))

        uploaded = dropped.sweep_and_upload(
            since_mtime=0,
            uploader=uploader,
            hasher=self._sha256,
            roots=[str(tmp_path)],
            exclude_prefixes=(),
        )

        assert len(uploaded) == 2
        # Dump paths follow the files/<sha256> convention.
        for path, dump in calls:
            assert dump.startswith("files/")
            assert dump.endswith(self._sha256(path))

    def test_dedupes_identical_content_by_sha256(self, tmp_path):
        (tmp_path / "x").write_bytes(b"same")
        (tmp_path / "y").write_bytes(b"same")  # identical content

        calls = []
        uploaded = dropped.sweep_and_upload(
            since_mtime=0,
            uploader=lambda p, d: calls.append((p, d)),
            hasher=self._sha256,
            roots=[str(tmp_path)],
            exclude_prefixes=(),
        )
        # Same sha256 -> uploaded once.
        assert len(uploaded) == 1
        assert len(calls) == 1

    def test_already_uploaded_set_respected(self, tmp_path):
        f = tmp_path / "f"
        f.write_bytes(b"abc")
        sha = self._sha256(str(f))

        calls = []
        uploaded = dropped.sweep_and_upload(
            since_mtime=0,
            uploader=lambda p, d: calls.append(p),
            hasher=self._sha256,
            already_uploaded={sha},
            roots=[str(tmp_path)],
            exclude_prefixes=(),
        )
        assert uploaded == set()
        assert calls == []

    def test_uploader_exception_doesnt_abort_sweep(self, tmp_path):
        (tmp_path / "a").write_bytes(b"AA")
        (tmp_path / "b").write_bytes(b"BB")

        bad_paths = []

        def flaky_uploader(path, dump_path):
            if path.endswith("a"):
                bad_paths.append(path)
                raise RuntimeError("network down")

        uploaded = dropped.sweep_and_upload(
            since_mtime=0,
            uploader=flaky_uploader,
            hasher=self._sha256,
            roots=[str(tmp_path)],
            exclude_prefixes=(),
        )
        # The one that did NOT raise was recorded.  The other was
        # attempted (recorded in bad_paths) but no sha was returned.
        assert len(bad_paths) == 1
        assert len(uploaded) == 1

    def test_extra_paths_uploaded(self, tmp_path):
        # An extra hint outside the sweep roots.
        outside = tmp_path / "outside"
        outside.write_bytes(b"hello")

        calls = []
        empty_root = tmp_path / "empty"
        empty_root.mkdir()

        uploaded = dropped.sweep_and_upload(
            since_mtime=0,
            uploader=lambda p, d: calls.append(p),
            hasher=self._sha256,
            roots=[str(empty_root)],
            extra_paths=[str(outside)],
            exclude_prefixes=(),
        )
        assert str(outside) in calls
        assert len(uploaded) == 1

    def test_extra_paths_that_disappear_are_skipped(self, tmp_path):
        ghost = tmp_path / "ghost"  # never created
        calls = []
        uploaded = dropped.sweep_and_upload(
            since_mtime=0,
            uploader=lambda p, d: calls.append(p),
            hasher=self._sha256,
            roots=[],
            extra_paths=[str(ghost)],
            exclude_prefixes=(),
        )
        assert uploaded == set()
        assert calls == []
