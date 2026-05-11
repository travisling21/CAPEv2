# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""End-of-analysis fallback sweep for dropped files on Linux.

The pyinotify-based FileCollector auxiliary handles the real-time
push path.  This sweep catches two failure modes the push path can't:

  1. FileCollector isn't available (pyinotify not installed) -- the
     module silently disables itself, so without this sweep the
     analyzer captures nothing.
  2. Files that appear in the brief window between FileCollector.stop()
     and analyzer shutdown, or in directories that weren't covered by
     the watch recursion.

Pure stdlib so the analyzer keeps its tiny dependency surface.
"""

import logging
import os
from typing import Iterable, Iterator, Optional, Set

log = logging.getLogger(__name__)

# Directories we sweep at end-of-analysis.  Tight list to keep walks
# fast on large filesystems -- malware *usually* drops here.  Expand
# via the `extra_roots` kwarg if a specific package needs more.
DEFAULT_ROOTS = (
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/root",
    "/home",
)

# Anything we touch ourselves.
DEFAULT_EXCLUDE_PREFIXES = (
    "/proc",
    "/sys",
    "/dev/pts",
    "/dev/mqueue",
    "/run",
)

# Hard cap so a runaway dropper doesn't make the sweep itself the
# bottleneck.  Adjust if you ever see this hit in practice.
MAX_FILES = 2000
MAX_FILE_BYTES = 256 * 1024 * 1024


def iter_candidate_files(
    *,
    since_mtime: float,
    roots: Iterable[str] = DEFAULT_ROOTS,
    exclude_prefixes: Iterable[str] = DEFAULT_EXCLUDE_PREFIXES,
    max_files: int = MAX_FILES,
    max_bytes: int = MAX_FILE_BYTES,
) -> Iterator[str]:
    """Yield candidate file paths for upload.

    A path is a candidate when:
      - it exists and is a regular file (not a symlink/socket/etc.)
      - mtime >= since_mtime (created or modified during this analysis)
      - it's not under any excluded prefix
      - it's <= max_bytes
    """
    seen = 0
    excludes = tuple(exclude_prefixes)
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            # Prune excluded sub-trees in-place so os.walk doesn't recurse.
            dirnames[:] = [d for d in dirnames if not _excluded(os.path.join(dirpath, d), excludes)]
            for name in filenames:
                if seen >= max_files:
                    log.warning("Dropped-file sweep hit MAX_FILES=%d; stopping", max_files)
                    return
                path = os.path.join(dirpath, name)
                if _excluded(path, excludes):
                    continue
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                # Symlinks, devices, fifos, sockets: skip.
                if not _is_regular_file(st):
                    continue
                if st.st_mtime < since_mtime:
                    continue
                if st.st_size > max_bytes:
                    log.info("Skipping oversized dropped file (%d bytes): %s", st.st_size, path)
                    continue
                seen += 1
                yield path


def _excluded(path: str, excludes) -> bool:
    return any(path == e or path.startswith(e + os.sep) for e in excludes)


def _is_regular_file(st) -> bool:
    import stat as _stat
    return _stat.S_ISREG(st.st_mode)


def sweep_and_upload(
    *,
    since_mtime: float,
    uploader,
    hasher,
    already_uploaded: Optional[Set[str]] = None,
    roots: Iterable[str] = DEFAULT_ROOTS,
    exclude_prefixes: Iterable[str] = DEFAULT_EXCLUDE_PREFIXES,
    extra_paths: Iterable[str] = (),
    max_files: int = MAX_FILES,
) -> Set[str]:
    """Sweep `roots` for new files and upload each via `uploader`.

    Dedupes by SHA-256.  Returns the set of sha256 hashes uploaded by
    this call.  Pass an existing `already_uploaded` set to skip files
    a sibling collector already shipped.

    `uploader(path, dump_path)` matches lib.common.results.upload_to_host.
    `hasher(path)` matches lib.common.hashing.sha256_file.
    """
    already = set(already_uploaded or ())
    uploaded: Set[str] = set()
    candidates: Iterator[str] = iter_candidate_files(
        since_mtime=since_mtime,
        roots=roots,
        exclude_prefixes=exclude_prefixes,
        max_files=max_files,
    )
    # Tack on caller-supplied hints (e.g. paths a strace handler saw).
    seen_paths: Set[str] = set()

    def _process(path: str) -> None:
        if path in seen_paths:
            return
        seen_paths.add(path)
        try:
            sha256 = hasher(path)
        except OSError as e:
            log.debug("Hash failed for %s: %s", path, e)
            return
        if sha256 in already or sha256 in uploaded:
            return
        try:
            uploader(path, f"files/{sha256}")
        except Exception as e:  # uploader is third-party; defend.
            log.warning("Upload failed for %s: %s", path, e)
            return
        uploaded.add(sha256)

    for path in candidates:
        _process(path)
    for path in extra_paths:
        if os.path.isfile(path):
            _process(path)
    return uploaded
