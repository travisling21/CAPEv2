# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Replay helpers for utils/replay.py.

Pure logic: locate a cached analysis, load its report, decide which
stages to re-run.  The CLI wraps these.

The goal is to make "I added a new YARA rule / config extractor /
reporting module, regenerate task 42's report" a one-liner that
doesn't touch the VM.

  python utils/replay.py 42 --reporting-only
  python utils/replay.py 42 --reporting-only --module stix
  python utils/replay.py 42 --signatures-only --signature-name my_rule
  python utils/replay.py 1-50 --processing-only --module CAPE
"""

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

log = logging.getLogger(__name__)


@dataclass
class ReplayOptions:
    """What stages a single replay should execute."""

    run_processing: bool = False
    run_signatures: bool = False
    run_reporting: bool = False
    # Optional name filters; empty string == no filter.
    processing_name: str = ""
    signature_name: str = ""
    reporting_name: str = ""

    def stages(self) -> List[str]:
        out = []
        if self.run_processing:
            out.append("processing")
        if self.run_signatures:
            out.append("signatures")
        if self.run_reporting:
            out.append("reporting")
        return out


@dataclass
class ReplayResult:
    """Outcome of a single task's replay."""

    task_id: int
    stages_run: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


def parse_id_spec(spec: str) -> Iterator[int]:
    """Expand a CLI id spec into individual task ids.

    Accepts:
        "42"        -> [42]
        "1,2,3"     -> [1, 2, 3]
        "10-13"     -> [10, 11, 12, 13]
        "1,5-7,42"  -> [1, 5, 6, 7, 42]

    Yields rather than returning a list so callers can stream large
    ranges without materializing them.
    """
    for piece in spec.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "-" in piece:
            lo, hi = piece.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if hi_i < lo_i:
                raise ValueError(f"Range {piece!r} has descending bounds")
            for n in range(lo_i, hi_i + 1):
                yield n
        else:
            yield int(piece)


def analysis_dir(cuckoo_root: str, task_id: int) -> str:
    return os.path.join(cuckoo_root, "storage", "analyses", str(task_id))


def cached_report_path(cuckoo_root: str, task_id: int) -> str:
    return os.path.join(analysis_dir(cuckoo_root, task_id), "reports", "report.json")


def load_cached_report(cuckoo_root: str, task_id: int) -> Tuple[Optional[dict], Optional[str]]:
    """Load report.json from the analysis dir.

    Returns (results, None) on success or (None, error_message) on
    failure.  Callers use this so they can present a clean error
    rather than a traceback.
    """
    path = cached_report_path(cuckoo_root, task_id)
    if not os.path.isfile(path):
        return None, f"no cached report at {path}"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except (json.JSONDecodeError, OSError) as e:
        return None, f"failed to load {path}: {e}"


def validate_options(opts: ReplayOptions) -> Optional[str]:
    """Sanity-check a ReplayOptions instance.

    Returns an error string, or None when valid.
    """
    if not (opts.run_processing or opts.run_signatures or opts.run_reporting):
        return "must enable at least one of --processing-only, --signatures-only, --reporting-only"
    if opts.processing_name and not opts.run_processing:
        return "--module requires --processing-only"
    if opts.reporting_name and not opts.run_reporting:
        return "--module requires --reporting-only"
    if opts.signature_name and not opts.run_signatures:
        return "--signature-name requires --signatures-only"
    return None
