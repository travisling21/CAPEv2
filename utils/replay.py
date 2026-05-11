#!/usr/bin/env python
# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Replay processing / signatures / reporting against a cached analysis.

Use when you've added a new YARA rule, malware-config extractor, or
reporting module and want to regenerate an existing task's report
without re-running the VM.

Examples:

    # Regenerate every report (json, html, stix, ...) for task 42.
    poetry run python utils/replay.py 42 --reporting-only

    # Just regenerate the STIX bundle.
    poetry run python utils/replay.py 42 --reporting-only --module stix

    # Run just one signature against the cached behavior bson.
    poetry run python utils/replay.py 42 --signatures-only \\
            --signature-name my_new_yara_rule

    # Re-run a specific processing module across a range of tasks.
    poetry run python utils/replay.py 1-50 --processing-only --module CAPE

Notes:
- `--processing-only` filtering can be lossy because some processing
  modules consume keys produced by others.  When in doubt, omit
  `--module` and let the whole processing chain run.
- This command does NOT re-run anything inside the analysis VM.  If
  you need to re-run the sample, use the existing reschedule path
  in the web UI or /apiv2/tasks/reschedule/<id>/.
"""

import argparse
import logging
import os
import sys
from typing import List

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(HERE, ".."))

from lib.cuckoo.common.constants import CUCKOO_ROOT  # noqa: E402
from lib.cuckoo.common.path_utils import path_exists  # noqa: E402
from lib.cuckoo.core.database import Database, init_database  # noqa: E402
from lib.cuckoo.core.plugins import RunProcessing, RunReporting, RunSignatures  # noqa: E402
from lib.cuckoo.core.replay import (  # noqa: E402
    ReplayOptions,
    ReplayResult,
    analysis_dir,
    load_cached_report,
    parse_id_spec,
    validate_options,
)
from lib.cuckoo.core.startup import init_modules  # noqa: E402

log = logging.getLogger("cape.replay")


def _replay_single(task_id: int, opts: ReplayOptions) -> ReplayResult:
    """Replay configured stages against a single task."""
    result = ReplayResult(task_id=task_id)

    if not path_exists(analysis_dir(CUCKOO_ROOT, task_id)):
        result.error = "analysis folder missing"
        return result

    db = Database()
    with db.session.begin():
        task = db.view_task(task_id)
        if task is None:
            result.error = "task not in database"
            return result
        task_dict = task.to_dict()
        db.session.expunge_all()

    results, err = load_cached_report(CUCKOO_ROOT, task_id)
    if err and (opts.run_signatures or opts.run_reporting):
        # Processing produces the cached report; for the other two we
        # need it as input.
        result.error = err
        return result
    if results is None:
        results = {"statistics": {"processing": [], "signatures": [], "reporting": []}}

    if opts.run_processing:
        RunProcessing(task=task_dict, results=results).run(name=opts.processing_name)
        result.stages_run.append("processing")

    if opts.run_signatures:
        results.setdefault("statistics", {}).setdefault("signatures", [])
        RunSignatures(task=task_dict, results=results).run(opts.signature_name)
        result.stages_run.append("signatures")

    if opts.run_reporting:
        results.setdefault("statistics", {}).setdefault("reporting", [])
        # `reprocess=True` so reporting modules know they're operating on
        # an already-completed task and may overwrite outputs.
        rr = RunReporting(task=task_dict, results=results, reprocess=True)
        rr.run(name=opts.reporting_name)
        result.stages_run.append("reporting")

    return result


def main(argv: List[str] = None) -> int:
    parser = argparse.ArgumentParser(prog="replay", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ids", help="Task id spec: 42, 1,2,3, or 10-20 (combine: 1,5-7,42)")

    stages = parser.add_argument_group("Stages (pick at least one)")
    stages.add_argument("--processing-only", action="store_true",
                        help="Re-run processing modules")
    stages.add_argument("--signatures-only", action="store_true",
                        help="Re-run signatures against cached behavior data")
    stages.add_argument("--reporting-only", action="store_true",
                        help="Regenerate reports from the cached results")

    filters = parser.add_argument_group("Optional filters")
    filters.add_argument("--module",
                         help="Run only the named processing or reporting module "
                              "(class name, case-insensitive).  Use with --processing-only or --reporting-only.")
    filters.add_argument("--signature-name",
                         help="Run only the named signature class.  Requires --signatures-only.")

    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    opts = ReplayOptions(
        run_processing=args.processing_only,
        run_signatures=args.signatures_only,
        run_reporting=args.reporting_only,
        processing_name=args.module if args.processing_only else "",
        signature_name=args.signature_name or "",
        reporting_name=args.module if args.reporting_only else "",
    )
    err = validate_options(opts)
    if err:
        parser.error(err)

    init_database(exists_ok=True)
    init_modules()

    try:
        task_ids = list(parse_id_spec(args.ids))
    except ValueError as e:
        parser.error(f"Bad task id spec: {e}")

    failures = 0
    for tid in task_ids:
        outcome = _replay_single(tid, opts)
        if outcome.ok:
            log.info("task %d: ran %s", tid, ", ".join(outcome.stages_run) or "nothing")
        else:
            failures += 1
            log.error("task %d: %s", tid, outcome.error)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
