# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

"""STIX 2.1 reporting module.

Emits a STIX 2.1 bundle to `report.stix.json` in the task's reports
directory.  Pure dict-building lives in lib.cuckoo.common.stix_export
so it's unit-testable without the full Report stack.
"""

import logging
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.stix_export import DEFAULT_IDENTITY_NAME, make_bundle

log = logging.getLogger(__name__)

try:
    import orjson

    def _dumps(obj):
        return orjson.dumps(obj, option=orjson.OPT_INDENT_2)
except ImportError:
    import json

    def _dumps(obj):
        return json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")


class STIX(Report):
    """Write a STIX 2.1 bundle for the analysis."""

    # Run late so families/ttps/network are fully populated.
    order = 100

    def run(self, results):
        identity = (self.options.get("identity_name") or DEFAULT_IDENTITY_NAME).strip()
        try:
            bundle = make_bundle(results, identity_name=identity)
        except Exception as e:
            raise CuckooReportError(f"Failed to build STIX bundle: {e}")

        out_path = os.path.join(self.reports_path, "report.stix.json")
        try:
            with open(out_path, "wb") as fh:
                fh.write(_dumps(bundle))
        except OSError as e:
            raise CuckooReportError(f"Failed to write STIX report: {e}")

        log.debug(
            "STIX bundle written: %s (%d objects)",
            out_path, len(bundle.get("objects", [])),
        )
