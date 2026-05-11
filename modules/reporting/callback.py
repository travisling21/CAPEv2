# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

"""Webhook reporting module.

Pure delivery logic lives in lib.cuckoo.common.webhook_delivery so the
HMAC, retry, and payload code is testable without the full reporting
framework stack.
"""

import logging
from contextlib import suppress

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.webhook_delivery import (
    build_headers,
    build_standard_payload,
    deliver,
    encode_payload,
)
from lib.cuckoo.core.data.task import TASK_REPORTED
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)


def _api_base_url() -> str:
    with suppress(Exception):
        return Config("api").api.get("url") or ""
    return ""


class CALLBACKHOME(Report):
    """Notify operator-configured URLs that a task has finished."""

    order = 10000  # run after every other reporting module

    def run(self, results):
        urls = [u.strip() for u in (self.options.url or "").split(",") if u.strip()]
        if not urls:
            return

        task_id = int(results.get("info", {}).get("id", 0))
        if not task_id:
            log.warning("Webhook skipped: no task id in results")
            return

        # Mark TASK_REPORTED before delivery so a receiver that calls
        # back to /apiv2/tasks/view/<id>/ sees a consistent status.
        with Database().session.begin():
            Database().set_status(task_id, TASK_REPORTED)

        payload_mode = (self.options.get("payload") or "minimal").strip().lower()
        if payload_mode == "standard":
            payload = build_standard_payload(task_id, results, api_base_url=_api_base_url())
            event = payload["event"]
        else:
            payload = {"task_id": task_id}
            event = None

        body = encode_payload(payload)

        secret = self.options.get("secret")
        secret_bytes = secret.encode("utf-8") if secret else None
        headers = build_headers(
            payload_mode=payload_mode,
            event=event,
            secret=secret_bytes,
            body=body,
        )

        try:
            timeout = float(self.options.get("timeout", 10))
        except (TypeError, ValueError):
            timeout = 10.0
        try:
            retries = int(self.options.get("retries", 3))
        except (TypeError, ValueError):
            retries = 3

        for url in urls:
            deliver(url, body, headers, timeout=timeout, retries=retries)
