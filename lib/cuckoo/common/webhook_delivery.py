# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Pure helpers for the CALLBACKHOME webhook reporting module.

Extracted into lib.cuckoo.common so unit tests can import this module
without dragging in the full Report base class (which transitively
pulls PIL, lxml, peepdf, yara, ...).
"""

import hashlib
import hmac
import json
import logging
import random
import time
import uuid
from typing import Optional

import requests

log = logging.getLogger(__name__)

# Retry on these HTTP status codes (transient server errors).  4xx is
# never retried -- the receiver is telling us the request is bad.
RETRYABLE_STATUS = frozenset({500, 502, 503, 504, 429})
USER_AGENT = "CAPE-Webhook/2.0"


def sign(secret: bytes, body: bytes) -> str:
    """HMAC-SHA256 of body under secret, formatted as `sha256=<hex>`."""
    return "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()


def backoff_seconds(attempt: int) -> float:
    """Exponential backoff with ±25% jitter (1s, 2s, 4s, ...)."""
    base = 2 ** attempt
    return base * (1.0 + random.uniform(-0.25, 0.25))


def build_standard_payload(task_id: int, results: dict, *, api_base_url: Optional[str] = None) -> dict:
    """Self-contained event so receivers can skip a follow-up API call.

    Defensive against missing keys: malformed reports shouldn't crash
    webhook delivery.  `.get()` everywhere.
    """
    info = results.get("info", {}) or {}
    target = results.get("target", {}) or {}
    file_info = target.get("file", {}) or {}
    signatures = results.get("signatures", []) or []
    detections = results.get("detections", []) or []

    payload = {
        "event": "task.complete",
        "task_id": task_id,
        "status": info.get("category"),
        "package": info.get("package"),
        "machine": (info.get("machine") or {}).get("name"),
        "score": info.get("score"),
        "completed_on": info.get("ended"),
        "category": target.get("category"),
        "target": {
            "filename": file_info.get("name"),
            "sha256": file_info.get("sha256"),
            "md5": file_info.get("md5"),
            "size": file_info.get("size"),
            "type": file_info.get("type"),
        },
        "signatures": [
            {
                "name": s.get("name"),
                "severity": s.get("severity"),
                "description": s.get("description"),
            }
            for s in signatures
            if s.get("name")
        ],
        "detections": [
            d.get("family") if isinstance(d, dict) else d for d in detections
        ],
    }
    if api_base_url:
        payload["report_url"] = f"{api_base_url.rstrip('/')}/analysis/{task_id}/"
    return payload


def post_once(url: str, body: bytes, headers: dict, timeout: float) -> requests.Response:
    """Wrapped for tests to patch a single network call."""
    return requests.post(url, data=body, headers=headers, timeout=timeout)


def deliver(url: str, body: bytes, headers: dict, *, timeout: float, retries: int) -> bool:
    """POST with retry/backoff.  Returns True on a 2xx within the budget."""
    last_err = None
    for attempt in range(retries + 1):
        try:
            resp = post_once(url, body, headers, timeout)
        except requests.exceptions.RequestException as e:
            last_err = repr(e)
            if attempt == retries:
                break
            time.sleep(backoff_seconds(attempt))
            continue
        if 200 <= resp.status_code < 300:
            log.debug("Webhook %s delivered: %d", url, resp.status_code)
            return True
        if resp.status_code in RETRYABLE_STATUS and attempt < retries:
            log.info(
                "Webhook %s returned %d (attempt %d/%d), retrying",
                url, resp.status_code, attempt + 1, retries + 1,
            )
            time.sleep(backoff_seconds(attempt))
            continue
        last_err = f"HTTP {resp.status_code}"
        break

    log.error("Webhook %s failed permanently: %s", url, last_err)
    return False


def build_headers(*, payload_mode: str, event: Optional[str], secret: Optional[bytes], body: bytes) -> dict:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if payload_mode == "standard":
        if event:
            headers["X-CAPE-Event"] = event
        headers["X-CAPE-Delivery"] = str(uuid.uuid4())
    if secret:
        headers["X-CAPE-Signature"] = sign(secret, body)
    return headers


def encode_payload(payload: dict) -> bytes:
    """Stable JSON encoding for both delivery and signature verification."""
    return json.dumps(payload, default=str).encode("utf-8")
