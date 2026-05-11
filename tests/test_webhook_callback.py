# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Unit tests for the webhook delivery helpers used by the CALLBACKHOME
reporting module.

These tests target the pure helpers in lib.cuckoo.common.webhook_delivery
so we don't need to pull in the full reporting framework (Report base
class transitively imports PIL/lxml/yara/...).
"""

import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import requests

from lib.cuckoo.common import webhook_delivery as wd


class TestSign:
    def test_known_vector(self):
        # RFC 4231 test case 1.
        secret = b"\x0b" * 20
        body = b"Hi There"
        expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        assert wd.sign(secret, body) == expected

    def test_signature_changes_with_body(self):
        assert wd.sign(b"k", b"a") != wd.sign(b"k", b"b")

    def test_signature_changes_with_secret(self):
        assert wd.sign(b"k1", b"a") != wd.sign(b"k2", b"a")


class TestBackoff:
    def test_grows_geometrically_within_jitter(self):
        for attempt in range(5):
            sec = wd.backoff_seconds(attempt)
            lo, hi = 0.75 * (2 ** attempt), 1.25 * (2 ** attempt)
            assert lo <= sec <= hi, (attempt, sec, lo, hi)


class TestStandardPayload:
    def _results(self, **overrides):
        base = {
            "info": {
                "id": 42,
                "category": "file",
                "package": "exe",
                "machine": {"name": "win10_1"},
                "score": 8.5,
                "ended": "2026-05-11T12:00:00Z",
            },
            "target": {
                "category": "file",
                "file": {
                    "name": "sample.exe",
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size": 12345,
                    "type": "PE32",
                },
            },
            "signatures": [
                {"name": "antianalysis_detectreg", "severity": 3, "description": "..."},
                {"name": "creates_exe", "severity": 2, "description": "..."},
            ],
            "detections": [{"family": "TrickBot"}, "Emotet"],
        }
        base.update(overrides)
        return base

    def test_full_payload_shape(self):
        out = wd.build_standard_payload(42, self._results(), api_base_url="https://cape.example.com")
        assert out["event"] == "task.complete"
        assert out["task_id"] == 42
        assert out["target"]["sha256"] == "a" * 64
        assert out["score"] == 8.5
        assert out["machine"] == "win10_1"
        assert {s["name"] for s in out["signatures"]} == {
            "antianalysis_detectreg", "creates_exe",
        }
        assert "TrickBot" in out["detections"]
        assert "Emotet" in out["detections"]
        assert out["report_url"] == "https://cape.example.com/analysis/42/"

    def test_missing_info_doesnt_crash(self):
        out = wd.build_standard_payload(7, {})
        assert out["task_id"] == 7
        assert out["target"]["sha256"] is None
        assert out["signatures"] == []
        assert out["detections"] == []
        assert "report_url" not in out  # api_base_url not given

    def test_signatures_without_name_filtered(self):
        results = self._results(signatures=[
            {"name": "good", "severity": 1},
            {"severity": 2},               # no name -- drop
            {"name": "", "severity": 1},   # falsy name -- drop
        ])
        out = wd.build_standard_payload(1, results)
        assert [s["name"] for s in out["signatures"]] == ["good"]

    def test_json_serializable(self):
        out = wd.build_standard_payload(1, self._results())
        decoded = json.loads(json.dumps(out, default=str))
        assert decoded["task_id"] == 1

    def test_api_base_url_trailing_slash_normalized(self):
        out = wd.build_standard_payload(
            9, self._results(), api_base_url="https://x.example.com/////"
        )
        assert out["report_url"] == "https://x.example.com/analysis/9/"


class TestBuildHeaders:
    def test_minimal_no_extras(self):
        h = wd.build_headers(payload_mode="minimal", event=None, secret=None, body=b"{}")
        assert h["Content-Type"] == "application/json"
        assert "X-CAPE-Signature" not in h
        assert "X-CAPE-Event" not in h
        assert "X-CAPE-Delivery" not in h

    def test_standard_adds_event_and_delivery(self):
        h = wd.build_headers(payload_mode="standard", event="task.complete", secret=None, body=b"{}")
        assert h["X-CAPE-Event"] == "task.complete"
        assert "X-CAPE-Delivery" in h
        assert "X-CAPE-Signature" not in h  # no secret

    def test_signature_present_with_secret(self):
        body = b'{"task_id":1}'
        h = wd.build_headers(payload_mode="minimal", event=None, secret=b"s", body=body)
        assert h["X-CAPE-Signature"] == wd.sign(b"s", body)


class TestDeliver:
    def _resp(self, status):
        return MagicMock(spec=requests.Response, status_code=status)

    def test_2xx_succeeds_first_try(self):
        with patch.object(wd, "post_once", return_value=self._resp(200)) as post:
            ok = wd.deliver("http://x", b"{}", {}, timeout=1, retries=3)
        assert ok is True
        assert post.call_count == 1

    def test_5xx_retries_then_succeeds(self):
        side = [self._resp(503), self._resp(503), self._resp(200)]
        with patch.object(wd, "post_once", side_effect=side), \
             patch.object(wd, "backoff_seconds", return_value=0):
            ok = wd.deliver("http://x", b"{}", {}, timeout=1, retries=3)
        assert ok is True

    def test_5xx_exhausts_retries(self):
        side = [self._resp(503)] * 4
        with patch.object(wd, "post_once", side_effect=side), \
             patch.object(wd, "backoff_seconds", return_value=0):
            ok = wd.deliver("http://x", b"{}", {}, timeout=1, retries=3)
        assert ok is False

    def test_4xx_does_not_retry(self):
        with patch.object(wd, "post_once", return_value=self._resp(400)) as post:
            ok = wd.deliver("http://x", b"{}", {}, timeout=1, retries=3)
        assert ok is False
        assert post.call_count == 1

    def test_429_does_retry(self):
        side = [self._resp(429), self._resp(200)]
        with patch.object(wd, "post_once", side_effect=side), \
             patch.object(wd, "backoff_seconds", return_value=0):
            ok = wd.deliver("http://x", b"{}", {}, timeout=1, retries=3)
        assert ok is True

    def test_network_error_retries(self):
        side = [requests.exceptions.ConnectionError("boom"), self._resp(200)]
        with patch.object(wd, "post_once", side_effect=side), \
             patch.object(wd, "backoff_seconds", return_value=0):
            ok = wd.deliver("http://x", b"{}", {}, timeout=1, retries=3)
        assert ok is True

    def test_network_error_exhausts(self):
        side = [requests.exceptions.ConnectionError("boom")] * 4
        with patch.object(wd, "post_once", side_effect=side), \
             patch.object(wd, "backoff_seconds", return_value=0):
            ok = wd.deliver("http://x", b"{}", {}, timeout=1, retries=3)
        assert ok is False
