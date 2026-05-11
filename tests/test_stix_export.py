# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Unit tests for the STIX 2.1 bundle builder."""

import json
import re

import pytest

from lib.cuckoo.common import stix_export as sx


# STIX 2.1 ID format: <type>--<uuid>
ID_RE = re.compile(r"^[a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def _full_results():
    return {
        "info": {
            "id": 42,
            "category": "file",
            "package": "exe",
            "score": 8.5,
            "started": "2026-05-11 12:00:00",
            "ended": "2026-05-11 12:05:00",
        },
        "target": {
            "category": "file",
            "file": {
                "name": "sample.exe",
                "sha256": "a" * 64,
                "sha1": "b" * 40,
                "md5": "c" * 32,
                "size": 12345,
                "type": "PE32",
            },
        },
        "detections": [{"family": "TrickBot"}, "Emotet"],
        "ttps": [
            {"ttp": "T1059.001", "name": "PowerShell"},
            {"technique_id": "T1055", "technique": "Process Injection"},
        ],
        "network": {
            "dns": [
                {
                    "request": "example.com",
                    "answers": [{"data": "93.184.216.34"}],
                },
                {"request": "evil.example"},
            ],
            "hosts": ["1.2.3.4", {"ip": "5.6.7.8"}],
            "http": [
                {"uri": "http://example.com/index.html"},
                {"uri": "http://evil.example/payload.bin"},
            ],
        },
        "report_url": "https://cape.example.com/analysis/42/",
    }


class TestBundleShape:
    def test_minimal_results_still_produces_valid_bundle(self):
        b = sx.make_bundle({})
        assert b["type"] == "bundle"
        assert ID_RE.match(b["id"])
        # Always at least the identity + report SDOs.
        types = [o["type"] for o in b["objects"]]
        assert "identity" in types
        assert "report" in types

    def test_full_results_emits_expected_object_types(self):
        b = sx.make_bundle(_full_results())
        types = {o["type"] for o in b["objects"]}
        assert "identity" in types
        assert "file" in types
        assert "malware" in types
        assert "attack-pattern" in types
        assert "domain-name" in types
        assert "ipv4-addr" in types
        assert "url" in types
        assert "observed-data" in types
        assert "relationship" in types
        assert "report" in types

    def test_all_object_ids_are_valid_stix(self):
        b = sx.make_bundle(_full_results())
        for o in b["objects"]:
            assert ID_RE.match(o["id"]), o

    def test_bundle_is_json_serializable(self):
        b = sx.make_bundle(_full_results())
        text = json.dumps(b)
        # Round-trips
        assert json.loads(text) == b


class TestStability:
    def test_same_input_same_ids(self):
        a = sx.make_bundle(_full_results())
        b = sx.make_bundle(_full_results())
        # Object IDs are deterministic.  `created/modified/published`
        # timestamps are not -- they reflect "now" -- but we don't
        # care about those for dedup purposes.
        ids_a = sorted(o["id"] for o in a["objects"])
        ids_b = sorted(o["id"] for o in b["objects"])
        assert ids_a == ids_b

    def test_different_task_ids_share_iocs_but_not_reports(self):
        # File/Malware/Domain/IP/URL/AttackPattern IDs are global (so
        # downstream TIPs dedupe by content); Report and ObservedData
        # IDs are task-scoped (so each analysis is a distinct event).
        r1 = _full_results()
        r2 = _full_results()
        r2["info"]["id"] = 99
        a = sx.make_bundle(r1)
        b = sx.make_bundle(r2)

        report_a = next(o for o in a["objects"] if o["type"] == "report")
        report_b = next(o for o in b["objects"] if o["type"] == "report")
        assert report_a["id"] != report_b["id"]

        # The same SHA-256 sample yields the same File SCO id.
        file_a = next(o for o in a["objects"] if o["type"] == "file")
        file_b = next(o for o in b["objects"] if o["type"] == "file")
        assert file_a["id"] == file_b["id"]


class TestFileMapping:
    def test_hashes_uppercased_to_stix_form(self):
        b = sx.make_bundle(_full_results())
        f = next(o for o in b["objects"] if o["type"] == "file")
        assert f["hashes"]["SHA-256"] == "a" * 64
        assert f["hashes"]["SHA-1"] == "b" * 40
        assert f["hashes"]["MD5"] == "c" * 32
        assert f["name"] == "sample.exe"
        assert f["size"] == 12345

    def test_invalid_hashes_dropped(self):
        r = _full_results()
        r["target"]["file"]["sha256"] = "not-a-hash"
        r["target"]["file"]["md5"] = "tooshort"
        b = sx.make_bundle(r)
        files = [o for o in b["objects"] if o["type"] == "file"]
        # sha1 is still valid, so file should still appear.
        assert len(files) == 1
        assert "SHA-256" not in files[0]["hashes"]
        assert "MD5" not in files[0]["hashes"]
        assert "SHA-1" in files[0]["hashes"]

    def test_no_hashes_no_file_sco(self):
        r = _full_results()
        r["target"]["file"] = {"name": "x.exe", "size": 1}
        b = sx.make_bundle(r)
        files = [o for o in b["objects"] if o["type"] == "file"]
        assert files == []


class TestMalwareFamilies:
    def test_each_family_emits_malware_sdo(self):
        b = sx.make_bundle(_full_results())
        mals = [o for o in b["objects"] if o["type"] == "malware"]
        names = {o["name"] for o in mals}
        assert names == {"TrickBot", "Emotet"}
        for m in mals:
            assert m["is_family"] is True

    def test_sample_indicates_each_family(self):
        b = sx.make_bundle(_full_results())
        rels = [o for o in b["objects"] if o["type"] == "relationship" and o["relationship_type"] == "indicates"]
        assert len(rels) == 2

    def test_no_families_no_malware_sdos(self):
        r = _full_results()
        r["detections"] = []
        b = sx.make_bundle(r)
        mals = [o for o in b["objects"] if o["type"] == "malware"]
        assert mals == []


class TestAttackPatterns:
    def test_each_ttp_emits_attack_pattern(self):
        b = sx.make_bundle(_full_results())
        aps = [o for o in b["objects"] if o["type"] == "attack-pattern"]
        ext_ids = {ap["external_references"][0]["external_id"] for ap in aps}
        assert ext_ids == {"T1059.001", "T1055"}

    def test_attack_pattern_url_uses_attack_mitre_org(self):
        b = sx.make_bundle({"info": {"id": 1}, "ttps": [{"ttp": "T1059.001", "name": "PowerShell"}]})
        ap = next(o for o in b["objects"] if o["type"] == "attack-pattern")
        # Sub-techniques become T1059/001 in the URL path.
        assert ap["external_references"][0]["url"].endswith("T1059/001/")

    def test_ttps_as_dict_supported(self):
        b = sx.make_bundle({
            "info": {"id": 1},
            "ttps": {"T1059": {"name": "Command and Scripting Interpreter"}},
        })
        aps = [o for o in b["objects"] if o["type"] == "attack-pattern"]
        assert len(aps) == 1
        assert aps[0]["external_references"][0]["external_id"] == "T1059"


class TestNetworkMapping:
    def test_dns_request_emits_domain_name_sco(self):
        b = sx.make_bundle(_full_results())
        domains = sorted(o["value"] for o in b["objects"] if o["type"] == "domain-name")
        assert domains == ["evil.example", "example.com"]

    def test_dns_answer_emits_ipv4_sco(self):
        b = sx.make_bundle(_full_results())
        ips = sorted(o["value"] for o in b["objects"] if o["type"] == "ipv4-addr")
        # 93.184.216.34 from DNS + 1.2.3.4 and 5.6.7.8 from hosts.
        assert "93.184.216.34" in ips
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips

    def test_http_uri_emits_url_sco(self):
        b = sx.make_bundle(_full_results())
        urls = sorted(o["value"] for o in b["objects"] if o["type"] == "url")
        assert urls == ["http://evil.example/payload.bin", "http://example.com/index.html"]

    def test_duplicate_dns_requests_deduped(self):
        r = _full_results()
        r["network"] = {
            "dns": [
                {"request": "x.example", "answers": [{"data": "1.1.1.1"}]},
                {"request": "x.example", "answers": [{"data": "1.1.1.1"}]},
            ],
        }
        b = sx.make_bundle(r)
        domains = [o for o in b["objects"] if o["type"] == "domain-name"]
        ips = [o for o in b["objects"] if o["type"] == "ipv4-addr"]
        assert len(domains) == 1
        assert len(ips) == 1


class TestReportSDO:
    def test_score_above_5_adds_malicious_activity_label(self):
        b = sx.make_bundle(_full_results())
        report = next(o for o in b["objects"] if o["type"] == "report")
        assert "malware-analysis" in report["labels"]
        assert "malicious-activity" in report["labels"]

    def test_low_score_omits_malicious_activity_label(self):
        r = _full_results()
        r["info"]["score"] = 1.0
        b = sx.make_bundle(r)
        report = next(o for o in b["objects"] if o["type"] == "report")
        assert "malicious-activity" not in report["labels"]

    def test_report_url_becomes_external_reference(self):
        b = sx.make_bundle(_full_results())
        report = next(o for o in b["objects"] if o["type"] == "report")
        assert any(
            ref.get("source_name") == "cape" and "analysis/42" in ref.get("url", "")
            for ref in report.get("external_references", [])
        )

    def test_object_refs_cover_all_non_report_sdos(self):
        b = sx.make_bundle(_full_results())
        report = next(o for o in b["objects"] if o["type"] == "report")
        all_ids = {o["id"] for o in b["objects"] if o["type"] != "report"}
        # Every non-report SDO must be referenced by the Report.
        assert all_ids.issubset(set(report["object_refs"]))


class TestIdentity:
    def test_custom_identity_name_threaded_through(self):
        b = sx.make_bundle(_full_results(), identity_name="Acme SOC")
        ident = next(o for o in b["objects"] if o["type"] == "identity")
        assert ident["name"] == "Acme SOC"

    def test_identity_created_by_ref_chain(self):
        b = sx.make_bundle(_full_results())
        ident = next(o for o in b["objects"] if o["type"] == "identity")
        for o in b["objects"]:
            if o.get("created_by_ref"):
                assert o["created_by_ref"] == ident["id"]


class TestDefensiveness:
    @pytest.mark.parametrize("results", [
        {},
        {"info": {}},
        {"info": {"id": "not-a-number"}},
        {"info": {"id": 1}, "ttps": "garbage"},
        {"info": {"id": 1}, "network": "garbage"},
        {"info": {"id": 1}, "network": {"dns": [None, "string-not-dict"]}},
        {"info": {"id": 1}, "detections": [None, 42, {"family": ""}]},
        {"info": {"id": 1, "score": "not-a-number"}},
    ])
    def test_does_not_raise_on_malformed_input(self, results):
        # Should produce SOME bundle, never raise.
        b = sx.make_bundle(results)
        assert b["type"] == "bundle"
        assert b["objects"]
