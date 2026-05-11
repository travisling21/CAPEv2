# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Tests for the replay helpers."""

import json
import os

import pytest

# Pure-helper module: no full-stack imports needed.
from lib.cuckoo.core import replay


class TestParseIdSpec:
    def test_single_id(self):
        assert list(replay.parse_id_spec("42")) == [42]

    def test_comma_list(self):
        assert list(replay.parse_id_spec("1,2,3")) == [1, 2, 3]

    def test_range(self):
        assert list(replay.parse_id_spec("10-13")) == [10, 11, 12, 13]

    def test_mixed(self):
        assert list(replay.parse_id_spec("1,5-7,42")) == [1, 5, 6, 7, 42]

    def test_whitespace_tolerated(self):
        assert list(replay.parse_id_spec(" 1 , 2 ,3 ")) == [1, 2, 3]

    def test_descending_range_rejected(self):
        with pytest.raises(ValueError):
            list(replay.parse_id_spec("10-5"))

    def test_garbage_rejected(self):
        with pytest.raises(ValueError):
            list(replay.parse_id_spec("abc"))


class TestValidateOptions:
    def test_no_stage_selected_rejected(self):
        opts = replay.ReplayOptions()
        assert "at least one" in replay.validate_options(opts)

    def test_processing_name_requires_processing_only(self):
        opts = replay.ReplayOptions(run_reporting=True, processing_name="CAPE")
        assert "--processing-only" in replay.validate_options(opts)

    def test_reporting_name_requires_reporting_only(self):
        opts = replay.ReplayOptions(run_processing=True, reporting_name="stix")
        assert "--reporting-only" in replay.validate_options(opts)

    def test_signature_name_requires_signatures_only(self):
        opts = replay.ReplayOptions(run_reporting=True, signature_name="foo")
        assert "--signature-name" in replay.validate_options(opts)

    def test_valid_processing(self):
        opts = replay.ReplayOptions(run_processing=True, processing_name="CAPE")
        assert replay.validate_options(opts) is None

    def test_valid_reporting(self):
        opts = replay.ReplayOptions(run_reporting=True, reporting_name="stix")
        assert replay.validate_options(opts) is None

    def test_valid_signatures(self):
        opts = replay.ReplayOptions(run_signatures=True, signature_name="my_rule")
        assert replay.validate_options(opts) is None

    def test_multiple_stages_allowed(self):
        opts = replay.ReplayOptions(run_processing=True, run_signatures=True, run_reporting=True)
        assert replay.validate_options(opts) is None


class TestStagesProperty:
    def test_lists_each_enabled_stage(self):
        opts = replay.ReplayOptions(run_processing=True, run_signatures=True, run_reporting=True)
        assert opts.stages() == ["processing", "signatures", "reporting"]

    def test_empty_when_none_set(self):
        assert replay.ReplayOptions().stages() == []


class TestLoadCachedReport:
    def test_missing_dir_returns_error(self, tmp_path):
        results, err = replay.load_cached_report(str(tmp_path), 999)
        assert results is None
        assert "no cached report" in err

    def test_loads_valid_json(self, tmp_path):
        # Lay out storage/analyses/42/reports/report.json under tmp_path
        rd = tmp_path / "storage" / "analyses" / "42" / "reports"
        rd.mkdir(parents=True)
        (rd / "report.json").write_text(json.dumps({"hello": "world"}))

        results, err = replay.load_cached_report(str(tmp_path), 42)
        assert err is None
        assert results == {"hello": "world"}

    def test_invalid_json_reports_error(self, tmp_path):
        rd = tmp_path / "storage" / "analyses" / "7" / "reports"
        rd.mkdir(parents=True)
        (rd / "report.json").write_text("this is not json {")

        results, err = replay.load_cached_report(str(tmp_path), 7)
        assert results is None
        assert "failed to load" in err


class TestPaths:
    def test_analysis_dir_layout(self, tmp_path):
        d = replay.analysis_dir(str(tmp_path), 99)
        assert d.endswith(os.path.join("storage", "analyses", "99"))

    def test_cached_report_path_layout(self, tmp_path):
        p = replay.cached_report_path(str(tmp_path), 99)
        assert p.endswith(os.path.join("99", "reports", "report.json"))


class TestReplayResultStatus:
    def test_ok_without_error(self):
        r = replay.ReplayResult(task_id=1, stages_run=["reporting"])
        assert r.ok is True

    def test_not_ok_with_error(self):
        r = replay.ReplayResult(task_id=1, error="boom")
        assert r.ok is False
