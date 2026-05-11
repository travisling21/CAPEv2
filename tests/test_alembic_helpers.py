# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Tests for the alembic_helpers module.

We hit the real checked-in migrations tree at utils/db_migration/
because it's the source of truth for the head revision -- testing
against a synthetic tree wouldn't catch the bug we care about most
(drift between the migrations folder and the constant the startup
path checks against).

The stamp/upgrade tests use an in-memory SQLite engine so they're
hermetic.
"""

import importlib.util
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# Import the helpers under test without dragging in the full database
# module (which transitively imports the whole CAPE stack).
_spec = importlib.util.spec_from_file_location(
    "alembic_helpers",
    os.path.join(ROOT, "lib", "cuckoo", "core", "alembic_helpers.py"),
)
ah = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ah)


# The stamp/upgrade tests invoke `alembic command.stamp` and
# `command.upgrade`, which load env.py from utils/db_migration/.  That
# env.py imports lib.cuckoo.core.database, which transitively imports
# PIL, lxml, yara, etc.  In CI (full deps installed) this Just Works;
# locally we skip these tests with a clear reason.
def _full_stack_available() -> bool:
    for mod in ("PIL", "pytz", "yara", "lxml"):
        if importlib.util.find_spec(mod) is None:
            return False
    return True


needs_full_stack = pytest.mark.skipif(
    not _full_stack_available(),
    reason="Stamp/upgrade exercises env.py which loads the full CAPE stack",
)


@pytest.fixture
def sqlite_engine():
    from sqlalchemy import create_engine
    eng = create_engine("sqlite:///:memory:")
    yield eng
    eng.dispose()


class TestHeadDiscovery:
    def test_head_is_a_revision_id(self):
        head = ah.get_head_revision()
        assert isinstance(head, str)
        assert head  # non-empty
        # Alembic revision ids are typically 12 hex chars, but the
        # repo uses some shorter ids too -- just assert it's plain
        # alphanumeric/underscore.
        assert all(c.isalnum() or c == "_" for c in head)

    def test_head_matches_actual_migration_file(self):
        # Walk the versions dir and confirm the head revision id
        # actually appears as a `revision = '...'` line in some script.
        head = ah.get_head_revision()
        versions = os.path.join(ah.MIGRATIONS_DIR, "versions")
        found = False
        for fn in os.listdir(versions):
            full = os.path.join(versions, fn)
            if not os.path.isfile(full):
                continue
            with open(full, encoding="utf-8", errors="replace") as f:
                if f"revision = '{head}'" in f.read() or f'revision = "{head}"' in f.read():
                    found = True
                    break
        assert found, f"head {head!r} not found in any migration script"


class TestCurrentRevision:
    def test_returns_none_for_blank_db(self, sqlite_engine):
        # Nothing created yet -- alembic_version doesn't exist.
        assert ah.current_db_revision(sqlite_engine) is None

    @needs_full_stack
    def test_returns_value_after_stamp(self, sqlite_engine):
        stamped = ah.stamp_to_head(sqlite_engine)
        current = ah.current_db_revision(sqlite_engine)
        assert current == stamped
        assert current == ah.get_head_revision()


@needs_full_stack
class TestStampAndUpgrade:
    def test_stamp_creates_version_table(self, sqlite_engine):
        from sqlalchemy import inspect

        # Before: no alembic_version table.
        before = inspect(sqlite_engine).has_table("alembic_version")
        assert before is False

        ah.stamp_to_head(sqlite_engine)

        # After: table exists with one row at head.
        after = inspect(sqlite_engine).has_table("alembic_version")
        assert after is True
        assert ah.current_db_revision(sqlite_engine) == ah.get_head_revision()

    def test_upgrade_idempotent_when_already_at_head(self, sqlite_engine):
        ah.stamp_to_head(sqlite_engine)
        before = ah.current_db_revision(sqlite_engine)
        # Upgrade-to-head on a DB already at head is a no-op.
        head = ah.upgrade_to_head(sqlite_engine)
        after = ah.current_db_revision(sqlite_engine)
        assert before == after == head


class TestAlembicConfig:
    def test_config_points_at_real_migrations_dir(self):
        cfg = ah._alembic_config()
        assert os.path.isdir(cfg.get_main_option("script_location"))

    def test_database_url_threaded_through(self):
        cfg = ah._alembic_config(database_url="sqlite:///fake.db")
        assert cfg.get_main_option("sqlalchemy.url") == "sqlite:///fake.db"
