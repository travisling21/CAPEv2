# Copyright (C) CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2

"""Alembic plumbing for the main task DB.

Replaces the manually-maintained SCHEMA_VERSION constant in
database.py with values read from the actual Alembic migrations dir
at runtime, and centralizes the stamp / upgrade / mismatch logic so
the startup path doesn't have to think about it.

Why this is worth doing:

  * The old code kept SCHEMA_VERSION = "2b3c4d5e6f7g" hard-coded in
    database.py.  Every time someone added a migration they had to
    remember to bump that string in two places, and a divergence
    means CAPE refuses to start with a confusing message.
  * Fresh databases ran `Base.metadata.create_all()` and then INSERTed
    `(version_num='2b3c4d5e6f7g')` into alembic_version themselves --
    no Alembic involvement.  That works until someone later tries to
    `alembic upgrade head` on the same DB: Alembic re-runs every
    migration because it thinks the schema is blank.
  * Schema mismatch was handled by printing an error and sys.exit().
    Operators want an option to auto-upgrade on startup; this module
    exposes that as `database.auto_migrate = yes`.

This module is pure logic -- no side effects at import.
"""

import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

# Anchor to the existing checked-in alembic tree at utils/db_migration/.
# Moving the migrations would only require changing one constant.
_HERE = os.path.dirname(os.path.abspath(__file__))
_CUCKOO_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
MIGRATIONS_DIR = os.path.join(_CUCKOO_ROOT, "utils", "db_migration")
ALEMBIC_INI = os.path.join(MIGRATIONS_DIR, "alembic.ini")


def _alembic_config(database_url: Optional[str] = None):
    """Build an alembic Config pointing at our migrations.

    Imported lazily so this module is cheap to import in non-DB
    contexts (e.g. settings.py snapshots, doc builds).
    """
    from alembic.config import Config

    cfg = Config(ALEMBIC_INI)
    cfg.set_main_option("script_location", MIGRATIONS_DIR)
    if database_url:
        cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def get_head_revision() -> str:
    """Return the current Alembic head revision id.

    Reads from the migrations dir at runtime so adding a new
    migration script automatically updates the value the database
    startup path checks against.
    """
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(_alembic_config())
    head = script.get_current_head()
    if head is None:
        raise RuntimeError(
            f"No Alembic head revision found under {MIGRATIONS_DIR}; "
            "the migrations directory is empty or misconfigured."
        )
    return head


def current_db_revision(engine) -> Optional[str]:
    """Return the revision id stored in `alembic_version`, or None if
    the table is missing (fresh DB).
    """
    from alembic.migration import MigrationContext

    try:
        with engine.connect() as conn:
            ctx = MigrationContext.configure(conn)
            return ctx.get_current_revision()
    except Exception as e:
        log.debug("Could not read current alembic revision: %s", e)
        return None


def stamp_to_head(engine) -> str:
    """Mark a fresh DB as being at the current head revision.

    Used after Base.metadata.create_all() so future `alembic upgrade
    head` runs are no-ops, not full re-applies.  Returns the head id.
    """
    from alembic import command

    head = get_head_revision()
    cfg = _alembic_config(database_url=str(engine.url.render_as_string(hide_password=False)))
    command.stamp(cfg, head)
    return head


def upgrade_to_head(engine) -> str:
    """Run `alembic upgrade head` against `engine`.

    Returns the head revision id (the version the DB is now at).
    """
    from alembic import command

    head = get_head_revision()
    cfg = _alembic_config(database_url=str(engine.url.render_as_string(hide_password=False)))
    command.upgrade(cfg, "head")
    return head
