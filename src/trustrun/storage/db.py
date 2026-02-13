"""SQLite database connection management and schema migrations."""

from __future__ import annotations

import logging
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 2

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    pid INTEGER NOT NULL,
    command TEXT NOT NULL DEFAULT '',
    policy_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    start_time REAL NOT NULL,
    end_time REAL
);

CREATE TABLE IF NOT EXISTS connection_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    process_name TEXT NOT NULL DEFAULT '',
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    local_ip TEXT NOT NULL DEFAULT '',
    local_port INTEGER NOT NULL DEFAULT 0,
    hostname TEXT NOT NULL DEFAULT '',
    org TEXT NOT NULL DEFAULT '',
    protocol TEXT NOT NULL DEFAULT 'tcp',
    status TEXT NOT NULL DEFAULT 'ESTABLISHED',
    timestamp REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS violations (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    action TEXT NOT NULL,
    rule_match TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    timestamp REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(id),
    FOREIGN KEY (event_id) REFERENCES connection_events(id)
);

CREATE TABLE IF NOT EXISTS policies (
    name TEXT PRIMARY KEY,
    yaml_content TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_results (
    id TEXT PRIMARY KEY,
    directory TEXT NOT NULL,
    policy_name TEXT NOT NULL DEFAULT '',
    files_scanned INTEGER NOT NULL DEFAULT 0,
    files_skipped INTEGER NOT NULL DEFAULT 0,
    duration REAL NOT NULL DEFAULT 0,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line INTEGER NOT NULL,
    col INTEGER NOT NULL DEFAULT 0,
    pattern_name TEXT NOT NULL,
    matched_text TEXT NOT NULL,
    context_line TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info',
    extracted_endpoint TEXT NOT NULL DEFAULT '',
    language TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (scan_id) REFERENCES scan_results(id)
);

CREATE INDEX IF NOT EXISTS idx_events_session
    ON connection_events(session_id);
CREATE INDEX IF NOT EXISTS idx_violations_session
    ON violations(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan
    ON scan_findings(scan_id);
"""


async def get_db(db_path: str | Path) -> aiosqlite.Connection:
    """Open (or create) the database and run migrations."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    db = await aiosqlite.connect(str(db_path))
    db.row_factory = aiosqlite.Row
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA foreign_keys=ON")

    await _migrate(db)
    return db


async def _migrate(db: aiosqlite.Connection) -> None:
    """Run schema migrations if needed."""
    # Check if schema_version table exists
    cursor = await db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    )
    row = await cursor.fetchone()

    if row is None:
        # Fresh database — create everything
        await db.executescript(SCHEMA_SQL)
        await db.execute(
            "INSERT INTO schema_version (version) VALUES (?)",
            (SCHEMA_VERSION,),
        )
        await db.commit()
        logger.info("Database initialized at schema version %d", SCHEMA_VERSION)
        return

    cursor = await db.execute("SELECT version FROM schema_version")
    row = await cursor.fetchone()
    current = row[0] if row else 0

    if current < SCHEMA_VERSION:
        logger.info(
            "Migrating database from version %d to %d",
            current,
            SCHEMA_VERSION,
        )
        if current < 2:
            await db.execute(
                "ALTER TABLE connection_events "
                "ADD COLUMN org TEXT NOT NULL DEFAULT ''"
            )
        await db.execute(
            "UPDATE schema_version SET version = ?",
            (SCHEMA_VERSION,),
        )
        await db.commit()
