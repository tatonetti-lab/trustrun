"""Repository classes for async CRUD operations on SQLite."""

from __future__ import annotations

import time
import uuid

import aiosqlite

from trustrun.scanner.models import ScanResult
from trustrun.session.models import (
    ConnectionEvent,
    Session,
    SessionStatus,
    Violation,
)


class SessionRepo:
    """CRUD for monitoring sessions."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def create(self, session: Session) -> None:
        await self._db.execute(
            "INSERT INTO sessions "
            "(id, pid, command, policy_name, status, start_time, end_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                session.id,
                session.pid,
                session.command,
                session.policy_name,
                session.status.value,
                session.start_time,
                session.end_time,
            ),
        )
        await self._db.commit()

    async def update_status(
        self,
        session_id: str,
        status: SessionStatus,
        end_time: float | None = None,
    ) -> None:
        await self._db.execute(
            "UPDATE sessions SET status = ?, end_time = ? WHERE id = ?",
            (status.value, end_time, session_id),
        )
        await self._db.commit()

    async def get(self, session_id: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM sessions WHERE id = ?", (session_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def list_all(self, limit: int = 50, offset: int = 0) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(row) async for row in cursor]


class EventRepo:
    """CRUD for connection events."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def create(self, session_id: str, event: ConnectionEvent) -> None:
        await self._db.execute(
            "INSERT INTO connection_events "
            "(id, session_id, pid, process_name, remote_ip, "
            "remote_port, local_ip, local_port, hostname, org, "
            "protocol, status, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.id,
                session_id,
                event.pid,
                event.process_name,
                event.remote_ip,
                event.remote_port,
                event.local_ip,
                event.local_port,
                event.hostname,
                event.org,
                event.protocol,
                event.status,
                event.timestamp,
            ),
        )
        await self._db.commit()

    async def list_by_session(self, session_id: str) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM connection_events WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        )
        return [dict(row) async for row in cursor]


class ViolationRepo:
    """CRUD for violations."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def create(self, session_id: str, violation: Violation) -> None:
        await self._db.execute(
            "INSERT INTO violations "
            "(id, session_id, event_id, action, rule_match, "
            "reason, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                violation.id,
                session_id,
                violation.event.id,
                violation.action,
                violation.rule_match,
                violation.reason,
                violation.timestamp,
            ),
        )
        await self._db.commit()

    async def list_by_session(self, session_id: str) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM violations WHERE session_id = ? ORDER BY timestamp",
            (session_id,),
        )
        return [dict(row) async for row in cursor]


class PolicyRepo:
    """CRUD for stored policies."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def save(
        self,
        name: str,
        yaml_content: str,
        description: str = "",
    ) -> None:
        now = time.time()
        await self._db.execute(
            "INSERT OR REPLACE INTO policies "
            "(name, yaml_content, description, created_at, updated_at) "
            "VALUES (?, ?, ?, COALESCE("
            "  (SELECT created_at FROM policies WHERE name = ?), ?"
            "), ?)",
            (name, yaml_content, description, name, now, now),
        )
        await self._db.commit()

    async def get(self, name: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM policies WHERE name = ?", (name,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def list_all(self) -> list[dict]:
        cursor = await self._db.execute("SELECT * FROM policies ORDER BY name")
        return [dict(row) async for row in cursor]


class ScanRepo:
    """CRUD for scan results and findings."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    async def save_result(self, result: ScanResult) -> str:
        scan_id = uuid.uuid4().hex[:12]
        await self._db.execute(
            "INSERT INTO scan_results "
            "(id, directory, policy_name, files_scanned, "
            "files_skipped, duration, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                result.directory,
                result.policy_name,
                result.files_scanned,
                result.files_skipped,
                result.duration,
                result.timestamp,
            ),
        )

        for finding in result.findings:
            await self._db.execute(
                "INSERT INTO scan_findings "
                "(scan_id, file_path, line, col, pattern_name, "
                "matched_text, context_line, severity, "
                "extracted_endpoint, language) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    finding.file_path,
                    finding.line,
                    finding.column,
                    finding.pattern_name,
                    finding.matched_text,
                    finding.context_line,
                    finding.severity.value,
                    finding.extracted_endpoint,
                    finding.language,
                ),
            )

        await self._db.commit()
        return scan_id

    async def get(self, scan_id: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM scan_results WHERE id = ?", (scan_id,)
        )
        row = await cursor.fetchone()
        if not row:
            return None

        result = dict(row)
        cursor = await self._db.execute(
            "SELECT * FROM scan_findings WHERE scan_id = ? "
            "ORDER BY severity, file_path, line",
            (scan_id,),
        )
        result["findings"] = [dict(r) async for r in cursor]
        return result

    async def list_all(self, limit: int = 50, offset: int = 0) -> list[dict]:
        cursor = await self._db.execute(
            "SELECT * FROM scan_results ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )
        return [dict(row) async for row in cursor]
