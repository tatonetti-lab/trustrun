"""Tests for the SQLite storage layer."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from trustrun.session.models import ConnectionEvent, Session, SessionStatus, Violation


def run_async(coro):
    """Helper to run async functions in sync tests."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def db(db_path: Path):
    from trustrun.storage.db import get_db

    conn = run_async(get_db(db_path))
    yield conn
    run_async(conn.close())


class TestSessionRepo:
    def test_create_and_get(self, db):
        from trustrun.storage.repos import SessionRepo

        repo = SessionRepo(db)
        session = Session(
            pid=1234,
            policy_name="test-policy",
            command="curl example.com",
            status=SessionStatus.RUNNING,
        )
        run_async(repo.create(session))
        result = run_async(repo.get(session.id))
        assert result is not None
        assert result["pid"] == 1234
        assert result["policy_name"] == "test-policy"
        assert result["status"] == "running"

    def test_list_all(self, db):
        from trustrun.storage.repos import SessionRepo

        repo = SessionRepo(db)
        for i in range(3):
            s = Session(pid=1000 + i, policy_name="test")
            run_async(repo.create(s))

        results = run_async(repo.list_all())
        assert len(results) == 3

    def test_update_status(self, db):
        from trustrun.storage.repos import SessionRepo

        repo = SessionRepo(db)
        session = Session(pid=1, policy_name="test")
        run_async(repo.create(session))
        run_async(
            repo.update_status(session.id, SessionStatus.STOPPED, 1000.0)
        )
        result = run_async(repo.get(session.id))
        assert result["status"] == "stopped"
        assert result["end_time"] == 1000.0


class TestEventRepo:
    def test_create_and_list(self, db):
        from trustrun.storage.repos import EventRepo, SessionRepo

        session_repo = SessionRepo(db)
        event_repo = EventRepo(db)

        session = Session(pid=1, policy_name="test")
        run_async(session_repo.create(session))

        event = ConnectionEvent(
            pid=1,
            process_name="curl",
            remote_ip="1.2.3.4",
            remote_port=443,
            org="Test Org",
        )
        run_async(event_repo.create(session.id, event))

        events = run_async(event_repo.list_by_session(session.id))
        assert len(events) == 1
        assert events[0]["remote_ip"] == "1.2.3.4"
        assert events[0]["org"] == "Test Org"


class TestViolationRepo:
    def test_create_and_list(self, db):
        from trustrun.storage.repos import (
            EventRepo,
            SessionRepo,
            ViolationRepo,
        )

        session_repo = SessionRepo(db)
        event_repo = EventRepo(db)
        violation_repo = ViolationRepo(db)

        session = Session(pid=1, policy_name="test")
        run_async(session_repo.create(session))

        event = ConnectionEvent(
            pid=1,
            process_name="curl",
            remote_ip="9.9.9.9",
            remote_port=80,
        )
        run_async(event_repo.create(session.id, event))

        violation = Violation(
            event=event,
            action="block",
            rule_match="*.blocked.com",
            reason="Test block",
        )
        run_async(violation_repo.create(session.id, violation))

        violations = run_async(
            violation_repo.list_by_session(session.id)
        )
        assert len(violations) == 1
        assert violations[0]["action"] == "block"


class TestPolicyRepo:
    def test_save_and_get(self, db):
        from trustrun.storage.repos import PolicyRepo

        repo = PolicyRepo(db)
        run_async(
            repo.save("test-policy", "name: test\nrules: []", "A test")
        )

        result = run_async(repo.get("test-policy"))
        assert result is not None
        assert result["name"] == "test-policy"
        assert "rules" in result["yaml_content"]

    def test_list_all(self, db):
        from trustrun.storage.repos import PolicyRepo

        repo = PolicyRepo(db)
        run_async(repo.save("a-policy", "name: a"))
        run_async(repo.save("b-policy", "name: b"))

        results = run_async(repo.list_all())
        assert len(results) == 2


class TestScanRepo:
    def test_save_and_get(self, db):
        from trustrun.scanner.models import Finding, ScanResult, Severity
        from trustrun.storage.repos import ScanRepo

        repo = ScanRepo(db)
        result = ScanResult(
            directory="/tmp/test",
            files_scanned=10,
            files_skipped=2,
            duration=1.5,
            policy_name="test",
            findings=[
                Finding(
                    file_path="/tmp/test/app.py",
                    line=5,
                    column=10,
                    pattern_name="url",
                    matched_text="https://api.example.com",
                    context_line='url = "https://api.example.com"',
                    severity=Severity.WARNING,
                    extracted_endpoint="https://api.example.com",
                    language="python",
                )
            ],
        )
        scan_id = run_async(repo.save_result(result))

        saved = run_async(repo.get(scan_id))
        assert saved is not None
        assert saved["files_scanned"] == 10
        assert len(saved["findings"]) == 1
        assert saved["findings"][0]["pattern_name"] == "url"
