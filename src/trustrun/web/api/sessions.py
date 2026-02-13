"""REST API for monitoring sessions."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from trustrun.storage.repos import (
    EventRepo,
    SessionRepo,
    ViolationRepo,
)

router = APIRouter(tags=["sessions"])


@router.get("/sessions")
async def list_sessions(request: Request):
    repo = SessionRepo(request.app.state.db)
    sessions = await repo.list_all()
    return sessions


@router.get("/sessions/{session_id}")
async def get_session(session_id: str, request: Request):
    session_repo = SessionRepo(request.app.state.db)
    event_repo = EventRepo(request.app.state.db)
    violation_repo = ViolationRepo(request.app.state.db)

    session = await session_repo.get(session_id)
    if not session:
        return JSONResponse(
            status_code=404,
            content={"detail": "Session not found"},
        )

    session["events"] = await event_repo.list_by_session(session_id)
    session["violations"] = await violation_repo.list_by_session(session_id)
    return session


@router.post("/sessions/{session_id}/stop")
async def stop_session(session_id: str, request: Request):
    repo = SessionRepo(request.app.state.db)
    session = await repo.get(session_id)
    if not session:
        return JSONResponse(
            status_code=404,
            content={"detail": "Session not found"},
        )

    import time

    from trustrun.session.models import SessionStatus

    await repo.update_status(session_id, SessionStatus.STOPPED, end_time=time.time())
    return {"status": "stopped", "session_id": session_id}
