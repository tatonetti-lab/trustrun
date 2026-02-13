"""WebSocket endpoint for real-time session event streaming."""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from trustrun.storage.repos import EventRepo, ViolationRepo

router = APIRouter(tags=["live"])


@router.websocket("/ws/sessions/{session_id}")
async def session_ws(websocket: WebSocket, session_id: str):
    """Stream new events and violations for a session in real-time."""
    await websocket.accept()

    db = websocket.app.state.db
    event_repo = EventRepo(db)
    violation_repo = ViolationRepo(db)

    last_event_count = 0
    last_violation_count = 0

    try:
        while True:
            events = await event_repo.list_by_session(session_id)
            violations = await violation_repo.list_by_session(session_id)

            if len(events) > last_event_count:
                new_events = events[last_event_count:]
                for event in new_events:
                    await websocket.send_text(
                        json.dumps({"type": "event", "data": event})
                    )
                last_event_count = len(events)

            if len(violations) > last_violation_count:
                new_violations = violations[last_violation_count:]
                for v in new_violations:
                    await websocket.send_text(
                        json.dumps({"type": "violation", "data": v})
                    )
                last_violation_count = len(violations)

            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        pass
