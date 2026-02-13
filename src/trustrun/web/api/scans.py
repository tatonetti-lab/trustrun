"""REST API for scan results."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from trustrun.storage.repos import ScanRepo

router = APIRouter(tags=["scans"])


@router.get("/scans")
async def list_scans(request: Request):
    repo = ScanRepo(request.app.state.db)
    return await repo.list_all()


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    repo = ScanRepo(request.app.state.db)
    result = await repo.get(scan_id)
    if not result:
        return JSONResponse(
            status_code=404,
            content={"detail": "Scan not found"},
        )
    return result
