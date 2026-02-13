"""REST API for policy management."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from trustrun.storage.repos import PolicyRepo

router = APIRouter(tags=["policies"])


class PolicyCreate(BaseModel):
    name: str
    yaml_content: str
    description: str = ""


@router.get("/policies")
async def list_policies(request: Request):
    repo = PolicyRepo(request.app.state.db)
    return await repo.list_all()


@router.get("/policies/{name}")
async def get_policy(name: str, request: Request):
    repo = PolicyRepo(request.app.state.db)
    policy = await repo.get(name)
    if not policy:
        return JSONResponse(
            status_code=404,
            content={"detail": "Policy not found"},
        )
    return policy


@router.post("/policies")
async def create_policy(body: PolicyCreate, request: Request):
    repo = PolicyRepo(request.app.state.db)
    await repo.save(body.name, body.yaml_content, body.description)
    return {"status": "created", "name": body.name}


@router.put("/policies/{name}")
async def update_policy(name: str, body: PolicyCreate, request: Request):
    repo = PolicyRepo(request.app.state.db)
    await repo.save(name, body.yaml_content, body.description)
    return {"status": "updated", "name": name}
