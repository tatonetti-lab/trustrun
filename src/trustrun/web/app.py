"""FastAPI application factory for the TrustRun web UI."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from trustrun import __version__
from trustrun.config import TrustRunConfig
from trustrun.storage.db import get_db

_FRONTEND_DIR = Path(__file__).parent / "frontend"


async def create_app(
    config: TrustRunConfig | None = None,
) -> FastAPI:
    """Build and return the FastAPI application."""
    config = config or TrustRunConfig.load()

    app = FastAPI(
        title="TrustRun",
        version=__version__,
        docs_url="/api/docs",
    )

    # Store config and db in app state
    app.state.config = config
    db_path = config.data_dir / "trustrun.db"
    app.state.db = await get_db(db_path)

    # Register API routers
    from trustrun.web.api.live import router as live_router
    from trustrun.web.api.policies import router as policies_router
    from trustrun.web.api.scans import router as scans_router
    from trustrun.web.api.sessions import router as sessions_router

    app.include_router(sessions_router, prefix="/api")
    app.include_router(policies_router, prefix="/api")
    app.include_router(scans_router, prefix="/api")
    app.include_router(live_router, prefix="/api")

    # Serve frontend static files
    if _FRONTEND_DIR.is_dir():
        app.mount(
            "/",
            StaticFiles(directory=str(_FRONTEND_DIR), html=True),
            name="frontend",
        )

    @app.on_event("shutdown")
    async def shutdown() -> None:
        if hasattr(app.state, "db"):
            await app.state.db.close()

    return app
