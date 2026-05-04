"""FastAPI dashboard.

Build via `build_app(db_path)` — reads from a Twin DB file. Each request
opens a fresh DuckDB connection (cheap; DuckDB is single-file).
"""
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

TEMPLATES_DIR = Path(__file__).parent / "templates"


def build_app(db_path: Path) -> FastAPI:
    """Construct a FastAPI app bound to the given Twin DB path."""
    app = FastAPI(title="vmware-harden")
    app.state.db_path = db_path
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.state.templates = templates

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "index.html",
            {"page": "summary"},
        )

    return app
