from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .database import init_database
from .schemas import ModelDetailResponse, ModelInfoResponse, ScanRequest, ScanResponse
from .services import AnalyzerService, RateLimiter
from .settings import Settings, get_settings


def _client_key(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "anonymous"


def _frontend_dir(settings: Settings) -> Path:
    return settings.project_root / "frontend"


def _frontend_dist_dir(settings: Settings) -> Path:
    return _frontend_dir(settings) / "dist"


def _serve_spa_path(settings: Settings, relative_path: str = "") -> FileResponse | HTMLResponse:
    dist_dir = _frontend_dist_dir(settings)
    index_file = dist_dir / "index.html"
    if not index_file.exists():
        return HTMLResponse(
            """
            <!DOCTYPE html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>BaitDetector frontend missing</title>
              <style>
                body {
                  margin: 0;
                  min-height: 100vh;
                  display: grid;
                  place-items: center;
                  padding: 32px;
                  font-family: system-ui, sans-serif;
                  background: #ffffff;
                  color: #111111;
                }
                main {
                  max-width: 720px;
                  line-height: 1.6;
                }
                code {
                  padding: 2px 6px;
                  border-radius: 6px;
                  background: #f3f4f6;
                }
              </style>
            </head>
            <body>
              <main>
                <h1>BaitDetector frontend build not found</h1>
                <p>Run <code>cd frontend && npm install && npm run build</code> for production hosting, or <code>npm run dev</code> inside <code>frontend/</code> for hot reload during development.</p>
              </main>
            </body>
            </html>
            """,
            status_code=503,
        )

    if relative_path:
        candidate = (dist_dir / relative_path).resolve()
        try:
            candidate.relative_to(dist_dir.resolve())
        except ValueError as exc:
            raise HTTPException(status_code=404) from exc
        if candidate.is_file():
            return FileResponse(candidate)
        if Path(relative_path).suffix:
            raise HTTPException(status_code=404)

    return FileResponse(index_file)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    static_dir = Path(__file__).resolve().parent / "static"

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        init_database(settings)
        app.state.settings = settings
        app.state.analyzer = AnalyzerService(settings)
        app.state.rate_limiter = RateLimiter(
            max_requests=settings.rate_limit_requests,
            window_seconds=settings.rate_limit_window_seconds,
        )
        yield

    app = FastAPI(
        title="BaitDetector",
        version="0.2.0",
        description="Phishing-first URL risk scanner with a local model and no external enrichment.",
        lifespan=lifespan,
    )
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.post("/api/scan", response_model=ScanResponse)
    async def scan_api(request: Request, payload: ScanRequest) -> ScanResponse:
        request.app.state.rate_limiter.enforce(_client_key(request))
        analyzer: AnalyzerService = request.app.state.analyzer
        try:
            return analyzer.scan(url=payload.url, deep_scan=payload.deep_scan)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/model-info", response_model=ModelInfoResponse)
    async def model_info(request: Request) -> ModelInfoResponse:
        analyzer: AnalyzerService = request.app.state.analyzer
        return analyzer.model_info()

    @app.get("/api/model-details", response_model=ModelDetailResponse)
    async def model_details(request: Request) -> ModelDetailResponse:
        analyzer: AnalyzerService = request.app.state.analyzer
        return ModelDetailResponse(**analyzer.model_details())

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse, response_model=None, include_in_schema=False)
    async def spa_index():
        return _serve_spa_path(settings)

    @app.get("/{full_path:path}", response_class=HTMLResponse, response_model=None, include_in_schema=False)
    async def spa_catch_all(full_path: str):
        return _serve_spa_path(settings, full_path)

    return app


def run_dev() -> None:
    import uvicorn

    uvicorn.run("baitdetector.app:create_app", factory=True, host="127.0.0.1", port=8000, reload=True)
