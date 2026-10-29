"""Main FastAPI application entrypoint for OSS Dependency Intelligence."""
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path
from backend.app.core.config import settings
from backend.app.core.database import init_db
from backend.app.api.v1.endpoints import router as api_v1_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite tables on startup
    init_db()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Understand Your Dependencies. Detect Risks. Ship with Confidence.",
    version=settings.VERSION,
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API v1 Router
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

# Static Frontend mounting
web_dist = Path(__file__).resolve().parent.parent.parent / "apps" / "web" / "dist"
if web_dist.exists() and (web_dist / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=web_dist / "assets"), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        target = web_dist / full_path
        if target.exists() and target.is_file():
            return FileResponse(target)
        return FileResponse(web_dist / "index.html")
else:
    @app.get("/")
    def root():
        return {
            "name": settings.PROJECT_NAME,
            "version": settings.VERSION,
            "tagline": settings.TAGLINE,
            "docs_url": "/docs",
            "api_prefix": settings.API_V1_PREFIX
        }
