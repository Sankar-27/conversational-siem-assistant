from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import time

from app.core.config import settings
from app.core.logging import setup_logging, logger
from app.core.security_middleware import RateLimitMiddleware, AuditLogMiddleware
from app.api import api_router
from app.db.session import init_db

# Setup structured logging
setup_logging(debug=settings.DEBUG)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: initialize database tables
    try:
        await init_db()
        logger.info("database_initialized")
    except Exception as e:
        logger.warning("database_init_warning", error=str(e))
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="AI-powered conversational SIEM investigation assistant",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )


    # Security middleware (Phase 7)
    app.add_middleware(AuditLogMiddleware)
    app.add_middleware(RateLimitMiddleware, limit=settings.RATE_LIMIT_INVESTIGATE)

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Request timing middleware
    @app.middleware("http")
    async def add_process_time_header(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        response.headers["X-Process-Time"] = f"{elapsed:.3f}s"
        logger.info("http_request", method=request.method, path=request.url.path,
                    status=response.status_code, elapsed_s=round(elapsed, 3))
        return response

    # Register routes
    app.include_router(api_router, prefix=settings.API_PREFIX)

    @app.get("/health")
    async def health():
        from app.modules.rag.vector_store import get_knowledge_store
        store = get_knowledge_store()
        return {
            "status": "ok",
            "version": settings.APP_VERSION,
            "siem_mode": settings.SIEM_MODE,
            "llm_provider": settings.LLM_PROVIDER,
            "knowledge_docs": len(store._chunks) if hasattr(store, "_chunks") else 0,
        }

    @app.get("/metrics")
    async def metrics():
        return {
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "siem_mode": settings.SIEM_MODE,
        }

    return app


app = create_app()
