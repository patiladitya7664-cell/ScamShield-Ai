
"""
=========================================================
SCAMSHIELD AI - MAIN APPLICATION
=========================================================

FastAPI entry point for the ScamShield AI Engine.
"""

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from utils.logger import logger


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

APP_NAME = "ScamShield AI"
APP_VERSION = "1.0.0"

DEFAULT_CORS_ORIGINS = [
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:5000",
    "http://localhost:5173",
    "http://localhost:5500",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:3001",
    "http://127.0.0.1:5000",
    "http://127.0.0.1:5173",
    "http://127.0.0.1:5500",
]


def get_cors_origins():
    """
    Read allowed frontend origins from environment.

    Example:
    CORS_ORIGINS=http://localhost:5173,https://example.com
    """

    configured_origins = os.getenv("CORS_ORIGINS", "").strip()

    if not configured_origins:
        return DEFAULT_CORS_ORIGINS

    return [
        origin.strip().rstrip("/")
        for origin in configured_origins.split(",")
        if origin.strip()
    ]


# =========================================================
# APPLICATION LIFESPAN
# =========================================================


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "ScamShield AI Engine starting..."
    )

    app.state.startup_time = datetime.now(
        timezone.utc
    )

    try:
        yield

    finally:
        logger.info(
            "ScamShield AI Engine shutting down..."
        )


# =========================================================
# FASTAPI APPLICATION
# =========================================================


app = FastAPI(
    title=APP_NAME + " Engine",
    description=(
        "Hybrid AI-powered scam detection, "
        "evidence extraction, specialized agent "
        "orchestration and victim safety analysis service."
    ),
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)


# =========================================================
# CORS CONFIGURATION
# =========================================================


app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
)


# =========================================================
# REGISTER API ROUTES
# =========================================================


app.include_router(
    router,
    prefix="/api/ai",
    tags=["ScamShield AI"],
)


# =========================================================
# ROOT ENDPOINT
# =========================================================


@app.get("/", tags=["System"])
async def root():
    return {
        "success": True,
        "application": APP_NAME,
        "service": "Hybrid AI Engine",
        "status": "running",
        "version": APP_VERSION,
        "documentation": "/docs",
        "health": "/api/ai/health",
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }


# =========================================================
# APPLICATION HEALTH
# =========================================================


@app.get("/health", tags=["System"])
async def application_health():
    return {
        "success": True,
        "application": APP_NAME,
        "service": "ScamShield AI Engine",
        "status": "healthy",
        "version": APP_VERSION,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }
