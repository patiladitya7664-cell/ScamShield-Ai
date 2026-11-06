"""
=========================================================
SCAMSHIELD AI - API ROUTES
=========================================================

Version: 1.1.0

Main AI analysis and controlled decoy simulation endpoints.

Endpoints:
- GET  /health
- POST /analyze
- POST /decoy/start
- POST /decoy/continue
- POST /decoy/end

=========================================================
"""

from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from services.ai_pipeline import ai_pipeline
from utils.logger import logger


router = APIRouter()

API_VERSION = "1.1.0"

EvidenceType = Literal[
    "message",
    "url",
    "call",
    "transaction",
    "screenshot",
    "email",
]


# =========================================================
# REQUEST MODELS
# =========================================================


class AnalysisRequest(BaseModel):

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    evidence: str = Field(
        ...,
        min_length=1,
        max_length=20000,
    )

    evidence_type: EvidenceType = "message"

    metadata: Optional[Dict[str, Any]] = None


class DecoyStartRequest(BaseModel):

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    scam_message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )


class DecoyContinueRequest(BaseModel):

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    session_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )

    scam_message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
    )


class DecoyEndRequest(BaseModel):

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid",
    )

    session_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )


# =========================================================
# RESPONSE VALIDATION
# =========================================================


def validate_service_response(
    result: Any,
) -> Dict[str, Any]:
    """
    Validate internal service response.
    """

    if not isinstance(result, dict):

        raise RuntimeError(
            "Invalid internal service response."
        )

    return result


def raise_service_error(
    result: Dict[str, Any],
    status_code: int = 422,
):
    """
    Convert unsuccessful service responses
    into safe HTTP errors.
    """

    if not result.get("success", False):

        metadata = result.get("metadata")

        if not isinstance(metadata, dict):
            metadata = {}

        errors = result.get("errors")

        if not isinstance(errors, list):
            errors = []

        raise HTTPException(
            status_code=status_code,

            detail={
                "success": False,

                "message": result.get(
                    "message",
                    "The requested operation could not be completed.",
                ),

                "status": result.get(
                    "status",
                    "failed",
                ),

                "request_id": result.get(
                    "request_id"
                ),

                "errors": errors,

                "metadata": {
                    "request_id": metadata.get(
                        "request_id"
                    ),

                    "duration_seconds": metadata.get(
                        "duration_seconds"
                    ),
                },
            },
        )


# =========================================================
# HEALTH CHECK
# =========================================================


@router.get("/health")
def health_check():

    return {
        "success": True,

        "service": "ScamShield AI Engine",

        "status": "online",

        "version": API_VERSION,

        "pipeline_version": ai_pipeline.VERSION,

        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),
    }


# =========================================================
# MAIN AI ANALYSIS
# =========================================================


@router.post("/analyze")
def analyze_evidence(
    request: AnalysisRequest,
):

    try:

        logger.info(
            "AI analysis API request received | type=%s",
            request.evidence_type,
        )

        result = ai_pipeline.analyze(
            evidence=request.evidence,

            evidence_type=request.evidence_type,

            metadata=request.metadata,
        )

        result = validate_service_response(
            result
        )

        raise_service_error(
            result,
            status_code=422,
        )

        return result

    except HTTPException:
        raise

    except Exception:

        logger.exception(
            "Evidence analysis API failed."
        )

        raise HTTPException(
            status_code=500,

            detail={
                "success": False,

                "message": (
                    "AI analysis service encountered an error."
                ),
            },
        )


# =========================================================
# DECOY SIMULATION - START
# =========================================================


@router.post("/decoy/start")
def start_decoy_simulation(
    request: DecoyStartRequest,
):

    try:

        logger.info(
            "Decoy simulation start requested."
        )

        result = (
            ai_pipeline.orchestrator.start_decoy_simulation(
                request.scam_message
            )
        )

        result = validate_service_response(
            result
        )

        raise_service_error(
            result,
            status_code=422,
        )

        return result

    except HTTPException:
        raise

    except Exception:

        logger.exception(
            "Decoy simulation start failed."
        )

        raise HTTPException(
            status_code=500,

            detail={
                "success": False,

                "message": (
                    "Could not start decoy simulation."
                ),
            },
        )


# =========================================================
# DECOY SIMULATION - CONTINUE
# =========================================================


@router.post("/decoy/continue")
def continue_decoy_simulation(
    request: DecoyContinueRequest,
):

    try:

        logger.info(
            "Decoy simulation continuation requested."
        )

        result = (
            ai_pipeline.orchestrator.continue_decoy_simulation(
                session_id=request.session_id,

                scam_message=request.scam_message,
            )
        )

        result = validate_service_response(
            result
        )

        raise_service_error(
            result,
            status_code=422,
        )

        return result

    except HTTPException:
        raise

    except Exception:

        logger.exception(
            "Decoy simulation continuation failed."
        )

        raise HTTPException(
            status_code=500,

            detail={
                "success": False,

                "message": (
                    "Could not continue decoy simulation."
                ),
            },
        )


# =========================================================
# DECOY SIMULATION - END
# =========================================================


@router.post("/decoy/end")
def end_decoy_simulation(
    request: DecoyEndRequest,
):

    try:

        logger.info(
            "Decoy simulation termination requested."
        )

        result = (
            ai_pipeline.orchestrator.end_decoy_simulation(
                session_id=request.session_id
            )
        )

        result = validate_service_response(
            result
        )

        raise_service_error(
            result,
            status_code=404,
        )

        return result

    except HTTPException:
        raise

    except Exception:

        logger.exception(
            "Decoy simulation termination failed."
        )

        raise HTTPException(
            status_code=500,

            detail={
                "success": False,

                "message": (
                    "Could not end decoy simulation."
                ),
            },
        )