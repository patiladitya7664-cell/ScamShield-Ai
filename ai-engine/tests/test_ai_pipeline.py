"""
=========================================================
SCAMSHIELD AI - CENTRAL AI PIPELINE REGRESSION TEST SUITE
=========================================================

Version: 1.0.0
Target: AIPipeline v1.3.0

Coverage:
    1. Initialization and version.
    2. Input validation.
    3. All six evidence types.
    4. Guardian authoritative result.
    5. Gemini advisory-only enforcement.
    6. Gemini unavailable and exception handling.
    7. Orchestration failure handling.
    8. Guardian failure handling.
    9. Partial agent failures.
    10. Agent results and orchestration metadata.
    11. Machine learning response.
    12. Metadata filtering.
    13. Request ID uniqueness.
    14. Response schema.
    15. Internal exception handling.
    16. Safe helper functions.

All external services are mocked.
No live Gemini API or database required.
=========================================================
"""

import math
import re

import pytest

from unittest.mock import Mock

from services.ai_pipeline import AIPipeline


# =========================================================
# TEST FIXTURES
# =========================================================

VALID_EVIDENCE = (
    "URGENT: Your bank account will be blocked today. "
    "Share your OTP immediately."
)


VALID_ANALYSIS = {

    "evidence_type": "message",

    "fraud_category": "fraud_message",

    "detected_categories": [
        "fraud_message",
    ],

    "risk_score": 45,

    "risk_level": "MEDIUM",

    "summary": "Moderate risk detected.",

    "signals": [
        "threat_or_intimidation",
        "otp_or_credential_request",
    ],

    "detected_rules": [],

    "indicators": {},

    "explanations": [
        "Threat language detected.",
    ],

    "recommendations": [
        "Do not share OTPs.",
    ],

    "scoring": {},

    "machine_learning": {

        "available": False,

        "prediction": None,

        "confidence": None,

        "method": "not_available",

    },

    "analysis_method": "rule_based",

}


def create_orchestration_result(

    success=True,

    guardian_success=True,

    guardian_analysis=None,

    errors=None,

    metadata=None,

):

    guardian_analysis = (
        guardian_analysis
        if guardian_analysis is not None
        else VALID_ANALYSIS.copy()
    )

    return {

        "success": success,

        "analysis_id": "test-analysis-123",

        "orchestrator": {

            "name": "AgentOrchestrator",

            "version": "1.1.0",

            "status": (
                "completed"
                if success
                else "failed"
            ),

        },

        "results": {

            "guardian": {

                "success": guardian_success,

                "analysis": guardian_analysis,

            },

            "intelligence": {

                "success": True,

                "agent": {
                    "name": "IntelligenceAgent",
                },

            },

            "victim_safety": {

                "success": True,

                "agent": {
                    "name": "VictimSafetyAgent",
                },

            },

            "decoy": {

                "status": "not_started",

            },

        },

        "errors": (
            errors
            if errors is not None
            else []
        ),

        "metadata": {

            "agents_executed": [
                "guardian",
                "intelligence",
                "victim_safety",
            ],

            "agents_successful": [
                "guardian",
                "intelligence",
                "victim_safety",
            ],

            "agents_failed": [],

            "agents_skipped": [],

            **(
                metadata
                if metadata is not None
                else {}
            ),

        },

        "verification": {

            "status": "UNVERIFIED",

            "external_verification": False,

        },

    }


class FakeOrchestrator:

    def __init__(self, result=None, exception=None):

        self.result = (
            result
            if result is not None
            else create_orchestration_result()
        )

        self.exception = exception

        self.calls = []

    def analyze(self, evidence, evidence_type):

        self.calls.append({

            "evidence": evidence,

            "evidence_type": evidence_type,

        })

        if self.exception:

            raise self.exception

        return self.result


class FakeGemini:

    def __init__(self, result=None, exception=None):

        self.result = (

            result

            if result is not None

            else {

                "available": True,

                "status": "success",

                "version": "2.1.0",

                "model": "gemini-test-model",

                "advisory_only": False,

                "scam_intent": "Credential harvesting.",

                "advisory_confidence": "high",

            }

        )

        self.exception = exception

        self.calls = []

    def analyze(

        self,

        evidence,

        evidence_type,

        deterministic_result,

    ):

        self.calls.append({

            "evidence": evidence,

            "evidence_type": evidence_type,

            "deterministic_result": deterministic_result,

        })

        if self.exception:

            raise self.exception

        return self.result


@pytest.fixture
def orchestrator():

    return FakeOrchestrator()


@pytest.fixture
def gemini():

    return FakeGemini()


@pytest.fixture
def pipeline(orchestrator, gemini):

    return AIPipeline(

        orchestrator=orchestrator,

        gemini=gemini,

    )


# =========================================================
# 1. INITIALIZATION
# =========================================================

def test_pipeline_initialization(pipeline):

    assert pipeline is not None

    assert pipeline.VERSION == "1.3.0"


def test_pipeline_supported_evidence_types(pipeline):

    assert pipeline.SUPPORTED_EVIDENCE_TYPES == {

        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",

    }


def test_pipeline_maximum_evidence_length(pipeline):

    assert pipeline.MAX_EVIDENCE_LENGTH == 20000


# =========================================================
# 2. INPUT VALIDATION
# =========================================================

@pytest.mark.parametrize(

    "evidence",

    [

        None,

        123,

        12.5,

        [],

        {},

        True,

    ],

)

def test_validate_rejects_non_string_evidence(

    pipeline,

    evidence,

):

    result = pipeline.analyze(

        evidence=evidence,

    )

    assert result["success"] is False

    assert "Evidence must be a string." in result["message"]


@pytest.mark.parametrize(

    "evidence",

    [

        "",

        "   ",

        "\n\t",

    ],

)

def test_validate_rejects_empty_evidence(

    pipeline,

    evidence,

):

    result = pipeline.analyze(

        evidence=evidence,

    )

    assert result["success"] is False

    assert "Evidence cannot be empty." in result["message"]


def test_validate_rejects_oversized_evidence(pipeline):

    result = pipeline.analyze(

        evidence="A" * 20001,

    )

    assert result["success"] is False

    assert "maximum allowed length" in result["message"]


def test_validate_accepts_maximum_evidence_length(pipeline):

    evidence = "A" * 200