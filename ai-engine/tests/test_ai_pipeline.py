
"""
=========================================================
SCAMSHIELD AI - CENTRAL AI PIPELINE REGRESSION TEST SUITE
=========================================================

Version: 1.1.0
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
    17. Gemini strict response validation.
    18. Gemini malicious response protection.

All external services are mocked.
No live Gemini API or database required.
=========================================================
"""
import sys
from pathlib import Path

# Add AI Engine root directory to Python path
AI_ENGINE_ROOT = Path(__file__).resolve().parents[1]

if str(AI_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_ROOT))

from services.ai_pipeline import AIPipeline

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


VALID_GEMINI_RESPONSE = {

    "available": True,

    "status": "success",

    "version": "2.1.0",

    "model": "gemini-test-model",

    "advisory_only": False,

    "scam_intent": "Credential harvesting.",

    "social_engineering_tactics": [
        "Urgency",
        "Threatening language",
    ],

    "contextual_indicators": [
        "OTP request",
        "Account blocking threat",
    ],

    "explanation": (
        "The message uses urgency and threats "
        "to encourage credential disclosure."
    ),

    "supporting_evidence": [
        "Share your OTP immediately.",
    ],

    "alternative_interpretations": [
        "Could be an educational example.",
    ],

    "advisory_confidence": "high",

    "safety_notes": [
        "Never share OTPs.",
    ],

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

    def __init__(
        self,
        result=None,
        exception=None,
    ):

        self.result = (
            result
            if result is not None
            else create_orchestration_result()
        )

        self.exception = exception

        self.calls = []

    def analyze(
        self,
        evidence,
        evidence_type,
    ):

        self.calls.append({

            "evidence": evidence,

            "evidence_type": evidence_type,

        })

        if self.exception:

            raise self.exception

        return self.result


class FakeGemini:

    def __init__(
        self,
        result=None,
        exception=None,
    ):

        self.result = (
            result
            if result is not None
            else VALID_GEMINI_RESPONSE.copy()
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
def pipeline(
    orchestrator,
    gemini,
):

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


def test_pipeline_metadata_depth(pipeline):

    assert pipeline.MAX_METADATA_DEPTH == 10


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

    assert result["message"] == (
        "Evidence must be a string."
    )


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

    assert result["message"] == (
        "Evidence cannot be empty."
    )


def test_validate_rejects_oversized_evidence(pipeline):

    result = pipeline.analyze(

        evidence="A" * 20001,

    )

    assert result["success"] is False

    assert "maximum allowed length" in result["message"]


def test_validate_accepts_maximum_evidence_length(pipeline):

    evidence = "A" * 20000

    normalized_evidence, evidence_type = (
        pipeline._validate_input(
            evidence,
            "message",
        )
    )

    assert len(normalized_evidence) == 20000

    assert evidence_type == "message"


@pytest.mark.parametrize(

    "evidence_type",

    [

        None,
        123,
        [],
        {},
        True,

    ],

)

def test_validate_rejects_non_string_evidence_type(

    pipeline,
    evidence_type,

):

    result = pipeline.analyze(

        evidence=VALID_EVIDENCE,

        evidence_type=evidence_type,

    )

    assert result["success"] is False

    assert result["message"] == (
        "Evidence type must be a string."
    )


def test_validate_rejects_unsupported_evidence_type(pipeline):

    result = pipeline.analyze(

        evidence=VALID_EVIDENCE,

        evidence_type="unknown",

    )

    assert result["success"] is False

    assert result["message"] == (
        "Unsupported evidence type."
    )


def test_validate_normalizes_evidence_type(pipeline):

    evidence, evidence_type = pipeline._validate_input(

        VALID_EVIDENCE,

        " MESSAGE ",

    )

    assert evidence == VALID_EVIDENCE

    assert evidence_type == "message"


# =========================================================
# 3. ALL SIX EVIDENCE TYPES
# =========================================================

@pytest.mark.parametrize(

    "evidence_type",

    [

        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",

    ],

)

def test_pipeline_supports_all_evidence_types(

    orchestrator,
    gemini,
    evidence_type,

):

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=gemini,

    )

    result = pipeline.analyze(

        evidence=VALID_EVIDENCE,

        evidence_type=evidence_type,

    )

    assert result["success"] is True

    assert result["metadata"]["evidence_type"] == evidence_type

    assert orchestrator.calls[-1]["evidence_type"] == evidence_type

    assert gemini.calls[-1]["evidence_type"] == evidence_type


# =========================================================
# 4. GUARDIAN AUTHORITATIVE RESULT
# =========================================================

def test_guardian_result_is_authoritative(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["category"] == (
        "fraud_message"
    )

    assert result["result"]["risk_score"] == 45

    assert result["result"]["risk_level"] == "MEDIUM"


def test_guardian_result_passed_to_gemini(

    pipeline,
    gemini,

):

    pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    deterministic = gemini.calls[-1][
        "deterministic_result"
    ]

    assert deterministic["fraud_category"] == "fraud_message"

    assert deterministic["risk_score"] == 45

    assert deterministic["risk_level"] == "MEDIUM"


def test_gemini_cannot_modify_guardian_category(

    orchestrator,
):

    malicious_gemini = VALID_GEMINI_RESPONSE.copy()

    malicious_gemini.update({

        "fraud_category": "safe",

        "category": "safe",

    })

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(
            result=malicious_gemini,
        ),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["category"] == (
        "fraud_message"
    )

    assert "fraud_category" not in result["gemini_advisory"]

    assert "category" not in result["gemini_advisory"]


def test_gemini_cannot_modify_guardian_risk_score(

    orchestrator,

):

    malicious_gemini = VALID_GEMINI_RESPONSE.copy()

    malicious_gemini["risk_score"] = 0

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(
            result=malicious_gemini,
        ),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["risk_score"] == 45

    assert "risk_score" not in result["gemini_advisory"]


def test_gemini_cannot_modify_guardian_risk_level(

    orchestrator,

):

    malicious_gemini = VALID_GEMINI_RESPONSE.copy()

    malicious_gemini["risk_level"] = "LOW"

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(
            result=malicious_gemini,
        ),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["risk_level"] == "MEDIUM"

    assert "risk_level" not in result["gemini_advisory"]


# =========================================================
# 5. GEMINI ADVISORY-ONLY ENFORCEMENT
# =========================================================

def test_gemini_success_response(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    advisory = result["gemini_advisory"]

    assert advisory["available"] is True

    assert advisory["status"] == "success"

    assert advisory["advisory_only"] is True


def test_gemini_advisory_fields_are_preserved(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    advisory = result["gemini_advisory"]

    assert advisory["scam_intent"] == (
        "Credential harvesting."
    )

    assert advisory["advisory_confidence"] == "high"

    assert "Urgency" in (
        advisory["social_engineering_tactics"]
    )


def test_gemini_advisory_only_is_forced_true(

    orchestrator,

):

    malicious_response = VALID_GEMINI_RESPONSE.copy()

    malicious_response["advisory_only"] = False

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(
            result=malicious_response,
        ),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["gemini_advisory"]["advisory_only"] is True


def test_gemini_unknown_fields_are_discarded(

    orchestrator,

):

    response = VALID_GEMINI_RESPONSE.copy()

    response["unknown_field"] = "unexpected"

    response["internal_debug"] = {
        "secret": "should_not_appear",
    }

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(
            result=response,
        ),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    advisory = result["gemini_advisory"]

    assert "unknown_field" not in advisory

    assert "internal_debug" not in advisory


def test_gemini_authoritative_fields_are_discarded(

    orchestrator,

):

    response = VALID_GEMINI_RESPONSE.copy()

    response.update({

        "risk_score": 0,

        "risk_level": "LOW",

        "fraud_category": "safe",

        "category": "safe",

        "detected_categories": [],

        "prediction": "safe",

    })

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(
            result=response,
        ),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    advisory = result["gemini_advisory"]

    forbidden_fields = {

        "risk_score",
        "risk_level",
        "fraud_category",
        "category",
        "detected_categories",
        "prediction",

    }

    assert forbidden_fields.isdisjoint(
        advisory.keys()
    )


# =========================================================
# 6. GEMINI STRICT RESPONSE VALIDATION
# =========================================================

def test_gemini_rejects_non_dictionary_response(pipeline):

    assert pipeline._normalize_gemini_advisory(
        "invalid"
    ) is None


@pytest.mark.parametrize(

    "available",

    [

        None,
        "true",
        1,
        0,

    ],

)

def test_gemini_rejects_invalid_available_value(

    pipeline,
    available,

):

    response = VALID_GEMINI_RESPONSE.copy()

    response["available"] = available

    assert pipeline._normalize_gemini_advisory(
        response
    ) is None


@pytest.mark.parametrize(

    "status",

    [

        None,
        "failed",
        "unknown",
        "SUCCESS",

    ],

)

def test_gemini_rejects_invalid_status(

    pipeline,
    status,

):

    response = VALID_GEMINI_RESPONSE.copy()

    response["status"] = status

    assert pipeline._normalize_gemini_advisory(
        response
    ) is None


def test_gemini_rejects_status_availability_mismatch(pipeline):

    response = VALID_GEMINI_RESPONSE.copy()

    response["available"] = False

    response["status"] = "success"

    assert pipeline._normalize_gemini_advisory(
        response
    ) is None


def test_gemini_rejects_missing_required_fields(pipeline):

    required_fields = [

        "scam_intent",
        "social_engineering_tactics",
        "contextual_indicators",
        "explanation",
        "supporting_evidence",
        "alternative_interpretations",
        "advisory_confidence",
        "safety_notes",

    ]

    for field in required_fields:

        response = VALID_GEMINI_RESPONSE.copy()

        response.pop(field)

        assert pipeline._normalize_gemini_advisory(
            response
        ) is None


@pytest.mark.parametrize(

    "field",

    [

        "scam_intent",
        "explanation",

    ],

)

def test_gemini_rejects_invalid_string_fields(

    pipeline,
    field,

):

    response = VALID_GEMINI_RESPONSE.copy()

    response[field] = ["invalid"]

    assert pipeline._normalize_gemini_advisory(
        response
    ) is None


@pytest.mark.parametrize(

    "field",

    [

        "social_engineering_tactics",
        "contextual_indicators",
        "supporting_evidence",
        "alternative_interpretations",
        "safety_notes",

    ],

)

def test_gemini_rejects_invalid_list_fields(

    pipeline,
    field,

):

    response = VALID_GEMINI_RESPONSE.copy()

    response[field] = "not-a-list"

    assert pipeline._normalize_gemini_advisory(
        response
    ) is None


@pytest.mark.parametrize(

    "field",

    [

        "social_engineering_tactics",
        "contextual_indicators",
        "supporting_evidence",
        "alternative_interpretations",
        "safety_notes",

    ],

)

def test_gemini_rejects_non_string_list_items(

    pipeline,
    field,

):

    response = VALID_GEMINI_RESPONSE.copy()

    response[field] = [
        "valid",
        123,
    ]

    assert pipeline._normalize_gemini_advisory(
        response
    ) is None


@pytest.mark.parametrize(

    "confidence",

    [

        None,
        123,
        "unknown",
        "very_high",
        "invalid",

    ],

)

def test_gemini_rejects_invalid_confidence(

    pipeline,
    confidence,

):

    response = VALID_GEMINI_RESPONSE.copy()

    response["advisory_confidence"] = confidence

    assert pipeline._normalize_gemini_advisory(
        response
    ) is None


def test_gemini_normalizes_confidence_case(pipeline):

    response = VALID_GEMINI_RESPONSE.copy()

    response["advisory_confidence"] = "HIGH"

    normalized = pipeline._normalize_gemini_advisory(
        response
    )

    assert normalized is not None

    assert normalized["advisory_confidence"] == "high"


def test_gemini_truncates_string_fields(pipeline):

    response = VALID_GEMINI_RESPONSE.copy()

    response["scam_intent"] = "A" * 2000

    response["explanation"] = "B" * 3000

    normalized = pipeline._normalize_gemini_advisory(
        response
    )

    assert len(normalized["scam_intent"]) == 1000

    assert len(normalized["explanation"]) == 2000


def test_gemini_truncates_list_item_count(pipeline):

    response = VALID_GEMINI_RESPONSE.copy()

    response["social_engineering_tactics"] = [
        f"item-{index}"
        for index in range(20)
    ]

    normalized = pipeline._normalize_gemini_advisory(
        response
    )

    assert len(
        normalized["social_engineering_tactics"]
    ) == 10


def test_gemini_truncates_list_item_length(pipeline):

    response = VALID_GEMINI_RESPONSE.copy()

    response["safety_notes"] = [
        "A" * 1000,
    ]

    normalized = pipeline._normalize_gemini_advisory(
        response
    )

    assert len(
        normalized["safety_notes"][0]
    ) == 500


def test_gemini_removes_empty_list_items(pipeline):

    response = VALID_GEMINI_RESPONSE.copy()

    response["safety_notes"] = [

        "Valid note",

        "",

        "   ",

    ]

    normalized = pipeline._normalize_gemini_advisory(
        response
    )

    assert normalized["safety_notes"] == [
        "Valid note",
    ]


def test_gemini_unavailable_response_normalization(pipeline):

    response = {

        "available": False,

        "status": "unavailable",

        "version": "2.1.0",

        "model": "gemini-test-model",

        "reason": "API unavailable.",

    }

    normalized = pipeline._normalize_gemini_advisory(
        response
    )

    assert normalized["available"] is False

    assert normalized["status"] == "unavailable"

    assert normalized["advisory_only"] is True

    assert normalized["reason"] == "API unavailable."


def test_gemini_unavailable_response_ignores_advisory_data(pipeline):

    response = {

        "available": False,

        "status": "unavailable",

        "reason": "Service unavailable.",

        "scam_intent": "Must not be accepted.",

        "risk_score": 0,

    }

    normalized = pipeline._normalize_gemini_advisory(
        response
    )

    assert normalized["scam_intent"] == ""

    assert "risk_score" not in normalized


# =========================================================
# 7. GEMINI UNAVAILABLE AND EXCEPTION HANDLING
# =========================================================

def test_gemini_exception_does_not_interrupt_analysis(

    orchestrator,

):

    gemini = FakeGemini(
        exception=RuntimeError("Gemini unavailable."),
    )

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=gemini,

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["risk_score"] == 45

    assert result["gemini_advisory"]["available"] is False


def test_gemini_invalid_response_does_not_interrupt_analysis(

    orchestrator,

):

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(
            result="invalid-response",
        ),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["category"] == "fraud_message"

    assert result["gemini_advisory"]["available"] is False


def test_gemini_missing_fields_do_not_interrupt_analysis(

    orchestrator,

):

    invalid_response = {

        "available": True,

        "status": "success",

        "version": "2.1.0",

        "model": "test",

        "scam_intent": "Fraud",

    }

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(
            result=invalid_response,
        ),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["risk_score"] == 45

    assert result["gemini_advisory"]["available"] is False


def test_gemini_unavailable_metadata(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["metadata"]["gemini_advisory_enabled"] is True

    assert result["metadata"]["gemini_advisory_available"] is True

    assert result["metadata"]["gemini_status"] == "success"


def test_gemini_unconfigured_service(orchestrator):

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=None,

    )

    pipeline.gemini = None

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["gemini_advisory"]["available"] is False

    assert result["metadata"]["gemini_advisory_enabled"] is False


# =========================================================
# 8. ORCHESTRATION FAILURE HANDLING
# =========================================================

def test_orchestrator_exception_returns_safe_error():

    orchestrator = FakeOrchestrator(

        exception=RuntimeError(
            "Internal orchestrator error."
        ),

    )

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is False

    assert result["status"] == "failed"

    assert result["message"] == (
        "An internal AI pipeline error occurred."
    )


def test_orchestrator_invalid_response_returns_safe_error():

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(
            result="invalid",
        ),

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is False

    assert result["status"] == "failed"


def test_orchestration_failure_response():

    failed_result = create_orchestration_result(

        success=False,

        errors=[
            {
                "agent": "guardian",
                "message": "Execution failed.",
            },
        ],

    )

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(
            result=failed_result,
        ),

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is False

    assert result["status"] == "failed"

    assert result["errors"][0]["agent"] == "guardian"


def test_orchestration_failure_does_not_call_gemini(

    orchestrator,

):

    failed_result = create_orchestration_result(
        success=False,
    )

    orchestrator.result = failed_result

    gemini = FakeGemini()

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=gemini,

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is False

    assert gemini.calls == []


# =========================================================
# 9. GUARDIAN FAILURE HANDLING
# =========================================================

def test_guardian_failure_returns_safe_error():

    orchestration = create_orchestration_result(

        success=True,

        guardian_success=False,

    )

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(
            result=orchestration,
        ),

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is False

    assert result["message"] == (
        "Primary fraud analysis was unavailable."
    )


def test_guardian_empty_analysis_returns_safe_error():

    orchestration = create_orchestration_result(

        guardian_analysis={},

    )

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(
            result=orchestration,
        ),

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is False

    assert result["status"] == "failed"


def test_guardian_failure_does_not_call_gemini():

    orchestration = create_orchestration_result(

        guardian_success=False,

    )

    gemini = FakeGemini()

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(
            result=orchestration,
        ),

        gemini=gemini,

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is False

    assert gemini.calls == []


# =========================================================
# 10. PARTIAL AGENT FAILURES
# =========================================================

def test_partial_agent_failure_preserves_guardian_result():

    orchestration = create_orchestration_result(

        metadata={

            "agents_failed": [
                "intelligence",
            ],

        },

    )

    orchestration["results"]["intelligence"] = {

        "success": False,

        "error": "Intelligence unavailable.",

    }

    orchestration["errors"] = [

        {

            "agent": "intelligence",

            "message": "Intelligence execution failed.",

        },

    ]

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(
            result=orchestration,
        ),

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["risk_score"] == 45

    assert result["intelligence"]["success"] is False

    assert result["errors"][0]["agent"] == "intelligence"


def test_victim_safety_failure_preserves_guardian_result():

    orchestration = create_orchestration_result()

    orchestration["results"]["victim_safety"] = {

        "success": False,

        "error": "Victim safety unavailable.",

    }

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(
            result=orchestration,
        ),

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["result"]["category"] == "fraud_message"

    assert result["victim_safety"]["success"] is False


# =========================================================
# 11. AGENT RESULTS AND ORCHESTRATION METADATA
# =========================================================

def test_agent_results_are_preserved(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert "guardian" in result["agent_results"]

    assert "intelligence" in result["agent_results"]

    assert "victim_safety" in result["agent_results"]

    assert "decoy" in result["agent_results"]


def test_orchestration_metadata_is_preserved(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    orchestration = result["orchestration"]

    assert orchestration["name"] == "AgentOrchestrator"

    assert orchestration["version"] == "1.1.0"

    assert orchestration["status"] == "completed"


def test_agent_execution_summary(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    orchestration = result["orchestration"]

    assert "guardian" in orchestration["agents_executed"]

    assert "intelligence" in orchestration["agents_executed"]

    assert "victim_safety" in orchestration["agents_executed"]


def test_decoy_is_not_automatically_started(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["agent_results"]["decoy"]["status"] == (
        "not_started"
    )


# =========================================================
# 12. MACHINE LEARNING RESPONSE
# =========================================================

def test_machine_learning_response(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    ml = result["machine_learning"]

    assert ml["available"] is False

    assert ml["prediction"] is None

    assert ml["confidence"] is None

    assert ml["method"] == "not_available"

    assert ml["probability_calibrated"] is False


def test_machine_learning_available_result():

    analysis = VALID_ANALYSIS.copy()

    analysis["machine_learning"] = {

        "available": True,

        "prediction": "fraud",

        "confidence": 0.87,

        "method": "machine_learning",

    }

    orchestration = create_orchestration_result(
        guardian_analysis=analysis,
    )

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(
            result=orchestration,
        ),

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["machine_learning"]["available"] is True

    assert result["machine_learning"]["prediction"] == "fraud"

    assert result["machine_learning"]["confidence"] == 0.87

    assert result["machine_learning"]["probability_calibrated"] is False


# =========================================================
# 13. METADATA FILTERING
# =========================================================

def test_metadata_filter_removes_sensitive_fields(pipeline):

    metadata = {

        "source": "dashboard",

        "evidence": "private evidence",

        "message": "private message",

        "password": "secret",

        "otp": "123456",

        "token": "secret-token",

        "safe_value": "visible",

    }

    filtered = pipeline._filter_safe_metadata(
        metadata
    )

    assert filtered == {

        "source": "dashboard",

        "safe_value": "visible",

    }


def test_metadata_filter_removes_normalized_sensitive_keys(pipeline):

    metadata = {

        "phone_number": "9999999999",

        "account-number": "123456",

        "bank details": "private",

        "card_number": "1234",

        "upi_id": "user@bank",

        "safe": "allowed",

    }

    filtered = pipeline._filter_safe_metadata(
        metadata
    )

    assert filtered == {
        "safe": "allowed",
    }


def test_metadata_filter_preserves_safe_nested_values(pipeline):

    metadata = {

        "source": "dashboard",

        "details": {

            "platform": "web",

            "count": 5,

            "enabled": True,

        },

        "tags": [
            "analysis",
            "security",
        ],

    }

    filtered = pipeline._filter_safe_metadata(
        metadata
    )

    assert filtered == metadata


def test_metadata_filter_rejects_non_finite_floats(pipeline):

    metadata = {

        "nan": float("nan"),

        "positive_infinity": float("inf"),

        "negative_infinity": float("-inf"),

        "safe": 10.5,

    }

    filtered = pipeline._filter_safe_metadata(
        metadata
    )

    assert filtered == {
        "safe": 10.5,
    }


def test_metadata_filter_rejects_unsupported_objects(pipeline):

    metadata = {

        "mock": Mock(),

        "safe": "allowed",

    }

    filtered = pipeline._filter_safe_metadata(
        metadata
    )

    assert filtered == {
        "safe": "allowed",
    }


def test_metadata_filter_rejects_non_string_keys(pipeline):

    metadata = {

        123: "invalid",

        "safe": "allowed",

    }

    filtered = pipeline._filter_safe_metadata(
        metadata
    )

    assert filtered == {
        "safe": "allowed",
    }


def test_metadata_filter_rejects_excessive_depth(pipeline):

    metadata = {

        "level1": {

            "level2": {

                "level3": "safe",

            },

        },

    }

    filtered = pipeline._filter_safe_metadata(
        metadata
    )

    assert filtered["level1"]["level2"]["level3"] == "safe"


def test_metadata_filter_rejects_non_dictionary_input(pipeline):

    assert pipeline._filter_safe_metadata(
        "invalid"
    ) == {}


def test_metadata_is_attached_to_pipeline_response(pipeline):

    metadata = {

        "source": "web",

        "platform": "dashboard",

    }

    result = pipeline.analyze(

        evidence=VALID_EVIDENCE,

        metadata=metadata,

    )

    assert result["success"] is True

    assert result["metadata"]["context"] == metadata


def test_sensitive_metadata_is_not_attached(pipeline):

    metadata = {

        "source": "web",

        "otp": "123456",

        "password": "secret",

    }

    result = pipeline.analyze(

        evidence=VALID_EVIDENCE,

        metadata=metadata,

    )

    context = result["metadata"]["context"]

    assert "source" in context

    assert "otp" not in context

    assert "password" not in context


# =========================================================
# 14. REQUEST ID UNIQUENESS
# =========================================================

def test_request_ids_are_unique(pipeline):

    first = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    second = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert first["request_id"] != second["request_id"]


def test_request_id_is_valid_uuid(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    uuid_value = result["request_id"]

    assert re.fullmatch(
        r"[0-9a-fA-F-]{36}",
        uuid_value,
    )


# =========================================================
# 15. RESPONSE SCHEMA
# =========================================================

def test_success_response_schema(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    required_fields = {

        "success",
        "request_id",
        "service",
        "status",
        "result",
        "gemini_advisory",
        "intelligence",
        "victim_safety",
        "machine_learning",
        "agent_results",
        "errors",
        "metadata",
        "orchestration",
        "verification",
        "disclaimer",

    }

    assert required_fields.issubset(
        result.keys()
    )


def test_success_response_identity(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is True

    assert result["service"] == "ScamShield AI"


def test_verification_remains_unverified(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["verification"]["status"] == "UNVERIFIED"

    assert result["verification"]["external_verification"] is False


def test_disclaimer_mentions_guardian_and_gemini(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    disclaimer = result["disclaimer"]

    assert "Guardian" in disclaimer

    assert "Gemini" in disclaimer

    assert "probabilities" in disclaimer


def test_metadata_contains_pipeline_version(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["metadata"]["pipeline_version"] == "1.3.0"


def test_metadata_contains_duration(pipeline):

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert isinstance(
        result["metadata"]["duration_seconds"],
        float,
    )

    assert result["metadata"]["duration_seconds"] >= 0


def test_error_response_schema(pipeline):

    result = pipeline.analyze(
        evidence=None,
    )

    required_fields = {

        "success",
        "request_id",
        "service",
        "status",
        "message",
        "errors",
        "metadata",
        "verification",
        "disclaimer",

    }

    assert required_fields.issubset(
        result.keys()
    )

    assert result["success"] is False


# =========================================================
# 16. INTERNAL EXCEPTION HANDLING
# =========================================================

def test_internal_pipeline_exception_is_safe():

    orchestrator = FakeOrchestrator()

    orchestrator.analyze = Mock(
        side_effect=RuntimeError("Internal failure.")
    )

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert result["success"] is False

    assert result["status"] == "failed"

    assert result["message"] == (
        "An internal AI pipeline error occurred."
    )


def test_internal_error_does_not_expose_exception_details():

    orchestrator = FakeOrchestrator(

        exception=RuntimeError(
            "PRIVATE_INTERNAL_SECRET"
        ),

    )

    pipeline = AIPipeline(

        orchestrator=orchestrator,

        gemini=FakeGemini(),

    )

    result = pipeline.analyze(
        evidence=VALID_EVIDENCE,
    )

    assert "PRIVATE_INTERNAL_SECRET" not in str(result)


def test_error_response_contains_unverified_status(pipeline):

    result = pipeline.analyze(
        evidence=None,
    )

    assert result["verification"]["status"] == "UNVERIFIED"

    assert result["verification"]["external_verification"] is False


# =========================================================
# 17. SAFE HELPER FUNCTIONS
# =========================================================

def test_safe_dict_with_dictionary():

    value = {
        "key": "value",
    }

    assert AIPipeline._safe_dict(value) == value


@pytest.mark.parametrize(

    "value",

    [

        None,
        [],
        "invalid",
        123,

    ],

)

def test_safe_dict_with_invalid_values(value):

    assert AIPipeline._safe_dict(value) == {}


def test_safe_list_with_list():

    value = [
        1,
        2,
        3,
    ]

    assert AIPipeline._safe_list(value) == value


@pytest.mark.parametrize(

    "value",

    [

        None,
        {},
        "invalid",
        123,

    ],

)

def test_safe_list_with_invalid_values(value):

    assert AIPipeline._safe_list(value) == []


@pytest.mark.parametrize(

    "value, expected",

    [

        (45, 45.0),

        (150, 100),

        (-10, 0),

        (45.678, 45.68),

        ("75", 75.0),

        ("invalid", 0),

        (None, 0),

        (float("inf"), 0),

        (float("-inf"), 0),

        (float("nan"), 0),

    ],

)

def test_safe_score(value, expected):

    assert AIPipeline._safe_score(value) == expected


def test_normalize_errors_with_strings():

    result = AIPipeline._normalize_errors([

        "First error",

        "Second error",

    ])

    assert result == [

        {

            "agent": "unknown",

            "message": "First error",

        },

        {

            "agent": "unknown",

            "message": "Second error",

        },

    ]


def test_normalize_errors_with_dictionaries():

    result = AIPipeline._normalize_errors([

        {

            "agent": "guardian",

            "message": "Guardian failed.",

        },

    ])

    assert result[0]["agent"] == "guardian"

    assert result[0]["message"] == "Guardian failed."


def test_normalize_errors_rejects_invalid_input():

    assert AIPipeline._normalize_errors(
        "invalid"
    ) == []


def test_timestamp_returns_iso_format():

    timestamp = AIPipeline._timestamp()

    assert isinstance(timestamp, str)

    assert "T" in timestamp

    assert "+" in timestamp or timestamp.endswith("Z")


def test_safe_score_never_exceeds_range():

    values = [

        -100,

        0,

        25,

        50,

        100,

        150,

    ]

    for value in values:

        score = AIPipeline._safe_score(value)

        assert 0 <= score <= 100


# =========================================================
# 18. ORCHESTRATION AND METADATA HELPERS
# =========================================================

def test_get_orchestration_status():

    result = {

        "orchestrator": {

            "status": "completed",

        },

    }

    assert AIPipeline._get_orchestration_status(
        result
    ) == "completed"


def test_get_orchestration_status_fallback():

    result = {
        "status": "partial",
    }

    assert AIPipeline._get_orchestration_status(
        result
    ) == "partial"


def test_get_orchestration_status_invalid():

    result = {

        "orchestrator": {

            "status": 123,

        },

    }

    assert AIPipeline._get_orchestration_status(
        result
    ) == "unknown"


def test_build_agent_summary(pipeline):

    orchestration = create_orchestration_result()

    summary = pipeline._build_agent_summary(
        orchestration
    )

    assert "guardian" in summary["agents_executed"]

    assert "intelligence" in summary["agents_successful"]

    assert summary["agents_failed"] == []

    assert summary["agents_skipped"] == []


# =========================================================
# 19. PUBLIC FUNCTION AND GEMINI CONFIGURATION
# =========================================================

def test_gemini_configuration_detection(pipeline):

    assert pipeline._is_gemini_configured() is True


def test_gemini_configuration_detection_when_missing():

    pipeline = AIPipeline(

        orchestrator=FakeOrchestrator(),

        gemini=None,

    )

    pipeline.gemini = None

    assert pipeline._is_gemini_configured() is False


def test_run_gemini_advisory_returns_normalized_response(pipeline):

    deterministic = {

        "fraud_category": "fraud_message",

        "risk_score": 45,

        "risk_level": "MEDIUM",

        "summary": "Test",

        "signals": [],

        "detected_rules": [],

        "indicators": {},

    }

    result = pipeline._run_gemini_advisory(

        evidence=VALID_EVIDENCE,

        evidence_type="message",

        deterministic_result=deterministic,

    )

    assert result["available"] is True

    assert result["advisory_only"] is True


def test_run_gemini_advisory_handles_exception(pipeline):

    pipeline.gemini = FakeGemini(

        exception=RuntimeError("Gemini failed."),

    )

    result = pipeline._run_gemini_advisory(

        evidence=VALID_EVIDENCE,

        evidence_type="message",

        deterministic_result={},

    )

    assert result["available"] is False

    assert result["status"] == "unavailable"


# =========================================================
# END OF TEST SUITE
# =========================================================
