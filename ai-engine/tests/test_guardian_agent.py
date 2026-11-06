"""
=========================================================
SCAMSHIELD AI - GUARDIAN AGENT TEST SUITE
=========================================================

Version: 1.3.0

Test Coverage:
    1. Agent initialization and metadata.
    2. Supported evidence types.
    3. Input validation.
    4. Fraud detector integration.
    5. Risk score normalization.
    6. Risk level consistency.
    7. All 12 fraud categories.
    8. Multiple category validation.
    9. Signal and indicator preservation.
   10. Machine learning validation.
   11. Summary generation.
   12. Error handling.
   13. Privacy and verification guarantees.
   14. Public function compatibility.
   15. Response integrity.
   16. Malformed detector responses.
   17. Metadata validation.
   18. Repeated analysis consistency.

=========================================================
"""

import sys
import math

from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest

import agents.guardian_agent as guardian_module

from agents.guardian_agent import (
    GuardianAgent,
    guardian_agent,
    run_guardian_analysis,
)


# =========================================================
# CONSTANTS
# =========================================================

ALL_CATEGORIES = [
    "fraud_message",
    "fraud_call",
    "url_phishing",
    "email_scam",
    "investment_scam",
    "digital_arrest",
    "upi_banking_fraud",
    "card_fraud",
    "ecommerce_scam",
    "job_loan_scam",
    "sextortion_blackmail",
    "social_media_scam",
]


# =========================================================
# FAKE DETECTOR
# =========================================================

class FakeDetector:

    def __init__(self, response=None, exception=None):

        self.response = response if response is not None else {

            "success": True,

            "fraud_category": "fraud_message",

            "detected_categories": [
                "fraud_message"
            ],

            "risk_score": 75,

            "risk_level": "CRITICAL",

            "signals": [
                "otp_or_credential_request"
            ],

            "detected_rules": [
                "otp_request"
            ],

            "indicators": {

                "urls": [
                    "https://example.com"
                ],

                "phone_numbers": [],

                "emails": [],

                "upi_ids": [],

            },

            "explanations": [
                "OTP request detected."
            ],

            "recommendations": [
                "Do not share OTP."
            ],

            "scoring": {

                "base_score": 50,

                "final_score": 75,

            },

            "machine_learning": {

                "available": False,

                "prediction": None,

                "confidence": None,

                "method": "not_available",

            },

            "analysis_method": "rule_based",

        }

        self.exception = exception

        self.calls = []

    def analyze(self, evidence, evidence_type="message"):

        self.calls.append({

            "evidence": evidence,

            "evidence_type": evidence_type,

        })

        if self.exception:

            raise self.exception

        return self.response


# =========================================================
# FIXTURES
# =========================================================

@pytest.fixture
def detector():

    return FakeDetector()


@pytest.fixture
def agent(detector):

    return GuardianAgent(detector=detector)


@pytest.fixture
def sample_response():

    return {

        "success": True,

        "fraud_category": "fraud_message",

        "detected_categories": [
            "fraud_message"
        ],

        "risk_score": 75,

        "risk_level": "CRITICAL",

        "signals": [
            "otp_or_credential_request"
        ],

        "detected_rules": [
            "otp_request"
        ],

        "indicators": {

            "urls": [
                "https://example.com"
            ],

            "phone_numbers": [
                "9876543210"
            ],

            "emails": [],

            "upi_ids": [],

        },

        "explanations": [
            "OTP request detected."
        ],

        "recommendations": [
            "Do not share OTP."
        ],

        "scoring": {
            "final_score": 75
        },

        "machine_learning": {

            "available": True,

            "prediction": "suspicious",

            "confidence": 0.91,

            "method": "trained_model",

        },

        "analysis_method": "hybrid",

    }


# =========================================================
# INITIALIZATION TESTS
# =========================================================

def test_agent_initialization(agent):

    assert isinstance(agent, GuardianAgent)


def test_agent_name(agent):

    assert agent.AGENT_NAME == "GuardianAgent"


def test_agent_version(agent):

    assert agent.VERSION == "1.3.0"


def test_detector_initialization():

    agent = GuardianAgent()

    assert agent.detector is not None


def test_custom_detector_injection(detector):

    agent = GuardianAgent(detector=detector)

    assert agent.detector is detector


def test_global_guardian_instance():

    assert isinstance(guardian_agent, GuardianAgent)


def test_supported_evidence_types(agent):

    assert agent.SUPPORTED_EVIDENCE_TYPES == {

        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",

    }


# =========================================================
# EVIDENCE TYPE TESTS
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
def test_supported_evidence_type_analysis(
    agent,
    detector,
    evidence_type,
):

    result = agent.analyze(
        "Suspicious evidence",
        evidence_type=evidence_type,
    )

    assert result["success"] is True

    assert (
        result["analysis"]["evidence_type"]
        == evidence_type
    )

    assert (
        detector.calls[0]["evidence_type"]
        == evidence_type
    )


def test_screenshot_evidence_is_text_based(agent):

    result = agent.analyze(
        "Extracted screenshot text",
        evidence_type="screenshot",
    )

    assert result["success"] is True

    assert (
        result["analysis"]["evidence_type"]
        == "screenshot"
    )


def test_call_evidence_is_text_based(agent):

    result = agent.analyze(
        "Extracted call transcript",
        evidence_type="call",
    )

    assert result["success"] is True

    assert (
        result["analysis"]["evidence_type"]
        == "call"
    )


# =========================================================
# BASIC ANALYSIS TESTS
# =========================================================

def test_normal_analysis(agent):

    result = agent.analyze(
        "Your bank account is blocked. Share OTP."
    )

    assert result["success"] is True


def test_analysis_response_structure(agent):

    result = agent.analyze("Suspicious message")

    assert result["success"] is True

    assert "agent" in result
    assert "analysis_id" in result
    assert "analysis" in result
    assert "metadata" in result
    assert "verification" in result
    assert "disclaimer" in result


def test_agent_metadata(agent):

    result = agent.analyze("Suspicious message")

    assert result["agent"]["name"] == "GuardianAgent"

    assert result["agent"]["version"] == "1.3.0"

    assert result["agent"]["status"] == "completed"


def test_analysis_id_generated(agent):

    result = agent.analyze("Suspicious message")

    assert isinstance(result["analysis_id"], str)

    assert len(result["analysis_id"]) > 0


def test_unique_analysis_ids(agent):

    first = agent.analyze("First message")

    second = agent.analyze("Second message")

    assert first["analysis_id"] != second["analysis_id"]


def test_analysis_success_boolean(agent):

    result = agent.analyze("Test message")

    assert result["success"] is True

    assert isinstance(result["success"], bool)


def test_analysis_method_preserved(agent, sample_response):

    agent.detector.response = sample_response

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["analysis_method"]
        == "hybrid"
    )


# =========================================================
# INPUT VALIDATION TESTS
# =========================================================

@pytest.mark.parametrize(
    "evidence",
    [
        "",
        " ",
        "\n",
        "\t",
        "   \n   ",
    ],
)
def test_empty_evidence_rejected(agent, evidence):

    result = agent.analyze(evidence)

    assert result["success"] is False

    assert result["agent"]["status"] == "invalid_input"


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        123,
        45.5,
        True,
        False,
        [],
        {},
    ],
)
def test_non_string_evidence_rejected(agent, evidence):

    result = agent.analyze(evidence)

    assert result["success"] is False

    assert result["agent"]["status"] == "invalid_input"


def test_whitespace_evidence_trimmed(agent, detector):

    agent.analyze("   Suspicious message   ")

    assert (
        detector.calls[0]["evidence"]
        == "Suspicious message"
    )


def test_maximum_evidence_length(agent):

    evidence = "A" * GuardianAgent.MAX_EVIDENCE_LENGTH

    result = agent.analyze(evidence)

    assert result["success"] is True


def test_excessive_evidence_rejected(agent):

    evidence = "A" * (
        GuardianAgent.MAX_EVIDENCE_LENGTH + 1
    )

    result = agent.analyze(evidence)

    assert result["success"] is False

    assert result["agent"]["status"] == "invalid_input"


@pytest.mark.parametrize(
    "evidence_type",
    [
        "",
        "invalid",
        "unknown",
        "image",
        "video",
        "audio",
        "document",
    ],
)
def test_unsupported_evidence_type(agent, evidence_type):

    result = agent.analyze(
        "Suspicious evidence",
        evidence_type=evidence_type,
    )

    assert result["success"] is False

    assert result["agent"]["status"] == "invalid_input"


@pytest.mark.parametrize(
    "evidence_type",
    [
        None,
        123,
        True,
        False,
        [],
        {},
    ],
)
def test_non_string_evidence_type(agent, evidence_type):

    result = agent.analyze(
        "Suspicious evidence",
        evidence_type=evidence_type,
    )

    assert result["success"] is False

    assert result["agent"]["status"] == "invalid_input"


def test_evidence_type_normalization(agent):

    result = agent.analyze(
        "Suspicious message",
        evidence_type="  MESSAGE  ",
    )

    assert result["success"] is True

    assert result["analysis"]["evidence_type"] == "message"


# =========================================================
# DETECTOR INTEGRATION TESTS
# =========================================================

def test_detector_called_once(agent, detector):

    agent.analyze("Suspicious message")

    assert len(detector.calls) == 1


def test_detector_receives_evidence(agent, detector):

    agent.analyze("Bank OTP verification")

    assert (
        detector.calls[0]["evidence"]
        == "Bank OTP verification"
    )


def test_detector_receives_evidence_type(agent, detector):

    agent.analyze(
        "Suspicious URL",
        evidence_type="url",
    )

    assert detector.calls[0]["evidence_type"] == "url"


def test_detector_failure(agent):

    agent.detector.exception = RuntimeError(
        "Detector unavailable"
    )

    result = agent.analyze("Suspicious message")

    assert result["success"] is False

    assert result["agent"]["status"] == "failed"


def test_detector_invalid_response(agent):

    agent.detector.response = None

    result = agent.analyze("Suspicious message")

    assert result["success"] is False


@pytest.mark.parametrize(
    "response",
    [
        [],
        "invalid",
        123,
        True,
        False,
    ],
)
def test_detector_non_dictionary_response(agent, response):

    agent.detector.response = response

    result = agent.analyze("Suspicious message")

    assert result["success"] is False


def test_detector_reports_failure(agent):

    agent.detector.response = {

        "success": False,

        "error": "Detection failed",

    }

    result = agent.analyze("Suspicious message")

    assert result["success"] is False


def test_detector_missing_success_field(agent):

    agent.detector.response = {

        "fraud_category": "fraud_message",

        "risk_score": 75,

    }

    result = agent.analyze("Suspicious message")

    assert result["success"] is False


def test_detector_success_must_be_boolean_true(agent):

    agent.detector.response = {

        "success": 1,

        "risk_score": 75,

    }

    result = agent.analyze("Suspicious message")

    assert result["success"] is False


# =========================================================
# RISK SCORE TESTS
# =========================================================

@pytest.mark.parametrize(
    "score,expected",
    [
        (0, 0),
        (10, 10),
        (25, 25),
        (45.5, 46),
        (75, 75),
        (99.9, 100),
        (100, 100),
        (-10, 0),
        (-100, 0),
        (150, 100),
        ("85", 85),
        ("invalid", 0),
        (None, 0),
        (float("nan"), 0),
        (float("inf"), 0),
        (float("-inf"), 0),
        (True, 0),
        (False, 0),
    ],
)
def test_safe_score(score, expected):

    assert GuardianAgent._safe_score(score) == expected


def test_score_string_conversion():

    assert GuardianAgent._safe_score("75.5") == 76


def test_score_decimal_rounding():

    assert GuardianAgent._safe_score(45.5) == 46


# =========================================================
# RISK LEVEL CONSISTENCY TESTS
# =========================================================

@pytest.mark.parametrize(
    "score,expected",
    [
        (0, "LOW"),
        (24, "LOW"),
        (25, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_risk_level_from_score(score, expected):

    assert (
        GuardianAgent._risk_level_from_score(score)
        == expected
    )


@pytest.mark.parametrize(
    "score,expected",
    [
        (0, "LOW"),
        (24, "LOW"),
        (25, "MEDIUM"),
        (49, "MEDIUM"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_analysis_risk_consistency(
    agent,
    score,
    expected,
):

    agent.detector.response["risk_score"] = score

    # Deliberately provide a mismatching level.

    agent.detector.response["risk_level"] = "LOW"

    result = agent.analyze("Suspicious message")

    analysis = result["analysis"]

    assert analysis["risk_score"] == score

    assert analysis["risk_level"] == expected


def test_invalid_risk_score_fallback(agent):

    agent.detector.response["risk_score"] = "invalid"

    result = agent.analyze("Suspicious message")

    assert result["analysis"]["risk_score"] == 0

    assert result["analysis"]["risk_level"] == "LOW"


def test_detector_risk_level_does_not_override_score(agent):

    agent.detector.response["risk_score"] = 90

    agent.detector.response["risk_level"] = "LOW"

    result = agent.analyze("Suspicious message")

    assert result["analysis"]["risk_level"] == "CRITICAL"


# =========================================================
# CATEGORY TESTS
# =========================================================

def test_supported_category_count():

    assert len(GuardianAgent.SUPPORTED_CATEGORIES) == 12


@pytest.mark.parametrize(
    "category",
    ALL_CATEGORIES,
)
def test_all_twelve_categories_supported(
    agent,
    category,
):

    agent.detector.response.update({

        "fraud_category": category,

        "detected_categories": [category],

    })

    result = agent.analyze("Suspicious evidence")

    analysis = result["analysis"]

    assert analysis["fraud_category"] == category

    assert category in analysis["detected_categories"]


def test_invalid_primary_category_without_detected_categories(agent):

    agent.detector.response.update({

        "fraud_category": 123,

        "detected_categories": [],

    })

    result = agent.analyze("Suspicious evidence")

    assert result["analysis"]["fraud_category"] == "unknown"


def test_invalid_primary_category_uses_valid_detected_category(agent):

    agent.detector.response.update({

        "fraud_category": "invalid_category",

        "detected_categories": [
            "investment_scam"
        ],

    })

    result = agent.analyze("Investment evidence")

    assert (
        result["analysis"]["fraud_category"]
        == "investment_scam"
    )


def test_invalid_categories_are_removed(agent):

    agent.detector.response.update({

        "fraud_category": "fraud_message",

        "detected_categories": [

            "fraud_message",

            "invalid_category",

            123,

            None,

            "investment_scam",

        ],

    })

    result = agent.analyze("Suspicious evidence")

    assert result["analysis"]["detected_categories"] == [

        "fraud_message",

        "investment_scam",

    ]


def test_duplicate_categories_removed(agent):

    agent.detector.response.update({

        "fraud_category": "fraud_message",

        "detected_categories": [

            "fraud_message",

            "fraud_message",

            "investment_scam",

            "investment_scam",

        ],

    })

    result = agent.analyze("Suspicious evidence")

    categories = result["analysis"]["detected_categories"]

    assert categories == [

        "fraud_message",

        "investment_scam",

    ]


def test_primary_category_added_to_detected_categories(agent):

    agent.detector.response.update({

        "fraud_category": "digital_arrest",

        "detected_categories": [],

    })

    result = agent.analyze("Suspicious evidence")

    assert (
        result["analysis"]["detected_categories"]
        == ["digital_arrest"]
    )


def test_fraud_categories_fallback(agent):

    agent.detector.response = {

        "success": True,

        "fraud_categories": [
            "investment_scam"
        ],

    }

    result = agent.analyze("Investment offer")

    assert (
        result["analysis"]["detected_categories"]
        == ["investment_scam"]
    )

    assert (
        result["analysis"]["fraud_category"]
        == "investment_scam"
    )


def test_invalid_category_container(agent):

    agent.detector.response.update({

        "fraud_category": "invalid",

        "detected_categories": "invalid",

    })

    result = agent.analyze("Suspicious evidence")

    assert result["analysis"]["fraud_category"] == "unknown"

    assert result["analysis"]["detected_categories"] == []


# =========================================================
# SIGNAL AND RULE TESTS
# =========================================================

def test_signals_preserved(agent):

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["signals"]
        == ["otp_or_credential_request"]
    )


def test_detected_rules_preserved(agent):

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["detected_rules"]
        == ["otp_request"]
    )


def test_explanations_preserved(agent):

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["explanations"]
        == ["OTP request detected."]
    )


def test_recommendations_preserved(agent):

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["recommendations"]
        == ["Do not share OTP."]
    )


def test_invalid_list_fields_fallback(agent):

    agent.detector.response.update({

        "signals": "invalid",

        "detected_rules": {},

        "explanations": None,

        "recommendations": 123,

    })

    result = agent.analyze("Suspicious message")

    analysis = result["analysis"]

    assert analysis["signals"] == []

    assert analysis["detected_rules"] == []

    assert analysis["explanations"] == []

    assert analysis["recommendations"] == []


def test_non_string_list_entries_removed(agent):

    agent.detector.response["signals"] = [

        "otp_or_credential_request",

        123,

        None,

        "",

        "threat_or_intimidation",

    ]

    result = agent.analyze("Suspicious message")

    assert result["analysis"]["signals"] == [

        "otp_or_credential_request",

        "threat_or_intimidation",

    ]


# =========================================================
# INDICATOR AND SCORING TESTS
# =========================================================

def test_indicators_preserved(agent):

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["indicators"]["urls"]
        == ["https://example.com"]
    )


def test_scoring_preserved(agent):

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["scoring"]["final_score"]
        == 75
    )


def test_invalid_indicators_fallback(agent):

    agent.detector.response["indicators"] = "invalid"

    result = agent.analyze("Suspicious message")

    assert result["analysis"]["indicators"] == {}


def test_invalid_scoring_fallback(agent):

    agent.detector.response["scoring"] = []

    result = agent.analyze("Suspicious message")

    assert result["analysis"]["scoring"] == {}


# =========================================================
# MACHINE LEARNING TESTS
# =========================================================

def test_ml_available_false(agent):

    result = agent.analyze("Suspicious message")

    ml = result["analysis"]["machine_learning"]

    assert ml["available"] is False

    assert ml["prediction"] is None

    assert ml["confidence"] is None


def test_ml_result_preserved(agent, sample_response):

    agent.detector.response = sample_response

    result = agent.analyze("Suspicious message")

    ml = result["analysis"]["machine_learning"]

    assert ml["available"] is True

    assert ml["prediction"] == "suspicious"

    assert ml["confidence"] == 0.91

    assert ml["method"] == "trained_model"


@pytest.mark.parametrize(
    "confidence",
    [
        0,
        0.5,
        0.91,
        1,
        "0.85",
    ],
)
def test_valid_ml_confidence(agent, confidence):

    agent.detector.response["machine_learning"] = {

        "available": True,

        "prediction": "suspicious",

        "confidence": confidence,

        "method": "trained_model",

    }

    result = agent.analyze("Suspicious message")

    ml = result["analysis"]["machine_learning"]

    assert ml["available"] is True

    assert ml["confidence"] == float(confidence)


@pytest.mark.parametrize(
    "confidence",
    [
        -0.1,
        1.1,
        float("nan"),
        float("inf"),
        float("-inf"),
        "invalid",
        None,
        True,
        False,
    ],
)
def test_invalid_ml_confidence(agent, confidence):

    agent.detector.response["machine_learning"] = {

        "available": True,

        "prediction": "suspicious",

        "confidence": confidence,

        "method": "trained_model",

    }

    result = agent.analyze("Suspicious message")

    ml = result["analysis"]["machine_learning"]

    assert ml["available"] is True

    assert ml["confidence"] is None


def test_invalid_ml_prediction(agent):

    agent.detector.response["machine_learning"] = {

        "available": True,

        "prediction": 123,

        "confidence": 0.9,

        "method": "trained_model",

    }

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["machine_learning"]["prediction"]
        is None
    )


def test_empty_ml_prediction(agent):

    agent.detector.response["machine_learning"] = {

        "available": True,

        "prediction": "  ",

        "confidence": 0.9,

        "method": "trained_model",

    }

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["machine_learning"]["prediction"]
        is None
    )


def test_invalid_ml_method(agent):

    agent.detector.response["machine_learning"] = {

        "available": True,

        "prediction": "suspicious",

        "confidence": 0.9,

        "method": 123,

    }

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["machine_learning"]["method"]
        == "unknown"
    )


def test_ml_unavailable_fallback(agent):

    agent.detector.response["machine_learning"] = None

    result = agent.analyze("Suspicious message")

    ml = result["analysis"]["machine_learning"]

    assert ml["available"] is False

    assert ml["prediction"] is None

    assert ml["confidence"] is None

    assert ml["method"] == "not_available"


def test_invalid_ml_container_fallback(agent):

    agent.detector.response["machine_learning"] = "invalid"

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["machine_learning"]["available"]
        is False
    )


def test_ml_available_must_be_boolean_true(agent):

    agent.detector.response["machine_learning"] = {

        "available": 1,

        "prediction": "suspicious",

        "confidence": 0.9,

        "method": "trained_model",

    }

    result = agent.analyze("Suspicious message")

    assert (
        result["analysis"]["machine_learning"]["available"]
        is False
    )


# =========================================================
# ANALYSIS METHOD TESTS
# =========================================================

@pytest.mark.parametrize(
    "method,expected",
    [
        ("rule_based", "rule_based"),
        ("hybrid", "hybrid"),
        ("machine_learning", "machine_learning"),
        (" HYBRID ", "hybrid"),
        ("", "rule_based"),
        (None, "rule_based"),
        (123, "rule_based"),
    ],
)
def test_analysis_method_normalization(
    agent,
    method,
    expected,
):

    agent.detector.response["analysis_method"] = method

    result = agent.analyze("Suspicious message")

    assert result["analysis"]["analysis_method"] == expected


# =========================================================
# SUMMARY TESTS
# =========================================================

@pytest.mark.parametrize(
    "risk_level,score,expected",
    [
        ("CRITICAL", 95, "Critical risk detected"),
        ("HIGH", 75, "High risk detected"),
        ("MEDIUM", 45, "Moderate risk detected"),
        ("LOW", 10, "Low risk detected"),
    ],
)
def test_summary_generation(
    agent,
    risk_level,
    score,
    expected,
):

    summary = agent._generate_summary(
        risk_level,
        "fraud_message",
        score,
    )

    assert expected in summary


def test_summary_contains_score(agent):

    summary = agent._generate_summary(
        "HIGH",
        "fraud_message",
        85,
    )

    assert "85/100" in summary


def test_summary_formats_category(agent):

    summary = agent._generate_summary(
        "HIGH",
        "investment_scam",
        85,
    )

    assert "Investment Scam" in summary


def test_low_risk_summary_contains_safety_notice(agent):

    summary = agent._generate_summary(
        "LOW",
        "unknown",
        10,
    )

    assert "does not guarantee" in summary


def test_analysis_contains_summary(agent):

    result = agent.analyze("Suspicious message")

    assert isinstance(result["analysis"]["summary"], str)

    assert len(result["analysis"]["summary"]) > 0


# =========================================================
# METADATA TESTS
# =========================================================

def test_metadata_contains_duration(agent):

    result = agent.analyze("Suspicious message")

    assert isinstance(
        result["metadata"]["duration_ms"],
        (int, float),
    )


def test_duration_non_negative(agent):

    result = agent.analyze("Suspicious message")

    assert result["metadata"]["duration_ms"] >= 0


def test_metadata_contains_timestamp(agent):

    result = agent.analyze("Suspicious message")

    timestamp = result["metadata"]["timestamp"]

    assert isinstance(timestamp, str)

    parsed = datetime.fromisoformat(timestamp)

    assert parsed.tzinfo is not None


def test_metadata_contains_analysis_method(agent):

    result = agent.analyze("Suspicious message")

    assert (
        result["metadata"]["analysis_method"]
        == "rule_based"
    )


def test_metadata_contains_model_availability(agent):

    result = agent.analyze("Suspicious message")

    assert result["metadata"]["model_available"] is False


def test_metadata_contains_evidence_type(agent):

    result = agent.analyze(
        "Suspicious URL",
        evidence_type="url",
    )

    assert result["metadata"]["evidence_type"] == "url"


# =========================================================
# VERIFICATION AND PRIVACY TESTS
# =========================================================

def test_verification_status_unverified(agent):

    result = agent.analyze("Suspicious message")

    assert result["verification"]["status"] == "UNVERIFIED"


def test_external_verification_not_performed(agent):

    result = agent.analyze("Suspicious message")

    assert (
        result["verification"]["external_verification"]
        is False
    )


def test_disclaimer_present(agent):

    result = agent.analyze("Suspicious message")

    assert isinstance(result["disclaimer"], str)

    assert len(result["disclaimer"]) > 0


def test_disclaimer_not_definitive(agent):

    result = agent.analyze("Suspicious message")

    disclaimer = result["disclaimer"].lower()

    assert "not a" in disclaimer

    assert "official channels" in disclaimer


def test_error_does_not_expose_detector_exception(agent):

    agent.detector.exception = RuntimeError(
        "Sensitive internal information"
    )

    result = agent.analyze("Suspicious message")

    assert result["success"] is False

    assert (
        "Sensitive internal information"
        not in result["error"]
    )


def test_error_response_does_not_include_evidence(agent):

    sensitive_evidence = "My private account information"

    agent.detector.exception = RuntimeError("Failure")

    result = agent.analyze(sensitive_evidence)

    assert sensitive_evidence not in str(result)


# =========================================================
# ERROR RESPONSE TESTS
# =========================================================

def test_error_response_structure(agent):

    agent.detector.exception = RuntimeError("Internal error")

    result = agent.analyze("Suspicious message")

    assert result["success"] is False

    assert "agent" in result

    assert "analysis_id" in result

    assert "error" in result

    assert "metadata" in result

    assert "verification" in result


def test_error_response_agent_metadata(agent):

    agent.detector.exception = RuntimeError("Internal error")

    result = agent.analyze("Suspicious message")

    assert result["agent"]["name"] == "GuardianAgent"

    assert result["agent"]["version"] == "1.3.0"

    assert result["agent"]["status"] == "failed"


def test_error_response_safe_message(agent):

    agent.detector.exception = RuntimeError(
        "Sensitive internal exception"
    )

    result = agent.analyze("Suspicious message")

    assert (
        result["error"]
        == "Guardian Agent could not complete the analysis."
    )

    assert (
        "Sensitive internal exception"
        not in result["error"]
    )


def test_invalid_input_error_code(agent):

    result = agent.analyze("")

    assert result["agent"]["status"] == "invalid_input"


def test_error_response_remains_unverified(agent):

    agent.detector.exception = RuntimeError("Failure")

    result = agent.analyze("Suspicious message")

    assert result["verification"]["status"] == "UNVERIFIED"

    assert (
        result["verification"]["external_verification"]
        is False
    )


def test_error_duration_non_negative(agent):

    agent.detector.exception = RuntimeError("Failure")

    result = agent.analyze("Suspicious message")

    assert result["metadata"]["duration_ms"] >= 0


# =========================================================
# PUBLIC FUNCTION TESTS
# =========================================================

def test_public_function(monkeypatch):

    fake = FakeDetector()

    custom_agent = GuardianAgent(detector=fake)

    monkeypatch.setattr(
        guardian_module,
        "guardian_agent",
        custom_agent,
    )

    result = run_guardian_analysis(
        "Suspicious message"
    )

    assert result["success"] is True


def test_public_function_with_evidence_type(monkeypatch):

    fake = FakeDetector()

    custom_agent = GuardianAgent(detector=fake)

    monkeypatch.setattr(
        guardian_module,
        "guardian_agent",
        custom_agent,
    )

    result = run_guardian_analysis(
        "Suspicious URL",
        evidence_type="url",
    )

    assert result["success"] is True

    assert result["analysis"]["evidence_type"] == "url"


def test_public_function_default_evidence_type(monkeypatch):

    fake = FakeDetector()

    custom_agent = GuardianAgent(detector=fake)

    monkeypatch.setattr(
        guardian_module,
        "guardian_agent",
        custom_agent,
    )

    result = run_guardian_analysis("Test evidence")

    assert result["analysis"]["evidence_type"] == "message"


# =========================================================
# HELPER FUNCTION TESTS
# =========================================================

@pytest.mark.parametrize(
    "value,expected",
    [
        (["a", "b"], ["a", "b"]),
        ([], []),
        ("invalid", []),
        (None, []),
        (123, []),
        ({}, []),
    ],
)
def test_safe_list(value, expected):

    assert GuardianAgent._safe_list(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        (["a", "b"], ["a", "b"]),
        ([], []),
        ("invalid", []),
        (None, []),
        (123, []),
        ({}, []),
    ],
)
def test_safe_string_list(value, expected):

    assert GuardianAgent._safe_string_list(value) == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ({"a": 1}, {"a": 1}),
        ({}, {}),
        ([], {}),
        ("invalid", {}),
        (None, {}),
        (123, {}),
    ],
)
def test_safe_dict(value, expected):

    assert GuardianAgent._safe_dict(value) == expected


# =========================================================
# INTEGRITY TESTS
# =========================================================

def test_analysis_does_not_change_detector_risk_score(
    agent,
    sample_response,
):

    agent.detector.response = sample_response

    original_score = sample_response["risk_score"]

    agent.analyze("Suspicious message")

    assert sample_response["risk_score"] == original_score


def test_analysis_does_not_mutate_detector_response(
    agent,
    sample_response,
):

    agent.detector.response = sample_response

    original = {

        **sample_response,

        "indicators": dict(sample_response["indicators"]),

        "scoring": dict(sample_response["scoring"]),

    }

    agent.analyze("Suspicious message")

    assert sample_response == original


def test_multiple_analyses_independent(agent):

    first = agent.analyze("First suspicious message")

    second = agent.analyze("Second suspicious message")

    assert first["analysis_id"] != second["analysis_id"]


def test_failed_response_has_boolean_success(agent):

    agent.detector.exception = RuntimeError("Failure")

    result = agent.analyze("Suspicious message")

    assert isinstance(result["success"], bool)


def test_success_response_has_boolean_success(agent):

    result = agent.analyze("Suspicious message")

    assert isinstance(result["success"], bool)


def test_detector_response_not_modified(agent):

    original = dict(agent.detector.response)

    agent.analyze("Suspicious message")

    assert agent.detector.response == original


# =========================================================
# DIRECT EXECUTION
# =========================================================

if __name__ == "__main__":

    print("\n" + "=" * 65)

    print("SCAMSHIELD AI - GUARDIAN AGENT TEST SUITE")

    print("Version: 1.3.0")

    print("=" * 65)

    print("\nRun this test suite using pytest.")

    print("\nCommand:")

    print("python -m pytest tests/test_guardian_agent.py -v")

    print("\n" + "=" * 65)