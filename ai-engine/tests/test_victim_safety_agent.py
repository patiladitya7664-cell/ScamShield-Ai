"""
=========================================================
SCAMSHIELD AI - VICTIM SAFETY AGENT TEST SUITE
=========================================================

Version: 1.2.0

Test Coverage:
1. Agent initialization and version.
2. English exposure detection.
3. Hinglish exposure detection.
4. Negation handling.
5. Scammer request vs actual victim exposure.
6. User-reported exposures.
7. Precautionary recommendations.
8. Immediate actions.
9. Safety-level assessment.
10. Risk-score validation.
11. Evidence validation.
12. Emergency guidance.
13. Agent response structure.
14. Public function compatibility.

Run:
    pytest tests/test_victim_safety_agent.py -v

=========================================================
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import math
import pytest

from agents.victim_safety_agent import (
    VictimSafetyAgent,
    run_victim_safety_analysis,
)


# =========================================================
# FIXTURE
# =========================================================

@pytest.fixture
def agent():

    return VictimSafetyAgent()


# =========================================================
# HELPER
# =========================================================

def analyze(
    agent,
    evidence,
    risk_level="UNKNOWN",
    risk_score=None,
    detected_signals=None,
    evidence_type="message",
    reported_exposures=None,
):

    return agent.analyze(
        evidence=evidence,
        risk_level=risk_level,
        risk_score=risk_score,
        detected_signals=detected_signals,
        evidence_type=evidence_type,
        reported_exposures=reported_exposures,
    )


def get_exposures(result):

    return result["safety_assessment"]["detected_exposures"]


# =========================================================
# 1. INITIALIZATION TESTS
# =========================================================

def test_agent_initialization(agent):

    assert agent is not None


def test_agent_name(agent):

    assert agent.AGENT_NAME == "VictimSafetyAgent"


def test_agent_version(agent):

    assert agent.AGENT_VERSION == "1.2.0"


def test_supported_evidence_types(agent):

    expected = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    assert agent.SUPPORTED_EVIDENCE_TYPES == expected


# =========================================================
# 2. BASIC ANALYSIS TESTS
# =========================================================

def test_normal_message_analysis(agent):

    result = analyze(
        agent,
        "Hello, how are you?"
    )

    assert result["success"] is True

    assert result["agent"]["status"] == "completed"

    assert result["agent"]["version"] == "1.2.0"


def test_analysis_id_generated(agent):

    result = analyze(
        agent,
        "Please verify your account."
    )

    assert result["analysis_id"]

    assert isinstance(
        result["analysis_id"],
        str
    )


def test_metadata_generated(agent):

    result = analyze(
        agent,
        "Hello user."
    )

    metadata = result["metadata"]

    assert metadata["evidence_type"] == "message"

    assert metadata["analysis_method"] == (
        "rule_based_safety_assessment"
    )

    assert metadata["duration_ms"] >= 0

    assert metadata["automatic_actions_performed"] is False


# =========================================================
# 3. ENGLISH EXPOSURE DETECTION
# =========================================================

@pytest.mark.parametrize(
    "evidence, expected_exposure",
    [

        (
            "I shared my OTP",
            "otp_shared"
        ),

        (
            "I have shared my OTP",
            "otp_shared"
        ),

        (
            "I gave him my OTP",
            "otp_shared"
        ),

        (
            "I sent him OTP",
            "otp_shared"
        ),

        (
            "I shared my bank details",
            "bank_details_shared"
        ),

        (
            "I shared my card details",
            "bank_details_shared"
        ),

        (
            "I shared my password",
            "password_shared"
        ),

        (
            "I gave him my password",
            "password_shared"
        ),

        (
            "I sent the money",
            "payment_made"
        ),

        (
            "I transferred the money",
            "payment_made"
        ),

        (
            "I made the payment",
            "payment_made"
        ),

        (
            "I clicked on the link",
            "suspicious_link_opened"
        ),

        (
            "I opened the suspicious link",
            "suspicious_link_opened"
        ),

        (
            "I installed AnyDesk",
            "remote_access_granted"
        ),

        (
            "I installed TeamViewer",
            "remote_access_granted"
        ),

        (
            "I gave them remote access",
            "remote_access_granted"
        ),

    ]
)
def test_english_exposure_detection(
    agent,
    evidence,
    expected_exposure
):

    result = analyze(
        agent,
        evidence
    )

    assert result["success"] is True

    assert expected_exposure in get_exposures(result)


# =========================================================
# 4. HINGLISH EXPOSURE DETECTION
# =========================================================

@pytest.mark.parametrize(
    "evidence, expected_exposure",
    [

        (
            "Maine OTP share kar diya",
            "otp_shared"
        ),

        (
            "Maine OTP bata diya",
            "otp_shared"
        ),

        (
            "Maine OTP de diya",
            "otp_shared"
        ),

        (
            "Maine bank details de diye",
            "bank_details_shared"
        ),

        (
            "Maine bank details share kar diye",
            "bank_details_shared"
        ),

        (
            "Maine card details share kar diye",
            "bank_details_shared"
        ),

        (
            "Maine password de diya",
            "password_shared"
        ),

        (
            "Maine apna password bata diya",
            "password_shared"
        ),

        (
            "Maine paise bhej diye",
            "payment_made"
        ),

        (
            "Maine payment kar diya",
            "payment_made"
        ),

        (
            "Maine payment kar di",
            "payment_made"
        ),

        (
            "Maine link par click kiya",
            "suspicious_link_opened"
        ),

        (
            "Maine link open kiya",
            "suspicious_link_opened"
        ),

        (
            "Maine AnyDesk install kiya",
            "remote_access_granted"
        ),

        (
            "Maine remote access de diya",
            "remote_access_granted"
        ),

    ]
)
def test_hinglish_exposure_detection(
    agent,
    evidence,
    expected_exposure
):

    result = analyze(
        agent,
        evidence
    )

    assert result["success"] is True

    assert expected_exposure in get_exposures(result)


# =========================================================
# 5. NEGATION HANDLING
# =========================================================

@pytest.mark.parametrize(
    "evidence",
    [

        "I did not share my OTP",

        "I didn't share my OTP",

        "I have not shared my OTP",

        "I haven't shared my OTP",

        "I never shared my OTP",

        "I did not share my password",

        "I did not send the money",

        "I did not click on the link",

        "I did not install AnyDesk",

        "I did not give them remote access",

    ]
)
def test_english_negation(
    agent,
    evidence
):

    result = analyze(
        agent,
        evidence
    )

    assert result["success"] is True

    assert get_exposures(result) == []


def test_hinglish_negation_without_exposure_pattern(agent):

    result = analyze(
        agent,
        "Maine OTP share nahi kiya."
    )

    assert result["success"] is True

    assert "otp_shared" not in get_exposures(result)


def test_negation_after_unrelated_clause(agent):

    result = analyze(
        agent,
        "I received a suspicious message, but I did not share my OTP."
    )

    assert result["success"] is True

    assert "otp_shared" not in get_exposures(result)


def test_positive_exposure_after_but(agent):

    result = analyze(
        agent,
        "I did not share my OTP, but I shared my password."
    )

    assert result["success"] is True

    exposures = get_exposures(result)

    assert "password_shared" in exposures

    assert "otp_shared" not in exposures


# =========================================================
# 6. SCAMMER REQUEST VS ACTUAL EXPOSURE
# =========================================================

def test_otp_request_is_not_actual_exposure(agent):

    result = analyze(
        agent,
        "The caller asked me to share my OTP.",
        detected_signals=[
            "otp_or_credential_request"
        ],
    )

    assert result["success"] is True

    assessment = result["safety_assessment"]

    assert assessment["detected_exposures"] == []

    assert assessment["potentially_compromised"] is False

    assert assessment["sensitive_request_detected"] is True


def test_password_request_is_not_password_sharing(agent):

    result = analyze(
        agent,
        "The caller asked for my password.",
        detected_signals=[
            "otp_or_credential_request"
        ],
    )

    assert result["success"] is True

    assert "password_shared" not in get_exposures(result)


def test_payment_pressure_is_not_payment_made(agent):

    result = analyze(
        agent,
        "The caller pressured me to transfer money.",
        detected_signals=[
            "financial_pressure"
        ],
    )

    assert result["success"] is True

    assert "payment_made" not in get_exposures(result)


# =========================================================
# 7. USER-REPORTED EXPOSURES
# =========================================================

@pytest.mark.parametrize(
    "exposure",
    [

        "otp_shared",

        "bank_details_shared",

        "password_shared",

        "payment_made",

        "suspicious_link_opened",

        "remote_access_granted",

    ]
)
def test_user_reported_exposure(
    agent,
    exposure
):

    result = analyze(
        agent,
        "I need help securing my account.",
        reported_exposures=[exposure],
    )

    assert result["success"] is True

    assert exposure in get_exposures(result)

    assert exposure in (
        result["safety_assessment"]["reported_exposures"]
    )


def test_duplicate_reported_exposures_removed(agent):

    result = analyze(
        agent,
        "I need account protection.",
        reported_exposures=[
            "otp_shared",
            "otp_shared",
        ],
    )

    exposures = get_exposures(result)

    assert exposures.count("otp_shared") == 1


def test_invalid_reported_exposure(agent):

    result = analyze(
        agent,
        "Please secure my account.",
        reported_exposures=[
            "unknown_exposure"
        ],
    )

    assert result["success"] is False

    assert result["error"]["code"] == "invalid_input"


# =========================================================
# 8. PRECAUTIONARY ACTIONS
# =========================================================

@pytest.mark.parametrize(
    "signal, expected_title",
    [

        (
            "otp_or_credential_request",
            "Do not share OTP or credentials"
        ),

        (
            "cvv_request",
            "Protect your card information"
        ),

        (
            "financial_pressure",
            "Pause before making any payment"
        ),

        (
            "remote_access_request",
            "Do not grant remote access"
        ),

        (
            "threat_or_intimidation",
            "Do not act under threats"
        ),

        (
            "suspicious_link",
            "Avoid opening suspicious links"
        ),

        (
            "investment_guarantee",
            "Verify investment claims"
        ),

        (
            "upi_payment_manipulation",
            "Verify UPI payment requests"
        ),

        (
            "email_spoofing",
            "Verify the sender independently"
        ),

        (
            "impersonation",
            "Verify the person's identity"
        ),

    ]
)
def test_precautionary_action_generation(
    agent,
    signal,
    expected_title
):

    result = analyze(
        agent,
        "A suspicious request was received.",
        detected_signals=[signal],
    )

    assert result["success"] is True

    actions = result["precautionary_actions"]

    titles = [
        item["title"]
        for item in actions
    ]

    assert expected_title in titles


def test_precautionary_action_does_not_mark_compromised(agent):

    result = analyze(
        agent,
        "The caller requested my OTP.",
        detected_signals=[
            "otp_or_credential_request"
        ],
    )

    assert result["success"] is True

    assert result["precautionary_actions"]

    assert result["safety_assessment"]["potentially_compromised"] is False


def test_precautionary_actions_in_immediate_actions(agent):

    result = analyze(
        agent,
        "Someone requested my OTP.",
        detected_signals=[
            "otp_or_credential_request"
        ],
    )

    assert result["success"] is True

    assert len(result["immediate_actions"]) >= 1


def test_duplicate_precautionary_actions_removed(agent):

    result = analyze(
        agent,
        "Suspicious request received.",
        detected_signals=[
            "otp_or_credential_request",
            "otp_or_credential_request",
        ],
    )

    titles = [
        item["title"]
        for item in result["precautionary_actions"]
    ]

    assert len(titles) == len(set(titles))


# =========================================================
# 9. IMMEDIATE ACTIONS
# =========================================================

@pytest.mark.parametrize(
    "exposure",
    [

        "otp_shared",

        "bank_details_shared",

        "password_shared",

        "payment_made",

        "suspicious_link_opened",

        "remote_access_granted",

    ]
)
def test_immediate_action_generation(
    agent,
    exposure
):

    result = analyze(
        agent,
        "Please help secure my account.",
        reported_exposures=[exposure],
    )

    assert result["success"] is True

    actions = result["immediate_actions"]

    assert len(actions) >= 1

    assert all(
        "priority" in action
        and "title" in action
        and "action" in action
        for action in actions
    )


def test_payment_exposure_has_critical_action(agent):

    result = analyze(
        agent,
        "I sent the money.",
    )

    assert result["success"] is True

    actions = result["immediate_actions"]

    assert any(
        action["priority"] == "CRITICAL"
        for action in actions
    )


def test_action_objects_are_independent(agent):

    first = agent._get_immediate_actions(
        ["otp_shared"]
    )

    second = agent._get_immediate_actions(
        ["otp_shared"]
    )

    first[0]["title"] = "Modified"

    assert second[0]["title"] != "Modified"


# =========================================================
# 10. SAFETY LEVEL TESTS
# =========================================================

@pytest.mark.parametrize(
    "exposure, expected_level",
    [

        ("payment_made", "URGENT"),

        ("otp_shared", "URGENT"),

        ("remote_access_granted", "URGENT"),

        ("bank_details_shared", "HIGH"),

        ("password_shared", "HIGH"),

        ("suspicious_link_opened", "ELEVATED"),

    ]
)
def test_safety_level_from_exposure(
    agent,
    exposure,
    expected_level
):

    result = analyze(
        agent,
        "Please help me.",
        reported_exposures=[exposure],
    )

    assert result["success"] is True

    assert (
        result["safety_assessment"]["safety_level"]
        == expected_level
    )


def test_high_guardian_signal_safety_level(agent):

    result = analyze(
        agent,
        "Suspicious message received.",
        risk_level="HIGH",
        detected_signals=[
            "otp_or_credential_request"
        ],
    )

    assert result["success"] is True

    assert (
        result["safety_assessment"]["safety_level"]
        == "HIGH"
    )


def test_medium_guardian_signal_safety_level(agent):

    result = analyze(
        agent,
        "Suspicious message received.",
        risk_level="MEDIUM",
        detected_signals=[
            "financial_pressure"
        ],
    )

    assert result["success"] is True

    assert (
        result["safety_assessment"]["safety_level"]
        == "ELEVATED"
    )


# =========================================================
# 11. RISK SCORE VALIDATION
# =========================================================

@pytest.mark.parametrize(
    "risk_score",
    [

        0,

        25,

        45,

        75,

        100,

        45.5,

        99.99,

    ]
)
def test_valid_risk_scores(
    agent,
    risk_score
):

    result = analyze(
        agent,
        "Suspicious message received.",
        risk_score=risk_score,
    )

    assert result["success"] is True


@pytest.mark.parametrize(
    "risk_score",
    [

        -1,

        101,

        "45",

        True,

        False,

        float("nan"),

        float("inf"),

        float("-inf"),

    ]
)
def test_invalid_risk_scores(
    agent,
    risk_score
):

    result = analyze(
        agent,
        "Suspicious message received.",
        risk_score=risk_score,
    )

    assert result["success"] is False

    assert result["error"]["code"] == "invalid_input"


# =========================================================
# 12. EVIDENCE VALIDATION
# =========================================================

def test_empty_evidence(agent):

    result = analyze(
        agent,
        ""
    )

    assert result["success"] is False


def test_whitespace_evidence(agent):

    result = analyze(
        agent,
        "     "
    )

    assert result["success"] is False


def test_non_string_evidence(agent):

    result = analyze(
        agent,
        12345
    )

    assert result["success"] is False


def test_maximum_evidence_length(agent):

    evidence = "A" * (
        agent.MAX_EVIDENCE_LENGTH + 1
    )

    result = analyze(
        agent,
        evidence
    )

    assert result["success"] is False


def test_unsupported_evidence_type(agent):

    result = analyze(
        agent,
        "Suspicious message.",
        evidence_type="video",
    )

    assert result["success"] is False


def test_unsupported_risk_level(agent):

    result = analyze(
        agent,
        "Suspicious message.",
        risk_level="EXTREME",
    )

    assert result["success"] is False


def test_detected_signals_must_be_list(agent):

    result = analyze(
        agent,
        "Suspicious message.",
        detected_signals="otp_or_credential_request",
    )

    assert result["success"] is False


# =========================================================
# 13. SIGNAL NORMALIZATION
# =========================================================

def test_signal_normalization(agent):

    result = agent._normalize_signals(
        [
            " OTP_OR_CREDENTIAL_REQUEST ",
            "financial_pressure",
            "financial_pressure",
            None,
        ]
    )

    assert result == [
        "otp_or_credential_request",
        "financial_pressure",
    ]


def test_sensitive_request_detection(agent):

    result = agent._has_sensitive_request(
        [
            "otp_or_credential_request"
        ]
    )

    assert result is True


def test_non_sensitive_signal(agent):

    result = agent._has_sensitive_request(
        [
            "neutral_indicator"
        ]
    )

    assert result is False


# =========================================================
# 14. EMERGENCY GUIDANCE
# =========================================================

def test_emergency_guidance_available(agent):

    result = analyze(
        agent,
        "I transferred the money.",
    )

    guidance = result["emergency_guidance"]

    assert guidance["country"] == "India"

    assert guidance["cybercrime_helpline"] == "1930"

    assert guidance["reporting_portal"] == (
        "https://cybercrime.gov.in/"
    )


def test_financial_fraud_reporting_recommended(agent):

    result = analyze(
        agent,
        "I sent the money.",
    )

    guidance = result["emergency_guidance"]

    assert guidance["financial_fraud_report_recommended"] is True


def test_no_financial_exposure_reporting_flag(agent):

    result = analyze(
        agent,
        "I received a suspicious message.",
    )

    guidance = result["emergency_guidance"]

    assert guidance["financial_fraud_report_recommended"] is False


# =========================================================
# 15. EXPOSURE VERIFICATION
# =========================================================

def test_exposure_remains_unverified(agent):

    result = analyze(
        agent,
        "I shared my OTP.",
    )

    assessment = result["safety_assessment"]

    assert assessment["verification_status"] == "UNVERIFIED"

    assert (
        assessment["exposure_sources"]["verification_status"]
        == "UNVERIFIED"
    )


def test_automatic_actions_never_performed(agent):

    result = analyze(
        agent,
        "I transferred the money.",
    )

    assert (
        result["metadata"]["automatic_actions_performed"]
        is False
    )


def test_important_notice_present(agent):

    result = analyze(
        agent,
        "I received a suspicious message.",
    )

    assert result["important_notice"]

    assert "cannot independently confirm" in (
        result["important_notice"]
    )


# =========================================================
# 16. PUBLIC FUNCTION TEST
# =========================================================

def test_public_function():

    result = run_victim_safety_analysis(
        evidence="I shared my OTP.",
        risk_level="HIGH",
        risk_score=80.5,
        detected_signals=[
            "otp_or_credential_request"
        ],
        evidence_type="message",
    )

    assert result["success"] is True

    assert result["agent"]["name"] == "VictimSafetyAgent"

    assert result["agent"]["version"] == "1.2.0"

    assert "otp_shared" in get_exposures(result)


# =========================================================
# 17. MIXED EXPOSURE TEST
# =========================================================

def test_multiple_exposures_detected(agent):

    result = analyze(
        agent,
        (
            "I shared my OTP. "
            "I shared my password. "
            "I sent the money."
        ),
    )

    assert result["success"] is True

    exposures = get_exposures(result)

    assert "otp_shared" in exposures

    assert "password_shared" in exposures

    assert "payment_made" in exposures

    assert result["safety_assessment"]["safety_level"] == "URGENT"


# =========================================================
# 18. EVIDENCE TYPE TEST
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

    ]
)
def test_supported_evidence_types(
    agent,
    evidence_type
):

    result = analyze(
        agent,
        "Suspicious evidence.",
        evidence_type=evidence_type,
    )

    assert result["success"] is True

    assert (
        result["metadata"]["evidence_type"]
        == evidence_type
    )


# =========================================================
# TEST SUMMARY
# =========================================================

def test_agent_recommendations_available(agent):

    assert isinstance(
        agent.recommendations,
        dict
    )

    assert "otp" in agent.recommendations

    assert "bank" in agent.recommendations

    assert "password" in agent.recommendations

    assert "payment" in agent.recommendations


# =========================================================
# END
# =========================================================