"""
=========================================================
SCAMSHIELD AI - AGENT ORCHESTRATOR TEST SUITE
=========================================================

Coverage:
1. Initialization and configuration.
2. Input validation.
3. Agent response validation.
4. Guardian execution.
5. Intelligence execution.
6. Victim Safety execution.
7. Agent failure handling.
8. Unified response structure.
9. Metadata and execution tracking.
10. Controlled Decoy lifecycle.
11. Public analysis function.
12. Logging failure handling.

Run:
pytest tests/test_agent_orchestrator.py -v
=========================================================
"""

import importlib
from unittest.mock import Mock

import pytest

from services.agent_orchestrator import (
    AgentOrchestrator,
    run_complete_analysis,
)


# =========================================================
# MODULE REFERENCE
# =========================================================

orchestrator_module = importlib.import_module(
    "services.agent_orchestrator"
)


# =========================================================
# TEST FIXTURES
# =========================================================

@pytest.fixture
def orchestrator(monkeypatch):

    monkeypatch.setattr(
        orchestrator_module,
        "log_agent_execution",
        Mock(),
    )

    instance = AgentOrchestrator()

    instance.guardian = Mock()
    instance.intelligence = Mock()
    instance.victim_safety = Mock()
    instance.decoy = Mock()

    instance.guardian.analyze.return_value = {
        "success": True,
        "analysis": {
            "risk_level": "HIGH",
            "risk_score": 85,
            "signals": [
                "otp_request",
                "financial_pressure",
            ],
        },
    }

    instance.intelligence.analyze.return_value = {
        "success": True,
        "indicators": ["suspicious_link"],
    }

    instance.victim_safety.analyze.return_value = {
        "success": True,
        "recommendations": ["Do not share OTP."],
    }

    instance.decoy.start_session.return_value = {
        "success": True,
        "session_id": "test-session",
    }

    instance.decoy.continue_session.return_value = {
        "success": True,
        "session_id": "test-session",
    }

    instance.decoy.end_session.return_value = {
        "success": True,
        "message": "Simulation ended.",
    }

    return instance


@pytest.fixture
def valid_evidence():

    return (
        "Your bank account will be blocked. "
        "Share your OTP immediately."
    )


# =========================================================
# INITIALIZATION TESTS
# =========================================================

def test_agent_orchestrator_initialization(orchestrator):

    assert isinstance(orchestrator, AgentOrchestrator)


def test_orchestrator_version(orchestrator):

    assert orchestrator.VERSION == "1.1.0"


def test_all_four_agents_are_initialized(orchestrator):

    assert orchestrator.guardian is not None
    assert orchestrator.intelligence is not None
    assert orchestrator.victim_safety is not None
    assert orchestrator.decoy is not None


def test_supported_evidence_types(orchestrator):

    expected = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    assert orchestrator.SUPPORTED_EVIDENCE_TYPES == expected


def test_maximum_evidence_length(orchestrator):

    assert orchestrator.MAX_EVIDENCE_LENGTH == 20000


# =========================================================
# SAFE HELPER TESTS
# =========================================================

def test_safe_dict_accepts_dictionary(orchestrator):

    value = {"success": True}

    assert orchestrator._safe_dict(value) == value


@pytest.mark.parametrize(
    "value",
    [None, [], "text", 123, True],
)
def test_safe_dict_rejects_non_dictionary(orchestrator, value):

    assert orchestrator._safe_dict(value) == {}


def test_safe_list_accepts_list(orchestrator):

    assert orchestrator._safe_list([1, 2]) == [1, 2]


@pytest.mark.parametrize(
    "value",
    [None, {}, "text", 123],
)
def test_safe_list_rejects_non_list(orchestrator, value):

    assert orchestrator._safe_list(value) == []


def test_safe_string_accepts_string(orchestrator):

    assert orchestrator._safe_string("hello") == "hello"


def test_safe_string_returns_default_for_non_string(orchestrator):

    assert orchestrator._safe_string(123, "default") == "default"


def test_timestamp_is_utc_iso_format(orchestrator):

    from datetime import datetime

    timestamp = orchestrator._timestamp()

    parsed = datetime.fromisoformat(timestamp)

    assert parsed.tzinfo is not None


# =========================================================
# INPUT VALIDATION TESTS
# =========================================================

def test_validate_input_success(orchestrator):

    evidence, evidence_type = orchestrator._validate_input(
        "  Suspicious message  ",
        " MESSAGE ",
    )

    assert evidence == "Suspicious message"
    assert evidence_type == "message"


@pytest.mark.parametrize(
    "evidence",
    [None, 123, 45.5, True, False, [], {}],
)
def test_validate_input_rejects_non_string_evidence(
    orchestrator,
    evidence,
):

    with pytest.raises(
        ValueError,
        match="Evidence must be a string",
    ):

        orchestrator._validate_input(evidence, "message")


@pytest.mark.parametrize(
    "evidence",
    ["", " ", "\n", "\t", "  \n  "],
)
def test_validate_input_rejects_empty_evidence(
    orchestrator,
    evidence,
):

    with pytest.raises(
        ValueError,
        match="Evidence cannot be empty",
    ):

        orchestrator._validate_input(evidence, "message")


def test_validate_input_rejects_oversized_evidence(orchestrator):

    evidence = "A" * (
        orchestrator.MAX_EVIDENCE_LENGTH + 1
    )

    with pytest.raises(
        ValueError,
        match="maximum allowed length",
    ):

        orchestrator._validate_input(evidence, "message")


def test_validate_input_accepts_maximum_evidence(orchestrator):

    evidence = "A" * orchestrator.MAX_EVIDENCE_LENGTH

    result, evidence_type = orchestrator._validate_input(
        evidence,
        "message",
    )

    assert len(result) == orchestrator.MAX_EVIDENCE_LENGTH
    assert evidence_type == "message"


@pytest.mark.parametrize(
    "evidence_type",
    [None, 123, True, [], {}],
)
def test_validate_input_rejects_non_string_evidence_type(
    orchestrator,
    evidence_type,
):

    with pytest.raises(
        ValueError,
        match="Evidence type must be a string",
    ):

        orchestrator._validate_input(
            "test evidence",
            evidence_type,
        )


@pytest.mark.parametrize(
    "evidence_type",
    ["", "unknown", "audio", "video", "document"],
)
def test_validate_input_rejects_unsupported_evidence_type(
    orchestrator,
    evidence_type,
):

    with pytest.raises(
        ValueError,
        match="Unsupported evidence type",
    ):

        orchestrator._validate_input(
            "test evidence",
            evidence_type,
        )


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
def test_validate_input_accepts_all_supported_types(
    orchestrator,
    evidence_type,
):

    evidence, result_type = orchestrator._validate_input(
        "Test evidence",
        evidence_type,
    )

    assert evidence == "Test evidence"
    assert result_type == evidence_type


# =========================================================
# AGENT RESPONSE VALIDATION
# =========================================================

def test_validate_agent_result_accepts_valid_response():

    result = {"success": True}

    assert AgentOrchestrator._validate_agent_result(
        result,
        "Guardian",
    ) == result


def test_validate_agent_result_accepts_failed_response():

    result = {
        "success": False,
        "error": {},
    }

    assert AgentOrchestrator._validate_agent_result(
        result,
        "Guardian",
    ) == result


@pytest.mark.parametrize(
    "result",
    [None, [], "invalid", 123, True],
)
def test_validate_agent_result_rejects_non_dictionary(result):

    response = AgentOrchestrator._validate_agent_result(
        result,
        "Guardian",
    )

    assert response["success"] is False
    assert response["error"]["code"] == "invalid_agent_response"


@pytest.mark.parametrize(
    "result",
    [
        {},
        {"data": "test"},
        {"success": "true"},
        {"success": 1},
        {"success": None},
    ],
)
def test_validate_agent_result_rejects_missing_success(result):

    response = AgentOrchestrator._validate_agent_result(
        result,
        "Guardian",
    )

    assert response["success"] is False
    assert response["error"]["code"] == "missing_success_status"


# =========================================================
# SUCCESSFUL ANALYSIS TESTS
# =========================================================

def test_analyze_returns_success(orchestrator, valid_evidence):

    result = orchestrator.analyze(valid_evidence)

    assert result["success"] is True


def test_analyze_returns_analysis_id(orchestrator, valid_evidence):

    result = orchestrator.analyze(valid_evidence)

    assert isinstance(result["analysis_id"], str)
    assert len(result["analysis_id"]) > 0


def test_analysis_ids_are_unique(orchestrator, valid_evidence):

    first = orchestrator.analyze(valid_evidence)
    second = orchestrator.analyze(valid_evidence)

    assert first["analysis_id"] != second["analysis_id"]


def test_analyze_returns_completed_status(orchestrator, valid_evidence):

    result = orchestrator.analyze(valid_evidence)

    assert result["orchestrator"]["status"] == "completed"


def test_all_primary_agents_execute(orchestrator, valid_evidence):

    orchestrator.analyze(valid_evidence)

    orchestrator.guardian.analyze.assert_called_once()
    orchestrator.intelligence.analyze.assert_called_once()
    orchestrator.victim_safety.analyze.assert_called_once()


def test_agents_receive_correct_evidence(
    orchestrator,
    valid_evidence,
):

    orchestrator.analyze(valid_evidence, "message")

    orchestrator.guardian.analyze.assert_called_once_with(
        evidence=valid_evidence,
        evidence_type="message",
    )

    orchestrator.intelligence.analyze.assert_called_once_with(
        evidence=valid_evidence,
        evidence_type="message",
    )


def test_victim_safety_receives_guardian_context(
    orchestrator,
    valid_evidence,
):

    orchestrator.analyze(valid_evidence)

    orchestrator.victim_safety.analyze.assert_called_once_with(
        evidence=valid_evidence,
        evidence_type="message",
        risk_level="HIGH",
        risk_score=85,
        detected_signals=[
            "otp_request",
            "financial_pressure",
        ],
    )


def test_decoy_does_not_start_automatically(
    orchestrator,
    valid_evidence,
):

    orchestrator.analyze(valid_evidence)

    orchestrator.decoy.start_session.assert_not_called()
    orchestrator.decoy.continue_session.assert_not_called()


def test_decoy_status_is_not_started(orchestrator, valid_evidence):

    result = orchestrator.analyze(valid_evidence)

    assert result["results"]["decoy"]["status"] == "not_started"


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
def test_analyze_supports_all_evidence_types(
    orchestrator,
    valid_evidence,
    evidence_type,
):

    result = orchestrator.analyze(
        valid_evidence,
        evidence_type,
    )

    assert result["success"] is True
    assert result["metadata"]["evidence_type"] == evidence_type


def test_analyze_normalizes_evidence_type(
    orchestrator,
    valid_evidence,
):

    result = orchestrator.analyze(
        valid_evidence,
        " URL ",
    )

    assert result["success"] is True
    assert result["metadata"]["evidence_type"] == "url"


# =========================================================
# GUARDIAN FAILURE TESTS
# =========================================================

def test_guardian_exception_is_handled(
    orchestrator,
    valid_evidence,
):

    orchestrator.guardian.analyze.side_effect = RuntimeError(
        "failure"
    )

    result = orchestrator.analyze(valid_evidence)

    assert result["success"] is False
    assert result["orchestrator"]["status"] == "failed"


def test_guardian_failure_stops_primary_pipeline(
    orchestrator,
    valid_evidence,
):

    orchestrator.guardian.analyze.return_value = {
        "success": False,
        "error": {"code": "guardian_failed"},
    }

    orchestrator.analyze(valid_evidence)

    orchestrator.intelligence.analyze.assert_not_called()
    orchestrator.victim_safety.analyze.assert_not_called()


def test_guardian_invalid_response_is_handled(
    orchestrator,
    valid_evidence,
):

    orchestrator.guardian.analyze.return_value = None

    result = orchestrator.analyze(valid_evidence)

    assert result["success"] is False
    assert result["results"]["guardian"]["success"] is False


def test_guardian_missing_analysis_is_handled(
    orchestrator,
    valid_evidence,
):

    orchestrator.guardian.analyze.return_value = {
        "success": True,
        "analysis": {},
    }

    result = orchestrator.analyze(valid_evidence)

    assert result["success"] is False
    assert result["orchestrator"]["status"] == "failed"


def test_guardian_failed_execution_has_error_entry(
    orchestrator,
    valid_evidence,
):

    orchestrator.guardian.analyze.side_effect = RuntimeError()

    result = orchestrator.analyze(valid_evidence)

    assert any(
        error["agent"] == "guardian"
        for error in result["errors"]
    )


# =========================================================
# INTELLIGENCE FAILURE TESTS
# =========================================================

def test_intelligence_exception_is_handled(
    orchestrator,
    valid_evidence,
):

    orchestrator.intelligence.analyze.side_effect = RuntimeError()

    result = orchestrator.analyze(valid_evidence)

    assert result["success"] is True
    assert result["orchestrator"]["status"] == "partial"


def test_intelligence_failure_does_not_stop_victim_safety(
    orchestrator,
    valid_evidence,
):

    orchestrator.intelligence.analyze.side_effect = RuntimeError()

    orchestrator.analyze(valid_evidence)

    orchestrator.victim_safety.analyze.assert_called_once()


def test_intelligence_failed_response_is_tracked(
    orchestrator,
    valid_evidence,
):

    orchestrator.intelligence.analyze.return_value = {
        "success": False,
        "error": {"code": "intelligence_failed"},
    }

    result = orchestrator.analyze(valid_evidence)

    assert result["orchestrator"]["status"] == "partial"

    assert (
        "intelligence"
        in result["metadata"]["agents_failed"]
    )


# =========================================================
# VICTIM SAFETY FAILURE TESTS
# =========================================================

def test_victim_safety_exception_is_handled(
    orchestrator,
    valid_evidence,
):

    orchestrator.victim_safety.analyze.side_effect = RuntimeError()

    result = orchestrator.analyze(valid_evidence)

    assert result["success"] is True
    assert result["orchestrator"]["status"] == "partial"


def test_victim_safety_failure_does_not_erase_guardian_result(
    orchestrator,
    valid_evidence,
):

    orchestrator.victim_safety.analyze.side_effect = RuntimeError()

    result = orchestrator.analyze(valid_evidence)

    assert result["results"]["guardian"]["success"] is True


def test_victim_safety_failed_response_is_tracked(
    orchestrator,
    valid_evidence,
):

    orchestrator.victim_safety.analyze.return_value = {
        "success": False,
        "error": {"code": "safety_failed"},
    }

    result = orchestrator.analyze(valid_evidence)

    assert result["orchestrator"]["status"] == "partial"

    assert (
        "victim_safety"
        in result["metadata"]["agents_failed"]
    )


# =========================================================
# UNIFIED RESPONSE TESTS
# =========================================================

def test_response_contains_required_fields(
    orchestrator,
    valid_evidence,
):

    result = orchestrator.analyze(valid_evidence)

    required = {
        "success",
        "analysis_id",
        "orchestrator",
        "results",
        "errors",
        "metadata",
        "verification",
        "disclaimer",
    }

    assert required.issubset(result.keys())


def test_response_contains_all_agent_results(
    orchestrator,
    valid_evidence,
):

    result = orchestrator.analyze(valid_evidence)

    expected = {
        "guardian",
        "intelligence",
        "victim_safety",
        "decoy",
    }

    assert expected.issubset(result["results"].keys())


def test_response_contains_orchestrator_information(
    orchestrator,
    valid_evidence,
):

    result = orchestrator.analyze(valid_evidence)

    assert (
        result["orchestrator"]["name"]
        == "ScamShield AI Agent Orchestrator"
    )

    assert result["orchestrator"]["version"] == "1.1.0"


def test_response_metadata_contains_execution_details(
    orchestrator,
    valid_evidence,
):

    result = orchestrator.analyze(valid_evidence)

    metadata = result["metadata"]

    assert metadata["evidence_type"] == "message"
    assert isinstance(metadata["duration_ms"], (int, float))
    assert metadata["duration_ms"] >= 0


def test_response_tracks_successful_agents(
    orchestrator,
    valid_evidence,
):

    result = orchestrator.analyze(valid_evidence)

    successful = result["metadata"]["agents_successful"]

    assert "guardian" in successful
    assert "intelligence" in successful
    assert "victim_safety" in successful


def test_response_tracks_failed_agents(
    orchestrator,
    valid_evidence,
):

    orchestrator.intelligence.analyze.side_effect = RuntimeError()

    result = orchestrator.analyze(valid_evidence)

    assert (
        "intelligence"
        in result["metadata"]["agents_failed"]
    )


def test_response_tracks_executed_agents(
    orchestrator,
    valid_evidence,
):

    result = orchestrator.analyze(valid_evidence)

    executed = result["metadata"]["agents_executed"]

    assert executed == [
        "guardian",
        "intelligence",
        "victim_safety",
    ]


def test_response_contains_verification_disclaimer(
    orchestrator,
    valid_evidence,
):

    result = orchestrator.analyze(valid_evidence)

    assert result["verification"]["status"] == "UNVERIFIED"

    assert (
        result["verification"]["external_verification"]
        is False
    )

    assert isinstance(result["disclaimer"], str)
    assert len(result["disclaimer"]) > 0


def test_invalid_input_returns_failed_response(orchestrator):

    result = orchestrator.analyze("")

    assert result["success"] is False
    assert result["orchestrator"]["status"] == "failed"
    assert result["metadata"]["evidence_type"] is None


def test_invalid_input_does_not_execute_agents(orchestrator):

    orchestrator.analyze("")

    orchestrator.guardian.analyze.assert_not_called()
    orchestrator.intelligence.analyze.assert_not_called()
    orchestrator.victim_safety.analyze.assert_not_called()


# =========================================================
# CONTROLLED DECOY SIMULATION TESTS
# =========================================================

def test_start_decoy_simulation_success(orchestrator):

    result = orchestrator.start_decoy_simulation(
        "Suspicious message",
    )

    assert result["success"] is True

    orchestrator.decoy.start_session.assert_called_once_with(
        "Suspicious message"
    )


def test_start_decoy_simulation_handles_exception(orchestrator):

    orchestrator.decoy.start_session.side_effect = RuntimeError()

    result = orchestrator.start_decoy_simulation(
        "Suspicious message"
    )

    assert result["success"] is False
    assert result["error"]["code"] == "decoy_start_failed"


def test_start_decoy_simulation_validates_response(orchestrator):

    orchestrator.decoy.start_session.return_value = None

    result = orchestrator.start_decoy_simulation(
        "Suspicious message"
    )

    assert result["success"] is False


def test_continue_decoy_simulation_success(orchestrator):

    result = orchestrator.continue_decoy_simulation(
        "test-session",
        "Another suspicious message",
    )

    assert result["success"] is True

    orchestrator.decoy.continue_session.assert_called_once_with(
        "test-session",
        "Another suspicious message",
    )


def test_continue_decoy_simulation_handles_exception(orchestrator):

    orchestrator.decoy.continue_session.side_effect = RuntimeError()

    result = orchestrator.continue_decoy_simulation(
        "test-session",
        "Suspicious message",
    )

    assert result["success"] is False
    assert result["error"]["code"] == "decoy_continue_failed"


def test_continue_decoy_simulation_validates_response(orchestrator):

    orchestrator.decoy.continue_session.return_value = None

    result = orchestrator.continue_decoy_simulation(
        "test-session",
        "Suspicious message",
    )

    assert result["success"] is False


def test_end_decoy_simulation_success(orchestrator):

    result = orchestrator.end_decoy_simulation("test-session")

    assert result["success"] is True

    orchestrator.decoy.end_session.assert_called_once_with(
        "test-session"
    )


def test_end_decoy_simulation_handles_exception(orchestrator):

    orchestrator.decoy.end_session.side_effect = RuntimeError()

    result = orchestrator.end_decoy_simulation("test-session")

    assert result["success"] is False
    assert result["error"]["code"] == "decoy_end_failed"


def test_end_decoy_simulation_validates_response(orchestrator):

    orchestrator.decoy.end_session.return_value = None

    result = orchestrator.end_decoy_simulation("test-session")

    assert result["success"] is False


# =========================================================
# LOGGING SAFETY TESTS
# =========================================================

def test_logging_failure_does_not_crash_analysis(
    orchestrator,
    valid_evidence,
    monkeypatch,
):

    monkeypatch.setattr(
        orchestrator_module,
        "log_agent_execution",
        Mock(
            side_effect=RuntimeError("logging failure")
        ),
    )

    result = orchestrator.analyze(valid_evidence)

    assert result["success"] is True


def test_logging_is_attempted_after_analysis(
    orchestrator,
    valid_evidence,
    monkeypatch,
):

    logging_mock = Mock()

    monkeypatch.setattr(
        orchestrator_module,
        "log_agent_execution",
        logging_mock,
    )

    orchestrator.analyze(valid_evidence)

    logging_mock.assert_called_once()


# =========================================================
# PUBLIC FUNCTION TESTS
# =========================================================

def test_run_complete_analysis_uses_singleton(monkeypatch):

    expected = {
        "success": True,
        "analysis_id": "public-test",
    }

    mock_analyze = Mock(return_value=expected)

    monkeypatch.setattr(
        orchestrator_module.agent_orchestrator,
        "analyze",
        mock_analyze,
    )

    result = run_complete_analysis(
        "Suspicious message",
        "message",
    )

    assert result == expected

    mock_analyze.assert_called_once_with(
        evidence="Suspicious message",
        evidence_type="message",
    )


def test_run_complete_analysis_default_evidence_type(
    monkeypatch,
):

    mock_analyze = Mock(
        return_value={"success": True}
    )

    monkeypatch.setattr(
        orchestrator_module.agent_orchestrator,
        "analyze",
        mock_analyze,
    )

    run_complete_analysis("Suspicious message")

    mock_analyze.assert_called_once_with(
        evidence="Suspicious message",
        evidence_type="message",
    )


# =========================================================
# END OF TEST SUITE
# =========================================================