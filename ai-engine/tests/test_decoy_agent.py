"""
SCAMSHIELD AI - DECOY AGENT TEST SUITE

Run from the ai-engine directory:
    python -m pytest tests/test_decoy_agent.py -v
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.decoy_agent import (
    DecoyAgent,
    decoy_agent,
    start_decoy_simulation,
    continue_decoy_simulation,
    end_decoy_simulation,
)


@pytest.fixture
def agent():
    return DecoyAgent()


@pytest.fixture
def active_session(agent):
    result = agent.start_session("Hello, please verify this message.")
    assert result["success"] is True
    return result["session_id"]


# ---------------------------------------------------------------------
# Initialization and constants
# ---------------------------------------------------------------------

def test_agent_initialization(agent):
    assert isinstance(agent.sessions, dict)
    assert agent.sessions == {}
    assert agent._lock is not None


def test_agent_name():
    assert DecoyAgent.AGENT_NAME == "DecoyAgent"


def test_agent_version():
    assert DecoyAgent.AGENT_VERSION == "1.1.0"


def test_simulation_only_constant():
    assert DecoyAgent.SIMULATION_ONLY is True


def test_session_limits_are_positive():
    assert DecoyAgent.MAX_MESSAGE_LENGTH > 0
    assert DecoyAgent.MAX_HISTORY_LENGTH >= 2
    assert DecoyAgent.MAX_ACTIVE_SESSIONS > 0
    assert DecoyAgent.SESSION_TTL_SECONDS > 0


# ---------------------------------------------------------------------
# Message validation
# ---------------------------------------------------------------------

@pytest.mark.parametrize("message", ["", " ", "\n", "\t", " \n  "])
def test_start_rejects_empty_message(agent, message):
    result = agent.start_session(message)
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"
    assert agent.sessions == {}


@pytest.mark.parametrize("message", [None, 123, 45.5, True, False, [], {}])
def test_start_rejects_non_string_message(agent, message):
    result = agent.start_session(message)
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


def test_start_trims_message(agent):
    result = agent.start_session("   Verify this first.   ")
    assert result["success"] is True
    session = agent.sessions[result["session_id"]]
    assert session["history"][0]["message"] == "Verify this first."


def test_start_accepts_maximum_message_length(agent):
    message = "x" * agent.MAX_MESSAGE_LENGTH
    result = agent.start_session(message)
    assert result["success"] is True
    assert len(agent.sessions[result["session_id"]]["history"][0]["message"]) == agent.MAX_MESSAGE_LENGTH


def test_start_rejects_message_over_maximum_length(agent):
    result = agent.start_session("x" * (agent.MAX_MESSAGE_LENGTH + 1))
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("message", ["", "  ", "\n", "\t"])
def test_continue_rejects_empty_message(agent, active_session, message):
    result = agent.continue_session(active_session, message)
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("message", [None, 1, 2.5, True, False, [], {}])
def test_continue_rejects_non_string_message(agent, active_session, message):
    result = agent.continue_session(active_session, message)
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


def test_continue_rejects_oversized_message(agent, active_session):
    result = agent.continue_session(
        active_session, "x" * (agent.MAX_MESSAGE_LENGTH + 1)
    )
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


# ---------------------------------------------------------------------
# Session ID validation
# ---------------------------------------------------------------------

@pytest.mark.parametrize("session_id", [None, 123, 1.5, True, False, [], {}])
def test_continue_rejects_non_string_session_id(agent, session_id):
    result = agent.continue_session(session_id, "A message")
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("session_id", ["", " ", "not-a-uuid", "1234", "{" + "x" * 36 + "}"])
def test_continue_rejects_invalid_session_id(agent, session_id):
    result = agent.continue_session(session_id, "A message")
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("session_id", [None, 123, True, [], {}])
def test_end_rejects_non_string_session_id(agent, session_id):
    result = agent.end_session(session_id)
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("session_id", ["", " ", "invalid", "not-a-uuid"])
def test_end_rejects_invalid_session_id(agent, session_id):
    result = agent.end_session(session_id)
    assert result["success"] is False
    assert result["error"]["code"] == "invalid_input"


def test_valid_session_id_is_uuid(agent, active_session):
    assert str(UUID(active_session)) == active_session


def test_session_id_whitespace_is_trimmed(agent, active_session):
    result = agent.continue_session(f" {active_session} ", "Another message")
    assert result["success"] is True


# ---------------------------------------------------------------------
# Start session response and storage
# ---------------------------------------------------------------------

def test_start_session_success(agent):
    result = agent.start_session("Please share your OTP.")
    assert result["success"] is True
    assert result["status"] == "active"
    assert result["simulation_only"] is True
    assert result["agent"] == "DecoyAgent"
    assert result["agent_version"] == DecoyAgent.AGENT_VERSION


def test_start_session_returns_session_id(agent):
    result = agent.start_session("Hello")
    assert isinstance(result["session_id"], str)
    UUID(result["session_id"])


def test_start_session_stores_session(agent):
    result = agent.start_session("Hello")
    session = agent.sessions[result["session_id"]]
    assert session["status"] == "active"
    assert session["simulation_only"] is True


def test_start_session_initial_history_has_two_entries(agent):
    result = agent.start_session("Hello")
    history = agent.sessions[result["session_id"]]["history"]
    assert len(history) == 2
    assert history[0]["speaker"] == "simulated_scammer"
    assert history[1]["speaker"] == "simulated_victim"


def test_start_session_stores_original_message(agent):
    message = "Please send your OTP now."
    result = agent.start_session(message)
    assert agent.sessions[result["session_id"]]["history"][0]["message"] == message


def test_start_session_stores_simulated_response(agent):
    result = agent.start_session("Please send your OTP.")
    assert agent.sessions[result["session_id"]]["history"][1]["message"] == result["simulated_response"]


def test_start_session_timestamps_are_iso_utc(agent):
    result = agent.start_session("Hello")
    session = agent.sessions[result["session_id"]]
    for item in session["history"]:
        parsed = datetime.fromisoformat(item["timestamp"])
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == timedelta(0)


def test_start_session_metadata(agent):
    result = agent.start_session("Hello")
    assert isinstance(result["metadata"]["duration_ms"], (int, float))
    assert result["metadata"]["duration_ms"] >= 0
    assert result["metadata"]["session_expiry_seconds"] == agent.SESSION_TTL_SECONDS
    datetime.fromisoformat(result["metadata"]["created_at"])


def test_start_session_safety_notice(agent):
    result = agent.start_session("Hello")
    assert "fictional simulation" in result["safety_notice"].lower()
    assert "no real person" in result["safety_notice"].lower()


def test_start_session_returns_independent_conversation_copy(agent):
    result = agent.start_session("Hello")
    result["conversation"].clear()
    assert len(agent.sessions[result["session_id"]]["history"]) == 2


def test_start_sessions_have_unique_ids(agent):
    first = agent.start_session("First")
    second = agent.start_session("Second")
    assert first["session_id"] != second["session_id"]


# ---------------------------------------------------------------------
# Tactic detection
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Act immediately, this is urgent.", "urgency"),
        ("Send me your OTP.", "otp_collection"),
        ("Please transfer money now.", "financial_pressure"),
        ("I am a police officer.", "impersonation"),
        ("You will be arrested.", "threats"),
        ("Click this link to verify your account.", "suspicious_link"),
        ("Install AnyDesk for remote access.", "remote_access"),
        ("Guaranteed returns with double your money.", "investment_manipulation"),
        ("Pay job registration fee.", "job_or_loan_fee"),
        ("Share your Aadhaar and PAN.", "personal_information_collection"),
        ("I will leak your private photos.", "blackmail"),
    ],
)
def test_detects_each_tactic(agent, message, expected):
    assert expected in agent._detect_tactics(message)


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("Abhi OTP bhejo", "otp_collection"),
        ("Turant paise bhejo", "urgency"),
        ("Paisa transfer karo", "financial_pressure"),
        ("Aaj hi payment required", "urgency"),
    ],
)
def test_detects_hinglish_tactics(agent, message, expected):
    assert expected in agent._detect_tactics(message)


def test_tactic_detection_is_case_insensitive(agent):
    assert "otp_collection" in agent._detect_tactics("SHARE YOUR OTP")


def test_tactic_detection_handles_multiple_tactics(agent):
    detected = agent._detect_tactics(
        "I am a police officer. Send OTP immediately or your account will be blocked."
    )
    assert "impersonation" in detected
    assert "otp_collection" in detected
    assert "urgency" in detected
    assert "threats" in detected


def test_tactic_detection_does_not_duplicate_tactic(agent):
    detected = agent._detect_tactics("OTP, verification code, and share your OTP")
    assert detected.count("otp_collection") == 1


def test_tactic_detection_uses_word_boundaries(agent):
    assert "otp_collection" not in agent._detect_tactics("adopting a new approach")


def test_tactic_detection_empty_message_returns_empty_list(agent):
    assert agent._detect_tactics("") == []


def test_tactic_detection_unrelated_message_returns_empty_list(agent):
    assert agent._detect_tactics("The weather is pleasant today.") == []


# ---------------------------------------------------------------------
# Safe response generation and priority
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    ("tactic", "expected_fragment"),
    [
        ("blackmail", "blackmail"),
        ("otp_collection", "OTP"),
        ("personal_information_collection", "banking details"),
        ("remote_access", "remote-access"),
        ("threats", "official authority"),
        ("financial_pressure", "transfer money"),
        ("job_or_loan_fee", "advance fee"),
        ("investment_manipulation", "guaranteed-return"),
        ("suspicious_link", "unknown links"),
        ("impersonation", "verify"),
        ("urgency", "urgency"),
    ],
)
def test_generates_safe_response_for_each_tactic(tactic, expected_fragment):
    response = DecoyAgent._generate_response([tactic])
    assert isinstance(response, str)
    assert expected_fragment.lower() in response.lower()


def test_generates_safe_default_response():
    response = DecoyAgent._generate_response([])
    assert "verify" in response.lower()
    assert "before" in response.lower()


def test_response_priority_prefers_blackmail():
    response = DecoyAgent._generate_response(["urgency", "blackmail", "otp_collection"])
    assert "blackmail" in response.lower()


def test_response_priority_prefers_otp_over_threats():
    response = DecoyAgent._generate_response(["threats", "otp_collection"])
    assert "OTP" in response


def test_response_generation_does_not_contact_external_services():
    response = DecoyAgent._generate_response(["suspicious_link"])
    assert "open unknown links" in response.lower()


def test_response_does_not_encourage_sharing_sensitive_information():
    response = DecoyAgent._generate_response(["otp_collection"])
    assert "cannot share" in response.lower()


# ---------------------------------------------------------------------
# Continue session
# ---------------------------------------------------------------------

def test_continue_session_success(agent, active_session):
    result = agent.continue_session(active_session, "Please pay processing fee.")
    assert result["success"] is True
    assert result["status"] == "active"
    assert result["simulation_only"] is True


def test_continue_session_returns_same_session_id(agent, active_session):
    result = agent.continue_session(active_session, "Another message")
    assert result["session_id"] == active_session


def test_continue_session_appends_two_history_entries(agent, active_session):
    result = agent.continue_session(active_session, "Send money")
    assert len(result["conversation"]) == 4
    assert result["conversation"][-2]["speaker"] == "simulated_scammer"
    assert result["conversation"][-1]["speaker"] == "simulated_victim"


def test_continue_session_preserves_previous_history(agent, active_session):
    initial = agent.sessions[active_session]["history"][0]["message"]
    agent.continue_session(active_session, "Second message")
    assert agent.sessions[active_session]["history"][0]["message"] == initial


def test_continue_session_updates_detected_tactics(agent, active_session):
    result = agent.continue_session(active_session, "Share your OTP.")
    assert "otp_collection" in result["detected_tactics"]
    assert "otp_collection" in result["all_detected_tactics"]


def test_continue_session_accumulates_tactics_without_duplicates(agent, active_session):
    agent.continue_session(active_session, "Share OTP.")
    result = agent.continue_session(active_session, "Send OTP immediately.")
    assert result["all_detected_tactics"].count("otp_collection") == 1


def test_continue_session_updates_last_activity(agent, active_session):
    before = agent.sessions[active_session]["last_activity_at"]
    agent.continue_session(active_session, "Another message")
    after = agent.sessions[active_session]["last_activity_at"]
    assert datetime.fromisoformat(after) >= datetime.fromisoformat(before)


def test_continue_session_metadata(agent, active_session):
    result = agent.continue_session(active_session, "Another message")
    assert result["metadata"]["history_length"] == 4
    assert result["metadata"]["duration_ms"] >= 0


def test_continue_session_returns_copy_of_history(agent, active_session):
    result = agent.continue_session(active_session, "Another message")
    result["conversation"].clear()
    assert len(agent.sessions[active_session]["history"]) == 4


def test_continue_session_unknown_valid_uuid(agent):
    result = agent.continue_session(
        "00000000-0000-4000-8000-000000000000", "Hello"
    )
    assert result["success"] is False
    assert result["error"]["code"] == "session_not_found"


def test_continue_session_missing_session(agent):
    result = agent.continue_session("00000000-0000-4000-8000-000000000000", "Hello")
    assert result["success"] is False


def test_continue_session_history_limit(agent, active_session):
    # Initial history has 2 entries; each continuation appends 2.
    for index in range((agent.MAX_HISTORY_LENGTH // 2) - 1):
        result = agent.continue_session(active_session, f"Message {index}")
        assert result["success"] is True
    assert len(agent.sessions[active_session]["history"]) == agent.MAX_HISTORY_LENGTH

    result = agent.continue_session(active_session, "One more message")
    assert result["success"] is False
    assert result["error"]["code"] == "history_limit_reached"


# ---------------------------------------------------------------------
# End session
# ---------------------------------------------------------------------

def test_end_session_success(agent, active_session):
    result = agent.end_session(active_session)
    assert result["success"] is True
    assert result["status"] == "completed"
    assert result["simulation_only"] is True


def test_end_session_reports_conversation_length(agent, active_session):
    result = agent.end_session(active_session)
    assert result["conversation_length"] == 2


def test_end_session_returns_detected_tactics(agent):
    started = agent.start_session("Please share your OTP.")
    ended = agent.end_session(started["session_id"])
    assert "otp_collection" in ended["detected_tactics"]


def test_end_session_removes_session_from_storage(agent, active_session):
    result = agent.end_session(active_session)
    assert result["success"] is True
    assert active_session not in agent.sessions


def test_end_session_frees_active_capacity(agent, active_session):
    agent.MAX_ACTIVE_SESSIONS = 1
    ended = agent.end_session(active_session)
    assert ended["success"] is True
    new_session = agent.start_session("A new simulation")
    assert new_session["success"] is True


def test_end_session_unknown_session(agent):
    result = agent.end_session("00000000-0000-4000-8000-000000000000")
    assert result["success"] is False
    assert result["error"]["code"] == "session_not_found"


def test_continue_after_end_fails(agent, active_session):
    agent.end_session(active_session)
    result = agent.continue_session(active_session, "Another message")
    assert result["success"] is False
    assert result["error"]["code"] == "session_not_found"


def test_end_session_twice_fails(agent, active_session):
    agent.end_session(active_session)
    result = agent.end_session(active_session)
    assert result["success"] is False
    assert result["error"]["code"] == "session_not_found"


# ---------------------------------------------------------------------
# Expiry and cleanup
# ---------------------------------------------------------------------

def test_expired_session_is_not_continued(agent, active_session):
    old = (datetime.now(timezone.utc) - timedelta(seconds=agent.SESSION_TTL_SECONDS + 5)).isoformat()
    agent.sessions[active_session]["last_activity_at"] = old

    result = agent.continue_session(active_session, "Are you there?")
    assert result["success"] is False
    assert result["error"]["code"] == "session_not_found"
    assert active_session not in agent.sessions


def test_expired_session_is_removed_by_cleanup(agent, active_session):
    old = (datetime.now(timezone.utc) - timedelta(seconds=agent.SESSION_TTL_SECONDS + 5)).isoformat()
    agent.sessions[active_session]["last_activity_at"] = old
    agent._cleanup_expired_sessions()
    assert active_session not in agent.sessions


def test_non_expired_session_survives_cleanup(agent, active_session):
    agent._cleanup_expired_sessions()
    assert active_session in agent.sessions


def test_cleanup_removes_session_with_missing_activity_timestamp(agent, active_session):
    del agent.sessions[active_session]["last_activity_at"]
    agent._cleanup_expired_sessions()
    assert active_session not in agent.sessions


def test_cleanup_removes_session_with_invalid_timestamp(agent, active_session):
    agent.sessions[active_session]["last_activity_at"] = "not-a-timestamp"
    agent._cleanup_expired_sessions()
    assert active_session not in agent.sessions


def test_lookup_removes_session_with_naive_timestamp(agent, active_session):
    old = (datetime.now(timezone.utc) - timedelta(seconds=agent.SESSION_TTL_SECONDS + 5))
    agent.sessions[active_session]["last_activity_at"] = old.replace(tzinfo=None).isoformat()
    result = agent.continue_session(active_session, "Continue")
    assert result["success"] is False
    assert active_session not in agent.sessions


# ---------------------------------------------------------------------
# Capacity handling
# ---------------------------------------------------------------------

def test_capacity_limit_reached(agent):
    agent.MAX_ACTIVE_SESSIONS = 1
    first = agent.start_session("First session")
    second = agent.start_session("Second session")
    assert first["success"] is True
    assert second["success"] is False
    assert second["error"]["code"] == "session_capacity_reached"
    assert len(agent.sessions) == 1


def test_expired_sessions_are_cleaned_before_capacity_check(agent):
    agent.MAX_ACTIVE_SESSIONS = 1
    first = agent.start_session("First session")
    old = (datetime.now(timezone.utc) - timedelta(seconds=agent.SESSION_TTL_SECONDS + 5)).isoformat()
    agent.sessions[first["session_id"]]["last_activity_at"] = old

    second = agent.start_session("Second session")
    assert second["success"] is True
    assert first["session_id"] not in agent.sessions


# ---------------------------------------------------------------------
# Error response and public wrappers
# ---------------------------------------------------------------------

def test_error_response_structure():
    result = DecoyAgent._error_response("session-id", "message", "error_code")
    assert result["success"] is False
    assert result["agent"] == "DecoyAgent"
    assert result["session_id"] == "session-id"
    assert result["simulation_only"] is True
    assert result["error"]["code"] == "error_code"
    assert result["error"]["message"] == "message"


def test_error_response_sanitizes_non_string_session_id():
    result = DecoyAgent._error_response(123, "message", "error_code")
    assert result["session_id"] is None


def test_start_public_function(monkeypatch):
    local_agent = DecoyAgent()
    monkeypatch.setattr("agents.decoy_agent.decoy_agent", local_agent)
    result = start_decoy_simulation("Please share your OTP.")
    assert result["success"] is True
    assert result["session_id"] in local_agent.sessions


def test_continue_public_function(monkeypatch):
    local_agent = DecoyAgent()
    started = local_agent.start_session("Hello")
    monkeypatch.setattr("agents.decoy_agent.decoy_agent", local_agent)
    result = continue_decoy_simulation(started["session_id"], "Send money")
    assert result["success"] is True


def test_end_public_function(monkeypatch):
    local_agent = DecoyAgent()
    started = local_agent.start_session("Hello")
    monkeypatch.setattr("agents.decoy_agent.decoy_agent", local_agent)
    result = end_decoy_simulation(started["session_id"])
    assert result["success"] is True
    assert result["status"] == "completed"


def test_public_singleton_is_decoy_agent():
    assert isinstance(decoy_agent, DecoyAgent)


# ---------------------------------------------------------------------
# Simulation safety and state integrity
# ---------------------------------------------------------------------

def test_start_never_claims_real_contact(agent):
    result = agent.start_session("Please send OTP")
    assert result["simulation_only"] is True
    assert "no real person" in result["safety_notice"].lower()


def test_continue_never_claims_real_communication(agent, active_session):
    result = agent.continue_session(active_session, "Pay now")
    assert result["simulation_only"] is True
    assert "no real communication" in result["safety_notice"].lower()


def test_session_history_has_expected_speakers(agent, active_session):
    result = agent.continue_session(active_session, "Another message")
    assert [item["speaker"] for item in result["conversation"]] == [
        "simulated_scammer",
        "simulated_victim",
        "simulated_scammer",
        "simulated_victim",
    ]


def test_each_history_entry_has_timestamp(agent, active_session):
    result = agent.continue_session(active_session, "Another message")
    for item in result["conversation"]:
        assert "timestamp" in item
        datetime.fromisoformat(item["timestamp"])


def test_sessions_are_isolated(agent):
    first = agent.start_session("First message")
    second = agent.start_session("Second message")
    agent.continue_session(first["session_id"], "First follow-up")

    assert len(agent.sessions[first["session_id"]]["history"]) == 4
    assert len(agent.sessions[second["session_id"]]["history"]) == 2


def test_session_tactics_are_isolated(agent):
    first = agent.start_session("Share your OTP.")
    second = agent.start_session("The weather is nice.")

    assert "otp_collection" in agent.sessions[first["session_id"]]["detected_tactics"]
    assert agent.sessions[second["session_id"]]["detected_tactics"] == []


def test_session_tactics_are_not_lost_on_continue(agent):
    started = agent.start_session("Share your OTP.")
    result = agent.continue_session(started["session_id"], "I am a police officer.")
    assert "otp_collection" in result["all_detected_tactics"]
    assert "impersonation" in result["all_detected_tactics"]


def test_response_priority_order_is_unique():
    assert len(DecoyAgent.RESPONSE_PRIORITY) == len(set(DecoyAgent.RESPONSE_PRIORITY))


def test_all_priority_tactics_are_defined():
    assert set(DecoyAgent.RESPONSE_PRIORITY).issubset(set(DecoyAgent.SCAM_TACTICS))


def test_all_tactic_keyword_lists_are_nonempty():
    assert all(
        isinstance(keywords, list) and keywords
        for keywords in DecoyAgent.SCAM_TACTICS.values()
    )


def test_all_tactic_keywords_are_strings():
    assert all(
        isinstance(keyword, str) and keyword.strip()
        for keywords in DecoyAgent.SCAM_TACTICS.values()
        for keyword in keywords
    )
# ---------------------------------------------------------------------
# Additional edge-case audit
# ---------------------------------------------------------------------

def test_negated_otp_request_is_not_detected(agent):
    message = "I will not share my OTP with anyone."
    assert "otp_collection" not in agent._detect_tactics(message)


def test_educational_otp_warning_is_not_detected(agent):
    message = "Never share your OTP with anyone."
    assert "otp_collection" not in agent._detect_tactics(message)


def test_educational_phishing_warning_is_not_detected(agent):
    message = "Do not click unknown links or share banking details."
    detected = agent._detect_tactics(message)

    assert "suspicious_link" not in detected
    assert "personal_information_collection" not in detected


def test_uppercase_uuid_can_continue_session(agent, active_session):
    uppercase_id = active_session.upper()

    result = agent.continue_session(uppercase_id, "Another message")

    assert result["success"] is True


def test_uppercase_uuid_can_end_session(agent, active_session):
    uppercase_id = active_session.upper()

    result = agent.end_session(uppercase_id)

    assert result["success"] is True
    assert active_session not in agent.sessions


def test_concurrent_session_continuations_preserve_history(agent, active_session):
    from concurrent.futures import ThreadPoolExecutor

    messages = [f"Concurrent message {index}" for index in range(6)]

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(
            executor.map(
                lambda message: agent.continue_session(active_session, message),
                messages
            )
        )

    assert all(result["success"] is True for result in results)
    assert len(agent.sessions[active_session]["history"]) == 14


def test_normal_banking_discussion_does_not_trigger_tactics(agent):
    message = (
        "I am learning about online banking security "
        "and how authentication systems protect users."
    )

    assert agent._detect_tactics(message) == []