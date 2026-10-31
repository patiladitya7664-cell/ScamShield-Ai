
"""
=========================================================
SCAMSHIELD AI - DECOY AGENT
=========================================================

Purpose:
- Simulate controlled conversations for scam analysis.
- Generate safe decoy responses.
- Identify possible scammer tactics.
- Maintain simulated conversation history.
- Never contact real scammers or external services.

IMPORTANT:
This agent operates in simulation mode only.
=========================================================
"""

import re
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from time import perf_counter
from typing import Any, Dict, List
from uuid import uuid4

from utils.logger import decoy_logger, log_agent_execution


class DecoyAgent:

    AGENT_NAME = "DecoyAgent"
    AGENT_VERSION = "1.0.0"

    MAX_MESSAGE_LENGTH = 5000
    MAX_HISTORY_LENGTH = 20

    MAX_ACTIVE_SESSIONS = 500
    SESSION_TTL_SECONDS = 3600

    SIMULATION_ONLY = True

    # -----------------------------------------------------
    # SCAM TACTIC KEYWORDS
    # -----------------------------------------------------

    SCAM_TACTICS = {
        "urgency": [
            "immediately",
            "urgent",
            "right now",
            "last chance",
            "within 24 hours",
            "abhi",
            "turant",
        ],

        "otp_collection": [
            "otp",
            "verification code",
            "one time password",
        ],

        "financial_pressure": [
            "send money",
            "transfer money",
            "pay now",
            "processing fee",
            "payment required",
            "paise bhejo",
        ],

        "impersonation": [
            "police officer",
            "cyber crime officer",
            "bank manager",
            "government officer",
            "rbi officer",
            "customs officer",
        ],

        "threats": [
            "arrest",
            "jail",
            "account blocked",
            "legal action",
            "digital arrest",
            "warrant",
        ],

        "suspicious_link": [
            "click this link",
            "open this link",
            "verify your account",
            "download this app",
        ],

        "remote_access": [
            "anydesk",
            "teamviewer",
            "remote access",
            "screen sharing",
        ],
    }

    # -----------------------------------------------------
    # INITIALIZATION
    # -----------------------------------------------------

    def __init__(self):

        self.sessions: Dict[str, Dict[str, Any]] = {}

    # -----------------------------------------------------
    # START SIMULATION
    # -----------------------------------------------------

    def start_session(
        self,
        scam_message: str,
    ) -> Dict[str, Any]:

        start_time = perf_counter()
        session_id = str(uuid4())

        try:

            scam_message = self._validate_message(
                scam_message
            )

            self._cleanup_expired_sessions()

            if len(self.sessions) >= self.MAX_ACTIVE_SESSIONS:

                return self._error_response(
                    session_id,
                    "Maximum active simulation sessions reached.",
                    "session_capacity_reached",
                )

            detected_tactics = self._detect_tactics(
                scam_message
            )

            simulated_response = self._generate_response(
                detected_tactics
            )

            created_at = self._timestamp()

            session = {
                "session_id": session_id,
                "status": "active",
                "simulation_only": True,

                "history": [
                    {
                        "speaker": "simulated_scammer",
                        "message": scam_message,
                        "timestamp": created_at,
                    },
                    {
                        "speaker": "simulated_victim",
                        "message": simulated_response,
                        "timestamp": self._timestamp(),
                    },
                ],

                "detected_tactics": detected_tactics,
                "created_at": created_at,
                "last_activity_at": created_at,
            }

            self.sessions[session_id] = session

            duration_ms = round(
                (perf_counter() - start_time) * 1000,
                2,
            )

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Simulation started | "
                    f"Session ID: {session_id} | "
                    f"Tactics detected: {len(detected_tactics)}"
                ),
            )

            return {
                "success": True,

                "agent": self.AGENT_NAME,

                "session_id": session_id,

                "status": "active",

                "simulation_only": True,

                "detected_tactics": detected_tactics,

                "simulated_response": simulated_response,

                "conversation": deepcopy(session["history"]),

                "safety_notice": (
                    "This is a fictional simulation. "
                    "No real person or external service was contacted."
                ),

                "metadata": {
                    "duration_ms": duration_ms,
                    "created_at": created_at,
                    "session_expiry_seconds": (
                        self.SESSION_TTL_SECONDS
                    ),
                },
            }

        except ValueError as error:

            return self._error_response(
                session_id,
                str(error),
                "invalid_input",
            )

        except Exception:

            decoy_logger.exception(
                "Decoy simulation failed | session_id=%s",
                session_id,
            )

            log_agent_execution(
                self.AGENT_NAME,
                "ERROR",
                f"Simulation start failed | Session ID: {session_id}",
            )

            return self._error_response(
                session_id,
                "Simulation could not be started.",
                "simulation_failed",
            )

    # -----------------------------------------------------
    # CONTINUE SIMULATION
    # -----------------------------------------------------

    def continue_session(
        self,
        session_id: str,
        scam_message: str,
    ) -> Dict[str, Any]:

        start_time = perf_counter()

        try:

            session_id = self._validate_session_id(
                session_id
            )

            scam_message = self._validate_message(
                scam_message
            )

            session = self._get_active_session(
                session_id
            )

            if not session:

                return self._error_response(
                    session_id,
                    "Simulation session not found or expired.",
                    "session_not_found",
                )

            if session["status"] != "active":

                return self._error_response(
                    session_id,
                    "Simulation session is not active.",
                    "session_inactive",
                )

            # Two entries are added per conversation turn.
            # Check both before modifying session history.

            if (
                len(session["history"]) + 2
                > self.MAX_HISTORY_LENGTH
            ):

                return self._error_response(
                    session_id,
                    "Simulation conversation limit reached.",
                    "history_limit_reached",
                )

            detected_tactics = self._detect_tactics(
                scam_message
            )

            simulated_response = self._generate_response(
                detected_tactics
            )

            session["history"].append(
                {
                    "speaker": "simulated_scammer",
                    "message": scam_message,
                    "timestamp": self._timestamp(),
                }
            )

            session["history"].append(
                {
                    "speaker": "simulated_victim",
                    "message": simulated_response,
                    "timestamp": self._timestamp(),
                }
            )

            session["detected_tactics"] = sorted(
                set(
                    session["detected_tactics"]
                    + detected_tactics
                )
            )

            session["last_activity_at"] = self._timestamp()

            duration_ms = round(
                (perf_counter() - start_time) * 1000,
                2,
            )

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Simulation continued | "
                    f"Session ID: {session_id} | "
                    f"History entries: {len(session['history'])}"
                ),
            )

            return {
                "success": True,

                "agent": self.AGENT_NAME,

                "session_id": session_id,

                "status": session["status"],

                "simulation_only": True,

                "detected_tactics": detected_tactics,

                "all_detected_tactics": (
                    session["detected_tactics"]
                ),

                "simulated_response": simulated_response,

                "conversation": deepcopy(session["history"]),

                "safety_notice": (
                    "All conversation entries are simulated locally. "
                    "No real communication takes place."
                ),

                "metadata": {
                    "duration_ms": duration_ms,
                    "history_length": len(session["history"]),
                },
            }

        except ValueError as error:

            return self._error_response(
                session_id,
                str(error),
                "invalid_input",
            )

        except Exception:

            decoy_logger.exception(
                "Decoy session continuation failed | session_id=%s",
                session_id,
            )

            log_agent_execution(
                self.AGENT_NAME,
                "ERROR",
                f"Simulation continuation failed | Session ID: {session_id}",
            )

            return self._error_response(
                session_id,
                "Simulation could not be continued.",
                "simulation_failed",
            )

    # -----------------------------------------------------
    # DETECT SCAM TACTICS
    # -----------------------------------------------------

    def _detect_tactics(
        self,
        message: str,
    ) -> List[str]:

        text = message.lower()

        detected = []

        for tactic, keywords in self.SCAM_TACTICS.items():

            for keyword in keywords:

                pattern = (
                    r"(?<!\w)"
                    + re.escape(keyword.lower())
                    + r"(?!\w)"
                )

                if re.search(pattern, text):

                    detected.append(tactic)
                    break

        return detected

    # -----------------------------------------------------
    # GENERATE SAFE SIMULATED RESPONSE
    # -----------------------------------------------------

    @staticmethod
    def _generate_response(
        detected_tactics: List[str],
    ) -> str:

        if "otp_collection" in detected_tactics:

            return (
                "I cannot share any OTP or verification code. "
                "I will verify this request through the official "
                "service provider."
            )

        if "financial_pressure" in detected_tactics:

            return (
                "I will not transfer money without independently "
                "verifying the request through official channels."
            )

        if "threats" in detected_tactics:

            return (
                "I will verify this claim with the relevant official "
                "authority. I will not act under pressure."
            )

        if "remote_access" in detected_tactics:

            return (
                "I will not install remote-access software or "
                "share control of my device."
            )

        if "suspicious_link" in detected_tactics:

            return (
                "I will not open unknown links. I will visit the "
                "official website independently if verification "
                "is necessary."
            )

        if "impersonation" in detected_tactics:

            return (
                "Please provide an official reference. I will "
                "independently contact the organization to verify "
                "your identity."
            )

        if "urgency" in detected_tactics:

            return (
                "I need time to verify this request. I will not "
                "take action under artificial urgency."
            )

        return (
            "I will independently verify this message before "
            "sharing information or taking any action."
        )

    # -----------------------------------------------------
    # END SIMULATION
    # -----------------------------------------------------

    def end_session(
        self,
        session_id: str,
    ) -> Dict[str, Any]:

        try:

            session_id = self._validate_session_id(
                session_id
            )

            session = self._get_active_session(
                session_id
            )

            if not session:

                return self._error_response(
                    session_id,
                    "Simulation session not found or expired.",
                    "session_not_found",
                )

            if session["status"] != "active":

                return self._error_response(
                    session_id,
                    "Simulation session is already completed.",
                    "session_inactive",
                )

            session["status"] = "completed"

            session["ended_at"] = self._timestamp()

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Simulation completed | "
                    f"Session ID: {session_id} | "
                    f"History entries: {len(session['history'])}"
                ),
            )

            return {
                "success": True,

                "agent": self.AGENT_NAME,

                "session_id": session_id,

                "status": "completed",

                "simulation_only": True,

                "conversation_length": len(
                    session["history"]
                ),

                "detected_tactics": (
                    session["detected_tactics"]
                ),

                "message": "Simulation session completed.",
            }

        except ValueError as error:

            return self._error_response(
                session_id,
                str(error),
                "invalid_input",
            )

        except Exception:

            decoy_logger.exception(
                "Decoy session termination failed | session_id=%s",
                session_id,
            )

            log_agent_execution(
                self.AGENT_NAME,
                "ERROR",
                f"Simulation termination failed | Session ID: {session_id}",
            )

            return self._error_response(
                session_id,
                "Simulation could not be completed.",
                "simulation_failed",
            )

    # -----------------------------------------------------
    # SESSION VALIDATION
    # -----------------------------------------------------

    @staticmethod
    def _validate_session_id(
        session_id: str,
    ) -> str:

        if not isinstance(session_id, str):
            raise ValueError(
                "Session ID must be a string."
            )

        session_id = session_id.strip()

        if not session_id:
            raise ValueError(
                "Session ID cannot be empty."
            )

        try:
            uuid4_value = session_id

            # Validate UUID format.
            from uuid import UUID
            UUID(uuid4_value)

        except (ValueError, AttributeError):
            raise ValueError(
                "Invalid session ID format."
            )

        return session_id

    # -----------------------------------------------------
    # MESSAGE VALIDATION
    # -----------------------------------------------------

    def _validate_message(
        self,
        message: str,
    ) -> str:

        if not isinstance(message, str):
            raise ValueError(
                "Message must be a string."
            )

        message = message.strip()

        if not message:
            raise ValueError(
                "Message cannot be empty."
            )

        if len(message) > self.MAX_MESSAGE_LENGTH:
            raise ValueError(
                "Message exceeds the maximum length."
            )

        return message

    # -----------------------------------------------------
    # SESSION LOOKUP
    # -----------------------------------------------------

    def _get_active_session(
        self,
        session_id: str,
    ):

        session = self.sessions.get(session_id)

        if not session:
            return None

        last_activity = datetime.fromisoformat(
            session["last_activity_at"]
        )

        expiry_time = (
            last_activity
            + timedelta(seconds=self.SESSION_TTL_SECONDS)
        )

        if datetime.now(timezone.utc) >= expiry_time:

            self.sessions.pop(session_id, None)

            return None

        return session

    # -----------------------------------------------------
    # EXPIRED SESSION CLEANUP
    # -----------------------------------------------------

    def _cleanup_expired_sessions(self) -> None:

        now = datetime.now(timezone.utc)

        expired_sessions = []

        for session_id, session in self.sessions.items():

            try:

                last_activity = datetime.fromisoformat(
                    session["last_activity_at"]
                )

                expiry_time = (
                    last_activity
                    + timedelta(seconds=self.SESSION_TTL_SECONDS)
                )

                if now >= expiry_time:
                    expired_sessions.append(session_id)

            except (KeyError, TypeError, ValueError):

                expired_sessions.append(session_id)

        for session_id in expired_sessions:

            self.sessions.pop(session_id, None)

        if expired_sessions:

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Expired sessions cleaned: "
                    f"{len(expired_sessions)}"
                ),
            )

    # -----------------------------------------------------
    # TIMESTAMP
    # -----------------------------------------------------

    @staticmethod
    def _timestamp() -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()

    # -----------------------------------------------------
    # ERROR RESPONSE
    # -----------------------------------------------------

    @staticmethod
    def _error_response(
        session_id: Any,
        message: str,
        error_code: str,
    ) -> Dict[str, Any]:

        return {
            "success": False,

            "agent": "DecoyAgent",

            "session_id": (
                session_id
                if isinstance(session_id, str)
                else None
            ),

            "simulation_only": True,

            "error": {
                "code": error_code,
                "message": message,
            },
        }


# =========================================================
# REUSABLE AGENT INSTANCE
# =========================================================

decoy_agent = DecoyAgent()


# =========================================================
# PUBLIC FUNCTIONS
# =========================================================

def start_decoy_simulation(
    scam_message: str,
) -> Dict[str, Any]:

    return decoy_agent.start_session(
        scam_message
    )


def continue_decoy_simulation(
    session_id: str,
    scam_message: str,
) -> Dict[str, Any]:

    return decoy_agent.continue_session(
        session_id,
        scam_message,
    )


def end_decoy_simulation(
    session_id: str,
) -> Dict[str, Any]:

    return decoy_agent.end_session(
        session_id
    )
