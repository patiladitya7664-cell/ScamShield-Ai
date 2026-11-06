"""
=========================================================
SCAMSHIELD AI - DECOY AGENT
=========================================================

Version: 1.1.0

Purpose:
    1. Simulate controlled conversations for scam analysis.
    2. Generate safe simulated responses.
    3. Identify possible scammer tactics.
    4. Maintain simulated conversation history.
    5. Manage session expiry and lifecycle.
    6. Provide structured simulation results.
    7. Handle basic negation and protective warnings.
    8. Normalize session UUIDs.

IMPORTANT:
    Simulation mode only.
    No real scammers or external services are contacted.

=========================================================
"""

import re
import threading

from copy import deepcopy
from datetime import datetime, timezone, timedelta
from time import perf_counter
from typing import Any, Dict, List
from uuid import UUID, uuid4

from utils.logger import (
    decoy_logger,
    log_agent_execution,
)


class DecoyAgent:

    AGENT_NAME = "DecoyAgent"
    AGENT_VERSION = "1.1.0"

    MAX_MESSAGE_LENGTH = 5000
    MAX_HISTORY_LENGTH = 20

    MAX_ACTIVE_SESSIONS = 500
    SESSION_TTL_SECONDS = 3600

    SIMULATION_ONLY = True

    # =====================================================
    # PROTECTIVE / NEGATION PATTERNS
    # =====================================================

    PROTECTIVE_CONTEXT_PATTERN = re.compile(
        r"""
        (?:
            \bnever\b
            |
            \bdo\s+not\b
            |
            \bdon't\b
            |
            \bdont\b
            |
            \bwill\s+not\b
            |
            \bwon't\b
            |
            \bcannot\b
            |
            \bcan't\b
            |
            \bshould\s+not\b
            |
            \bshouldn't\b
            |
            \bmust\s+not\b
        )
        \s+
        (?:
            share
            |
            send
            |
            give
            |
            provide
            |
            disclose
            |
            reveal
            |
            tell
            |
            enter
            |
            submit
            |
            forward
            |
            click
            |
            open
            |
            install
            |
            transfer
            |
            pay
        )
        \b
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    # =====================================================
    # SCAM TACTIC KEYWORDS
    # =====================================================

    SCAM_TACTICS = {

        "urgency": [
            "immediately",
            "urgent",
            "right now",
            "last chance",
            "within 24 hours",
            "act now",
            "limited time",
            "abhi",
            "turant",
            "jaldi karo",
            "aaj hi",
            "abhi karo",
            "der mat karo",
        ],

        "otp_collection": [
            "otp",
            "verification code",
            "one time password",
            "share your otp",
            "send your otp",
            "otp bataiye",
            "otp bhejo",
            "otp batao",
            "code share karo",
        ],

        "financial_pressure": [
            "send money",
            "transfer money",
            "pay now",
            "processing fee",
            "payment required",
            "transfer funds",
            "make payment",
            "paise bhejo",
            "paisa transfer karo",
            "payment karo",
            "paise transfer karo",
        ],

        "impersonation": [
            "police officer",
            "cyber crime officer",
            "bank manager",
            "government officer",
            "rbi officer",
            "customs officer",
            "cbi officer",
            "income tax officer",
            "government department",
            "police department",
        ],

        "threats": [
            "arrest",
            "arrested",
            "will be arrested",
            "get arrested",
            "jail",
            "go to jail",
            "sent to jail",
            "police case",
            "legal action",
            "legal consequences",
            "criminal case",
            "warrant",
            "arrest warrant",
            "account blocked",
            "account will be blocked",
            "will be blocked",
            "account block",
            "block your account",
            "account freeze",
            "account frozen",
            "freeze your account",
            "bank account blocked",
            "bank account freeze",
            "digital arrest",
            "digital custody",
            "police custody",
            "you will be punished",
            "serious consequences",
            "face consequences",
            "we will take action",
            "police will arrest",
            "police will come",
            "giraftar kar lenge",
            "jail bhej denge",
            "account band kar denge",
            "account block kar denge",
            "police case hoga",
            "case darj hoga",
            "legal action lenge",
        ],

        "suspicious_link": [
            "click this link",
            "open this link",
            "verify your account",
            "download this app",
            "click here",
            "verification link",
            "visit this link",
            "open this url",
            "link par click",
            "link kholo",
        ],

        "remote_access": [
            "anydesk",
            "teamviewer",
            "remote access",
            "screen sharing",
            "screen share",
            "give me access",
            "remote control",
            "install remote app",
            "device access",
            "phone control",
        ],

        "investment_manipulation": [
            "guaranteed returns",
            "double your money",
            "risk free investment",
            "guaranteed profit",
            "daily profit",
            "sure shot returns",
            "fixed returns",
            "assured returns",
            "100 percent profit",
            "daily income",
        ],

        "job_or_loan_fee": [
            "job registration fee",
            "pay registration fee",
            "loan processing fee",
            "advance loan fee",
            "job confirmation fee",
            "placement fee",
            "interview fee",
            "job joining fee",
            "loan approval fee",
            "advance payment for job",
        ],

        "personal_information_collection": [
            "share your aadhaar",
            "share your pan",
            "card number",
            "cvv",
            "bank details",
            "account number",
            "password",
            "share your password",
            "debit card details",
            "credit card details",
            "personal information",
            "identity documents",
        ],

        "blackmail": [
            "leak your photos",
            "leak your private photos",
            "leak private photos",
            "leak your video",
            "leak your private video",
            "private video",
            "private photos",
            "private pictures",
            "intimate photos",
            "intimate video",
            "expose your pictures",
            "expose your photos",
            "expose your video",
            "share your private photos",
            "share your private video",
            "publish your photos",
            "post your private photos",
            "make your photos public",
            "send your photos to everyone",
            "pay or i will expose",
            "pay me or",
            "pay or i will leak",
            "otherwise i will expose",
            "otherwise i will leak",
            "i will make it viral",
            "make it viral",
            "viral your photos",
            "photos viral kar dunga",
            "video viral kar dunga",
            "photo leak kar dunga",
            "video leak kar dunga",
            "sabko bhej dunga",
            "paise nahi diye toh",
        ],

    }

    # =====================================================
    # RESPONSE PRIORITY
    # =====================================================

    RESPONSE_PRIORITY = [
        "blackmail",
        "otp_collection",
        "personal_information_collection",
        "remote_access",
        "threats",
        "financial_pressure",
        "job_or_loan_fee",
        "investment_manipulation",
        "suspicious_link",
        "impersonation",
        "urgency",
    ]

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self):

        self.sessions: Dict[str, Dict[str, Any]] = {}

        self._lock = threading.RLock()

    # =====================================================
    # START SIMULATION
    # =====================================================

    def start_session(self, scam_message: str) -> Dict[str, Any]:

        start_time = perf_counter()
        session_id = str(uuid4())

        try:

            scam_message = self._validate_message(scam_message)

            with self._lock:

                self._cleanup_expired_sessions()

                if len(self.sessions) >= self.MAX_ACTIVE_SESSIONS:

                    return self._error_response(
                        session_id,
                        "Maximum active simulation sessions reached.",
                        "session_capacity_reached",
                    )

                detected_tactics = self._detect_tactics(scam_message)

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

            duration_ms = self._duration_ms(start_time)

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
                "agent_version": self.AGENT_VERSION,
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
                    "session_expiry_seconds": self.SESSION_TTL_SECONDS,
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

    # =====================================================
    # CONTINUE SIMULATION
    # =====================================================

    def continue_session(
        self,
        session_id: str,
        scam_message: str,
    ) -> Dict[str, Any]:

        start_time = perf_counter()

        try:

            session_id = self._validate_session_id(session_id)
            scam_message = self._validate_message(scam_message)

            with self._lock:

                session = self._get_active_session(session_id)

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

                if (
                    len(session["history"]) + 2
                    > self.MAX_HISTORY_LENGTH
                ):

                    return self._error_response(
                        session_id,
                        "Simulation conversation limit reached.",
                        "history_limit_reached",
                    )

                detected_tactics = self._detect_tactics(scam_message)

                simulated_response = self._generate_response(
                    detected_tactics
                )

                session["history"].append({
                    "speaker": "simulated_scammer",
                    "message": scam_message,
                    "timestamp": self._timestamp(),
                })

                session["history"].append({
                    "speaker": "simulated_victim",
                    "message": simulated_response,
                    "timestamp": self._timestamp(),
                })

                session["detected_tactics"] = sorted(
                    set(
                        session["detected_tactics"]
                        + detected_tactics
                    )
                )

                session["last_activity_at"] = self._timestamp()

                conversation = deepcopy(session["history"])
                all_tactics = list(session["detected_tactics"])

            duration_ms = self._duration_ms(start_time)

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Simulation continued | "
                    f"Session ID: {session_id} | "
                    f"History entries: {len(conversation)}"
                ),
            )

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "agent_version": self.AGENT_VERSION,
                "session_id": session_id,
                "status": "active",
                "simulation_only": True,
                "detected_tactics": detected_tactics,
                "all_detected_tactics": all_tactics,
                "simulated_response": simulated_response,
                "conversation": conversation,

                "safety_notice": (
                    "All conversation entries are simulated locally. "
                    "No real communication takes place."
                ),

                "metadata": {
                    "duration_ms": duration_ms,
                    "history_length": len(conversation),
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

    # =====================================================
    # PROTECTIVE CONTEXT CHECK
    # =====================================================

    @classmethod
    def _is_protective_context(cls, text: str, match_start: int) -> bool:
        """
        Detect protective or educational instructions within the
        current sentence, rather than checking only text before a match.
        """
        if not isinstance(text, str):
            return False

        # Find the current sentence boundaries.
        delimiters = ".!?;\n"

        clause_start = 0
        for delimiter in delimiters:
            position = text.rfind(delimiter, 0, match_start)
            if position >= 0:
                clause_start = max(clause_start, position + 1)

        clause_end = len(text)

        for delimiter in delimiters:
            position = text.find(delimiter, match_start)
            if position >= 0:
                clause_end = min(clause_end, position)

        clause = text[clause_start:clause_end].strip()

        return bool(
            cls.PROTECTIVE_CONTEXT_PATTERN.search(clause)
        )
    # =====================================================
    # DETECT SCAM TACTICS
    # =====================================================

    def _detect_tactics(
        self,
        message: str,
    ) -> List[str]:

        if not isinstance(message, str) or not message:
            return []

        text = message.lower()

        detected = []

        for tactic, keywords in self.SCAM_TACTICS.items():

            for keyword in keywords:

                pattern = (
                    r"(?<!\w)"
                    + re.escape(keyword.lower())
                    + r"(?!\w)"
                )

                match = re.search(pattern, text)

                if not match:
                    continue

                # Ignore basic protective/negated statements.
                if self._is_protective_context(
                    text,
                    match.start(),
                ):
                    continue

                detected.append(tactic)
                break

        return detected

    # =====================================================
    # GENERATE SAFE SIMULATED RESPONSE
    # =====================================================

    @classmethod
    def _generate_response(
        cls,
        detected_tactics: List[str],
    ) -> str:

        tactics = set(detected_tactics)

        if not tactics:

            return (
                "I will independently verify this message "
                "before sharing information or taking any action."
            )

        for tactic in cls.RESPONSE_PRIORITY:

            if tactic not in tactics:
                continue

            if tactic == "blackmail":

                return (
                    "I will not pay or respond to blackmail demands. "
                    "I will preserve the evidence and seek help "
                    "through appropriate official channels."
                )

            if tactic == "otp_collection":

                return (
                    "I cannot share any OTP or verification code. "
                    "I will verify this request through the official "
                    "service provider."
                )

            if tactic == "personal_information_collection":

                return (
                    "I will not share my banking details, card "
                    "information, passwords or identity documents "
                    "through an unverified communication."
                )

            if tactic == "remote_access":

                return (
                    "I will not install remote-access software or "
                    "share control of my device."
                )

            if tactic == "threats":

                return (
                    "I will verify this claim with the relevant "
                    "official authority. I will not act under pressure."
                )

            if tactic == "financial_pressure":

                return (
                    "I will not transfer money without independently "
                    "verifying the request through official channels."
                )

            if tactic == "job_or_loan_fee":

                return (
                    "I will verify the employer or lender independently. "
                    "I will not pay an advance fee for an unverified offer."
                )

            if tactic == "investment_manipulation":

                return (
                    "I will independently verify the investment and "
                    "its risks. I will not trust guaranteed-return claims."
                )

            if tactic == "suspicious_link":

                return (
                    "I will not open unknown links. I will visit the "
                    "official website independently if verification "
                    "is necessary."
                )

            if tactic == "impersonation":

                return (
                    "Please provide an official reference. I will "
                    "independently contact the organization to verify "
                    "your identity."
                )

            if tactic == "urgency":

                return (
                    "I need time to verify this request. I will not "
                    "take action under artificial urgency."
                )

        return (
            "I will independently verify this communication "
            "before taking any action."
        )

    # =====================================================
    # END SIMULATION
    # =====================================================

    def end_session(
        self,
        session_id: str,
    ) -> Dict[str, Any]:

        try:

            session_id = self._validate_session_id(session_id)

            with self._lock:

                session = self._get_active_session(session_id)

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

                conversation_length = len(session["history"])
                detected_tactics = list(session["detected_tactics"])

                self.sessions.pop(session_id, None)

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Simulation completed | "
                    f"Session ID: {session_id} | "
                    f"History entries: {conversation_length}"
                ),
            )

            return {
                "success": True,
                "agent": self.AGENT_NAME,
                "session_id": session_id,
                "status": "completed",
                "simulation_only": True,
                "conversation_length": conversation_length,
                "detected_tactics": detected_tactics,
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

    # =====================================================
    # SESSION VALIDATION
    # =====================================================

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

            # Return canonical lowercase UUID.
            return str(UUID(session_id))

        except (ValueError, AttributeError, TypeError):

            raise ValueError(
                "Invalid session ID format."
            )

    # =====================================================
    # MESSAGE VALIDATION
    # =====================================================

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

    # =====================================================
    # SESSION LOOKUP
    # =====================================================

    def _get_active_session(
        self,
        session_id: str,
    ):

        session = self.sessions.get(session_id)

        if not session:
            return None

        try:

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

        except (KeyError, TypeError, ValueError):

            self.sessions.pop(session_id, None)
            return None

        return session

    # =====================================================
    # EXPIRED SESSION CLEANUP
    # =====================================================

    def _cleanup_expired_sessions(self) -> None:

        now = datetime.now(timezone.utc)

        expired_sessions = []

        for session_id, session in list(self.sessions.items()):

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
                f"Expired sessions cleaned: {len(expired_sessions)}",
            )

    # =====================================================
    # TIMESTAMP
    # =====================================================

    @staticmethod
    def _timestamp() -> str:

        return datetime.now(timezone.utc).isoformat()

    # =====================================================
    # DURATION
    # =====================================================

    @staticmethod
    def _duration_ms(start_time: float) -> float:

        return round(
            (perf_counter() - start_time) * 1000,
            2,
        )

    # =====================================================
    # ERROR RESPONSE
    # =====================================================

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

    return decoy_agent.start_session(scam_message)


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

    return decoy_agent.end_session(session_id)