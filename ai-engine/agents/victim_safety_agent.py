
"""
=========================================================
SCAMSHIELD AI - VICTIM SAFETY AGENT
=========================================================

Responsibilities:
- Identify possible victim exposure.
- Generate immediate safety recommendations.
- Prioritize financial and account protection.
- Use Guardian risk signals as supporting context.
- Provide emergency guidance.
- Never perform financial or account actions automatically.

=========================================================
"""

from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, List, Optional
from uuid import uuid4

from utils.logger import (
    victim_safety_logger,
    log_agent_execution,
)


class VictimSafetyAgent:

    AGENT_NAME = "VictimSafetyAgent"
    AGENT_VERSION = "1.0.0"

    MAX_EVIDENCE_LENGTH = 20000

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    SUPPORTED_RISK_LEVELS = {
        "UNKNOWN",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    # -----------------------------------------------------
    # EXPOSURE KEYWORDS
    # -----------------------------------------------------

    EXPOSURE_KEYWORDS = {
        "otp_shared": [
            "shared otp",
            "share otp",
            "otp shared",
            "told otp",
            "gave otp",
            "otp bata diya",
            "otp share kar diya",
        ],

        "bank_details_shared": [
            "shared bank details",
            "bank details shared",
            "shared account number",
            "shared card details",
            "card number shared",
            "bank details de diye",
        ],

        "password_shared": [
            "shared password",
            "password shared",
            "told my password",
            "password de diya",
        ],

        "payment_made": [
            "made payment",
            "sent money",
            "transferred money",
            "money transferred",
            "payment completed",
            "paise bhej diye",
            "payment kar diya",
        ],

        "suspicious_link_opened": [
            "opened suspicious link",
            "clicked suspicious link",
            "clicked the link",
            "link open kiya",
            "link par click kiya",
        ],

        "remote_access_granted": [
            "installed remote access",
            "installed anydesk",
            "installed teamviewer",
            "gave remote access",
            "screen sharing enabled",
            "remote access de diya",
        ],
    }

    # Guardian signals that indicate a possible sensitive request.
    # These do NOT prove that the victim actually shared information.

    SENSITIVE_REQUEST_SIGNALS = {
        "otp_or_credential_request",
        "financial_pressure",
        "remote_access_request",
        "threat_or_intimidation",
        "impersonation",
        "suspicious_link",
    }

    # -----------------------------------------------------
    # INITIALIZATION
    # -----------------------------------------------------

    def __init__(self):
        self.recommendations = self._build_recommendations()

    # -----------------------------------------------------
    # MAIN ANALYSIS
    # -----------------------------------------------------

    def analyze(
        self,
        evidence: str,
        risk_level: str = "UNKNOWN",
        risk_score: Optional[int] = None,
        detected_signals: Optional[List[str]] = None,
        evidence_type: str = "message",
        reported_exposures: Optional[List[str]] = None,
    ) -> Dict[str, Any]:

        start_time = perf_counter()
        analysis_id = str(uuid4())

        try:

            evidence, risk_level, evidence_type = (
                self._validate_input(
                    evidence,
                    risk_level,
                    risk_score,
                    evidence_type,
                    detected_signals,
                    reported_exposures,
                )
            )

            normalized_signals = self._normalize_signals(
                detected_signals
            )

            # ---------------------------------------------
            # EXPOSURE DETECTION
            # ---------------------------------------------

            exposure = self._detect_exposures(
                evidence,
                reported_exposures,
            )

            # ---------------------------------------------
            # SAFETY ASSESSMENT
            # ---------------------------------------------

            safety_level = self._determine_safety_level(
                risk_level,
                risk_score,
                exposure,
                normalized_signals,
            )

            immediate_actions = self._get_immediate_actions(
                exposure
            )

            general_actions = self._get_general_actions(
                safety_level
            )

            emergency_guidance = self._get_emergency_guidance(
                exposure
            )

            duration_ms = round(
                (perf_counter() - start_time) * 1000,
                2,
            )

            result = {
                "success": True,

                "agent": {
                    "name": self.AGENT_NAME,
                    "version": self.AGENT_VERSION,
                    "status": "completed",
                },

                "analysis_id": analysis_id,

                "safety_assessment": {
                    "safety_level": safety_level,

                    "risk_level_received": risk_level,

                    "risk_score_received": risk_score,

                    "detected_exposures": exposure,

                    "detected_risk_signals": normalized_signals,

                    "sensitive_request_detected": (
                        self._has_sensitive_request(
                            normalized_signals
                        )
                    ),

                    "potentially_compromised": bool(exposure),
                },

                "immediate_actions": immediate_actions,

                "recommended_actions": general_actions,

                "emergency_guidance": emergency_guidance,

                "important_notice": (
                    "These recommendations are precautionary. "
                    "The agent cannot confirm whether an account, "
                    "device or financial transaction is compromised. "
                    "Detected scam signals do not prove that the "
                    "victim has shared sensitive information."
                ),

                "metadata": {
                    "evidence_type": evidence_type,

                    "analysis_method": "rule_based_safety_assessment",

                    "created_at": datetime.now(
                        timezone.utc
                    ).isoformat(),

                    "duration_ms": duration_ms,
                },
            }

            # ---------------------------------------------
            # EXECUTION LOGGING
            # ---------------------------------------------

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Analysis ID: {analysis_id} | "
                    f"Safety level: {safety_level} | "
                    f"Exposure count: {len(exposure)} | "
                    f"Duration: {duration_ms} ms"
                ),
            )

            return result

        except ValueError as error:

            victim_safety_logger.warning(
                "Input validation failed | analysis_id=%s | error=%s",
                analysis_id,
                str(error),
            )

            return self._error_response(
                analysis_id,
                str(error),
                "invalid_input",
                start_time,
            )

        except Exception:

            victim_safety_logger.exception(
                "Victim Safety Agent failed | analysis_id=%s",
                analysis_id,
            )

            log_agent_execution(
                self.AGENT_NAME,
                "ERROR",
                f"Analysis ID: {analysis_id}",
            )

            return self._error_response(
                analysis_id,
                "Victim safety analysis could not be completed.",
                "analysis_failed",
                start_time,
            )

    # -----------------------------------------------------
    # INPUT VALIDATION
    # -----------------------------------------------------

    def _validate_input(
        self,
        evidence: str,
        risk_level: str,
        risk_score: Optional[int],
        evidence_type: str,
        detected_signals: Optional[List[str]],
        reported_exposures: Optional[List[str]],
    ):

        if not isinstance(evidence, str):
            raise ValueError(
                "Evidence must be a text string."
            )

        evidence = evidence.strip()

        if not evidence:
            raise ValueError(
                "Evidence cannot be empty."
            )

        if len(evidence) > self.MAX_EVIDENCE_LENGTH:
            raise ValueError(
                "Evidence exceeds the maximum length."
            )

        if not isinstance(risk_level, str):
            raise ValueError(
                "Risk level must be a string."
            )

        risk_level = risk_level.strip().upper()

        if risk_level not in self.SUPPORTED_RISK_LEVELS:
            raise ValueError(
                "Unsupported risk level."
            )

        if risk_score is not None:

            if (
                isinstance(risk_score, bool)
                or not isinstance(risk_score, int)
            ):
                raise ValueError(
                    "Risk score must be an integer."
                )

            if not 0 <= risk_score <= 100:
                raise ValueError(
                    "Risk score must be between 0 and 100."
                )

        if not isinstance(evidence_type, str):
            raise ValueError(
                "Evidence type must be a string."
            )

        evidence_type = evidence_type.strip().lower()

        if evidence_type not in self.SUPPORTED_EVIDENCE_TYPES:
            raise ValueError(
                "Unsupported evidence type."
            )

        if (
            detected_signals is not None
            and not isinstance(detected_signals, list)
        ):
            raise ValueError(
                "Detected signals must be a list."
            )

        if (
            reported_exposures is not None
            and not isinstance(reported_exposures, list)
        ):
            raise ValueError(
                "Reported exposures must be a list."
            )

        return evidence, risk_level, evidence_type

    # -----------------------------------------------------
    # SIGNAL NORMALIZATION
    # -----------------------------------------------------

    def _normalize_signals(
        self,
        detected_signals: Optional[List[str]],
    ) -> List[str]:

        if not detected_signals:
            return []

        normalized = []

        for signal in detected_signals:

            if not isinstance(signal, str):
                continue

            signal = signal.strip().lower()

            if signal and signal not in normalized:
                normalized.append(signal)

        return normalized

    # -----------------------------------------------------
    # SENSITIVE REQUEST DETECTION
    # -----------------------------------------------------

    def _has_sensitive_request(
        self,
        detected_signals: List[str],
    ) -> bool:

        return bool(
            self.SENSITIVE_REQUEST_SIGNALS.intersection(
                detected_signals
            )
        )

    # -----------------------------------------------------
    # EXPOSURE DETECTION
    # -----------------------------------------------------

    def _detect_exposures(
        self,
        evidence: str,
        reported_exposures: Optional[List[str]],
    ) -> List[str]:

        text = evidence.lower()

        detected = set()

        for exposure_type, keywords in self.EXPOSURE_KEYWORDS.items():

            if any(keyword in text for keyword in keywords):
                detected.add(exposure_type)

        # Explicitly reported exposures are user-provided
        # information, not independently verified facts.

        if reported_exposures is not None:

            valid_types = set(
                self.EXPOSURE_KEYWORDS.keys()
            )

            for item in reported_exposures:

                if not isinstance(item, str):
                    raise ValueError(
                        "Each reported exposure must be a string."
                    )

                item = item.strip()

                if item not in valid_types:
                    raise ValueError(
                        f"Unsupported exposure type: {item}"
                    )

                detected.add(item)

        return sorted(detected)

    # -----------------------------------------------------
    # SAFETY LEVEL
    # -----------------------------------------------------

    @classmethod
    def _determine_safety_level(
        cls,
        risk_level: str,
        risk_score: Optional[int],
        exposure: List[str],
        detected_signals: List[str],
    ) -> str:

        # Confirmed/reported possible exposure receives priority.

        if (
            "payment_made" in exposure
            or "otp_shared" in exposure
            or "remote_access_granted" in exposure
        ):
            return "URGENT"

        if (
            "bank_details_shared" in exposure
            or "password_shared" in exposure
        ):
            return "HIGH"

        if "suspicious_link_opened" in exposure:
            return "ELEVATED"

        # Sensitive scam requests elevate precautionary guidance,
        # but do not count as proof of victim exposure.

        if cls.SENSITIVE_REQUEST_SIGNALS.intersection(
            detected_signals
        ):
            if risk_level in {"CRITICAL", "HIGH"}:
                return "HIGH"

            return "ELEVATED"

        if risk_score is not None and risk_score >= 75:
            return "HIGH"

        if risk_level in {"CRITICAL", "HIGH"}:
            return "HIGH"

        if risk_level == "MEDIUM":
            return "ELEVATED"

        return "NORMAL"

    # -----------------------------------------------------
    # IMMEDIATE ACTIONS
    # -----------------------------------------------------

    def _get_immediate_actions(
        self,
        exposure: List[str],
    ) -> List[Dict[str, str]]:

        actions = []

        action_map = {

            "otp_shared": {
                "priority": "CRITICAL",
                "title": "Secure your bank and linked accounts",
                "action": (
                    "Contact your bank immediately using its official "
                    "number. Ask them to block affected banking "
                    "channels, cards or UPI access if necessary."
                ),
            },

            "bank_details_shared": {
                "priority": "CRITICAL",
                "title": "Contact your bank",
                "action": (
                    "Inform your bank that financial information may "
                    "have been exposed. Request monitoring and "
                    "appropriate account or card protection."
                ),
            },

            "password_shared": {
                "priority": "HIGH",
                "title": "Change exposed passwords",
                "action": (
                    "Change the affected password using the official "
                    "website or app. Change reused passwords on other "
                    "accounts and enable multi-factor authentication."
                ),
            },

            "payment_made": {
                "priority": "CRITICAL",
                "title": "Report the financial transaction immediately",
                "action": (
                    "Contact your bank or payment provider immediately. "
                    "In India, report suspected cyber financial fraud "
                    "through helpline 1930 and the official "
                    "National Cyber Crime Reporting Portal."
                ),
            },

            "suspicious_link_opened": {
                "priority": "HIGH",
                "title": "Secure your device",
                "action": (
                    "Close the suspicious page. Do not enter personal "
                    "information or download anything from it. If you "
                    "downloaded a file, avoid opening it and run a "
                    "security scan."
                ),
            },

            "remote_access_granted": {
                "priority": "CRITICAL",
                "title": "Stop unauthorized remote access",
                "action": (
                    "Disconnect the device from the internet if "
                    "unauthorized remote access may still be active. "
                    "Uninstall the remote-access application and "
                    "contact your bank from a separate trusted device."
                ),
            },
        }

        for exposure_type in exposure:

            action = action_map.get(exposure_type)

            if action:
                actions.append(action)

        return actions

    # -----------------------------------------------------
    # GENERAL SAFETY ACTIONS
    # -----------------------------------------------------

    def _get_general_actions(
        self,
        safety_level: str,
    ) -> List[str]:

        actions = [
            "Do not share OTPs, PINs, passwords or CVV with anyone.",
            "Do not transfer money under pressure or threats.",
            "Verify calls and messages through official channels.",
            "Preserve screenshots, transaction IDs and communication.",
            "Block and report suspicious contacts through the relevant platform.",
        ]

        if safety_level in {"URGENT", "HIGH"}:

            actions.insert(
                0,
                "Prioritize contacting your bank through an official channel.",
            )

        return actions

    # -----------------------------------------------------
    # EMERGENCY GUIDANCE
    # -----------------------------------------------------

    @staticmethod
    def _get_emergency_guidance(
        exposure: List[str],
    ) -> Dict[str, Any]:

        financial_exposure = any(
            item in exposure
            for item in [
                "payment_made",
                "otp_shared",
                "bank_details_shared",
            ]
        )

        return {
            "country": "India",

            "cybercrime_helpline": "1930",

            "reporting_portal": "https://cybercrime.gov.in/",

            "financial_fraud_report_recommended": (
                financial_exposure
            ),

            "instruction": (
                "For suspected financial cyber fraud, contact "
                "1930 immediately and submit a report through "
                "the official portal. Do not delay reporting."
            ),
        }

    # -----------------------------------------------------
    # ERROR RESPONSE
    # -----------------------------------------------------

    def _error_response(
        self,
        analysis_id: str,
        message: str,
        error_code: str,
        start_time: float,
    ) -> Dict[str, Any]:

        return {
            "success": False,

            "agent": {
                "name": self.AGENT_NAME,
                "version": self.AGENT_VERSION,
                "status": "failed",
            },

            "analysis_id": analysis_id,

            "error": {
                "code": error_code,
                "message": message,
            },

            "metadata": {
                "duration_ms": round(
                    (perf_counter() - start_time) * 1000,
                    2,
                ),
            },
        }

    # -----------------------------------------------------
    # RECOMMENDATION DEFINITIONS
    # -----------------------------------------------------

    @staticmethod
    def _build_recommendations() -> Dict[str, str]:

        return {
            "otp": "Never share OTP with anyone.",
            "bank": "Contact your bank through official channels.",
            "password": "Change exposed passwords immediately.",
            "payment": "Report suspicious financial transactions.",
            "device": "Secure your device and remove suspicious apps.",
            "evidence": "Preserve all relevant digital evidence.",
        }


# =========================================================
# REUSABLE AGENT INSTANCE
# =========================================================

victim_safety_agent = VictimSafetyAgent()


# =========================================================
# PUBLIC FUNCTION
# =========================================================

def run_victim_safety_analysis(
    evidence: str,
    risk_level: str = "UNKNOWN",
    risk_score: Optional[int] = None,
    detected_signals: Optional[List[str]] = None,
    evidence_type: str = "message",
    reported_exposures: Optional[List[str]] = None,
) -> Dict[str, Any]:

    return victim_safety_agent.analyze(
        evidence=evidence,
        risk_level=risk_level,
        risk_score=risk_score,
        detected_signals=detected_signals,
        evidence_type=evidence_type,
        reported_exposures=reported_exposures,
    )
