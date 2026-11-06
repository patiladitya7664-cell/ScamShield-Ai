"""
=========================================================
SCAMSHIELD AI - VICTIM SAFETY AGENT
=========================================================

Version: 1.2.0

Responsibilities:
- Identify possible victim exposure.
- Distinguish scammer requests from victim actions.
- Detect English and Hinglish exposure statements.
- Handle explicit negation carefully.
- Generate immediate safety recommendations.
- Generate precautionary actions for suspicious requests.
- Prioritize financial and account protection.
- Use Guardian risk signals as supporting context.
- Provide emergency guidance for Indian users.
- Never perform financial or account actions automatically.

IMPORTANT:
Text-based exposure detection is not independent verification.
All detected exposures remain unverified until confirmed.

=========================================================
"""

import math
import re

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
    AGENT_VERSION = "1.2.0"

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

    SUPPORTED_EXPOSURES = {
        "otp_shared",
        "bank_details_shared",
        "password_shared",
        "payment_made",
        "suspicious_link_opened",
        "remote_access_granted",
    }

    # =====================================================
    # NEGATION PATTERNS
    # =====================================================

    NEGATION_PATTERNS = [

        r"\b(?:did not|didn't|have not|haven't|never)\b",

        r"\bnot\b",

        r"\b(?:nahi|nahin|nhi)\b",

        r"\b(?:nahi kiya|nahi diya|nahi bataya)\b",

        r"\b(?:share nahi kiya|share nahi kiya hai)\b",

    ]

    # =====================================================
    # VICTIM EXPOSURE PATTERNS
    # =====================================================
    # These patterns identify possible first-person actions.
    # They do not establish that the action actually occurred.
    # =====================================================

    EXPOSURE_PATTERNS = {

        "otp_shared": [

            r"\bi\s+(?:have\s+)?shared\s+(?:(?:my|the)\s+)?otp\b",

            r"\bi\s+gave\s+(?:him|her|them)\s+(?:(?:my|the)\s+)?otp\b",

            r"\bi\s+told\s+(?:him|her|them)\s+(?:(?:my|the)\s+)?otp\b",

            r"\bi\s+sent\s+(?:him|her|them)\s+(?:(?:my|the)\s+)?otp\b",

            r"\bi\s+shared\s+my\s+otp\b",

            r"\bmaine\s+(?:apna\s+)?otp\s+(?:share|bata|de)\s+diya\b",

            r"\bmaine\s+otp\s+share\s+kar\s+diya\b",

            r"\bmaine\s+otp\s+bata\s+diya\b",

            r"\bmaine\s+otp\s+de\s+diya\b",

            r"\botp\s+share\s+kar\s+diya\b",

        ],

        "bank_details_shared": [

            r"\bi\s+(?:have\s+)?shared\s+my\s+bank\s+details\b",

            r"\bi\s+shared\s+my\s+card\s+details\b",

            r"\bi\s+gave\s+(?:him|her|them)\s+my\s+bank\s+details\b",

            r"\bi\s+sent\s+my\s+card\s+details\b",

            r"\bmaine\s+bank\s+details\s+de\s+diye\b",

            r"\bmaine\s+bank\s+details\s+share\s+kar\s+diye\b",

            r"\bmaine\s+card\s+details\s+share\s+kar\s+diye\b",

        ],

        "password_shared": [

            r"\bi\s+(?:have\s+)?shared\s+my\s+password\b",

            r"\bi\s+gave\s+(?:him|her|them)\s+my\s+password\b",

            r"\bi\s+told\s+(?:him|her|them)\s+my\s+password\b",

            r"\bi\s+sent\s+my\s+password\b",

            r"\bmaine\s+password\s+de\s+diya\b",

            r"\bmaine\s+password\s+share\s+kar\s+diya\b",

            r"\bmaine\s+apna\s+password\s+bata\s+diya\b",

        ],

        "payment_made": [

            r"\bi\s+(?:have\s+)?sent\s+(?:the\s+)?money\b",

            r"\bi\s+(?:have\s+)?transferred\s+(?:the\s+)?money\b",

            r"\bi\s+(?:have\s+)?made\s+(?:the\s+)?payment\b",

            r"\bi\s+(?:have\s+)?paid\s+(?:the\s+)?amount\b",

            r"\bmaine\s+paise\s+bhej\s+diye\b",

            r"\bmaine\s+payment\s+kar\s+diya\b",

            r"\bmaine\s+payment\s+kar\s+di\b",

            r"\bpaise\s+transfer\s+kar\s+diye\b",

            r"\bmaine\s+amount\s+transfer\s+kar\s+diya\b",

        ],

        "suspicious_link_opened": [

            r"\bi\s+(?:have\s+)?opened\s+(?:the\s+)?suspicious\s+link\b",

            r"\bi\s+(?:have\s+)?clicked\s+(?:on\s+)?(?:the\s+)?suspicious\s+link\b",

            r"\bi\s+(?:have\s+)?clicked\s+(?:on\s+)?the\s+link\b",

            r"\bi\s+opened\s+the\s+link\b",

            r"\bmaine\s+suspicious\s+link\s+open\s+kiya\b",

            r"\bmaine\s+link\s+par\s+click\s+kiya\b",

            r"\bmaine\s+link\s+open\s+kiya\b",

            r"\blink\s+open\s+kar\s+liya\b",

        ],

        "remote_access_granted": [

            r"\bi\s+(?:have\s+)?installed\s+anydesk\b",

            r"\bi\s+(?:have\s+)?installed\s+teamviewer\b",

            r"\bi\s+(?:have\s+)?installed\s+(?:a\s+)?remote\s+access\s+app\b",

            r"\bi\s+gave\s+(?:them\s+)?remote\s+access\b",

            r"\bi\s+enabled\s+screen\s+sharing\b",

            r"\bmaine\s+anydesk\s+install\s+kiya\b",

            r"\bmaine\s+teamviewer\s+install\s+kiya\b",

            r"\bmaine\s+remote\s+access\s+de\s+diya\b",

            r"\bmaine\s+screen\s+sharing\s+enable\s+ki\b",

        ],

    }

    # =====================================================
    # SENSITIVE REQUEST SIGNALS
    # =====================================================

    SENSITIVE_REQUEST_SIGNALS = {

        "otp_or_credential_request",
        "financial_pressure",
        "remote_access_request",
        "threat_or_intimidation",
        "impersonation",
        "suspicious_link",
        "upi_payment_manipulation",
        "cvv_request",
        "investment_guarantee",
        "email_spoofing",

    }

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self):

        self.recommendations = self._build_recommendations()

    # =====================================================
    # MAIN ANALYSIS
    # =====================================================

    def analyze(
        self,
        evidence: str,
        risk_level: str = "UNKNOWN",
        risk_score: Optional[float] = None,
        detected_signals: Optional[List[str]] = None,
        evidence_type: str = "message",
        reported_exposures: Optional[List[str]] = None,
    ) -> Dict[str, Any]:

        start_time = perf_counter()
        analysis_id = str(uuid4())

        try:

            (
                evidence,
                risk_level,
                risk_score,
                evidence_type,
            ) = self._validate_input(
                evidence,
                risk_level,
                risk_score,
                evidence_type,
                detected_signals,
                reported_exposures,
            )

            normalized_signals = self._normalize_signals(
                detected_signals
            )

            possible_exposures = self._detect_exposures(
                evidence
            )

            user_reported_exposures = (
                self._normalize_reported_exposures(
                    reported_exposures
                )
            )

            all_exposures = sorted(
                set(possible_exposures)
                | set(user_reported_exposures)
            )

            sensitive_request_detected = (
                self._has_sensitive_request(
                    normalized_signals
                )
            )

            safety_level = self._determine_safety_level(
                risk_level=risk_level,
                risk_score=risk_score,
                exposures=all_exposures,
                detected_signals=normalized_signals,
            )

            # Actual or reported exposure actions.
            immediate_actions = self._get_immediate_actions(
                all_exposures
            )

            # Precautionary actions for scammer requests.
            precautionary_actions = (
                self._get_precautionary_actions(
                    normalized_signals
                )
            )

            # Combine without confusing requests with exposures.
            combined_actions = (
                immediate_actions + precautionary_actions
            )

            general_actions = self._get_general_actions(
                safety_level
            )

            emergency_guidance = self._get_emergency_guidance(
                all_exposures
            )

            exposure_sources = {

                "user_reported": user_reported_exposures,

                "text_pattern_detected": possible_exposures,

                "verification_status": "UNVERIFIED",

            }

            potentially_compromised = bool(
                all_exposures
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

                    "detected_exposures": all_exposures,

                    "reported_exposures": user_reported_exposures,

                    "possible_exposures": possible_exposures,

                    "exposure_sources": exposure_sources,

                    "detected_risk_signals": normalized_signals,

                    "sensitive_request_detected": (
                        sensitive_request_detected
                    ),

                    "potentially_compromised": (
                        potentially_compromised
                    ),

                    "verification_status": "UNVERIFIED",

                },

                "immediate_actions": combined_actions,

                "precautionary_actions": precautionary_actions,

                "recommended_actions": general_actions,

                "emergency_guidance": emergency_guidance,

                "important_notice": (
                    "These recommendations are precautionary. "
                    "Text-based patterns and automated risk signals "
                    "cannot independently confirm account or device "
                    "compromise. User-reported and detected exposures "
                    "remain unverified until independently confirmed. "
                    "A suspicious request does not prove that the "
                    "victim shared information or made a payment."
                ),

                "metadata": {

                    "evidence_type": evidence_type,

                    "analysis_method": (
                        "rule_based_safety_assessment"
                    ),

                    "created_at": datetime.now(
                        timezone.utc
                    ).isoformat(),

                    "duration_ms": self._duration_ms(
                        start_time
                    ),

                    "automatic_actions_performed": False,

                },

            }

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Analysis ID: {analysis_id} | "
                    f"Safety level: {safety_level} | "
                    f"Exposure count: {len(all_exposures)} | "
                    f"Duration: {result['metadata']['duration_ms']} ms"
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

            try:

                log_agent_execution(
                    self.AGENT_NAME,
                    "ERROR",
                    f"Analysis ID: {analysis_id}",
                )

            except Exception:

                pass

            return self._error_response(
                analysis_id,
                "Victim safety analysis could not be completed.",
                "analysis_failed",
                start_time,
            )

    # =====================================================
    # INPUT VALIDATION
    # =====================================================

    def _validate_input(
        self,
        evidence: str,
        risk_level: str,
        risk_score: Optional[float],
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
                or not isinstance(risk_score, (int, float))
                or not math.isfinite(risk_score)
            ):

                raise ValueError(
                    "Risk score must be a finite number."
                )

            if not 0 <= risk_score <= 100:

                raise ValueError(
                    "Risk score must be between 0 and 100."
                )

            risk_score = float(risk_score)

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

        return (
            evidence,
            risk_level,
            risk_score,
            evidence_type,
        )

    # =====================================================
    # SIGNAL NORMALIZATION
    # =====================================================

    @staticmethod
    def _normalize_signals(
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

    # =====================================================
    # SENSITIVE REQUEST DETECTION
    # =====================================================

    @classmethod
    def _has_sensitive_request(
        cls,
        detected_signals: List[str],
    ) -> bool:

        return bool(
            cls.SENSITIVE_REQUEST_SIGNALS.intersection(
                detected_signals
            )
        )

    # =====================================================
    # NEGATION CHECK
    # =====================================================

    @classmethod
    def _is_negated(
        cls,
        text: str,
        match_start: int,
    ) -> bool:

        context_start = max(
            0,
            match_start - 70,
        )

        preceding_text = text[
            context_start:match_start
        ]

        # Check the most recent clause only.
        clauses = re.split(
            r"[,.;!?]|\bbut\b|\blekin\b|\bhowever\b",
            preceding_text,
        )

        recent_context = clauses[-1].strip()

        return any(
            re.search(
                pattern,
                recent_context,
                flags=re.IGNORECASE,
            )
            for pattern in cls.NEGATION_PATTERNS
        )

    # =====================================================
    # POSSIBLE EXPOSURE DETECTION
    # =====================================================

    def _detect_exposures(
        self,
        evidence: str,
    ) -> List[str]:

        text = evidence.lower()

        detected = []

        for exposure_type, patterns in self.EXPOSURE_PATTERNS.items():

            for pattern in patterns:

                for match in re.finditer(
                    pattern,
                    text,
                    flags=re.IGNORECASE,
                ):

                    if self._is_negated(
                        text,
                        match.start(),
                    ):

                        continue

                    detected.append(
                        exposure_type
                    )

                    break

                if exposure_type in detected:
                    break

        return sorted(set(detected))

    # =====================================================
    # USER-REPORTED EXPOSURES
    # =====================================================

    @staticmethod
    def _normalize_reported_exposures(
        reported_exposures: Optional[List[str]],
    ) -> List[str]:

        if reported_exposures is None:
            return []

        normalized = []

        for item in reported_exposures:

            if not isinstance(item, str):

                raise ValueError(
                    "Each reported exposure must be a string."
                )

            item = item.strip().lower()

            if item not in VictimSafetyAgent.SUPPORTED_EXPOSURES:

                raise ValueError(
                    f"Unsupported exposure type: {item}"
                )

            if item not in normalized:
                normalized.append(item)

        return sorted(normalized)

    # =====================================================
    # SAFETY LEVEL
    # =====================================================

    @classmethod
    def _determine_safety_level(
        cls,
        risk_level: str,
        risk_score: Optional[float],
        exposures: List[str],
        detected_signals: List[str],
    ) -> str:

        if any(
            item in exposures
            for item in [
                "payment_made",
                "otp_shared",
                "remote_access_granted",
            ]
        ):

            return "URGENT"

        if any(
            item in exposures
            for item in [
                "bank_details_shared",
                "password_shared",
            ]
        ):

            return "HIGH"

        if "suspicious_link_opened" in exposures:

            return "ELEVATED"

        if cls.SENSITIVE_REQUEST_SIGNALS.intersection(
            detected_signals
        ):

            if risk_level in {"CRITICAL", "HIGH"}:
                return "HIGH"

            return "ELEVATED"

        if risk_score is not None:

            if risk_score >= 75:
                return "HIGH"

            if risk_score >= 50:
                return "ELEVATED"

        if risk_level in {"CRITICAL", "HIGH"}:
            return "HIGH"

        if risk_level == "MEDIUM":
            return "ELEVATED"

        return "NORMAL"

    # =====================================================
    # ACTUAL EXPOSURE ACTIONS
    # =====================================================

    @staticmethod
    def _get_immediate_actions(
        exposures: List[str],
    ) -> List[Dict[str, str]]:

        action_map = {

            "otp_shared": {

                "priority": "CRITICAL",

                "title": "Secure your bank and linked accounts",

                "action": (
                    "Contact your bank immediately using its official "
                    "number. Explain that an OTP may have been exposed. "
                    "Ask about blocking affected banking channels, "
                    "cards or UPI access if necessary."
                ),

            },

            "bank_details_shared": {

                "priority": "CRITICAL",

                "title": "Contact your bank",

                "action": (
                    "Inform your bank that financial information may "
                    "have been exposed. Request appropriate account "
                    "or card protection."
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
                    "In India, call cybercrime helpline 1930 and report "
                    "the suspected financial fraud through the official "
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
                    "Remove the remote-access application and contact "
                    "your bank from a separate trusted device."
                ),

            },

        }

        actions = []

        for exposure_type in exposures:

            action = action_map.get(exposure_type)

            if action:
                actions.append(action.copy())

        return actions

    # =====================================================
    # PRECAUTIONARY ACTIONS
    # =====================================================
    # These actions apply to suspicious requests.
    # They do not imply that the victim shared information.
    # =====================================================

    @staticmethod
    def _get_precautionary_actions(
        detected_signals: List[str],
    ) -> List[Dict[str, str]]:

        action_map = {

            "otp_or_credential_request": {

                "priority": "HIGH",

                "title": "Do not share OTP or credentials",

                "action": (
                    "Do not share OTPs, passwords, PINs or CVV. "
                    "Legitimate bank representatives should not ask "
                    "you to disclose these confidential credentials."
                ),

            },

            "cvv_request": {

                "priority": "HIGH",

                "title": "Protect your card information",

                "action": (
                    "Do not disclose your CVV, card PIN or OTP to "
                    "any caller or message sender."
                ),

            },

            "financial_pressure": {

                "priority": "HIGH",

                "title": "Pause before making any payment",

                "action": (
                    "Do not transfer money under pressure. Verify the "
                    "request independently using an official contact."
                ),

            },

            "remote_access_request": {

                "priority": "HIGH",

                "title": "Do not grant remote access",

                "action": (
                    "Do not install remote-access applications or "
                    "share screen access with an unverified caller."
                ),

            },

            "threat_or_intimidation": {

                "priority": "HIGH",

                "title": "Do not act under threats",

                "action": (
                    "Do not transfer money or disclose personal details "
                    "because someone threatens arrest, account closure "
                    "or legal action. Verify claims through official "
                    "authorities."
                ),

            },

            "suspicious_link": {

                "priority": "HIGH",

                "title": "Avoid opening suspicious links",

                "action": (
                    "Do not open the link or enter credentials, "
                    "banking information or personal details on it."
                ),

            },

            "investment_guarantee": {

                "priority": "HIGH",

                "title": "Verify investment claims",

                "action": (
                    "Do not invest based on guaranteed-return claims. "
                    "Independently verify the provider and applicable "
                    "regulatory registration before investing."
                ),

            },

            "upi_payment_manipulation": {

                "priority": "HIGH",

                "title": "Verify UPI payment requests",

                "action": (
                    "Never enter your UPI PIN to receive money. "
                    "Check the transaction details in your official "
                    "banking or payment application."
                ),

            },

            "email_spoofing": {

                "priority": "MEDIUM",

                "title": "Verify the sender independently",

                "action": (
                    "Do not trust the display name alone. Check the "
                    "actual sender address and verify requests through "
                    "an official communication channel."
                ),

            },

            "impersonation": {

                "priority": "HIGH",

                "title": "Verify the person's identity",

                "action": (
                    "Contact the claimed organization or person using "
                    "a trusted, independently obtained contact method."
                ),

            },

        }

        actions = []

        added_titles = set()

        for signal in detected_signals:

            action = action_map.get(signal)

            if not action:
                continue

            if action["title"] in added_titles:
                continue

            actions.append(action.copy())

            added_titles.add(
                action["title"]
            )

        return actions

    # =====================================================
    # GENERAL SAFETY ACTIONS
    # =====================================================

    @staticmethod
    def _get_general_actions(
        safety_level: str,
    ) -> List[str]:

        actions = [

            "Never share OTPs, PINs, passwords or CVV with anyone.",

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

    # =====================================================
    # EMERGENCY GUIDANCE
    # =====================================================

    @staticmethod
    def _get_emergency_guidance(
        exposures: List[str],
    ) -> Dict[str, Any]:

        financial_exposure = any(
            item in exposures
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
                "For suspected financial cyber fraud, call 1930 "
                "immediately and submit a report through the official "
                "National Cyber Crime Reporting Portal. Do not delay "
                "reporting."
            ),

            "verification_status": "OFFICIAL_GUIDANCE_REFERENCE",

        }

    # =====================================================
    # DURATION
    # =====================================================

    @staticmethod
    def _duration_ms(
        start_time: float,
    ) -> float:

        return round(
            (perf_counter() - start_time) * 1000,
            2,
        )

    # =====================================================
    # ERROR RESPONSE
    # =====================================================

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

                "duration_ms": self._duration_ms(
                    start_time
                ),

                "created_at": datetime.now(
                    timezone.utc
                ).isoformat(),

            },

        }

    # =====================================================
    # RECOMMENDATION DEFINITIONS
    # =====================================================

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
    risk_score: Optional[float] = None,
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