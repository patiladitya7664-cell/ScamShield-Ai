
"""
=========================================================
SCAMSHIELD AI - GUARDIAN AGENT
=========================================================

Responsibilities:
- Primary fraud detection.
- Risk assessment.
- Detection explanation.
- Indicator preservation.
- Machine learning result reporting.

=========================================================
"""

import time
import uuid

from datetime import datetime, timezone

from detection.fraud_detector import FraudDetector

from utils.logger import (
    guardian_logger,
    log_agent_execution,
)


class GuardianAgent:
    """Primary fraud detection agent."""

    AGENT_NAME = "GuardianAgent"
    VERSION = "1.0.0"

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    MAX_EVIDENCE_LENGTH = 20000

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self, detector=None):
        self.detector = detector or FraudDetector()

    # =====================================================
    # MAIN ANALYSIS
    # =====================================================

    def analyze(self, evidence, evidence_type="message"):

        started_at = time.perf_counter()
        analysis_id = str(uuid.uuid4())

        try:

            evidence_type = self._validate_input(
                evidence,
                evidence_type,
            )

            detection = self.detector.analyze(evidence)

            if not isinstance(detection, dict):
                raise RuntimeError(
                    "Invalid fraud detector response."
                )

            if not detection.get("success", False):
                raise RuntimeError(
                    "Fraud detection failed."
                )

            analysis = self._build_analysis(
                detection,
                evidence_type,
            )

            duration_ms = round(
                (time.perf_counter() - started_at) * 1000,
                2,
            )

            result = {
                "success": True,

                "agent": {
                    "name": self.AGENT_NAME,
                    "version": self.VERSION,
                    "status": "completed",
                },

                "analysis_id": analysis_id,

                "analysis": analysis,

                "metadata": {
                    "duration_ms": duration_ms,
                    "timestamp": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "analysis_method": analysis[
                        "analysis_method"
                    ],
                    "model_available": analysis[
                        "machine_learning"
                    ]["available"],
                },

                "verification": {
                    "status": "UNVERIFIED",
                    "external_verification": False,
                },

                "disclaimer": (
                    "This is an automated risk assessment, not a "
                    "definitive determination of fraud. Verify suspicious "
                    "activity through official channels."
                ),
            }

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Analysis ID: {analysis_id} | "
                    f"Risk level: {analysis['risk_level']} | "
                    f"Duration: {duration_ms} ms"
                ),
            )

            return result

        except ValueError as exc:

            guardian_logger.warning(
                "Input validation failed | analysis_id=%s | error=%s",
                analysis_id,
                str(exc),
            )

            return self._error_response(
                analysis_id,
                str(exc),
                started_at,
                "invalid_input",
            )

        except Exception:

            guardian_logger.exception(
                "Guardian Agent failed | analysis_id=%s",
                analysis_id,
            )

            log_agent_execution(
                self.AGENT_NAME,
                "ERROR",
                f"Analysis ID: {analysis_id}",
            )

            return self._error_response(
                analysis_id,
                "Guardian Agent could not complete the analysis.",
                started_at,
                "failed",
            )

    # =====================================================
    # INPUT VALIDATION
    # =====================================================

    def _validate_input(self, evidence, evidence_type):

        if not isinstance(evidence, str):
            raise ValueError(
                "Evidence must be provided as text."
            )

        evidence = evidence.strip()

        if not evidence:
            raise ValueError(
                "Evidence cannot be empty."
            )

        if len(evidence) > self.MAX_EVIDENCE_LENGTH:
            raise ValueError(
                f"Evidence cannot exceed "
                f"{self.MAX_EVIDENCE_LENGTH} characters."
            )

        if not isinstance(evidence_type, str):
            raise ValueError(
                "Evidence type must be a string."
            )

        evidence_type = evidence_type.strip().lower()

        if evidence_type not in self.SUPPORTED_EVIDENCE_TYPES:
            raise ValueError(
                "Unsupported evidence type: "
                + evidence_type
            )

        return evidence_type

    # =====================================================
    # BUILD ANALYSIS
    # =====================================================

    def _build_analysis(self, detection, evidence_type):

        risk_score = self._safe_score(
            detection.get("risk_score", 0)
        )

        risk_level = str(
            detection.get("risk_level", "LOW")
        ).upper()

        category = detection.get(
            "fraud_category",
            "unknown",
        )

        ml_result = detection.get(
            "machine_learning",
            {},
        )

        if not isinstance(ml_result, dict):
            ml_result = {}

        indicators = self._safe_dict(
            detection.get("indicators")
        )

        scoring = self._safe_dict(
            detection.get("scoring")
        )

        return {
            "evidence_type": evidence_type,

            "fraud_category": category,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "summary": self._generate_summary(
                risk_level,
                category,
                risk_score,
            ),

            "signals": self._safe_list(
                detection.get("signals")
            ),

            "detected_rules": self._safe_list(
                detection.get("detected_rules")
            ),

            # Preserve indicators as a dictionary.
            "indicators": indicators,

            "explanations": self._safe_list(
                detection.get("explanations")
            ),

            "recommendations": self._safe_list(
                detection.get("recommendations")
            ),

            "scoring": scoring,

            "machine_learning": {
                "available": bool(
                    ml_result.get("available", False)
                ),
                "prediction": ml_result.get("prediction"),
                "confidence": ml_result.get("confidence"),
                "method": ml_result.get(
                    "method",
                    "not_available",
                ),
            },

            "analysis_method": detection.get(
                "analysis_method",
                "rule_based",
            ),
        }

    # =====================================================
    # SUMMARY GENERATION
    # =====================================================

    @staticmethod
    def _generate_summary(
        risk_level,
        category,
        score,
    ):

        category_name = (
            str(category)
            .replace("_", " ")
            .title()
        )

        if risk_level == "CRITICAL":

            return (
                f"Critical risk detected ({score}/100). "
                f"Possible category: {category_name}. "
                "Avoid further interaction and verify through "
                "official channels."
            )

        if risk_level == "HIGH":

            return (
                f"High risk detected ({score}/100). "
                f"Possible category: {category_name}. "
                "Do not share sensitive information or make payments."
            )

        if risk_level == "MEDIUM":

            return (
                f"Moderate risk detected ({score}/100). "
                f"Possible category: {category_name}. "
                "Review the evidence carefully before taking action."
            )

        return (
            f"Low risk detected ({score}/100). "
            "No strong fraud indicators were identified by current "
            "checks. This does not guarantee that the evidence is safe."
        )

    # =====================================================
    # SAFE DATA HELPERS
    # =====================================================

    @staticmethod
    def _safe_score(value):

        try:
            return max(
                0,
                min(
                    100,
                    round(float(value)),
                ),
            )

        except (TypeError, ValueError, OverflowError):
            return 0

    @staticmethod
    def _safe_list(value):

        return value if isinstance(value, list) else []

    @staticmethod
    def _safe_dict(value):

        return value if isinstance(value, dict) else {}

    # =====================================================
    # ERROR RESPONSE
    # =====================================================

    @staticmethod
    def _error_response(
        analysis_id,
        message,
        started_at,
        status,
    ):

        duration_ms = round(
            (time.perf_counter() - started_at) * 1000,
            2,
        )

        return {
            "success": False,

            "agent": {
                "name": GuardianAgent.AGENT_NAME,
                "version": GuardianAgent.VERSION,
                "status": status,
            },

            "analysis_id": analysis_id,

            "error": message,

            "metadata": {
                "duration_ms": duration_ms,
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
            },

            "verification": {
                "status": "UNVERIFIED",
            },
        }


# =========================================================
# REUSABLE GUARDIAN INSTANCE
# =========================================================

guardian_agent = GuardianAgent()


# =========================================================
# PUBLIC FUNCTION
# =====================================================

def run_guardian_analysis(
    evidence,
    evidence_type="message",
):

    return guardian_agent.analyze(
        evidence,
        evidence_type,
    )
