"""
=========================================================
SCAMSHIELD AI - GUARDIAN AGENT
=========================================================

Version: 1.3.0

Responsibilities:
    1. Primary fraud detection.
    2. Evidence type aware analysis.
    3. Risk assessment and normalization.
    4. Detection explanation.
    5. Indicator preservation.
    6. Machine learning result validation.
    7. Multiple fraud category validation.
    8. Safe analysis response generation.
    9. Detector response integrity.
   10. Backward-compatible public interface.

=========================================================
"""

import math
import time
import uuid

from datetime import datetime, timezone

from detection.fraud_detector import FraudDetector

from utils.logger import (
    guardian_logger,
    log_agent_execution,
)


class GuardianAgent:
    """Primary fraud detection and risk assessment agent."""

    AGENT_NAME = "GuardianAgent"
    VERSION = "1.3.0"

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    SUPPORTED_RISK_LEVELS = {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    SUPPORTED_CATEGORIES = {
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
    }

    RISK_THRESHOLDS = (
        (24, "LOW"),
        (49, "MEDIUM"),
        (74, "HIGH"),
        (100, "CRITICAL"),
    )

    MAX_EVIDENCE_LENGTH = 20000

    DISCLAIMER = (
        "This is an automated risk assessment, not a "
        "definitive determination of fraud. Machine learning "
        "predictions and risk scores are advisory. Verify "
        "suspicious activity through official channels."
    )

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self, detector=None):

        self.detector = (
            detector if detector is not None
            else FraudDetector()
        )

    # =====================================================
    # MAIN ANALYSIS
    # =====================================================

    def analyze(self, evidence, evidence_type="message"):

        started_at = time.perf_counter()
        analysis_id = str(uuid.uuid4())

        try:

            # INPUT VALIDATION

            evidence, evidence_type = self._validate_input(
                evidence,
                evidence_type,
            )

            # FRAUD DETECTION

            detection = self.detector.analyze(
                evidence,
                evidence_type=evidence_type,
            )

            self._validate_detector_response(detection)

            # BUILD ANALYSIS

            analysis = self._build_analysis(
                detection,
                evidence_type,
            )

            duration_ms = self._duration(started_at)

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

                    "timestamp": self._timestamp(),

                    "analysis_method": analysis[
                        "analysis_method"
                    ],

                    "model_available": analysis[
                        "machine_learning"
                    ]["available"],

                    "evidence_type": evidence_type,

                },

                "verification": {

                    "status": "UNVERIFIED",

                    "external_verification": False,

                },

                "disclaimer": self.DISCLAIMER,

            }

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Analysis ID: {analysis_id} | "
                    f"Evidence type: {evidence_type} | "
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

        return evidence, evidence_type

    # =====================================================
    # DETECTOR RESPONSE VALIDATION
    # =====================================================

    @staticmethod
    def _validate_detector_response(detection):

        if not isinstance(detection, dict):

            raise RuntimeError(
                "Invalid fraud detector response."
            )

        if detection.get("success") is not True:

            raise RuntimeError(
                "Fraud detection failed."
            )

    # =====================================================
    # BUILD ANALYSIS
    # =====================================================

    def _build_analysis(self, detection, evidence_type):

        risk_score = self._safe_score(
            detection.get("risk_score", 0)
        )

        # Risk level is derived from the normalized score.
        # This prevents score/level inconsistencies.

        risk_level = self._risk_level_from_score(
            risk_score
        )

        category = self._safe_category(
            detection.get("fraud_category")
        )

        detected_categories = self._safe_categories(
            detection.get(
                "detected_categories",
                detection.get("fraud_categories", []),
            )
        )

        # Preserve primary category in the category list.

        if category != "unknown":

            if category not in detected_categories:

                detected_categories.insert(0, category)

        elif detected_categories:

            category = detected_categories[0]

        ml_result = self._safe_dict(
            detection.get("machine_learning")
        )

        ml_result = self._normalize_ml_result(
            ml_result
        )

        analysis_method = self._safe_method(
            detection.get(
                "analysis_method",
                "rule_based",
            )
        )

        return {

            "evidence_type": evidence_type,

            "fraud_category": category,

            "detected_categories": detected_categories,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "summary": self._generate_summary(
                risk_level,
                category,
                risk_score,
            ),

            "signals": self._safe_string_list(
                detection.get("signals")
            ),

            "detected_rules": self._safe_string_list(
                detection.get("detected_rules")
            ),

            "indicators": self._safe_dict(
                detection.get("indicators")
            ),

            "explanations": self._safe_string_list(
                detection.get("explanations")
            ),

            "recommendations": self._safe_string_list(
                detection.get("recommendations")
            ),

            "scoring": self._safe_dict(
                detection.get("scoring")
            ),

            "machine_learning": ml_result,

            "analysis_method": analysis_method,

        }

    # =====================================================
    # CATEGORY VALIDATION
    # =====================================================

    @classmethod
    def _safe_category(cls, value):

        if not isinstance(value, str):

            return "unknown"

        value = value.strip().lower()

        if value not in cls.SUPPORTED_CATEGORIES:

            return "unknown"

        return value

    @classmethod
    def _safe_categories(cls, value):

        if not isinstance(value, list):

            return []

        categories = []
        seen = set()

        for item in value:

            category = cls._safe_category(item)

            if category == "unknown":
                continue

            if category in seen:
                continue

            seen.add(category)

            categories.append(category)

        return categories

    # =====================================================
    # RISK SCORE NORMALIZATION
    # =====================================================

    @staticmethod
    def _safe_score(value):

        # bool is a subclass of int in Python.
        # It must not be accepted as a legitimate score.

        if isinstance(value, bool):

            return 0

        try:

            score = float(value)

            if not math.isfinite(score):

                return 0

            return max(
                0,
                min(
                    100,
                    round(score),
                ),
            )

        except (TypeError, ValueError, OverflowError):

            return 0

    @classmethod
    def _risk_level_from_score(cls, score):

        for threshold, level in cls.RISK_THRESHOLDS:

            if score <= threshold:

                return level

        return "CRITICAL"

    @classmethod
    def _safe_risk_level(cls, value):

        if not isinstance(value, str):

            return "LOW"

        normalized = value.strip().upper()

        if normalized not in cls.SUPPORTED_RISK_LEVELS:

            return "LOW"

        return normalized

    # =====================================================
    # MACHINE LEARNING VALIDATION
    # =====================================================

    @staticmethod
    def _normalize_ml_result(ml_result):

        available = (
            ml_result.get("available") is True
        )

        prediction = ml_result.get("prediction")

        confidence = ml_result.get("confidence")

        method = ml_result.get(
            "method",
            "not_available",
        )

        if not available:

            return {

                "available": False,

                "prediction": None,

                "confidence": None,

                "method": "not_available",

            }

        if not isinstance(prediction, str):

            prediction = None

        elif not prediction.strip():

            prediction = None

        else:

            prediction = prediction.strip()

        if isinstance(confidence, bool):

            confidence = None

        else:

            try:

                confidence = float(confidence)

                if (
                    not math.isfinite(confidence)
                    or not 0 <= confidence <= 1
                ):

                    confidence = None

            except (TypeError, ValueError, OverflowError):

                confidence = None

        if not isinstance(method, str):

            method = "unknown"

        method = method.strip() or "unknown"

        return {

            "available": True,

            "prediction": prediction,

            "confidence": confidence,

            "method": method,

        }

    # =====================================================
    # ANALYSIS METHOD VALIDATION
    # =====================================================

    @staticmethod
    def _safe_method(value):

        if not isinstance(value, str):

            return "rule_based"

        value = value.strip().lower()

        if not value:

            return "rule_based"

        return value

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
    def _safe_list(value):

        return value if isinstance(value, list) else []

    @staticmethod
    def _safe_string_list(value):

        if not isinstance(value, list):

            return []

        return [
            item.strip()
            for item in value
            if isinstance(item, str) and item.strip()
        ]

    @staticmethod
    def _safe_dict(value):

        return value if isinstance(value, dict) else {}

    # =====================================================
    # TIMESTAMP AND DURATION
    # =====================================================

    @staticmethod
    def _timestamp():

        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def _duration(started_at):

        return round(
            (time.perf_counter() - started_at) * 1000,
            2,
        )

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

                "duration_ms": GuardianAgent._duration(
                    started_at
                ),

                "timestamp": GuardianAgent._timestamp(),

            },

            "verification": {

                "status": "UNVERIFIED",

                "external_verification": False,

            },

        }


# =========================================================
# REUSABLE GUARDIAN INSTANCE
# =========================================================

guardian_agent = GuardianAgent()


# =========================================================
# PUBLIC FUNCTION
# =========================================================

def run_guardian_analysis(
    evidence,
    evidence_type="message",
):

    return guardian_agent.analyze(
        evidence,
        evidence_type=evidence_type,
    )