"""
=========================================================
SCAMSHIELD AI - INTELLIGENCE AGENT
=========================================================

Responsibilities:
    1. Extract intelligence indicators.
    2. Identify URLs, phone numbers, emails and UPI IDs.
    3. Detect suspicious keyword categories.
    4. Preserve previously extracted indicators.
    5. Normalize and deduplicate extracted data.
    6. Clearly mark indicators as UNVERIFIED.
    7. Never claim external reputation verification.

No external contact or URL interaction is performed.

=========================================================
"""

from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, List, Optional
from uuid import uuid4

from extraction.evidence_extractor import EvidenceExtractor

from utils.logger import (
    intelligence_logger,
    log_agent_execution,
)


class IntelligenceAgent:

    AGENT_NAME = "IntelligenceAgent"
    AGENT_VERSION = "1.1.0"

    MAX_EVIDENCE_LENGTH = 20000

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    INDICATOR_FIELDS = {
        "urls": ["urls", "links"],
        "phone_numbers": ["phone_numbers", "phones"],
        "emails": ["emails", "email_addresses"],
        "upi_ids": ["upi_ids", "upi"],
    }

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self, extractor=None):

        self.extractor = extractor or EvidenceExtractor()

    # =====================================================
    # MAIN ANALYSIS
    # =====================================================

    def analyze(
        self,
        evidence: str,
        evidence_type: str = "message",
        existing_indicators: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        start_time = perf_counter()
        analysis_id = str(uuid4())

        started_at = self._timestamp()

        try:

            # ---------------------------------------------
            # INPUT VALIDATION
            # ---------------------------------------------

            evidence, evidence_type = self._validate_input(
                evidence,
                evidence_type,
            )

            # ---------------------------------------------
            # EXTRACT OR REUSE INDICATORS
            # ---------------------------------------------

            if existing_indicators is not None:

                if not isinstance(existing_indicators, dict):

                    raise ValueError(
                        "Existing indicators must be a dictionary."
                    )

                extracted = existing_indicators

                indicators_reused = True

            else:

                extracted = self.extractor.extract(
                    evidence
                )

                if not isinstance(extracted, dict):

                    raise RuntimeError(
                        "Invalid evidence extractor response."
                    )

                if not extracted.get("success", False):

                    raise RuntimeError(
                        "Evidence extraction failed."
                    )

                indicators_reused = False

            # ---------------------------------------------
            # NORMALIZE INDICATORS
            # ---------------------------------------------

            normalized = self._normalize_indicators(
                extracted
            )

            # ---------------------------------------------
            # SUMMARY AND COUNTS
            # ---------------------------------------------

            counts = self._build_counts(
                normalized
            )

            summary = self._build_summary(
                counts
            )

            duration_ms = self._duration_ms(
                start_time
            )

            # ---------------------------------------------
            # FINAL RESULT
            # ---------------------------------------------

            result = {

                "success": True,

                "agent": {

                    "name": self.AGENT_NAME,

                    "version": self.AGENT_VERSION,

                    "status": "completed",

                },

                "analysis_id": analysis_id,

                "evidence_type": evidence_type,

                "intelligence": {

                    "urls": normalized["urls"],

                    "phone_numbers": normalized["phone_numbers"],

                    "emails": normalized["emails"],

                    "upi_ids": normalized["upi_ids"],

                    "suspicious_keywords": normalized[
                        "suspicious_keywords"
                    ],

                },

                "summary": summary,

                "indicator_counts": counts,

                "verification": {

                    "status": "UNVERIFIED",

                    "external_lookup_performed": False,

                    "message": (
                        "Indicators are extracted from submitted evidence. "
                        "Their ownership, reputation and malicious status "
                        "have not been independently verified."
                    ),

                },

                "metadata": {

                    "analysis_method": "rule_based_extraction",

                    "analysis_started_at": started_at,

                    "completed_at": self._timestamp(),

                    "duration_ms": duration_ms,

                    "indicators_reused": indicators_reused,

                    "external_services_contacted": False,

                },

            }

            # ---------------------------------------------
            # EXECUTION LOG
            # ---------------------------------------------

            log_agent_execution(
                self.AGENT_NAME,
                "SUCCESS",
                (
                    f"Analysis ID: {analysis_id} | "
                    f"Evidence type: {evidence_type} | "
                    f"Total indicators: {summary['total_indicators']} | "
                    f"Duration: {duration_ms} ms"
                ),
            )

            return result

        except ValueError as error:

            intelligence_logger.warning(
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

            intelligence_logger.exception(
                "Intelligence Agent failed | analysis_id=%s",
                analysis_id,
            )

            log_agent_execution(
                self.AGENT_NAME,
                "ERROR",
                f"Analysis ID: {analysis_id}",
            )

            return self._error_response(
                analysis_id,
                "Intelligence analysis could not be completed.",
                "analysis_failed",
                start_time,
            )

    # =====================================================
    # INPUT VALIDATION
    # =====================================================

    def _validate_input(
        self,
        evidence: str,
        evidence_type: str,
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
                f"Evidence exceeds the maximum limit of "
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
    # INDICATOR NORMALIZATION
    # =====================================================

    def _normalize_indicators(
        self,
        extracted: Dict[str, Any],
    ) -> Dict[str, Any]:

        if not isinstance(extracted, dict):
            extracted = {}

        # Support both:
        # 1. Full EvidenceExtractor response.
        # 2. Direct indicators dictionary.

        indicators = extracted.get(
            "indicators",
            extracted,
        )

        if not isinstance(indicators, dict):
            indicators = {}

        normalized = {}

        # ---------------------------------------------
        # STANDARD INDICATORS
        # ---------------------------------------------

        for output_key, possible_keys in self.INDICATOR_FIELDS.items():

            normalized[output_key] = self._get_list(
                indicators,
                possible_keys,
            )

        # ---------------------------------------------
        # SUSPICIOUS KEYWORDS
        # ---------------------------------------------

        suspicious_keywords = extracted.get(
            "suspicious_keywords",
            indicators.get("suspicious_keywords", {}),
        )

        normalized["suspicious_keywords"] = (
            self._normalize_keywords(
                suspicious_keywords
            )
        )

        return normalized

    # =====================================================
    # KEYWORD NORMALIZATION
    # =====================================================

    @staticmethod
    def _normalize_keywords(
        value,
    ) -> Dict[str, List[str]]:

        if isinstance(value, dict):

            normalized = {}

            for category, matches in value.items():

                category_name = str(category).strip()

                if not category_name:
                    continue

                if isinstance(matches, str):

                    matches = [matches]

                if not isinstance(matches, (list, tuple, set)):
                    continue

                valid_matches = []

                for item in matches:

                    if not isinstance(item, str):
                        continue

                    item = item.strip()

                    if item and item not in valid_matches:
                        valid_matches.append(item)

                if valid_matches:

                    normalized[category_name] = valid_matches

            return normalized

        if isinstance(value, (list, tuple, set)):

            valid_matches = []

            for item in value:

                if isinstance(item, str):

                    item = item.strip()

                    if item and item not in valid_matches:
                        valid_matches.append(item)

            return (
                {"general": valid_matches}
                if valid_matches
                else {}
            )

        return {}

    # =====================================================
    # SAFE LIST EXTRACTION
    # =====================================================

    @staticmethod
    def _get_list(
        data: Dict[str, Any],
        possible_keys: List[str],
    ) -> List[str]:

        for key in possible_keys:

            value = data.get(key)

            if isinstance(value, str):
                value = [value]

            if isinstance(value, (list, tuple, set)):

                normalized = []

                for item in value:

                    if not isinstance(item, str):
                        continue

                    item = item.strip()

                    if item and item not in normalized:
                        normalized.append(item)

                return normalized

        return []

    # =====================================================
    # SUMMARY
    # =====================================================

    @staticmethod
    def _build_summary(
        counts: Dict[str, int],
    ) -> Dict[str, Any]:

        total = sum(counts.values())

        return {

            "total_indicators": total,

            "message": (
                "Intelligence indicators extracted successfully."
                if total
                else (
                    "No supported intelligence indicators "
                    "were detected."
                )
            ),

        }

    # =====================================================
    # INDICATOR COUNTS
    # =====================================================

    @staticmethod
    def _build_counts(
        indicators: Dict[str, Any],
    ) -> Dict[str, int]:

        keyword_categories = indicators.get(
            "suspicious_keywords",
            {},
        )

        keyword_count = sum(
            len(matches)
            for matches in keyword_categories.values()
        )

        return {

            "urls": len(
                indicators.get("urls", [])
            ),

            "phone_numbers": len(
                indicators.get("phone_numbers", [])
            ),

            "emails": len(
                indicators.get("emails", [])
            ),

            "upi_ids": len(
                indicators.get("upi_ids", [])
            ),

            "suspicious_keywords": keyword_count,

        }

    # =====================================================
    # TIMESTAMP
    # =====================================================

    @staticmethod
    def _timestamp() -> str:

        return datetime.now(
            timezone.utc
        ).isoformat()

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

            "verification": {

                "status": "UNVERIFIED",

                "external_lookup_performed": False,

            },

            "metadata": {

                "duration_ms": self._duration_ms(
                    start_time
                ),

                "timestamp": self._timestamp(),

            },

        }


# =========================================================
# REUSABLE AGENT INSTANCE
# =========================================================

intelligence_agent = IntelligenceAgent()


# =========================================================
# PUBLIC FUNCTION
# =========================================================

def run_intelligence_analysis(
    evidence: str,
    evidence_type: str = "message",
    existing_indicators: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:

    return intelligence_agent.analyze(
        evidence=evidence,
        evidence_type=evidence_type,
        existing_indicators=existing_indicators,
    )