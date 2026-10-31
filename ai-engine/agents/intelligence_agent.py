
"""
=========================================================
SCAMSHIELD AI - INTELLIGENCE AGENT
=========================================================

Responsibilities:
- Extract intelligence indicators.
- Identify URLs, phone numbers, emails and UPI IDs.
- Detect suspicious keyword categories.
- Preserve previously extracted indicators.
- Clearly mark indicators as UNVERIFIED.
- Never claim external reputation verification.

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

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self):

        self.extractor = EvidenceExtractor()

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

        try:

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

            else:

                extracted = self.extractor.extract(evidence)

                if not isinstance(extracted, dict):
                    raise RuntimeError(
                        "Invalid evidence extractor response."
                    )

                if not extracted.get("success", False):
                    raise RuntimeError(
                        "Evidence extraction failed."
                    )

            normalized = self._normalize_indicators(
                extracted
            )

            summary = self._build_summary(normalized)

            counts = self._build_counts(normalized)

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

                "evidence_type": evidence_type,

                "intelligence": {
                    "urls": normalized["urls"],
                    "phone_numbers": normalized["phone_numbers"],
                    "emails": normalized["emails"],
                    "upi_ids": normalized["upi_ids"],

                    # Preserve keyword categories.
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
                    "analysis_started_at": datetime.now(
                        timezone.utc
                    ).isoformat(),
                    "duration_ms": duration_ms,
                    "indicators_reused": (
                        existing_indicators is not None
                    ),
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
                "Unsupported evidence type."
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

        # Support both full extractor output and
        # a direct indicators dictionary.

        indicators = extracted.get(
            "indicators",
            extracted,
        )

        if not isinstance(indicators, dict):
            indicators = {}

        suspicious_keywords = extracted.get(
            "suspicious_keywords",
            indicators.get("suspicious_keywords", {}),
        )

        return {
            "urls": self._get_list(
                indicators,
                ["urls", "links"],
            ),

            "phone_numbers": self._get_list(
                indicators,
                ["phone_numbers", "phones"],
            ),

            "emails": self._get_list(
                indicators,
                ["emails", "email_addresses"],
            ),

            "upi_ids": self._get_list(
                indicators,
                ["upi_ids", "upi"],
            ),

            "suspicious_keywords": self._normalize_keywords(
                suspicious_keywords
            ),
        }

    # =====================================================
    # KEYWORD NORMALIZATION
    # =====================================================

    @staticmethod
    def _normalize_keywords(value) -> Dict[str, List[str]]:

        if isinstance(value, dict):

            normalized = {}

            for category, matches in value.items():

                if isinstance(matches, list):

                    valid_matches = [
                        str(item)
                        for item in matches
                        if isinstance(item, str) and item.strip()
                    ]

                    if valid_matches:
                        normalized[str(category)] = valid_matches

                elif isinstance(matches, str) and matches.strip():

                    normalized[str(category)] = [matches]

            return normalized

        if isinstance(value, list):

            valid_matches = [
                str(item)
                for item in value
                if isinstance(item, str) and item.strip()
            ]

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
    ) -> List[Any]:

        for key in possible_keys:

            value = data.get(key)

            if isinstance(value, list):

                return [
                    item
                    for item in value
                    if isinstance(item, str) and item.strip()
                ]

        return []

    # =====================================================
    # SUMMARY
    # =====================================================

    def _build_summary(
        self,
        indicators: Dict[str, Any],
    ) -> Dict[str, Any]:

        counts = self._build_counts(indicators)

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

        keyword_categories = indicators[
            "suspicious_keywords"
        ]

        keyword_count = sum(
            len(matches)
            for matches in keyword_categories.values()
        )

        return {
            "urls": len(indicators["urls"]),

            "phone_numbers": len(
                indicators["phone_numbers"]
            ),

            "emails": len(indicators["emails"]),

            "upi_ids": len(indicators["upi_ids"]),

            "suspicious_keywords": keyword_count,
        }

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
                "duration_ms": round(
                    (perf_counter() - start_time) * 1000,
                    2,
                ),
            },
        }


# =====================================================
# REUSABLE AGENT INSTANCE
# =====================================================

intelligence_agent = IntelligenceAgent()


# =====================================================
# PUBLIC FUNCTION
# =====================================================

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
