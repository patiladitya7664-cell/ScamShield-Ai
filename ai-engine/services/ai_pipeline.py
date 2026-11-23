"""
=========================================================
SCAMSHIELD AI - CENTRAL AI PIPELINE
=========================================================

Version: 1.3.0

Purpose:
- Coordinate the Agent Orchestrator.
- Execute deterministic fraud analysis.
- Integrate Gemini contextual advisory analysis.
- Preserve authoritative Guardian risk assessment.
- Preserve individual agent results.
- Handle partial and complete failures.
- Maintain safe metadata and request tracking.
- Track Gemini configuration and availability separately.

IMPORTANT:
- Guardian remains authoritative.
- Gemini is advisory only.
- Gemini cannot modify risk score or fraud category.
- Gemini failures never interrupt deterministic analysis.
=========================================================
"""

import math
import re
import time
import uuid

from datetime import datetime, timezone

from services.agent_orchestrator import AgentOrchestrator
from services.gemini_service import gemini_service

from utils.logger import logger


class AIPipeline:

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    MAX_EVIDENCE_LENGTH = 20000
    MAX_METADATA_DEPTH = 10

    # =================================================
    # GEMINI STRICT RESPONSE ALLOWLIST
    # =================================================

    GEMINI_ALLOWED_FIELDS = {
        "available",
        "status",
        "version",
        "model",
        "advisory_only",
        "reason",
        "scam_intent",
        "social_engineering_tactics",
        "contextual_indicators",
        "explanation",
        "supporting_evidence",
        "alternative_interpretations",
        "advisory_confidence",
        "safety_notes",
    }

    GEMINI_STRING_LIMITS = {
        "scam_intent": 1000,
        "explanation": 2000,
        "reason": 500,
        "version": 100,
        "model": 150,
    }

    GEMINI_LIST_LIMITS = {
        "social_engineering_tactics": 10,
        "contextual_indicators": 10,
        "supporting_evidence": 10,
        "alternative_interpretations": 10,
        "safety_notes": 10,
    }

    GEMINI_LIST_ITEM_MAX_LENGTH = 500

    GEMINI_ALLOWED_STATUSES = {
        "success",
        "unavailable",
    }

    GEMINI_ALLOWED_CONFIDENCE = {
        "low",
        "medium",
        "high",
    }

    VERSION = "1.3.0"

    # =================================================
    # INITIALIZATION
    # =================================================

    def __init__(
        self,
        orchestrator=None,
        gemini=None,
    ):

        self.orchestrator = (
            orchestrator
            if orchestrator is not None
            else AgentOrchestrator()
        )

        self.gemini = (
            gemini
            if gemini is not None
            else gemini_service
        )

        logger.info(
            "ScamShield AI Pipeline initialized | version=%s",
            self.VERSION,
        )

    # =================================================
    # INPUT VALIDATION
    # =================================================

    def _validate_input(
        self,
        evidence,
        evidence_type,
    ):

        if not isinstance(evidence, str):

            raise ValueError(
                "Evidence must be a string."
            )

        evidence = evidence.strip()

        if not evidence:

            raise ValueError(
                "Evidence cannot be empty."
            )

        if len(evidence) > self.MAX_EVIDENCE_LENGTH:

            raise ValueError(
                "Evidence exceeds maximum allowed length."
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

    # =================================================
    # SAFE HELPERS
    # =================================================

    @staticmethod
    def _timestamp():

        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def _safe_dict(value):

        return (
            value
            if isinstance(value, dict)
            else {}
        )

    @staticmethod
    def _safe_list(value):

        return (
            value
            if isinstance(value, list)
            else []
        )

    @staticmethod
    def _safe_score(value):

        try:

            score = float(value)

            if not math.isfinite(score):
                return 0

            return max(
                0,
                min(100, round(score, 2)),
            )

        except (TypeError, ValueError):

            return 0

    @staticmethod
    def _normalize_errors(errors):

        if not isinstance(errors, list):
            return []

        normalized = []

        for error in errors:

            if isinstance(error, str):

                normalized.append({

                    "agent": "unknown",

                    "message": error,

                })

            elif isinstance(error, dict):

                normalized.append({

                    "agent": str(
                        error.get(
                            "agent",
                            "unknown",
                        )
                    ),

                    "message": str(
                        error.get(
                            "message",
                            "An agent execution error occurred.",
                        )
                    ),

                })

        return normalized

    # =================================================
    # GEMINI CONFIGURATION STATUS
    # =================================================

    def _is_gemini_configured(self):

        return (
            self.gemini is not None
            and callable(
                getattr(
                    self.gemini,
                    "analyze",
                    None,
                )
            )
        )

    # =================================================
    # GEMINI UNAVAILABLE RESPONSE
    # =================================================

    @staticmethod
    def _gemini_unavailable_result(
        reason="Gemini advisory analysis is unavailable.",
    ):

        return {

            "available": False,

            "status": "unavailable",

            "version": "unknown",

            "model": "unknown",

            "advisory_only": True,

            "scam_intent": "",

            "social_engineering_tactics": [],

            "contextual_indicators": [],

            "explanation": (
                "Gemini contextual analysis could not "
                "be completed."
            ),

            "supporting_evidence": [],

            "alternative_interpretations": [],

            "advisory_confidence": "unknown",

            "safety_notes": [],

            "reason": reason,

        }

    # =================================================
    # GEMINI ADVISORY ANALYSIS
    # =================================================

    def _run_gemini_advisory(
        self,
        evidence,
        evidence_type,
        deterministic_result,
    ):
        """
        Execute Gemini contextual analysis.

        Gemini is strictly advisory.

        Only explicitly approved response fields
        are allowed into the pipeline.

        Guardian remains authoritative.
        """

        try:

            if not self._is_gemini_configured():

                logger.warning(
                    "Gemini service is not configured."
                )

                return self._gemini_unavailable_result(
                    "Gemini service is not configured."
                )

            logger.info(
                "Gemini advisory analysis started | type=%s",
                evidence_type,
            )

            gemini_result = self.gemini.analyze(

                evidence=evidence,

                evidence_type=evidence_type,

                deterministic_result=deterministic_result,

            )

            # =========================================
            # RESPONSE TYPE VALIDATION
            # =========================================

            if not isinstance(gemini_result, dict):

                logger.warning(
                    "Gemini returned a non-dictionary response."
                )

                return self._gemini_unavailable_result(
                    "Gemini returned an invalid response."
                )

            # =========================================
            # STRICT ALLOWLIST
            # =========================================

            normalized_result = self._normalize_gemini_advisory(
                gemini_result
            )

            if normalized_result is None:

                logger.warning(
                    "Gemini response rejected by strict allowlist."
                )

                return self._gemini_unavailable_result(
                    "Gemini response failed strict validation."
                )

            logger.info(
                "Gemini advisory analysis completed | status=%s",
                normalized_result.get("status"),
            )

            return normalized_result

        except Exception:

            logger.exception(
                "Gemini advisory analysis failed."
            )

            return self._gemini_unavailable_result(
                "Gemini service execution failed."
            )

    # =================================================
    # GEMINI RESPONSE NORMALIZATION
    # =================================================

    def _normalize_gemini_advisory(
        self,
        data,
    ):
        """
        Strictly normalize Gemini response.

        Unknown fields are discarded.

        Authoritative fraud information is never
        accepted from Gemini.
        """

        if not isinstance(data, dict):

            return None

        # =============================================
        # ONLY ALLOW EXPLICITLY APPROVED FIELDS
        # =============================================

        allowed_data = {

            key: value

            for key, value in data.items()

            if (
                isinstance(key, str)
                and key in self.GEMINI_ALLOWED_FIELDS
            )

        }

        # =============================================
        # AVAILABILITY VALIDATION
        # =============================================

        available = allowed_data.get(
            "available"
        )

        if not isinstance(available, bool):

            return None

        # =============================================
        # STATUS CONSISTENCY VALIDATION
        # =============================================

        incoming_status = allowed_data.get(
            "status"
        )

        if incoming_status not in self.GEMINI_ALLOWED_STATUSES:

            return None

        expected_status = (
            "success"
            if available is True
            else "unavailable"
        )

        if incoming_status != expected_status:

            return None

        # =============================================
        # COMMON RESPONSE METADATA
        # =============================================

        version = allowed_data.get(
            "version",
            "unknown",
        )

        model = allowed_data.get(
            "model",
            "unknown",
        )

        if not isinstance(version, str):
            version = "unknown"

        if not isinstance(model, str):
            model = "unknown"

        version = version.strip()[:100] or "unknown"

        model = model.strip()[:150] or "unknown"

        # =============================================
        # UNAVAILABLE RESPONSE
        # =============================================

        if available is False:

            reason = allowed_data.get(
                "reason",
                "Gemini advisory analysis is unavailable.",
            )

            if not isinstance(reason, str):

                reason = (
                    "Gemini advisory analysis is unavailable."
                )

            reason = (
                reason.strip()[:500]
                or "Gemini advisory analysis is unavailable."
            )

            return {

                "available": False,

                "status": "unavailable",

                "version": version,

                "model": model,

                "advisory_only": True,

                "reason": reason,

                "scam_intent": "",

                "social_engineering_tactics": [],

                "contextual_indicators": [],

                "explanation": "",

                "supporting_evidence": [],

                "alternative_interpretations": [],

                "advisory_confidence": "low",

                "safety_notes": [],

            }

        # =============================================
        # SUCCESS RESPONSE VALIDATION
        # =============================================

        required_fields = {

            "scam_intent",

            "social_engineering_tactics",

            "contextual_indicators",

            "explanation",

            "supporting_evidence",

            "alternative_interpretations",

            "advisory_confidence",

            "safety_notes",

        }

        if not required_fields.issubset(
            allowed_data.keys()
        ):

            return None

        # =============================================
        # STRING FIELD VALIDATION
        # =============================================

        normalized_strings = {}

        for field, max_length in self.GEMINI_STRING_LIMITS.items():

            if field not in allowed_data:
                continue

            value = allowed_data[field]

            if not isinstance(value, str):

                return None

            normalized_strings[field] = (
                value.strip()[:max_length]
            )

        # =============================================
        # LIST FIELD VALIDATION
        # =============================================

        normalized_lists = {}

        for field, max_items in self.GEMINI_LIST_LIMITS.items():

            if field not in allowed_data:
                continue

            value = allowed_data[field]

            if not isinstance(value, list):

                return None

            if not all(
                isinstance(item, str)
                for item in value
            ):

                return None

            normalized_lists[field] = [

                item.strip()[
                    :self.GEMINI_LIST_ITEM_MAX_LENGTH
                ]

                for item in value[:max_items]

                if item.strip()

            ]

        # =============================================
        # CONFIDENCE VALIDATION
        # =============================================

        confidence = allowed_data.get(
            "advisory_confidence"
        )

        if not isinstance(confidence, str):

            return None

        confidence = confidence.strip().lower()

        if confidence not in self.GEMINI_ALLOWED_CONFIDENCE:

            return None

        # =============================================
        # FINAL STRICT RESPONSE
        # =============================================

        return {

            "available": True,

            "status": "success",

            "version": version,

            "model": model,

            # Gemini cannot control this value.
            "advisory_only": True,

            "scam_intent": normalized_strings.get(
                "scam_intent",
                "",
            ),

            "social_engineering_tactics": normalized_lists.get(
                "social_engineering_tactics",
                [],
            ),

            "contextual_indicators": normalized_lists.get(
                "contextual_indicators",
                [],
            ),

            "explanation": normalized_strings.get(
                "explanation",
                "",
            ),

            "supporting_evidence": normalized_lists.get(
                "supporting_evidence",
                [],
            ),

            "alternative_interpretations": normalized_lists.get(
                "alternative_interpretations",
                [],
            ),

            "advisory_confidence": confidence,

            "safety_notes": normalized_lists.get(
                "safety_notes",
                [],
            ),

        }

    # =================================================
    # ORCHESTRATION STATUS
    # =================================================

    @classmethod
    def _get_orchestration_status(
        cls,
        orchestration_result,
    ):

        orchestration_result = cls._safe_dict(
            orchestration_result
        )

        orchestrator_info = cls._safe_dict(
            orchestration_result.get("orchestrator")
        )

        status = orchestrator_info.get(
            "status",
            orchestration_result.get(
                "status",
                "unknown",
            ),
        )

        return (
            status
            if isinstance(status, str)
            else "unknown"
        )

    # =================================================
    # METADATA BUILDER
    # =================================================

    def _build_metadata(
        self,
        request_id,
        evidence_type,
        started_at,
        orchestration_result=None,
        analysis_method="rule_based",
        gemini_advisory=None,
    ):

        orchestration_result = self._safe_dict(
            orchestration_result
        )

        gemini_advisory = self._safe_dict(
            gemini_advisory
        )

        gemini_configured = (
            self._is_gemini_configured()
        )

        return {

            "request_id": request_id,

            "analysis_id": orchestration_result.get(
                "analysis_id"
            ),

            "pipeline_version": self.VERSION,

            "evidence_type": evidence_type,

            "duration_seconds": round(
                time.perf_counter() - started_at,
                4,
            ),

            "completed_at": self._timestamp(),

            "analysis_method": analysis_method,

            "orchestration_status": (
                self._get_orchestration_status(
                    orchestration_result
                )
            ),

            "gemini_advisory_enabled": (
                gemini_configured
            ),

            "gemini_advisory_available": (
                gemini_advisory.get(
                    "available",
                    False,
                ) is True
            ),

            "gemini_status": gemini_advisory.get(
                "status",
                "unavailable",
            ),

            "gemini_version": gemini_advisory.get(
                "version",
                "unknown",
            ),

            "gemini_model": gemini_advisory.get(
                "model",
                "unknown",
            ),

        }

    # =================================================
    # SAFE ERROR RESPONSE
    # =================================================

    def _error_response(
        self,
        request_id,
        started_at,
        message,
        errors=None,
        evidence_type=None,
    ):

        metadata = {

            "request_id": request_id,

            "pipeline_version": self.VERSION,

            "duration_seconds": round(
                time.perf_counter() - started_at,
                4,
            ),

            "completed_at": self._timestamp(),

        }

        if evidence_type:

            metadata["evidence_type"] = evidence_type

        return {

            "success": False,

            "request_id": request_id,

            "service": "ScamShield AI",

            "status": "failed",

            "message": message,

            "errors": self._normalize_errors(
                errors or []
            ),

            "metadata": metadata,

            "verification": {

                "status": "UNVERIFIED",

                "external_verification": False,

            },

            "disclaimer": (
                "Analysis could not be completed. "
                "Do not treat missing results as evidence "
                "that the submitted content is safe."
            ),

        }

    # =================================================
    # SAFE CONTEXT FILTER
    # =================================================

    @staticmethod
    def _filter_safe_metadata(metadata):
        """
        Recursively filter sensitive metadata.

        Only safe primitive values and nested containers
        are retained.

        Unsupported objects, non-finite numbers,
        and excessive nesting are rejected.
        """

        if not isinstance(metadata, dict):
            return {}

        sensitive_keys = {
            "evidence",
            "message",
            "password",
            "otp",
            "token",
            "authorization",
            "bankdetails",
            "phonenumber",
            "email",
            "accountnumber",
            "cardnumber",
            "upiid",
            "cvv",
            "pin",
            "secret",
        }

        def sanitize(value, depth=0):

            if depth > AIPipeline.MAX_METADATA_DEPTH:
                return None

            # =========================================
            # NESTED DICTIONARIES
            # =========================================

            if isinstance(value, dict):

                safe_data = {}

                for key, item in value.items():

                    if not isinstance(key, str):
                        continue

                    normalized_key = re.sub(
                        r"[_\-\s]",
                        "",
                        key.strip().lower(),
                    )

                    if any(
                        sensitive in normalized_key
                        for sensitive in sensitive_keys
                    ):
                        continue

                    sanitized_value = sanitize(
                        item,
                        depth + 1,
                    )

                    if sanitized_value is not None:

                        safe_data[key] = sanitized_value

                return safe_data

            # =========================================
            # NESTED LISTS
            # =========================================

            if isinstance(value, list):

                safe_list = []

                for item in value:

                    sanitized = sanitize(
                        item,
                        depth + 1,
                    )

                    if sanitized is not None:

                        safe_list.append(sanitized)

                return safe_list

            # =========================================
            # FLOAT VALIDATION
            # =========================================

            if isinstance(value, float):

                return (
                    value
                    if math.isfinite(value)
                    else None
                )

            # =========================================
            # SAFE PRIMITIVE VALUES
            # =========================================

            if isinstance(value, (str, int, bool)):

                return value

            # =========================================
            # REJECT NONE AND UNSUPPORTED OBJECTS
            # =========================================

            return None

        return sanitize(metadata)

    # =================================================
    # AGENT EXECUTION SUMMARY
    # =================================================

    def _build_agent_summary(
        self,
        orchestration_result,
    ):

        orchestration_metadata = self._safe_dict(
            orchestration_result.get("metadata")
        )

        return {

            "agents_executed": self._safe_list(
                orchestration_metadata.get(
                    "agents_executed"
                )
            ),

            "agents_successful": self._safe_list(
                orchestration_metadata.get(
                    "agents_successful"
                )
            ),

            "agents_failed": self._safe_list(
                orchestration_metadata.get(
                    "agents_failed"
                )
            ),

            "agents_skipped": self._safe_list(
                orchestration_metadata.get(
                    "agents_skipped"
                )
            ),

        }

    # =================================================
    # MAIN ANALYSIS
    # =================================================

    def analyze(
        self,
        evidence,
        evidence_type="message",
        metadata=None,
    ):

        started_at = time.perf_counter()

        request_id = str(uuid.uuid4())

        normalized_evidence_type = None

        try:

            # =========================================
            # 1. INPUT VALIDATION
            # =========================================

            evidence, evidence_type = self._validate_input(
                evidence,
                evidence_type,
            )

            normalized_evidence_type = evidence_type

            logger.info(
                "AI pipeline started | request_id=%s | type=%s",
                request_id,
                evidence_type,
            )

            # =========================================
            # 2. RUN AGENT ORCHESTRATOR
            # =========================================

            orchestration_result = self.orchestrator.analyze(

                evidence=evidence,

                evidence_type=evidence_type,

            )

            if not isinstance(orchestration_result, dict):

                raise RuntimeError(
                    "Orchestrator returned an invalid response."
                )

            # =========================================
            # 3. EXTRACT ORCHESTRATION RESULTS
            # =========================================

            orchestration_status = (
                self._get_orchestration_status(
                    orchestration_result
                )
            )

            agent_results = self._safe_dict(
                orchestration_result.get("results")
            )

            errors = self._normalize_errors(
                orchestration_result.get("errors")
            )

            guardian_result = self._safe_dict(
                agent_results.get("guardian")
            )

            intelligence_result = self._safe_dict(
                agent_results.get("intelligence")
            )

            victim_safety_result = self._safe_dict(
                agent_results.get("victim_safety")
            )

            # =========================================
            # 4. COMPLETE ORCHESTRATION FAILURE
            # =========================================

            if not orchestration_result.get("success", False):

                logger.warning(
                    "AI orchestration failed | request_id=%s",
                    request_id,
                )

                return self._error_response(

                    request_id=request_id,

                    started_at=started_at,

                    message=(
                        "AI orchestration could not complete "
                        "the requested analysis."
                    ),

                    errors=errors,

                    evidence_type=evidence_type,

                )

            # =========================================
            # 5. GUARDIAN VALIDATION
            # =========================================

            guardian_analysis = self._safe_dict(
                guardian_result.get("analysis")
            )

            if not guardian_result.get("success", False):

                errors.append({

                    "agent": "guardian",

                    "message": (
                        "Guardian fraud analysis was unsuccessful."
                    ),

                })

                return self._error_response(

                    request_id=request_id,

                    started_at=started_at,

                    message=(
                        "Primary fraud analysis was unavailable."
                    ),

                    errors=errors,

                    evidence_type=evidence_type,

                )

            if not guardian_analysis:

                errors.append({

                    "agent": "guardian",

                    "message": (
                        "Guardian analysis structure was invalid."
                    ),

                })

                return self._error_response(

                    request_id=request_id,

                    started_at=started_at,

                    message=(
                        "Primary fraud analysis was unavailable."
                    ),

                    errors=errors,

                    evidence_type=evidence_type,

                )

            # =========================================
            # 6. AUTHORITATIVE DETERMINISTIC RESULT
            # =========================================

            guardian_category = guardian_analysis.get(
                "fraud_category",
                guardian_analysis.get(
                    "category",
                    "unknown",
                ),
            )

            deterministic_result = {

                "fraud_category": guardian_category,

                "risk_score": self._safe_score(
                    guardian_analysis.get("risk_score")
                ),

                "risk_level": guardian_analysis.get(
                    "risk_level",
                    "UNKNOWN",
                ),

                "summary": guardian_analysis.get(
                    "summary",
                    "",
                ),

                "signals": self._safe_list(
                    guardian_analysis.get("signals")
                ),

                "detected_rules": self._safe_list(
                    guardian_analysis.get("detected_rules")
                ),

                "indicators": self._safe_dict(
                    guardian_analysis.get("indicators")
                ),

            }

            # =========================================
            # 7. GEMINI ADVISORY INTEGRATION
            # =========================================

            gemini_advisory = self._run_gemini_advisory(

                evidence=evidence,

                evidence_type=evidence_type,

                deterministic_result=deterministic_result,

            )

            # =========================================
            # 8. MACHINE LEARNING INFORMATION
            # =========================================

            ml_result = self._safe_dict(
                guardian_analysis.get("machine_learning")
            )

            # =========================================
            # 9. PIPELINE METADATA
            # =========================================

            pipeline_metadata = self._build_metadata(

                request_id=request_id,

                evidence_type=evidence_type,

                started_at=started_at,

                orchestration_result=orchestration_result,

                analysis_method=guardian_analysis.get(
                    "analysis_method",
                    "rule_based",
                ),

                gemini_advisory=gemini_advisory,

            )

            safe_context = self._filter_safe_metadata(
                metadata
            )

            if safe_context:

                pipeline_metadata["context"] = safe_context

            # =========================================
            # 10. AGENT SUMMARY
            # =========================================

            agent_summary = self._build_agent_summary(
                orchestration_result
            )

            # =========================================
            # 11. FINAL UNIFIED RESPONSE
            # =========================================

            response = {

                "success": True,

                "request_id": request_id,

                "service": "ScamShield AI",

                "status": orchestration_status,

                # -------------------------------------
                # AUTHORITATIVE DETERMINISTIC RESULT
                # -------------------------------------

                "result": {

                    "category": guardian_category,

                    "risk_score": self._safe_score(
                        guardian_analysis.get("risk_score")
                    ),

                    "risk_level": guardian_analysis.get(
                        "risk_level",
                        "UNKNOWN",
                    ),

                    "summary": guardian_analysis.get(
                        "summary",
                        "",
                    ),

                    "explanations": self._safe_list(
                        guardian_analysis.get("explanations")
                    ),

                    "detected_rules": self._safe_list(
                        guardian_analysis.get("detected_rules")
                    ),

                    "signals": self._safe_list(
                        guardian_analysis.get("signals")
                    ),

                    "indicators": self._safe_dict(
                        guardian_analysis.get("indicators")
                    ),

                    "recommendations": self._safe_list(
                        guardian_analysis.get("recommendations")
                    ),

                    "scoring": self._safe_dict(
                        guardian_analysis.get("scoring")
                    ),

                },

                # -------------------------------------
                # GEMINI CONTEXTUAL ADVISORY
                # -------------------------------------

                "gemini_advisory": gemini_advisory,

                # -------------------------------------
                # OTHER AGENT RESULTS
                # -------------------------------------

                "intelligence": intelligence_result,

                "victim_safety": victim_safety_result,

                # -------------------------------------
                # MACHINE LEARNING
                # -------------------------------------

                "machine_learning": {

                    "available": ml_result.get(
                        "available",
                        False,
                    ),

                    "prediction": ml_result.get(
                        "prediction"
                    ),

                    "confidence": ml_result.get(
                        "confidence"
                    ),

                    "method": ml_result.get(
                        "method",
                        "not_available",
                    ),

                    "probability_calibrated": False,

                },

                # -------------------------------------
                # INDIVIDUAL AGENT RESULTS
                # -------------------------------------

                "agent_results": agent_results,

                # -------------------------------------
                # ERRORS
                # -------------------------------------

                "errors": errors,

                # -------------------------------------
                # METADATA
                # -------------------------------------

                "metadata": pipeline_metadata,

                # -------------------------------------
                # ORCHESTRATION
                # -------------------------------------

                "orchestration": {

                    "analysis_id": orchestration_result.get(
                        "analysis_id"
                    ),

                    "name": self._safe_dict(
                        orchestration_result.get("orchestrator")
                    ).get(
                        "name",
                        "AgentOrchestrator",
                    ),

                    "version": self._safe_dict(
                        orchestration_result.get("orchestrator")
                    ).get("version"),

                    "status": orchestration_status,

                    **agent_summary,

                },

                # -------------------------------------
                # VERIFICATION
                # -------------------------------------

                "verification": (

                    self._safe_dict(
                        orchestration_result.get("verification")
                    )

                    or {

                        "status": "UNVERIFIED",

                        "external_verification": False,

                    }

                ),

                # -------------------------------------
                # DISCLAIMER
                # -------------------------------------

                "disclaimer": (

                    "ScamShield AI provides automated "
                    "fraud risk analysis and precautionary "
                    "recommendations. "

                    "Guardian provides the authoritative "
                    "deterministic risk assessment. "

                    "Gemini provides contextual advisory "
                    "insights only and cannot modify the "
                    "deterministic risk score or category. "

                    "Risk scores are heuristic indicators, "
                    "not guaranteed fraud probabilities. "

                    "Machine learning confidence is not a "
                    "calibrated fraud probability. "

                    "Extracted indicators are unverified. "
                    "Verify suspicious claims through "
                    "official channels."

                ),

            }

            # =========================================
            # 12. COMPLETION LOGGING
            # =========================================

            logger.info(

                "AI pipeline completed | "
                "request_id=%s | "
                "status=%s | "
                "gemini_available=%s | "
                "gemini_status=%s",

                request_id,

                orchestration_status,

                gemini_advisory.get(
                    "available",
                    False,
                ),

                gemini_advisory.get(
                    "status",
                    "unknown",
                ),

            )

            return response

        # =============================================
        # INPUT VALIDATION ERRORS
        # =============================================

        except ValueError as error:

            logger.warning(

                "AI pipeline input rejected | "
                "request_id=%s | error=%s",

                request_id,

                str(error),

            )

            return self._error_response(

                request_id=request_id,

                started_at=started_at,

                message=str(error),

                evidence_type=normalized_evidence_type,

            )

        # =============================================
        # INTERNAL ERRORS
        # =============================================

        except Exception:

            logger.exception(

                "AI pipeline failed | request_id=%s",

                request_id,

            )

            return self._error_response(

                request_id=request_id,

                started_at=started_at,

                message=(
                    "An internal AI pipeline error occurred."
                ),

                errors=[{

                    "agent": "pipeline",

                    "message": (
                        "Analysis could not be completed."
                    ),

                }],

                evidence_type=normalized_evidence_type,

            )


# =====================================================
# SHARED PIPELINE INSTANCE
# =====================================================

ai_pipeline = AIPipeline()


# =====================================================
# PUBLIC FUNCTION
# =====================================================

def run_ai_pipeline(
    evidence,
    evidence_type="message",
    metadata=None,
):

    return ai_pipeline.analyze(

        evidence=evidence,

        evidence_type=evidence_type,

        metadata=metadata,

    )