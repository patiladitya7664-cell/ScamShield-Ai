
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

        Guardian remains authoritative.

        Gemini failures must never interrupt
        deterministic fraud analysis.
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

            if not isinstance(gemini_result, dict):

                logger.warning(
                    "Gemini returned an invalid response."
                )

                return self._gemini_unavailable_result(
                    "Gemini returned an invalid response."
                )

            normalized_result = dict(gemini_result)

            # =========================================
            # ENFORCE ADVISORY-ONLY STATUS
            # =========================================

            normalized_result["advisory_only"] = True

            # Gemini cannot modify authoritative
            # deterministic risk information.

            normalized_result.pop(
                "risk_score",
                None,
            )

            normalized_result.pop(
                "fraud_category",
                None,
            )

            normalized_result.pop(
                "category",
                None,
            )

            normalized_result.pop(
                "risk_level",
                None,
            )

            # =========================================
            # NORMALIZE AVAILABILITY
            # =========================================

            if normalized_result.get("available") is not True:

                normalized_result["available"] = False

                normalized_result["status"] = (
                    normalized_result.get(
                        "status",
                        "unavailable",
                    )
                )

            else:

                normalized_result["status"] = "success"

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

        if not isinstance(metadata, dict):
            return {}

        sensitive_keys = {

            "evidence",
            "message",
            "password",
            "otp",
            "token",
            "authorization",
            "bank_details",
            "phone_number",
            "email",
            "account_number",
            "card_number",
            "upi_id",
            "cvv",
            "pin",
            "secret",

        }

        safe_context = {}

        for key, value in metadata.items():

            if not isinstance(key, str):
                continue

            normalized_key = key.strip().lower()

            if normalized_key in sensitive_keys:
                continue

            if isinstance(
                value,
                (str, int, float, bool, type(None)),
            ):

                if isinstance(value, float):

                    if not math.isfinite(value):
                        continue

                safe_context[key] = value

        return safe_context

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
