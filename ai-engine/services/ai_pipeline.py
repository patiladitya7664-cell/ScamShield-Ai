
import time
import uuid

from datetime import datetime, timezone

from services.agent_orchestrator import AgentOrchestrator
from utils.logger import logger


class AIPipeline:
    """
    Central AI pipeline for ScamShield AI.

    Coordinates the agent orchestrator and prepares
    a unified analysis response.
    """

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    MAX_EVIDENCE_LENGTH = 20000
    VERSION = "1.0.0"

    # =================================================
    # INITIALIZATION
    # =================================================

    def __init__(self):
        self.orchestrator = AgentOrchestrator()
        logger.info("ScamShield AI Pipeline initialized.")

    # =================================================
    # INPUT VALIDATION
    # =================================================

    def _validate_input(self, evidence, evidence_type):
        if not isinstance(evidence, str):
            raise ValueError("Evidence must be a string.")

        evidence = evidence.strip()

        if not evidence:
            raise ValueError("Evidence cannot be empty.")

        if len(evidence) > self.MAX_EVIDENCE_LENGTH:
            raise ValueError(
                "Evidence exceeds maximum allowed length."
            )

        if not isinstance(evidence_type, str):
            raise ValueError("Evidence type must be a string.")

        evidence_type = evidence_type.strip().lower()

        if evidence_type not in self.SUPPORTED_EVIDENCE_TYPES:
            raise ValueError("Unsupported evidence type.")

        return evidence, evidence_type

    # =================================================
    # SAFE HELPERS
    # =================================================

    @staticmethod
    def _timestamp():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _safe_dict(value):
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _safe_list(value):
        return value if isinstance(value, list) else []

    # =================================================
    # METADATA BUILDER
    # =================================================

    def _build_metadata(
        self,
        request_id,
        evidence_type,
        started_at,
        analysis_method="rule_based",
        orchestration_result=None,
    ):
        orchestration_result = self._safe_dict(
            orchestration_result
        )

        duration = round(
            time.perf_counter() - started_at,
            4,
        )

        return {
            "request_id": request_id,
            "analysis_id": orchestration_result.get(
                "analysis_id"
            ),
            "pipeline_version": self.VERSION,
            "evidence_type": evidence_type,
            "duration_seconds": duration,
            "completed_at": self._timestamp(),
            "analysis_method": analysis_method,
            "orchestration_status": orchestration_result.get(
                "status",
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
            "message": message,
            "errors": self._safe_list(errors),
            "metadata": metadata,
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
            # -----------------------------------------
            # VALIDATE INPUT
            # -----------------------------------------

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

            # -----------------------------------------
            # RUN ORCHESTRATOR
            # -----------------------------------------

            orchestration_result = self.orchestrator.analyze(
                evidence=evidence,
                evidence_type=evidence_type,
            )

            orchestration_result = self._safe_dict(
                orchestration_result
            )

            if not orchestration_result:
                raise RuntimeError(
                    "Orchestrator returned an invalid response."
                )

            agent_results = self._safe_dict(
                orchestration_result.get("results")
            )

            errors = self._safe_list(
                orchestration_result.get("errors")
            )

            orchestration_status = orchestration_result.get(
                "status",
                "unknown",
            )

            # -----------------------------------------
            # HANDLE COMPLETE FAILURE
            # -----------------------------------------

            if not orchestration_result.get("success", False):
                pipeline_metadata = self._build_metadata(
                    request_id=request_id,
                    evidence_type=evidence_type,
                    started_at=started_at,
                    orchestration_result=orchestration_result,
                )

                logger.warning(
                    "AI orchestration unsuccessful | request_id=%s",
                    request_id,
                )

                return {
                    "success": False,
                    "request_id": request_id,
                    "service": "ScamShield AI",
                    "status": orchestration_status,
                    "message": (
                        "AI orchestration could not complete "
                        "the requested analysis."
                    ),
                    "agent_results": agent_results,
                    "errors": errors,
                    "metadata": pipeline_metadata,
                    "verification": self._safe_dict(
                        orchestration_result.get("verification")
                    ),
                    "disclaimer": (
                        "Analysis could not be completed. "
                        "Do not treat missing results as evidence "
                        "that the submitted content is safe."
                    ),
                }

            # -----------------------------------------
            # EXTRACT AGENT RESULTS
            # -----------------------------------------

            guardian_result = self._safe_dict(
                agent_results.get("guardian")
            )

            intelligence_result = self._safe_dict(
                agent_results.get("intelligence")
            )

            victim_safety_result = self._safe_dict(
                agent_results.get("victim_safety")
            )

            guardian_analysis = self._safe_dict(
                guardian_result.get("analysis")
            )

            # Guardian is essential for the primary result.
            if not guardian_analysis:
                errors.append(
                    "Guardian analysis was unavailable."
                )

                pipeline_metadata = self._build_metadata(
                    request_id=request_id,
                    evidence_type=evidence_type,
                    started_at=started_at,
                    orchestration_result=orchestration_result,
                )

                return {
                    "success": False,
                    "request_id": request_id,
                    "service": "ScamShield AI",
                    "status": orchestration_status,
                    "message": (
                        "Primary fraud analysis was unavailable."
                    ),
                    "agent_results": agent_results,
                    "errors": errors,
                    "metadata": pipeline_metadata,
                    "verification": {
                        "status": "UNVERIFIED",
                        "external_verification": False,
                    },
                    "disclaimer": (
                        "A complete risk assessment could not "
                        "be produced. Do not assume the evidence "
                        "is safe."
                    ),
                }

            # -----------------------------------------
            # MACHINE LEARNING INFORMATION
            # -----------------------------------------

            ml_result = self._safe_dict(
                guardian_analysis.get("machine_learning")
            )

            # -----------------------------------------
            # PIPELINE METADATA
            # -----------------------------------------

            pipeline_metadata = self._build_metadata(
                request_id=request_id,
                evidence_type=evidence_type,
                started_at=started_at,
                analysis_method=guardian_analysis.get(
                    "analysis_method",
                    "rule_based",
                ),
                orchestration_result=orchestration_result,
            )

            # Preserve safe scalar context only.
            if isinstance(metadata, dict):
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
                }

                safe_context = {}

                for key, value in metadata.items():
                    if not isinstance(key, str):
                        continue

                    if key.strip().lower() in sensitive_keys:
                        continue

                    if isinstance(
                        value,
                        (str, int, float, bool, type(None)),
                    ):
                        safe_context[key] = value

                if safe_context:
                    pipeline_metadata["context"] = safe_context

            # -----------------------------------------
            # ORCHESTRATION METADATA
            # -----------------------------------------

            orchestration_metadata = self._safe_dict(
                orchestration_result.get("metadata")
            )

            # -----------------------------------------
            # FINAL RESPONSE
            # -----------------------------------------

            response = {
                "success": True,
                "request_id": request_id,
                "service": "ScamShield AI",
                "status": orchestration_status,

                "result": {
                    "category": guardian_analysis.get(
                        "fraud_category",
                        "unknown",
                    ),
                    "risk_score": guardian_analysis.get(
                        "risk_score",
                        0,
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

                "intelligence": intelligence_result,

                "victim_safety": victim_safety_result,

                "machine_learning": {
                    "available": ml_result.get(
                        "available",
                        False,
                    ),
                    "prediction": ml_result.get("prediction"),
                    "confidence": ml_result.get("confidence"),
                    "method": ml_result.get(
                        "method",
                        "not_available",
                    ),
                },

                "agent_results": agent_results,

                "errors": errors,

                "metadata": pipeline_metadata,

                "orchestration": {
                    "analysis_id": orchestration_result.get(
                        "analysis_id"
                    ),
                    "status": orchestration_status,
                    "agents_executed": orchestration_metadata.get(
                        "agents_executed",
                        [],
                    ),
                    "agents_successful": orchestration_metadata.get(
                        "agents_successful",
                        [],
                    ),
                    "agents_failed": orchestration_metadata.get(
                        "agents_failed",
                        [],
                    ),
                },

                "verification": self._safe_dict(
                    orchestration_result.get("verification")
                ) or {
                    "status": "UNVERIFIED",
                    "external_verification": False,
                },

                "disclaimer": (
                    "AI-generated analysis is advisory. "
                    "Risk scores are heuristic indicators, "
                    "not guaranteed fraud probabilities. "
                    "Extracted indicators are unverified. "
                    "Verify suspicious claims through official channels."
                ),
            }

            logger.info(
                "AI pipeline completed | request_id=%s | status=%s",
                request_id,
                orchestration_status,
            )

            return response

        except ValueError as error:
            logger.warning(
                "AI pipeline input rejected | request_id=%s",
                request_id,
            )

            return self._error_response(
                request_id=request_id,
                started_at=started_at,
                message=str(error),
                evidence_type=normalized_evidence_type,
            )

        except Exception:
            logger.exception(
                "AI pipeline failed | request_id=%s",
                request_id,
            )

            return self._error_response(
                request_id=request_id,
                started_at=started_at,
                message="An internal AI pipeline error occurred.",
                errors=[
                    "Analysis could not be completed."
                ],
                evidence_type=normalized_evidence_type,
            )


# =========================================================
# SHARED PIPELINE INSTANCE
# =========================================================

ai_pipeline = AIPipeline()


# =========================================================
# PUBLIC FUNCTION
# =========================================================

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
