"""
=========================================================
SCAMSHIELD AI - AGENT ORCHESTRATOR
=========================================================

Version: 1.1.0

Purpose:
- Coordinate all four AI agents.
- Execute primary fraud detection.
- Extract intelligence indicators.
- Generate victim safety recommendations.
- Track individual agent execution.
- Keep decoy simulation separately controlled.
- Generate a unified analysis response.

No real-world communication is performed.
=========================================================
"""

from datetime import datetime, timezone
from time import perf_counter
from typing import Any, Dict, List
from uuid import uuid4

from agents.guardian_agent import GuardianAgent
from agents.intelligence_agent import IntelligenceAgent
from agents.victim_safety_agent import VictimSafetyAgent
from agents.decoy_agent import DecoyAgent

from utils.logger import logger, log_agent_execution


class AgentOrchestrator:

    VERSION = "1.1.0"

    SUPPORTED_EVIDENCE_TYPES = {
        "message",
        "url",
        "call",
        "transaction",
        "screenshot",
        "email",
    }

    MAX_EVIDENCE_LENGTH = 20000

    def __init__(self):

        self.guardian = GuardianAgent()
        self.intelligence = IntelligenceAgent()
        self.victim_safety = VictimSafetyAgent()
        self.decoy = DecoyAgent()

        logger.info(
            "ScamShield AI Agent Orchestrator initialized | version=%s",
            self.VERSION,
        )

    # =====================================================
    # SAFE HELPERS
    # =====================================================

    @staticmethod
    def _timestamp():

        return datetime.now(
            timezone.utc
        ).isoformat()

    @staticmethod
    def _safe_dict(value):

        return value if isinstance(value, dict) else {}

    @staticmethod
    def _safe_list(value):

        return value if isinstance(value, list) else []

    @staticmethod
    def _safe_string(value, default=""):

        if isinstance(value, str):
            return value

        return default

    # =====================================================
    # INPUT VALIDATION
    # =====================================================

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

    # =====================================================
    # AGENT RESPONSE VALIDATION
    # =====================================================

    @staticmethod
    def _validate_agent_result(
        result,
        agent_name,
    ):

        if not isinstance(result, dict):

            logger.error(
                "%s returned an invalid response.",
                agent_name,
            )

            return {
                "success": False,
                "error": {
                    "code": "invalid_agent_response",
                    "message": (
                        f"{agent_name} returned an invalid response."
                    ),
                },
            }

        if not isinstance(result.get("success"), bool):

            return {
                "success": False,
                "error": {
                    "code": "missing_success_status",
                    "message": (
                        f"{agent_name} returned an incomplete response."
                    ),
                },
            }

        return result

    # =====================================================
    # MAIN ANALYSIS
    # =====================================================

    def analyze(
        self,
        evidence: str,
        evidence_type: str = "message",
    ) -> Dict[str, Any]:

        start_time = perf_counter()
        analysis_id = str(uuid4())

        results = {
            "guardian": None,
            "intelligence": None,
            "victim_safety": None,

            "decoy": {
                "status": "not_started",
                "message": (
                    "Decoy simulation is a separate controlled "
                    "operation and was not started automatically."
                ),
            },
        }

        errors: List[Dict[str, str]] = []

        # =============================================
        # INPUT VALIDATION
        # =============================================

        try:

            evidence, evidence_type = self._validate_input(
                evidence,
                evidence_type,
            )

        except ValueError as error:

            return self._build_response(
                analysis_id=analysis_id,
                results=results,
                errors=[
                    {
                        "agent": "orchestrator",
                        "message": str(error),
                    }
                ],
                start_time=start_time,
                status="failed",
                evidence_type=None,
            )

        logger.info(
            "Agent orchestration started | analysis_id=%s | type=%s",
            analysis_id,
            evidence_type,
        )

        # =============================================
        # 1. GUARDIAN AGENT
        # =============================================

        guardian_result = self._run_guardian(
            evidence=evidence,
            evidence_type=evidence_type,
        )

        results["guardian"] = guardian_result

        if not guardian_result["success"]:

            errors.append({
                "agent": "guardian",
                "message": (
                    "Primary fraud analysis could not be completed."
                ),
            })

            return self._build_response(
                analysis_id=analysis_id,
                results=results,
                errors=errors,
                start_time=start_time,
                status="failed",
                evidence_type=evidence_type,
            )

        guardian_analysis = self._safe_dict(
            guardian_result.get("analysis")
        )

        if not guardian_analysis:

            errors.append({
                "agent": "guardian",
                "message": (
                    "Guardian returned an invalid analysis structure."
                ),
            })

            return self._build_response(
                analysis_id=analysis_id,
                results=results,
                errors=errors,
                start_time=start_time,
                status="failed",
                evidence_type=evidence_type,
            )

        # =============================================
        # 2. INTELLIGENCE AGENT
        # =============================================

        intelligence_result = self._run_intelligence(
            evidence=evidence,
            evidence_type=evidence_type,
        )

        results["intelligence"] = intelligence_result

        if not intelligence_result["success"]:

            errors.append({
                "agent": "intelligence",
                "message": (
                    "Intelligence analysis could not be completed."
                ),
            })

        # =============================================
        # 3. VICTIM SAFETY AGENT
        # =============================================

        risk_level = guardian_analysis.get(
            "risk_level",
            "UNKNOWN",
        )

        risk_score = guardian_analysis.get(
            "risk_score",
        )

        detected_signals = guardian_analysis.get(
            "signals",
            [],
        )

        safety_result = self._run_victim_safety(
            evidence=evidence,
            evidence_type=evidence_type,
            risk_level=risk_level,
            risk_score=risk_score,
            detected_signals=detected_signals,
        )

        results["victim_safety"] = safety_result

        if not safety_result["success"]:

            errors.append({
                "agent": "victim_safety",
                "message": (
                    "Victim safety analysis could not be completed."
                ),
            })

        # =============================================
        # 4. FINAL STATUS
        # =============================================

        status = (
            "completed"
            if not errors
            else "partial"
        )

        response = self._build_response(
            analysis_id=analysis_id,
            results=results,
            errors=errors,
            start_time=start_time,
            status=status,
            evidence_type=evidence_type,
        )

        logger.info(
            "Agent orchestration completed | analysis_id=%s | status=%s",
            analysis_id,
            status,
        )

        return response

    # =====================================================
    # GUARDIAN AGENT
    # =====================================================

    def _run_guardian(
        self,
        evidence,
        evidence_type,
    ):

        try:

            result = self.guardian.analyze(
                evidence=evidence,
                evidence_type=evidence_type,
            )

            return self._validate_agent_result(
                result,
                "Guardian",
            )

        except Exception:

            logger.exception(
                "Guardian Agent execution failed."
            )

            return {
                "success": False,
                "error": {
                    "code": "guardian_execution_failed",
                    "message": (
                        "Guardian Agent execution failed."
                    ),
                },
            }

    # =====================================================
    # INTELLIGENCE AGENT
    # =====================================================

    def _run_intelligence(
        self,
        evidence,
        evidence_type,
    ):

        try:

            result = self.intelligence.analyze(
                evidence=evidence,
                evidence_type=evidence_type,
            )

            return self._validate_agent_result(
                result,
                "Intelligence",
            )

        except Exception:

            logger.exception(
                "Intelligence Agent execution failed."
            )

            return {
                "success": False,
                "error": {
                    "code": "intelligence_execution_failed",
                    "message": (
                        "Intelligence Agent execution failed."
                    ),
                },
            }

    # =====================================================
    # VICTIM SAFETY AGENT
    # =====================================================

    def _run_victim_safety(
        self,
        evidence,
        evidence_type,
        risk_level,
        risk_score,
        detected_signals,
    ):

        try:

            result = self.victim_safety.analyze(
                evidence=evidence,
                evidence_type=evidence_type,
                risk_level=risk_level,
                risk_score=risk_score,
                detected_signals=detected_signals,
            )

            return self._validate_agent_result(
                result,
                "VictimSafety",
            )

        except Exception:

            logger.exception(
                "Victim Safety Agent execution failed."
            )

            return {
                "success": False,
                "error": {
                    "code": "victim_safety_execution_failed",
                    "message": (
                        "Victim Safety Agent execution failed."
                    ),
                },
            }

    # =====================================================
    # UNIFIED RESPONSE
    # =====================================================

    def _build_response(
        self,
        analysis_id,
        results,
        errors,
        start_time,
        status,
        evidence_type=None,
    ):

        duration = round(
            (perf_counter() - start_time) * 1000,
            2,
        )

        agents = [
            "guardian",
            "intelligence",
            "victim_safety",
        ]

        agents_executed = [
            name
            for name in agents
            if isinstance(results.get(name), dict)
        ]

        agents_successful = [
            name
            for name in agents
            if isinstance(results.get(name), dict)
            and results[name].get("success") is True
        ]

        agents_failed = [
            name
            for name in agents
            if isinstance(results.get(name), dict)
            and results[name].get("success") is False
        ]

        response = {
            "success": status != "failed",

            "analysis_id": analysis_id,

            "orchestrator": {
                "name": "ScamShield AI Agent Orchestrator",
                "version": self.VERSION,
                "status": status,
            },

            "results": results,

            "errors": errors,

            "metadata": {
                "created_at": self._timestamp(),

                "duration_ms": duration,

                "evidence_type": evidence_type,

                "agents_executed": agents_executed,

                "agents_successful": agents_successful,

                "agents_failed": agents_failed,

                "agents_skipped": [
                    name
                    for name in agents
                    if name not in agents_executed
                ],
            },

            "verification": {
                "status": "UNVERIFIED",

                "external_verification": False,

                "message": (
                    "Automated analysis is advisory. "
                    "Detected indicators and predictions require "
                    "independent verification."
                ),
            },

            "disclaimer": (
                "ScamShield AI provides automated risk analysis "
                "and precautionary recommendations. It cannot "
                "independently verify the identity of a sender "
                "or confirm that a reported event is genuine."
            ),
        }

        try:

            log_agent_execution(
                "AgentOrchestrator",
                status.upper(),
                (
                    f"Analysis ID: {analysis_id} | "
                    f"Status: {status} | "
                    f"Successful agents: {len(agents_successful)} | "
                    f"Failed agents: {len(agents_failed)} | "
                    f"Duration: {duration} ms"
                ),
            )

        except Exception:

            logger.exception(
                "Orchestrator execution logging failed."
            )

        return response

    # =====================================================
    # CONTROLLED DECOY SIMULATION
    # =====================================================

    def start_decoy_simulation(
        self,
        scam_message,
    ):

        try:

            result = self.decoy.start_session(
                scam_message
            )

            return self._validate_agent_result(
                result,
                "Decoy",
            )

        except Exception:

            logger.exception(
                "Decoy simulation start failed."
            )

            return {
                "success": False,
                "error": {
                    "code": "decoy_start_failed",
                    "message": (
                        "Could not start decoy simulation."
                    ),
                },
            }

    def continue_decoy_simulation(
        self,
        session_id,
        scam_message,
    ):

        try:

            result = self.decoy.continue_session(
                session_id,
                scam_message,
            )

            return self._validate_agent_result(
                result,
                "Decoy",
            )

        except Exception:

            logger.exception(
                "Decoy simulation continuation failed."
            )

            return {
                "success": False,
                "error": {
                    "code": "decoy_continue_failed",
                    "message": (
                        "Could not continue decoy simulation."
                    ),
                },
            }

    def end_decoy_simulation(
        self,
        session_id,
    ):

        try:

            result = self.decoy.end_session(
                session_id
            )

            return self._validate_agent_result(
                result,
                "Decoy",
            )

        except Exception:

            logger.exception(
                "Decoy simulation termination failed."
            )

            return {
                "success": False,
                "error": {
                    "code": "decoy_end_failed",
                    "message": (
                        "Could not end decoy simulation."
                    ),
                },
            }


# =========================================================
# REUSABLE ORCHESTRATOR
# =========================================================

agent_orchestrator = AgentOrchestrator()


# =========================================================
# PUBLIC ANALYSIS FUNCTION
# =========================================================

def run_complete_analysis(
    evidence,
    evidence_type="message",
):

    return agent_orchestrator.analyze(
        evidence=evidence,
        evidence_type=evidence_type,
    )