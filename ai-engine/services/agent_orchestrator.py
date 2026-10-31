
"""
=========================================================
SCAMSHIELD AI - AGENT ORCHESTRATOR
=========================================================

Purpose:
- Coordinate all four AI agents.
- Execute fraud detection and intelligence analysis.
- Generate victim safety recommendations.
- Keep Decoy simulation separately controlled.
- Combine results into one unified response.

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

    VERSION = "1.0.0"

    def __init__(self):

        self.guardian = GuardianAgent()
        self.intelligence = IntelligenceAgent()
        self.victim_safety = VictimSafetyAgent()
        self.decoy = DecoyAgent()

    # -----------------------------------------------------
    # MAIN PIPELINE
    # -----------------------------------------------------

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

        try:

            # =============================================
            # 1. GUARDIAN AGENT
            # =============================================

            guardian_result = self._run_guardian(
                evidence,
                evidence_type,
            )

            results["guardian"] = guardian_result

            if not guardian_result.get("success"):

                errors.append({
                    "agent": "guardian",
                    "message": (
                        "Primary fraud analysis could not be completed."
                    ),
                })

                # Guardian is the primary fraud assessment agent.
                # Without its result, downstream risk-dependent
                # processing must not invent risk information.

                return self._build_response(
                    analysis_id=analysis_id,
                    results=results,
                    errors=errors,
                    start_time=start_time,
                    status="failed",
                )

            guardian_analysis = guardian_result.get(
                "analysis",
                {},
            )

            if not isinstance(guardian_analysis, dict):

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
                )

            # =============================================
            # 2. INTELLIGENCE AGENT
            # =============================================

            intelligence_result = self._run_intelligence(
                evidence,
                evidence_type,
            )

            results["intelligence"] = intelligence_result

            if not intelligence_result.get("success"):

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

            if not safety_result.get("success"):

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

            return self._build_response(
                analysis_id=analysis_id,
                results=results,
                errors=errors,
                start_time=start_time,
                status=status,
            )

        except Exception:

            logger.exception(
                "Agent orchestration failed | analysis_id=%s",
                analysis_id,
            )

            errors.append({
                "agent": "orchestrator",
                "message": (
                    "Unexpected orchestration failure."
                ),
            })

            return self._build_response(
                analysis_id=analysis_id,
                results=results,
                errors=errors,
                start_time=start_time,
                status="failed",
            )

    # -----------------------------------------------------
    # GUARDIAN EXECUTION
    # -----------------------------------------------------

    def _run_guardian(
        self,
        evidence: str,
        evidence_type: str,
    ) -> Dict[str, Any]:

        try:

            return self.guardian.analyze(
                evidence=evidence,
                evidence_type=evidence_type,
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

    # -----------------------------------------------------
    # INTELLIGENCE EXECUTION
    # -----------------------------------------------------

    def _run_intelligence(
        self,
        evidence: str,
        evidence_type: str,
    ) -> Dict[str, Any]:

        try:

            return self.intelligence.analyze(
                evidence=evidence,
                evidence_type=evidence_type,
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

    # -----------------------------------------------------
    # VICTIM SAFETY EXECUTION
    # -----------------------------------------------------

    def _run_victim_safety(
        self,
        evidence: str,
        evidence_type: str,
        risk_level: str,
        risk_score: Any,
        detected_signals: Any,
    ) -> Dict[str, Any]:

        try:

            return self.victim_safety.analyze(
                evidence=evidence,
                evidence_type=evidence_type,
                risk_level=risk_level,
                risk_score=risk_score,
                detected_signals=detected_signals,
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

    # -----------------------------------------------------
    # UNIFIED RESPONSE
    # -----------------------------------------------------

    def _build_response(
        self,
        analysis_id: str,
        results: Dict[str, Any],
        errors: List[Dict[str, str]],
        start_time: float,
        status: str,
    ) -> Dict[str, Any]:

        duration = round(
            (perf_counter() - start_time) * 1000,
            2,
        )

        agents_executed = [
            name
            for name, result in results.items()
            if isinstance(result, dict)
            and result.get("success") is not None
        ]

        response = {
            "success": status != "failed",

            "analysis_id": analysis_id,

            "orchestrator": {
                "name": "ScamShield AI Agent Orchestrator",
                "version": self.VERSION,
                "status": status,
            },

            # AI Pipeline consumes this exact key.
            "results": results,

            "errors": errors,

            "metadata": {
                "created_at": datetime.now(
                    timezone.utc
                ).isoformat(),

                "duration_ms": duration,

                "agents_executed": agents_executed,

                "agents_successful": [
                    name
                    for name, result in results.items()
                    if isinstance(result, dict)
                    and result.get("success") is True
                ],

                "agents_failed": [
                    name
                    for name, result in results.items()
                    if isinstance(result, dict)
                    and result.get("success") is False
                ],
            },

            "verification": {
                "status": "UNVERIFIED",

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

        # ---------------------------------------------
        # STANDARD EXECUTION LOGGING
        # ---------------------------------------------

        log_agent_execution(
            "AgentOrchestrator",
            status.upper(),
            (
                f"Analysis ID: {analysis_id} | "
                f"Status: {status} | "
                f"Errors: {len(errors)} | "
                f"Duration: {duration} ms"
            ),
        )

        return response

    # -----------------------------------------------------
    # CONTROLLED DECOY SIMULATION
    # -----------------------------------------------------

    def start_decoy_simulation(
        self,
        scam_message: str,
    ) -> Dict[str, Any]:

        return self.decoy.start_session(
            scam_message
        )

    def continue_decoy_simulation(
        self,
        session_id: str,
        scam_message: str,
    ) -> Dict[str, Any]:

        return self.decoy.continue_session(
            session_id,
            scam_message,
        )

    def end_decoy_simulation(
        self,
        session_id: str,
    ) -> Dict[str, Any]:

        return self.decoy.end_session(
            session_id
        )


# =========================================================
# REUSABLE ORCHESTRATOR
# =========================================================

agent_orchestrator = AgentOrchestrator()


# =========================================================
# PUBLIC ANALYSIS FUNCTION
# =========================================================

def run_complete_analysis(
    evidence: str,
    evidence_type: str = "message",
) -> Dict[str, Any]:

    return agent_orchestrator.analyze(
        evidence=evidence,
        evidence_type=evidence_type,
    )
