
"""
ScamShield AI - Report Generator

Generates structured fraud analysis reports.
Supports JSON report generation and local report storage.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from typing import Any, Dict, Optional


class ReportGenerator:
    """Generate and save ScamShield AI analysis reports."""

    REPORT_VERSION = "1.0"

    def __init__(self, output_dir: Optional[str] = None):
        base_dir = Path(__file__).resolve().parents[1]

        self.output_dir = (
            Path(output_dir).resolve()
            if output_dir
            else base_dir / "reports"
        )

    @staticmethod
    def _safe_dict(value: Any) -> Dict:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _safe_list(value: Any) -> list:
        return value if isinstance(value, list) else []

    @staticmethod
    def _safe_text(value: Any, default: str = "") -> str:
        if value is None:
            return default

        return str(value).strip()

    @staticmethod
    def _sanitize_filename(value: str) -> str:
        value = re.sub(r"[^a-zA-Z0-9_-]", "_", value)
        return value[:80] or "analysis"

    def generate_report(
        self,
        analysis_result: Dict,
        evidence_type: str = "unknown",
        analysis_id: Optional[str] = None,
        include_evidence: bool = False,
        original_evidence: Optional[str] = None,
    ) -> Dict:
        """
        Generate a structured report from the orchestrator response.

        Raw evidence is excluded by default.
        """

        if not isinstance(analysis_result, dict):
            raise ValueError("analysis_result must be a dictionary.")

        results = self._safe_dict(analysis_result.get("results"))

        guardian = self._safe_dict(results.get("guardian"))
        guardian_analysis = self._safe_dict(
            guardian.get("analysis")
        )

        intelligence = self._safe_dict(
            results.get("intelligence")
        )

        victim_safety = self._safe_dict(
            results.get("victim_safety")
        )

        decoy = self._safe_dict(results.get("decoy"))

        report_id = str(analysis_id or uuid4())

        report = {
            "report_id": report_id,
            "report_version": self.REPORT_VERSION,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "project": "ScamShield AI",

            "analysis": {
                "analysis_id": self._safe_text(
                    analysis_result.get("analysis_id"),
                    report_id,
                ),
                "status": self._safe_text(
                    analysis_result.get("status"),
                    "unknown",
                ),
                "evidence_type": self._safe_text(
                    evidence_type,
                    "unknown",
                ),
                "fraud_category": self._safe_text(
                    guardian_analysis.get("fraud_category"),
                    "unknown",
                ),
                "risk_score": guardian_analysis.get(
                    "risk_score", 0
                ),
                "risk_level": self._safe_text(
                    guardian_analysis.get("risk_level"),
                    "UNKNOWN",
                ),
                "summary": self._safe_text(
                    guardian_analysis.get("summary")
                ),
            },

            "guardian_analysis": {
                "signals": self._safe_list(
                    guardian_analysis.get("signals")
                ),
                "detected_rules": self._safe_list(
                    guardian_analysis.get("detected_rules")
                ),
                "indicators": self._safe_dict(
                    guardian_analysis.get("indicators")
                ),
                "explanations": self._safe_list(
                    guardian_analysis.get("explanations")
                ),
                "recommendations": self._safe_list(
                    guardian_analysis.get("recommendations")
                ),
                "scoring": self._safe_dict(
                    guardian_analysis.get("scoring")
                ),
                "machine_learning": self._safe_dict(
                    guardian_analysis.get("machine_learning")
                ),
            },

            "intelligence_analysis": {
                "status": self._safe_text(
                    intelligence.get("status"),
                    "unknown",
                ),
                "result": intelligence,
            },

            "victim_safety": {
                "status": self._safe_text(
                    victim_safety.get("status"),
                    "unknown",
                ),
                "result": victim_safety,
            },

            "decoy_simulation": {
                "status": self._safe_text(
                    decoy.get("status"),
                    "not_started",
                ),
                "simulation_only": True,
            },

            "execution_metadata": self._safe_dict(
                analysis_result.get("metadata")
            ),

            "verification": self._safe_dict(
                analysis_result.get("verification")
            ),

            "disclaimer": self._safe_text(
                analysis_result.get("disclaimer"),
                "This report is an AI-assisted assessment. "
                "Findings are indicators, not proof of fraud.",
            ),

            "limitations": [
                "Risk score is heuristic and not a calibrated probability.",
                "Extracted indicators are unverified.",
                "AI-generated findings may contain false positives or false negatives.",
                "This report does not replace official cybercrime investigation.",
            ],
        }

        if include_evidence and original_evidence is not None:
            report["evidence"] = {
                "included": True,
                "content": str(original_evidence),
            }
        else:
            report["evidence"] = {
                "included": False,
                "message": "Original evidence was excluded for privacy.",
            }

        return report

    def save_report(
        self,
        report: Dict,
        filename: Optional[str] = None,
    ) -> Dict:
        """Save a generated report as a JSON file."""

        if not isinstance(report, dict):
            raise ValueError("report must be a dictionary.")

        try:
            self.output_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            report_id = self._sanitize_filename(
                self._safe_text(
                    report.get("report_id"),
                    str(uuid4()),
                )
            )

            if filename:
                safe_filename = self._sanitize_filename(
                    Path(filename).stem
                )
            else:
                safe_filename = report_id

            file_path = self.output_dir / f"{safe_filename}.json"

            with file_path.open(
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    report,
                    file,
                    indent=4,
                    ensure_ascii=False,
                    default=str,
                )

            return {
                "success": True,
                "report_id": report_id,
                "file_path": str(file_path),
                "format": "json",
                "message": "Report saved successfully.",
            }

        except (OSError, TypeError, ValueError) as error:
            return {
                "success": False,
                "report_id": report.get("report_id"),
                "error": str(error),
                "message": "Unable to save report.",
            }

    def generate_and_save(
        self,
        analysis_result: Dict,
        evidence_type: str = "unknown",
        analysis_id: Optional[str] = None,
    ) -> Dict:
        """Generate and save a report in one operation."""

        try:
            report = self.generate_report(
                analysis_result=analysis_result,
                evidence_type=evidence_type,
                analysis_id=analysis_id,
            )

            save_result = self.save_report(report)

            return {
                "success": save_result.get("success", False),
                "report": report,
                "storage": save_result,
            }

        except (ValueError, TypeError) as error:
            return {
                "success": False,
                "error": str(error),
                "message": "Report generation failed.",
            }


# Shared instance
report_generator = ReportGenerator()


def generate_analysis_report(
    analysis_result: Dict,
    evidence_type: str = "unknown",
    analysis_id: Optional[str] = None,
) -> Dict:
    """Module-level report generation helper."""

    return report_generator.generate_report(
        analysis_result=analysis_result,
        evidence_type=evidence_type,
        analysis_id=analysis_id,
    )


def save_analysis_report(report: Dict) -> Dict:
    """Module-level report saving helper."""

    return report_generator.save_report(report)
