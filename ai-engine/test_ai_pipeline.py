
"""
=========================================================
SCAMSHIELD AI - PIPELINE INTEGRATION TEST
=========================================================

Version: 1.1.0

Tests:
    1. Real AI pipeline execution.
    2. Agent orchestration.
    3. Guardian deterministic analysis.
    4. Guardian category integrity.
    5. Guardian risk score integrity.
    6. Guardian risk level integrity.
    7. Gemini advisory integration.
    8. Gemini advisory-only enforcement.
    9. Agent execution summary.
    10. Pipeline metadata.
    11. Machine learning response compatibility.
    12. Error and response structure validation.

IMPORTANT:
    Guardian remains authoritative.
    Gemini is advisory only.
=========================================================
"""

import json
import sys

from services.ai_pipeline import run_ai_pipeline


# =====================================================
# TEST CONFIGURATION
# =====================================================

EVIDENCE = (
    "URGENT: Your bank account will be blocked today. "
    "Share your OTP immediately with our bank executive "
    "to complete KYC verification. Do not delay."
)

EVIDENCE_TYPE = "message"


# =====================================================
# TEST UTILITIES
# =====================================================

def print_section(title):

    print("\n" + "=" * 65)
    print(title)
    print("=" * 65)


def print_check(name, passed):

    status = "PASS" if passed else "FAIL"

    print(f"[{status}] {name}")


def safe_dict(value):

    return value if isinstance(value, dict) else {}


def safe_list(value):

    return value if isinstance(value, list) else []


# =====================================================
# MAIN TEST
# =====================================================

def run_test():

    print_section(
        "SCAMSHIELD AI - PIPELINE INTEGRATION TEST"
    )

    print("\nEvidence Type:", EVIDENCE_TYPE)

    print("\n[1] Executing Real AI Pipeline...")

    response = run_ai_pipeline(

        evidence=EVIDENCE,

        evidence_type=EVIDENCE_TYPE,

    )

    if not isinstance(response, dict):

        print("[FAIL] Pipeline returned an invalid response.")

        return False

    # =================================================
    # PIPELINE STATUS
    # =================================================

    print_section("2. PIPELINE STATUS")

    success = response.get("success") is True

    print("Success:", response.get("success"))
    print("Status:", response.get("status"))
    print("Request ID:", response.get("request_id"))

    if not success:

        print("\n[FAIL] Pipeline execution unsuccessful.")

        print(
            json.dumps(
                response,
                indent=4,
                ensure_ascii=False,
                default=str,
            )
        )

        return False

    # =================================================
    # GUARDIAN VALIDATION
    # =================================================

    print_section("3. GUARDIAN DETERMINISTIC ANALYSIS")

    result = safe_dict(
        response.get("result")
    )

    agent_results = safe_dict(
        response.get("agent_results")
    )

    guardian_result = safe_dict(
        agent_results.get("guardian")
    )

    guardian_analysis = safe_dict(
        guardian_result.get("analysis")
    )

    pipeline_category = result.get("category")

    guardian_category = guardian_analysis.get(
        "fraud_category",
        guardian_analysis.get("category"),
    )

    pipeline_score = result.get("risk_score")

    guardian_score = guardian_analysis.get(
        "risk_score"
    )

    pipeline_level = result.get("risk_level")

    guardian_level = guardian_analysis.get(
        "risk_level"
    )

    print("Guardian Success:", guardian_result.get("success"))

    print("Pipeline Category:", pipeline_category)

    print("Guardian Category:", guardian_category)

    print("Pipeline Risk Score:", pipeline_score)

    print("Guardian Risk Score:", guardian_score)

    print("Pipeline Risk Level:", pipeline_level)

    print("Guardian Risk Level:", guardian_level)

    category_match = (
        pipeline_category == guardian_category
    )

    score_match = (
        pipeline_score == guardian_score
    )

    level_match = (
        pipeline_level == guardian_level
    )

    guardian_success = (
        guardian_result.get("success") is True
        and bool(guardian_analysis)
    )

    # =================================================
    # GEMINI VALIDATION
    # =================================================

    print_section("4. GEMINI ADVISORY")

    gemini = safe_dict(
        response.get("gemini_advisory")
    )

    gemini_available = (
        gemini.get("available") is True
    )

    print("Available:", gemini.get("available"))

    print("Status:", gemini.get("status"))

    print("Model:", gemini.get("model"))

    print("Version:", gemini.get("version"))

    print("Advisory Only:", gemini.get("advisory_only"))

    if gemini_available:

        print(
            "Scam Intent:",
            gemini.get("scam_intent"),
        )

        print(
            "Advisory Confidence:",
            gemini.get("advisory_confidence"),
        )

    else:

        print(
            "[WARNING] Gemini advisory is unavailable."
        )

        print(
            "Reason:",
            gemini.get("reason"),
        )

    # =================================================
    # AGENT EXECUTION
    # =================================================

    print_section("5. AGENT EXECUTION")

    orchestration = safe_dict(
        response.get("orchestration")
    )

    agents_executed = safe_list(
        orchestration.get("agents_executed")
    )

    agents_successful = safe_list(
        orchestration.get("agents_successful")
    )

    agents_failed = safe_list(
        orchestration.get("agents_failed")
    )

    agents_skipped = safe_list(
        orchestration.get("agents_skipped")
    )

    print("Agents Executed:", agents_executed)

    print("Agents Successful:", agents_successful)

    print("Agents Failed:", agents_failed)

    print("Agents Skipped:", agents_skipped)

    print("Orchestration Status:", orchestration.get("status"))

    # =================================================
    # PIPELINE METADATA
    # =================================================

    print_section("6. PIPELINE METADATA")

    metadata = safe_dict(
        response.get("metadata")
    )

    print(
        "Pipeline Version:",
        metadata.get("pipeline_version"),
    )

    print(
        "Analysis ID:",
        metadata.get("analysis_id"),
    )

    print(
        "Analysis Method:",
        metadata.get("analysis_method"),
    )

    print(
        "Duration:",
        metadata.get("duration_seconds"),
    )

    print(
        "Gemini Enabled:",
        metadata.get("gemini_advisory_enabled"),
    )

    print(
        "Gemini Available:",
        metadata.get("gemini_advisory_available"),
    )

    print(
        "Gemini Status:",
        metadata.get("gemini_status"),
    )

    # =================================================
    # MACHINE LEARNING
    # =================================================

    print_section("7. MACHINE LEARNING STATUS")

    ml_result = safe_dict(
        response.get("machine_learning")
    )

    print("Available:", ml_result.get("available"))

    print("Prediction:", ml_result.get("prediction"))

    print("Confidence:", ml_result.get("confidence"))

    print("Method:", ml_result.get("method"))

    print(
        "Probability Calibrated:",
        ml_result.get("probability_calibrated"),
    )

    # =================================================
    # FINAL VALIDATION
    # =================================================

    print_section("8. FINAL VALIDATION")

    checks = {

        "Pipeline Execution Successful": (
            success
        ),

        "Valid Request ID": (
            isinstance(
                response.get("request_id"),
                str,
            )
            and bool(response.get("request_id"))
        ),

        "Guardian Execution Successful": (
            guardian_success
        ),

        "Guardian Category Preserved": (
            category_match
        ),

        "Guardian Risk Score Preserved": (
            score_match
        ),

        "Guardian Risk Level Preserved": (
            level_match
        ),

        "Guardian Result Structure Valid": (
            isinstance(
                guardian_analysis,
                dict,
            )
            and bool(guardian_analysis)
        ),

        "Gemini Advisory Present": (
            isinstance(
                response.get("gemini_advisory"),
                dict,
            )
        ),

        "Gemini Advisory Only": (
            gemini.get("advisory_only") is True
        ),

        "Gemini Cannot Override Risk Score": (
            "risk_score" not in gemini
        ),

        "Gemini Cannot Override Fraud Category": (
            "fraud_category" not in gemini
            and "category" not in gemini
        ),

        "Agent Results Preserved": (
            isinstance(
                response.get("agent_results"),
                dict,
            )
        ),

        "Orchestration Summary Available": (
            isinstance(
                response.get("orchestration"),
                dict,
            )
        ),

        "Pipeline Metadata Available": (
            isinstance(
                response.get("metadata"),
                dict,
            )
        ),

        "Machine Learning Structure Valid": (
            isinstance(
                response.get("machine_learning"),
                dict,
            )
        ),

        "Errors Structure Valid": (
            isinstance(
                response.get("errors"),
                list,
            )
        ),

        "Verification Structure Available": (
            isinstance(
                response.get("verification"),
                dict,
            )
        ),

    }

    passed_count = 0

    for name, passed in checks.items():

        print_check(name, passed)

        if passed:
            passed_count += 1

    total_checks = len(checks)

    # =================================================
    # FINAL RESULT
    # =================================================

    print_section("9. TEST RESULT")

    print(
        f"RESULT: {passed_count}/{total_checks} CHECKS PASSED"
    )

    all_passed = (
        passed_count == total_checks
    )

    if all_passed:

        print(
            "\nSUCCESS: PIPELINE INTEGRATION TEST PASSED"
        )

    else:

        print(
            "\nFAILED: PIPELINE INTEGRATION TEST NEEDS ATTENTION"
        )

    print("=" * 65)

    # =================================================
    # COMPLETE RESPONSE
    # =================================================

    print("\nCOMPLETE PIPELINE RESPONSE:\n")

    print(
        json.dumps(
            response,
            indent=4,
            ensure_ascii=False,
            default=str,
        )
    )

    return all_passed


# =====================================================
# ENTRY POINT
# =====================================================

if __name__ == "__main__":

    try:

        test_passed = run_test()

        sys.exit(
            0 if test_passed else 1
        )

    except KeyboardInterrupt:

        print("\n[INTERRUPTED] Test execution cancelled.")

        sys.exit(1)

    except Exception as error:

        print(
            "\n[ERROR] Integration test execution failed:",
            str(error),
        )

        sys.exit(1)
