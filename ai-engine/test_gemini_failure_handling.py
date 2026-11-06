"""
=========================================================
SCAMSHIELD AI - GEMINI FAILURE HANDLING TEST
=========================================================

Tests:
1. Gemini exception handling.
2. Invalid Gemini response handling.
3. Gemini unavailable fallback.
4. Guardian authority protection.
5. Deterministic analysis continuity.

Gemini failures must never interrupt Guardian analysis.
=========================================================
"""

from services.ai_pipeline import AIPipeline


EVIDENCE = (
    "URGENT: Your bank account will be blocked today. "
    "Share your OTP immediately with our bank executive "
    "to complete KYC verification. Do not delay."
)


class MockGeminiException:

    def analyze(self, **kwargs):

        raise RuntimeError(
            "Simulated Gemini API failure."
        )


class MockGeminiInvalid:

    def analyze(self, **kwargs):

        return None


class MockGeminiUnavailable:

    def analyze(self, **kwargs):

        return {

            "available": False,

            "status": "unavailable",

            "reason": "Simulated API unavailability.",

        }


class MockGeminiOverride:

    def analyze(self, **kwargs):

        return {

            "available": True,

            "status": "success",

            "advisory_only": False,

            "risk_score": 0,

            "fraud_category": "safe",

            "category": "safe",

            "risk_level": "LOW",

            "scam_intent": "Possible credential theft",

            "advisory_confidence": "high",

        }


def run_scenario(name, gemini):

    print("\n" + "=" * 60)
    print(name)
    print("=" * 60)

    pipeline = AIPipeline(
        gemini=gemini,
    )

    response = pipeline.analyze(
        evidence=EVIDENCE,
        evidence_type="message",
    )

    if not isinstance(response, dict):

        return {
            "Pipeline Success": False,
        }

    result = response.get("result", {})

    guardian = (
        response.get("agent_results", {})
        .get("guardian", {})
        .get("analysis", {})
    )

    advisory = response.get(
        "gemini_advisory",
        {},
    )

    checks = {

        "Pipeline Success": (
            response.get("success") is True
        ),

        "Guardian Success": (
            guardian.get("risk_score") is not None
        ),

        "Guardian Score Preserved": (
            result.get("risk_score")
            == guardian.get("risk_score")
        ),

        "Guardian Category Preserved": (
            result.get("category")
            == guardian.get("fraud_category")
        ),

        "Gemini Advisory Only": (
            advisory.get("advisory_only") is True
        ),

    }

    for key, value in checks.items():

        print(
            f"{'[PASS]' if value else '[FAIL]'} {key}"
        )

    print(
        "Gemini Available:",
        advisory.get("available"),
    )

    print(
        "Gemini Status:",
        advisory.get("status"),
    )

    print(
        "Guardian Risk:",
        result.get("risk_score"),
    )

    print(
        "Guardian Category:",
        result.get("category"),
    )

    return checks


def run_test():

    print("\n" + "=" * 60)
    print("SCAMSHIELD AI - GEMINI FAILURE HANDLING TEST")
    print("=" * 60)

    scenarios = [

        (
            "TEST 1 - GEMINI EXCEPTION",
            MockGeminiException(),
        ),

        (
            "TEST 2 - INVALID GEMINI RESPONSE",
            MockGeminiInvalid(),
        ),

        (
            "TEST 3 - GEMINI UNAVAILABLE",
            MockGeminiUnavailable(),
        ),

        (
            "TEST 4 - GUARDIAN AUTHORITY PROTECTION",
            MockGeminiOverride(),
        ),

    ]

    total_passed = 0
    total_checks = 0

    for name, gemini in scenarios:

        checks = run_scenario(
            name,
            gemini,
        )

        for passed in checks.values():

            total_checks += 1

            if passed:
                total_passed += 1

    print("\n" + "=" * 60)
    print("FINAL TEST SUMMARY")
    print("=" * 60)

    print(
        f"Passed: {total_passed}/{total_checks}"
    )

    print(
        f"Failed: {total_checks - total_passed}"
    )

    if total_passed == total_checks:

        print(
            "\nSUCCESS: GEMINI FAILURE HANDLING PASSED!"
        )

    else:

        print(
            "\nWARNING: SOME FAILURE HANDLING TESTS FAILED."
        )

    print("=" * 60)


if __name__ == "__main__":

    run_test()