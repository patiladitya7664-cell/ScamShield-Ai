if str(AI_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_ENGINE_ROOT))


# =========================================================
# IMPORT PRODUCTION GEMINI SERVICE
# =========================================================

try:

    from services.gemini_service import gemini_service

except Exception as error:

    print("\nFAILED: Unable to import Gemini service.")
    print(type(error).__name__, str(error))
    sys.exit(1)


# =========================================================
# TEST EVIDENCE
# =========================================================

EVIDENCE = """
URGENT BANK ALERT:

Your bank account will be blocked today.

Complete your KYC verification immediately.

Share your OTP with our verification executive
to prevent account suspension.

Do not ignore this message.
"""

EVIDENCE_TYPE = "message"


# =========================================================
# DETERMINISTIC DETECTOR RESULT
# =========================================================

DETERMINISTIC_RESULT = {

    "fraud_category": "fraud_message",

    "risk_level": "HIGH",

    "risk_score": 85,

    "signals": [

        "urgent_kyc_warning",

        "otp_request",

        "threatening_account_block"

    ]

}


# =========================================================
# TEST EXECUTION
# =========================================================

def run_test():

    print("\n" + "=" * 65)

    print("SCAMSHIELD AI - GEMINI PRODUCTION SERVICE TEST")

    print("=" * 65)


    # -----------------------------------------------------
    # TEST 1: SERVICE INITIALIZATION
    # -----------------------------------------------------

    print("\n[TEST 1] Gemini Service Initialization")

    print("Service Available:", gemini_service.available)

    if not gemini_service.available:

        print("[FAILED] Gemini service is not initialized.")

        print("Reason:", gemini_service.last_error)

        return

    print("[PASSED] Gemini service initialized.")


    # -----------------------------------------------------
    # SAVE ORIGINAL DETERMINISTIC VALUES
    # -----------------------------------------------------

    original_score = DETERMINISTIC_RESULT["risk_score"]

    original_category = DETERMINISTIC_RESULT["fraud_category"]


    # -----------------------------------------------------
    # TEST 2: REAL GEMINI API REQUEST
    # -----------------------------------------------------

    print("\n[TEST 2] Sending Evidence to Gemini")

    print("Evidence Type:", EVIDENCE_TYPE)

    print("Model:", gemini_service.client is not None)

    print("\nWaiting for Gemini response...")


    result = gemini_service.analyze(

        evidence=EVIDENCE,

        evidence_type=EVIDENCE_TYPE,

        deterministic_result=DETERMINISTIC_RESULT

    )


    # -----------------------------------------------------
    # DISPLAY RESPONSE
    # -----------------------------------------------------

    print("\n[TEST 3] Gemini Advisory Response")

    print(

        json.dumps(

            result,

            indent=4,

            ensure_ascii=False

        )

    )


    # -----------------------------------------------------
    # VALIDATION CHECKS
    # -----------------------------------------------------

    print("\n[TEST 4] Response Validation")

    checks = {

        "Gemini response available":
            result.get("available") is True,

        "Successful response status":
            result.get("status") == "success",

        "Advisory-only mode":
            result.get("advisory_only") is True,

        "Model information present":
            bool(result.get("model")),

        "Scam intent is structured":
            isinstance(result.get("scam_intent"), str),

        "Explanation is structured":
            isinstance(result.get("explanation"), str),

        "Social engineering tactics are a list":
            isinstance(
                result.get("social_engineering_tactics"),
                list
            ),

        "Contextual indicators are a list":
            isinstance(
                result.get("contextual_indicators"),
                list
            ),

        "Supporting evidence is a list":
            isinstance(
                result.get("supporting_evidence"),
                list
            ),

        "Alternative interpretations are a list":
            isinstance(
                result.get("alternative_interpretations"),
                list
            ),

        "Safety notes are a list":
            isinstance(result.get("safety_notes"), list),

        "Advisory confidence is valid":
            result.get("advisory_confidence")
            in {"low", "medium", "high"},

        "No authoritative risk score returned":
            "risk_score" not in result,

        "No authoritative fraud category returned":
            "fraud_category" not in result

    }


    # -----------------------------------------------------
    # DETERMINISTIC AUTHORITY VALIDATION
    # -----------------------------------------------------

    checks["Deterministic risk score unchanged"] = (

        DETERMINISTIC_RESULT["risk_score"] == original_score

    )

    checks["Deterministic category unchanged"] = (

        DETERMINISTIC_RESULT["fraud_category"] == original_category

    )


    # -----------------------------------------------------
    # DISPLAY TEST RESULTS
    # -----------------------------------------------------

    passed = 0

    failed = 0

    for name, status in checks.items():

        if status:

            print(f"[PASS] {name}")

            passed += 1

        else:

            print(f"[FAIL] {name}")

            failed += 1


    # -----------------------------------------------------
    # FINAL REPORT
    # -----------------------------------------------------

    print("\n" + "=" * 65)

    print("FINAL TEST REPORT")

    print("=" * 65)

    print("Total Checks:", len(checks))

    print("Passed:", passed)

    print("Failed:", failed)

    print("Gemini Status:", result.get("status"))

    print("Gemini Model:", result.get("model"))

    print(
        "Deterministic Risk Score:",
        DETERMINISTIC_RESULT["risk_score"]
    )

    print(
        "Deterministic Category:",
        DETERMINISTIC_RESULT["fraud_category"]
    )

    if failed == 0:

        print("\nSUCCESS: ALL TESTS PASSED!")

        print(
            "Gemini production service is responding "
            "with advisory-only analysis."
        )

    else:

        print("\nWARNING: SOME TESTS FAILED.")

        if not result.get("available"):

            print("Gemini Error:", result.get("reason"))

    print("\n" + "=" * 65)


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    run_test()
