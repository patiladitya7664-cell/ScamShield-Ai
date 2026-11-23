"""
=========================================================
SCAMSHIELD AI - GEMINI CONNECTION TEST
=========================================================

Purpose:
- Verify Gemini API connectivity.
- Test configured primary model.
- Test fallback models if required.
- Enforce network timeout.
- Validate JSON response.
- Report genuine pytest failures.

Run:
python -m pytest test_gemini_connection.py -v --import-mode=importlib
=========================================================
"""

import os
import json
from pathlib import Path

import pytest

from dotenv import load_dotenv
from google import genai
from google.genai import types


# =========================================================
# CONFIGURATION
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

load_dotenv(PROJECT_ROOT / ".env", override=True)

API_KEY = os.getenv("GEMINI_API_KEY")

PRIMARY_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.5-flash"
)

FALLBACK_MODELS = [
    "gemini-3.5-flash",
]

REQUEST_TIMEOUT_MS = 15000

MAX_OUTPUT_TOKENS = 1000


# =========================================================
# TEST PROMPT
# =========================================================

TEST_PROMPT = """
Analyze this suspicious message for fraud indicators:

"Your bank account will be blocked today.
Share your OTP immediately to complete KYC."

Return valid JSON with:
{
    "is_suspicious": true,
    "risk_level": "HIGH",
    "fraud_category": "fraud_message",
    "signals": [],
    "explanation": ""
}
"""


# =========================================================
# MODEL NORMALIZATION
# =========================================================

def normalize_model_name(name):

    if not isinstance(name, str):
        raise ValueError("Model name must be a string.")

    return name.removeprefix("models/").strip()


# =========================================================
# JSON VALIDATION
# =========================================================

def validate_response(response_text):

    if not response_text:
        raise ValueError("Gemini returned an empty response.")

    try:
        parsed = json.loads(response_text)

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Gemini returned invalid JSON: {error}"
        ) from error

    if not isinstance(parsed, dict):
        raise ValueError("Gemini response must be a JSON object.")

    required_fields = {
        "is_suspicious",
        "risk_level",
        "fraud_category",
        "signals",
        "explanation"
    }

    missing_fields = required_fields - set(parsed.keys())

    if missing_fields:
        raise ValueError(
            f"Missing response fields: {sorted(missing_fields)}"
        )

    if not isinstance(parsed["is_suspicious"], bool):
        raise ValueError("is_suspicious must be boolean.")

    if not isinstance(parsed["signals"], list):
        raise ValueError("signals must be a list.")

    return parsed


# =========================================================
# GEMINI CONNECTION TEST
# =========================================================

def test_gemini():

    print("\n========== SCAMSHIELD GEMINI TEST ==========\n")

    # -----------------------------------------------------
    # STEP 1: API KEY VALIDATION
    # -----------------------------------------------------

    if not API_KEY:

        pytest.fail(
            "GEMINI_API_KEY not found in project root .env"
        )

    print("STEP 1: API key found.")

    # -----------------------------------------------------
    # STEP 2: SDK INITIALIZATION
    # -----------------------------------------------------

    try:

        client = genai.Client(
            api_key=API_KEY,
            http_options=types.HttpOptions(
                timeout=REQUEST_TIMEOUT_MS
            )
        )

        print("STEP 2: Gemini SDK initialized.")

    except Exception as error:

        pytest.fail(
            f"Gemini SDK initialization failed: "
            f"{type(error).__name__}: {error}"
        )

    # -----------------------------------------------------
    # STEP 3: BUILD MODEL TEST ORDER
    # -----------------------------------------------------

    models_to_test = []

    primary = normalize_model_name(PRIMARY_MODEL)

    models_to_test.append(primary)

    for model in FALLBACK_MODELS:

        model = normalize_model_name(model)

        if model not in models_to_test:
            models_to_test.append(model)

    print("\nModels scheduled for testing:")

    for model in models_to_test:
        print(" -", model)

    # -----------------------------------------------------
    # STEP 4: TEST API CONNECTION
    # -----------------------------------------------------

    successful_model = None
    successful_response = None

    errors = []

    for model_name in models_to_test:

        print(f"\nTesting model: {model_name}")

        try:

            response = client.models.generate_content(
                model=model_name,
                contents=TEST_PROMPT,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=MAX_OUTPUT_TOKENS,
                    response_mime_type="application/json"
                )
            )

            response_text = response.text

            parsed_response = validate_response(
                response_text
            )

            successful_model = model_name
            successful_response = parsed_response

            print("SUCCESS: Gemini API responded.")

            break

        except Exception as error:

            error_message = (
                f"{model_name}: "
                f"{type(error).__name__}: {error}"
            )

            errors.append(error_message)

            print("FAILED:", error_message)

    # -----------------------------------------------------
    # STEP 5: FINAL VALIDATION
    # -----------------------------------------------------

    print("\n========== FINAL RESULT ==========\n")

    if not successful_model:

        pytest.fail(
            "All Gemini models failed.\n"
            + "\n".join(errors)
        )

    print("STATUS: SUCCESS")
    print("Working Model:", successful_model)

    print("\nGemini Analysis Result:\n")

    print(
        json.dumps(
            successful_response,
            indent=4,
            ensure_ascii=False
        )
    )

    print("\n==================================\n")

    assert successful_model is not None
    assert successful_response is not None