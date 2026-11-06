import os
import json
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types


# =========================================================
# SCAMSHIELD AI - GEMINI CONNECTION TEST
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

load_dotenv(PROJECT_ROOT / ".env", override=True)

API_KEY = os.getenv("GEMINI_API_KEY")
PRIMARY_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

FALLBACK_MODELS = [
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
]

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


def normalize_model_name(name):
    """Remove models/ prefix if present."""
    return name.replace("models/", "", 1)


def test_gemini():

    print("\n========== SCAMSHIELD GEMINI TEST ==========\n")

    # STEP 1: API KEY CHECK
    if not API_KEY:
        print("FAILED: GEMINI_API_KEY not found in root .env")
        return

    print("STEP 1: API key found.")

    # STEP 2: SDK INITIALIZATION
    try:
        client = genai.Client(api_key=API_KEY)
        print("STEP 2: Gemini SDK initialized successfully.")

    except Exception as error:
        print("FAILED: SDK initialization error.")
        print(type(error).__name__, str(error))
        return

    # STEP 3: FETCH AVAILABLE MODELS
    print("\nSTEP 3: Checking available Gemini models...")

    available_models = []

    try:
        for model in client.models.list():

            model_name = normalize_model_name(model.name)

            supported_actions = getattr(
                model,
                "supported_actions",
                []
            ) or []

            if "generateContent" in supported_actions:
                available_models.append(model_name)

        print("\nModels supporting generateContent:")

        for model in available_models:
            print(" -", model)

    except Exception as error:
        print("Model listing unavailable:")
        print(type(error).__name__, str(error))

    # STEP 4: BUILD MODEL TEST ORDER
    models_to_test = []

    if PRIMARY_MODEL:
        models_to_test.append(PRIMARY_MODEL)

    for model in FALLBACK_MODELS:
        if model not in models_to_test:
            models_to_test.append(model)

    if available_models:

        models_to_test = [
            model
            for model in models_to_test
            if normalize_model_name(model) in available_models
        ]

        # Add other available Flash models as additional candidates.
        for model in available_models:
            if "flash" in model.lower() and model not in models_to_test:
                models_to_test.append(model)

    if not models_to_test:
        print("\nFAILED: No compatible Gemini models found.")
        return

    # STEP 5: TEST MODEL CONNECTION
    print("\nSTEP 4: Testing Gemini API...\n")

    successful_model = None
    successful_response = None

    for model_name in models_to_test:

        model_name = normalize_model_name(model_name)

        print(f"Testing model: {model_name}")

        try:

            response = client.models.generate_content(
                model=model_name,
                contents=TEST_PROMPT,
                config=types.GenerateContentConfig(
                    temperature=0.2,
                    max_output_tokens=1000,
                    response_mime_type="application/json"
                )
            )

            response_text = response.text

            if not response_text:
                print("FAILED: Empty response received.\n")
                continue

            parsed_response = json.loads(response_text)

            successful_model = model_name
            successful_response = parsed_response

            print("\nSUCCESS: Gemini API responded!")
            break

        except Exception as error:

            print(
                f"FAILED: {type(error).__name__}: {error}\n"
            )

    # STEP 6: FINAL RESULT
    print("\n========== FINAL RESULT ==========\n")

    if successful_model:

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

    else:

        print("STATUS: FAILED")
        print("No tested model returned a valid JSON response.")
        print("Check API availability and model access.")

    print("\n==================================\n")


if __name__ == "__main__":
    test_gemini()