
"""
=========================================================
SCAMSHIELD AI - FRAUD CATEGORY TEST SUITE
=========================================================

Version: 1.1.0

Tests:
    1. All 12 fraud categories.
    2. Multiple category detection.
    3. Primary category consistency.
    4. False-positive checks.
    5. Evidence type validation.
    6. Invalid input handling.
    7. Risk score boundaries.
    8. Signal weights and contributions.
    9. Duplicate signal handling.
    10. Metadata signal exclusion.
    11. Category-only scoring.
    12. Risk score clamping.
    13. ML response compatibility.

Run:
    python test_fraud_categories.py
=========================================================
"""

import unittest

from detection.fraud_detector import FraudDetector
from utils.risk_scorer import RiskScorer


class TestScamShieldFraudCategories(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        cls.detector = FraudDetector()
        cls.scorer = RiskScorer()

        cls.valid_risk_levels = {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }

        cls.supported_evidence_types = [
            "message",
            "url",
            "call",
            "transaction",
            "screenshot",
            "email",
        ]

    # =====================================================
    # COMMON VALIDATION
    # =====================================================

    def analyze_and_validate(
        self,
        evidence,
        evidence_type="message",
    ):

        result = self.detector.analyze(
            evidence=evidence,
            evidence_type=evidence_type,
        )

        self.assertIsInstance(result, dict)

        self.assertTrue(
            result.get("success"),
            msg=f"Analysis failed: {result}",
        )

        self.assertIsInstance(
            result.get("risk_score"),
            (int, float),
        )

        self.assertGreaterEqual(
            result["risk_score"],
            0,
        )

        self.assertLessEqual(
            result["risk_score"],
            100,
        )

        self.assertIn(
            result.get("risk_level"),
            self.valid_risk_levels,
        )

        self.assertIsInstance(
            result.get("fraud_categories"),
            list,
        )

        self.assertIsInstance(
            result.get("signals"),
            list,
        )

        self.assertIsInstance(
            result.get("detected_rules"),
            list,
        )

        return result

    # =====================================================
    # 1. FRAUD MESSAGE
    # =====================================================

    def test_01_fraud_message(self):

        result = self.analyze_and_validate(
            "Share your OTP to claim your reward."
        )

        self.assertIn(
            "fraud_message",
            result["fraud_categories"],
        )

        self.assertIn(
            "otp_or_credential_request",
            result["signals"],
        )

    # =====================================================
    # 2. FRAUD CALL
    # =====================================================

    def test_02_fraud_call(self):

        result = self.analyze_and_validate(
            "I am calling from the bank regarding your account.",
            "call",
        )

        self.assertIn(
            "fraud_call",
            result["fraud_categories"],
        )

        self.assertIn(
            "impersonation",
            result["signals"],
        )

    # =====================================================
    # 3. URL AND PHISHING
    # =====================================================

    def test_03_url_phishing(self):

        result = self.analyze_and_validate(
            "Click this link to verify your account immediately: "
            "https://secure-example.test/login",
            "url",
        )

        self.assertIn(
            "url_phishing",
            result["fraud_categories"],
        )

        self.assertIn(
            "suspicious_link",
            result["signals"],
        )

    # =====================================================
    # 4. EMAIL SCAM
    # =====================================================

    def test_04_email_scam(self):

        result = self.analyze_and_validate(
            "Fake email detected. Sender address mismatch "
            "and suspicious reply-to.",
            "email",
        )

        self.assertIn(
            "email_scam",
            result["fraud_categories"],
        )

        self.assertIn(
            "email_spoofing",
            result["signals"],
        )

    # =====================================================
    # 5. INVESTMENT SCAM
    # =====================================================

    def test_05_investment_scam(self):

        result = self.analyze_and_validate(
            "Guaranteed returns and double your money "
            "with this crypto investment."
        )

        self.assertIn(
            "investment_scam",
            result["fraud_categories"],
        )

        self.assertIn(
            "investment_guarantee",
            result["signals"],
        )

    # =====================================================
    # 6. DIGITAL ARREST
    # =====================================================

    def test_06_digital_arrest(self):

        result = self.analyze_and_validate(
            "Digital arrest notice. You are under arrest."
        )

        self.assertIn(
            "digital_arrest",
            result["fraud_categories"],
        )

    # =====================================================
    # 7. UPI AND BANKING FRAUD
    # =====================================================

    def test_07_upi_banking_fraud(self):

        result = self.analyze_and_validate(
            "Approve collect request in UPI to receive money.",
            "transaction",
        )

        self.assertIn(
            "upi_banking_fraud",
            result["fraud_categories"],
        )

        self.assertIn(
            "upi_payment_manipulation",
            result["signals"],
        )

    # =====================================================
    # 8. CREDIT AND DEBIT CARD FRAUD
    # =====================================================

    def test_08_card_fraud(self):

        result = self.analyze_and_validate(
            "Please share your CVV and card PIN "
            "for card verification."
        )

        self.assertIn(
            "card_fraud",
            result["fraud_categories"],
        )

        self.assertIn(
            "cvv_request",
            result["signals"],
        )

    # =====================================================
    # 9. E-COMMERCE SCAM
    # =====================================================

    def test_09_ecommerce_scam(self):

        result = self.analyze_and_validate(
            "Fake seller asks for payment before delivery "
            "of the product. Pay to release parcel."
        )

        self.assertIn(
            "ecommerce_scam",
            result["fraud_categories"],
        )

    # =====================================================
    # 10. JOB AND LOAN SCAM
    # =====================================================

    def test_10_job_loan_scam(self):

        result = self.analyze_and_validate(
            "Pay a job registration fee to get selected."
        )

        self.assertIn(
            "job_loan_scam",
            result["fraud_categories"],
        )

    # =====================================================
    # 11. SEXTORTION AND BLACKMAIL
    # =====================================================

    def test_11_sextortion_blackmail(self):

        result = self.analyze_and_validate(
            "Pay or I will expose your private photos."
        )

        self.assertIn(
            "sextortion_blackmail",
            result["fraud_categories"],
        )

        self.assertIn(
            "sextortion_or_blackmail",
            result["signals"],
        )

    # =====================================================
    # 12. SOCIAL MEDIA SCAM
    # =====================================================

    def test_12_social_media_scam(self):

        result = self.analyze_and_validate(
            "Fake Instagram account impersonation account."
        )

        self.assertIn(
            "social_media_scam",
            result["fraud_categories"],
        )

    # =====================================================
    # 13. MULTIPLE CATEGORY DETECTION
    # =====================================================

    def test_13_multiple_category_detection(self):

        result = self.analyze_and_validate(
            "Click this link to verify your account immediately."
        )

        self.assertGreaterEqual(
            len(result["fraud_categories"]),
            2,
            msg=(
                "Expected multiple matching categories, "
                f"got: {result['fraud_categories']}"
            ),
        )

        self.assertIn(
            result["fraud_category"],
            result["fraud_categories"],
        )

    # =====================================================
    # 14. PRIMARY CATEGORY CONSISTENCY
    # =====================================================

    def test_14_primary_category_consistency(self):

        result = self.analyze_and_validate(
            "Click this link to verify your account immediately."
        )

        categories = result["fraud_categories"]

        self.assertTrue(categories)

        self.assertIn(
            result["fraud_category"],
            categories,
        )

        selector = getattr(
            self.detector,
            "_select_primary_category",
            None,
        )

        if callable(selector):

            expected = selector(
                result.get("category_details", [])
            )

            self.assertEqual(
                result["fraud_category"],
                expected,
            )

        else:

            self.assertEqual(
                result["fraud_category"],
                categories[0],
            )

    # =====================================================
    # 15. BENIGN MESSAGE / FALSE POSITIVE
    # =====================================================

    def test_15_benign_message(self):

        result = self.analyze_and_validate(
            "Hello, how are you today? "
            "Hope you have a wonderful day."
        )

        self.assertEqual(
            result["fraud_categories"],
            [],
        )

        self.assertEqual(
            result["detected_rules"],
            [],
        )

        self.assertEqual(
            result["fraud_category"],
            "unknown",
        )

    # =====================================================
    # 16. SUPPORTED EVIDENCE TYPES
    # =====================================================

    def test_16_supported_evidence_types(self):

        evidence = "Please review this information carefully."

        for evidence_type in self.supported_evidence_types:

            with self.subTest(evidence_type=evidence_type):

                result = self.analyze_and_validate(
                    evidence,
                    evidence_type,
                )

                self.assertEqual(
                    result["evidence_type"],
                    evidence_type,
                )

    # =====================================================
    # 17. INVALID EVIDENCE TYPE
    # =====================================================

    def test_17_invalid_evidence_type(self):

        with self.assertRaises(ValueError):

            self.detector.analyze(
                evidence="Suspicious message",
                evidence_type="unknown_type",
            )

    # =====================================================
    # 18. EMPTY INPUT
    # =====================================================

    def test_18_empty_input(self):

        with self.assertRaises(ValueError):

            self.detector.analyze("")

    # =====================================================
    # 19. NON-STRING INPUT
    # =====================================================

    def test_19_non_string_input(self):

        with self.assertRaises(ValueError):

            self.detector.analyze(12345)

    # =====================================================
    # 20. EXCESSIVE INPUT LENGTH
    # =====================================================

    def test_20_excessive_input_length(self):

        excessive_evidence = "A" * 20001

        with self.assertRaises(ValueError):

            self.detector.analyze(
                excessive_evidence
            )

    # =====================================================
    # 21. RISK LEVEL BOUNDARIES
    # =====================================================

    def test_21_risk_level_boundaries(self):

        boundaries = [
            (0, "LOW"),
            (24, "LOW"),
            (25, "MEDIUM"),
            (49, "MEDIUM"),
            (50, "HIGH"),
            (74, "HIGH"),
            (75, "CRITICAL"),
            (100, "CRITICAL"),
        ]

        for score, expected_level in boundaries:

            with self.subTest(score=score):

                actual_level = self.scorer.get_risk_level(
                    score
                )

                self.assertEqual(
                    actual_level,
                    expected_level,
                )

    # =====================================================
    # 22. SIGNAL WEIGHT AND CONTRIBUTION
    # =====================================================

    def test_22_signal_weight(self):

        score, contributions = (
            self.scorer.calculate_signal_score(
                ["otp_or_credential_request"]
            )
        )

        self.assertEqual(
            score,
            25,
        )

        self.assertEqual(
            contributions.get("otp_or_credential_request"),
            25,
        )

    # =====================================================
    # 23. DUPLICATE SIGNAL HANDLING
    # =====================================================

    def test_23_duplicate_signal_handling(self):

        result = self.scorer.calculate(
            signals=[
                "urgent_payment",
                "urgent_payment",
            ],
            indicators={},
            base_score=0,
        )

        self.assertEqual(
            result["risk_score"],
            15,
        )

    # =====================================================
    # 24. METADATA SIGNAL EXCLUSION
    # =====================================================

    def test_24_metadata_signal_exclusion(self):

        score, contributions = (
            self.scorer.calculate_signal_score(
                ["shortened_url_detected"]
            )
        )

        self.assertEqual(
            score,
            0,
        )

        self.assertEqual(
            contributions,
            {},
        )

    # =====================================================
    # 25. MULTIPLE SIGNAL ADDITION
    # =====================================================

    def test_25_multiple_signal_addition(self):

        result = self.scorer.calculate(
            signals=[
                "urgent_payment",
                "otp_or_credential_request",
            ],
            indicators={},
            base_score=0,
        )

        self.assertEqual(
            result["risk_score"],
            40,
        )

        self.assertEqual(
            result["risk_level"],
            "MEDIUM",
        )

    # =====================================================
    # 26. CATEGORY-ONLY SCORING
    # =====================================================

    def test_26_category_only_scoring(self):

        result = self.scorer.calculate(
            signals=[],
            indicators={},
            base_score=0,
            categories=["fraud_message"],
        )

        self.assertEqual(
            result["risk_score"],
            0,
        )

        self.assertEqual(
            result["risk_level"],
            "LOW",
        )

        self.assertEqual(
            result["breakdown"]["category_count"],
            1,
        )

    # =====================================================
    # 27. RISK SCORE CLAMPING
    # =====================================================

    def test_27_risk_score_clamping(self):

        result = self.scorer.calculate(
            signals=[
                "otp_or_credential_request",
                "threat_or_intimidation",
                "sextortion_or_blackmail",
                "digital_arrest_threat",
                "investment_withdrawal_fee",
            ],
            indicators={},
            base_score=0,
        )

        self.assertEqual(
            result["risk_score"],
            100,
        )

        self.assertEqual(
            result["risk_level"],
            "CRITICAL",
        )

    # =====================================================
    # 28. ML RESPONSE COMPATIBILITY
    # =====================================================

    def test_28_ml_response_compatibility(self):

        result = self.analyze_and_validate(
            "Share your OTP to claim your reward."
        )

        ml_result = result.get("machine_learning")

        self.assertIsInstance(
            ml_result,
            dict,
        )

        self.assertIn(
            "fraud_message",
            result["fraud_categories"],
        )

    # =====================================================
    # 29. ANALYSIS METHOD
    # =====================================================

    def test_29_analysis_method(self):

        result = self.analyze_and_validate(
            "Share your OTP to claim your reward."
        )

        self.assertIsNotNone(
            result.get("analysis_method")
        )

    # =====================================================
    # 30. RECOMMENDATIONS
    # =====================================================

    def test_30_recommendations(self):

        result = self.analyze_and_validate(
            "Share your OTP to claim your reward."
        )

        self.assertIsInstance(
            result.get("recommendations"),
            list,
        )


# =========================================================
# TEST RUNNER
# =========================================================

if __name__ == "__main__":

    print("\n" + "=" * 65)
    print("SCAMSHIELD AI - FRAUD CATEGORY TEST SUITE")
    print("=" * 65)

    unittest.main(verbosity=2)
