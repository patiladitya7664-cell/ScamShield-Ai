"""
=========================================================
SCAMSHIELD AI - FRAUD DETECTOR REGRESSION TEST SUITE
=========================================================

Version: 1.0.0
Target: FraudDetector v3.4.0

Coverage:
    1. Detector initialization.
    2. Version validation.
    3. All 12 fraud categories.
    4. Multiple category detection.
    5. Primary category selection.
    6. Benign evidence handling.
    7. Evidence type validation.
    8. Input validation.
    9. Maximum evidence length.
    10. Context-aware detection.
    11. Advisory context.
    12. Educational context.
    13. Victim-reported fraud.
    14. URL extraction.
    15. Domain analysis.
    16. IP address detection.
    17. Shortened URL detection.
    18. Credential harvesting.
    19. Evidence-type signals.
    20. Indicator privacy.
    21. ML fallback.
    22. ML prediction validation.
    23. RiskScorer integration.
    24. Response contract.
    25. Analysis consistency.

Run:
    python -m pytest tests/test_fraud_detector.py -v

=========================================================
"""

import unittest

from unittest.mock import Mock

from detection.fraud_detector import FraudDetector


class TestFraudDetector(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        cls.detector = FraudDetector()

        cls.valid_categories = {
            "fraud_message",
            "fraud_call",
            "url_phishing",
            "email_scam",
            "investment_scam",
            "digital_arrest",
            "upi_banking_fraud",
            "card_fraud",
            "ecommerce_scam",
            "job_loan_scam",
            "sextortion_blackmail",
            "social_media_scam",
        }

        cls.valid_evidence_types = {
            "message",
            "url",
            "call",
            "transaction",
            "screenshot",
            "email",
        }

    def setUp(self):

        self.detector = FraudDetector()

    # =====================================================
    # 1. INITIALIZATION
    # =====================================================

    def test_01_detector_initialization(self):

        self.assertIsNotNone(self.detector)

        self.assertIsNotNone(
            self.detector.preprocessor
        )

        self.assertIsNotNone(
            self.detector.extractor
        )

        self.assertIsNotNone(
            self.detector.risk_scorer
        )

    # =====================================================
    # 2. VERSION
    # =====================================================

    def test_02_detector_version(self):

        self.assertEqual(
            self.detector.VERSION,
            "3.4.0",
        )

    # =====================================================
    # 3. CATEGORY DEFINITIONS
    # =====================================================

    def test_03_all_twelve_categories_supported(self):

        self.assertEqual(
            set(self.detector.FRAUD_CATEGORIES.keys()),
            self.valid_categories,
        )

    # =====================================================
    # 4. FRAUD MESSAGE
    # =====================================================

    def test_04_fraud_message_detection(self):

        result = self.detector.analyze(
            "Your account will be blocked. "
            "Verify your account immediately."
        )

        self.assertIn(
            "fraud_message",
            result["fraud_categories"],
        )

    # =====================================================
    # 5. FRAUD CALL
    # =====================================================

    def test_05_fraud_call_detection(self):

        result = self.detector.analyze(
            "I am calling from the bank regarding your account.",
            evidence_type="call",
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
    # 6. URL PHISHING
    # =====================================================

    def test_06_url_phishing_detection(self):

        result = self.detector.analyze(
            "Verify your account immediately at "
            "https://secure-account-verify.example.com/login"
        )

        self.assertIn(
            "url_phishing",
            result["fraud_categories"],
        )

    # =====================================================
    # 7. EMAIL SCAM
    # =====================================================

    def test_07_email_scam_detection(self):

        result = self.detector.analyze(
            "Fake email detected. Sender address mismatch "
            "and suspicious reply-to.",
            evidence_type="email",
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
    # 8. INVESTMENT SCAM
    # =====================================================

    def test_08_investment_scam_detection(self):

        result = self.detector.analyze(
            "Guaranteed returns and guaranteed profit. "
            "Double your money with this investment."
        )

        self.assertIn(
            "investment_scam",
            result["fraud_categories"],
        )

    # =====================================================
    # 9. DIGITAL ARREST
    # =====================================================

    def test_09_digital_arrest_detection(self):

        result = self.detector.analyze(
            "You are under digital arrest. "
            "Remain on video call during investigation."
        )

        self.assertIn(
            "digital_arrest",
            result["fraud_categories"],
        )

    # =====================================================
    # 10. UPI BANKING FRAUD
    # =====================================================

    def test_10_upi_banking_fraud_detection(self):

        result = self.detector.analyze(
            "Approve collect request in UPI to receive money.",
            evidence_type="transaction",
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
    # 11. CARD FRAUD
    # =====================================================

    def test_11_card_fraud_detection(self):

        result = self.detector.analyze(
            "Share your CVV and card details "
            "for card verification."
        )

        self.assertIn(
            "card_fraud",
            result["fraud_categories"],
        )

    # =====================================================
    # 12. E-COMMERCE SCAM
    # =====================================================

    def test_12_ecommerce_scam_detection(self):

        result = self.detector.analyze(
            "Pay parcel delivery charge to release parcel."
        )

        self.assertIn(
            "ecommerce_scam",
            result["fraud_categories"],
        )

    # =====================================================
    # 13. JOB AND LOAN SCAM
    # =====================================================

    def test_13_job_loan_scam_detection(self):

        result = self.detector.analyze(
            "Pay job registration fee for guaranteed job placement."
        )

        self.assertIn(
            "job_loan_scam",
            result["fraud_categories"],
        )

    # =====================================================
    # 14. SEXTORTION
    # =====================================================

    def test_14_sextortion_detection(self):

        result = self.detector.analyze(
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
    # 15. SOCIAL MEDIA SCAM
    # =====================================================

    def test_15_social_media_scam_detection(self):

        result = self.detector.analyze(
            "Fake Instagram account impersonation account."
        )

        self.assertIn(
            "social_media_scam",
            result["fraud_categories"],
        )

    # =====================================================
    # 16. MULTIPLE CATEGORY DETECTION
    # =====================================================

    def test_16_multiple_category_detection(self):

        result = self.detector.analyze(
            "Click this link to verify your account immediately."
        )

        self.assertGreaterEqual(
            len(result["fraud_categories"]),
            2,
        )

        self.assertIn(
            result["fraud_category"],
            result["fraud_categories"],
        )

    # =====================================================
    # 17. PRIMARY CATEGORY SELECTION
    # =====================================================

    def test_17_primary_category_priority(self):

        categories = [
            {
                "category": "fraud_message",
                "name": "Fraud Message",
            },
            {
                "category": "digital_arrest",
                "name": "Digital Arrest",
            },
            {
                "category": "url_phishing",
                "name": "URL Phishing",
            },
        ]

        primary = self.detector._select_primary_category(
            categories
        )

        self.assertEqual(
            primary,
            "digital_arrest",
        )

    # =====================================================
    # 18. BENIGN MESSAGE
    # =====================================================

    def test_18_benign_message(self):

        result = self.detector.analyze(
            "Hello, how are you? Have a nice day."
        )

        self.assertEqual(
            result["fraud_categories"],
            [],
        )

        self.assertEqual(
            result["fraud_category"],
            "unknown",
        )

        self.assertEqual(
            result["detected_rules"],
            [],
        )

    # =====================================================
    # 19. ADVISORY CONTEXT
    # =====================================================

    def test_19_advisory_context(self):

        result = self.detector.analyze(
            "Never share your OTP with anyone."
        )

        self.assertNotIn(
            "otp_or_credential_request",
            result["signals"],
        )

    # =====================================================
    # 20. EDUCATIONAL CONTEXT
    # =====================================================

    def test_20_educational_context(self):

        result = self.detector.analyze(
            "This article explains how OTP fraud works."
        )

        self.assertNotIn(
            "otp_or_credential_request",
            result["signals"],
        )

        self.assertEqual(
            result["fraud_categories"],
            [],
        )

    # =====================================================
    # 21. VICTIM-REPORTED FRAUD
    # =====================================================

    def test_21_victim_reported_credential_request(self):

        result = self.detector.analyze(
            "The scammer asked me to share my OTP."
        )

        self.assertIn(
            "otp_or_credential_request",
            result["signals"],
        )

    # =====================================================
    # 22. EVIDENCE TYPE VALIDATION
    # =====================================================

    def test_22_all_evidence_types_supported(self):

        evidence = "Sample evidence for testing."

        for evidence_type in self.valid_evidence_types:

            with self.subTest(
                evidence_type=evidence_type
            ):

                result = self.detector.analyze(
                    evidence,
                    evidence_type=evidence_type,
                )

                self.assertEqual(
                    result["evidence_type"],
                    evidence_type,
                )

    # =====================================================
    # 23. INVALID EVIDENCE TYPE
    # =====================================================

    def test_23_invalid_evidence_type(self):

        with self.assertRaises(ValueError):

            self.detector.analyze(
                "Test evidence",
                evidence_type="invalid_type",
            )

    # =====================================================
    # 24. NON-STRING EVIDENCE TYPE
    # =====================================================

    def test_24_non_string_evidence_type(self):

        with self.assertRaises(ValueError):

            self.detector.analyze(
                "Test evidence",
                evidence_type=None,
            )

    # =====================================================
    # 25. EMPTY EVIDENCE
    # =====================================================

    def test_25_empty_evidence(self):

        with self.assertRaises(ValueError):

            self.detector.analyze("")

    # =====================================================
    # 26. NON-STRING EVIDENCE
    # =====================================================

    def test_26_non_string_evidence(self):

        invalid_inputs = [
            None,
            123,
            [],
            {},
            True,
        ]

        for evidence in invalid_inputs:

            with self.subTest(evidence=evidence):

                with self.assertRaises(ValueError):

                    self.detector.analyze(evidence)

    # =====================================================
    # 27. MAXIMUM EVIDENCE LENGTH
    # =====================================================

    def test_27_maximum_evidence_length(self):

        evidence = "A" * (
            self.detector.MAX_EVIDENCE_LENGTH + 1
        )

        with self.assertRaises(ValueError):

            self.detector.analyze(evidence)

    # =====================================================
    # 28. URL EXTRACTION
    # =====================================================

    def test_28_url_extraction(self):

        urls = self.detector._extract_urls(
            "Visit https://example.com/test "
            "or www.example.org"
        )

        self.assertEqual(
            len(urls),
            2,
        )

        self.assertIn(
            "https://example.com/test",
            urls,
        )

        self.assertIn(
            "http://www.example.org",
            urls,
        )

    # =====================================================
    # 29. SHORTENED URL DETECTION
    # =====================================================

    def test_29_shortened_url_detection(self):

        result = self.detector.analyze(
            "https://bit.ly/example"
        )

        self.assertIn(
            "shortened_url_detected",
            result["signals"],
        )

    # =====================================================
    # 30. IP ADDRESS DOMAIN DETECTION
    # =====================================================

    def test_30_ip_address_domain_detection(self):

        result = self.detector._analyze_domain(
            "http://192.168.1.10/login"
        )

        self.assertTrue(
            result["is_ip_address"]
        )

    # =====================================================
    # 31. INVALID IP ADDRESS
    # =====================================================

    def test_31_invalid_ip_not_detected_as_ip(self):

        result = self.detector._analyze_domain(
            "http://999.999.999.999/login"
        )

        self.assertFalse(
            result["is_ip_address"]
        )

    # =====================================================
    # 32. TRANSACTION EVIDENCE SIGNALS
    # =====================================================

    def test_32_transaction_evidence_signals(self):

        signals = self.detector._get_evidence_type_signals(
            "UPI bank transfer completed.",
            "transaction",
        )

        self.assertIn(
            "financial_transaction_reference",
            signals,
        )

    # =====================================================
    # 33. CALL EVIDENCE SIGNALS
    # =====================================================

    def test_33_call_evidence_signals(self):

        signals = self.detector._get_evidence_type_signals(
            "This is a recorded voice call.",
            "call",
        )

        self.assertIn(
            "call_related_evidence",
            signals,
        )

    # =====================================================
    # 34. EMAIL EVIDENCE SIGNALS
    # =====================================================

    def test_34_email_evidence_signals(self):

        signals = self.detector._get_evidence_type_signals(
            "From: security@example.com Subject: Verification",
            "email",
        )

        self.assertIn(
            "email_header_or_template_detected",
            signals,
        )

    # =====================================================
    # 35. PRIVACY SANITIZATION
    # =====================================================

    def test_35_sensitive_indicator_sanitization(self):

        indicators = {
            "phone_number": "9876543210",
            "email": "person@example.com",
            "urls": [
                "https://example.com"
            ],
            "account_details": {
                "account_number": "123456789012"
            },
        }

        sanitized = self.detector._sanitize_indicators(
            indicators
        )

        self.assertEqual(
            sanitized["phone_number"],
            "[REDACTED]",
        )

        self.assertEqual(
            sanitized["email"],
            "[REDACTED]",
        )

        self.assertEqual(
            sanitized["account_details"]["account_number"],
            "[REDACTED]",
        )

        self.assertEqual(
            sanitized["urls"],
            ["https://example.com"],
        )

    # =====================================================
    # 36. ML UNAVAILABLE FALLBACK
    # =====================================================

    def test_36_ml_unavailable_fallback(self):

        self.detector.model = None

        result = self.detector._predict_ml(
            "Sample evidence"
        )

        self.assertFalse(
            result["available"]
        )

        self.assertIsNone(
            result["prediction"]
        )

        self.assertEqual(
            result["method"],
            "not_available",
        )

    # =====================================================
    # 37. ML PREDICTION
    # =====================================================

    def test_37_ml_prediction(self):

        model = Mock()

        model.predict.return_value = ["fraud"]

        model.predict_proba.return_value = [
            [0.10, 0.90]
        ]

        self.detector.model = model

        self.detector.model_metadata = {
            "model_version": "1.0.0",
            "production_ready": False,
        }

        result = self.detector._predict_ml(
            "Suspicious message"
        )

        self.assertTrue(
            result["available"]
        )

        self.assertEqual(
            result["prediction"],
            "fraud",
        )

        self.assertEqual(
            result["confidence"],
            0.9,
        )

    # =====================================================
    # 38. INVALID ML PROBABILITY
    # =====================================================

    def test_38_invalid_ml_probability_fallback(self):

        model = Mock()

        model.predict.return_value = ["fraud"]

        model.predict_proba.return_value = [
            [0.10, float("nan")]
        ]

        self.detector.model = model

        result = self.detector._predict_ml(
            "Suspicious evidence"
        )

        self.assertFalse(
            result["available"]
        )

        self.assertEqual(
            result["method"],
            "prediction_error",
        )

    # =====================================================
    # 39. RISK SCORING
    # =====================================================

    def test_39_risk_scoring_integration(self):

        result = self.detector._calculate_risk(
            signals=[
                "otp_or_credential_request"
            ],
            indicators={},
            categories=[
                "fraud_message"
            ],
        )

        self.assertEqual(
            result["risk_score"],
            25,
        )

        self.assertEqual(
            result["risk_level"],
            "MEDIUM",
        )

    # =====================================================
    # 40. CATEGORY DOES NOT INCREASE SCORE
    # =====================================================

    def test_40_category_only_scoring(self):

        result = self.detector._calculate_risk(
            signals=[],
            indicators={},
            categories=[
                "fraud_message"
            ],
        )

        self.assertEqual(
            result["risk_score"],
            0,
        )

        self.assertEqual(
            result["risk_level"],
            "LOW",
        )

    # =====================================================
    # 41. DUPLICATE SIGNAL HANDLING
    # =====================================================

    def test_41_duplicate_signal_handling(self):

        result = self.detector._calculate_risk(
            signals=[
                "urgent_payment",
                "urgent_payment",
                "urgent_payment",
            ],
            indicators={},
            categories=[],
        )

        self.assertEqual(
            result["risk_score"],
            15,
        )

    # =====================================================
    # 42. RESPONSE STRUCTURE
    # =====================================================

    def test_42_response_contract(self):

        result = self.detector.analyze(
            "Your account will be blocked. "
            "Verify your account immediately."
        )

        required_keys = [
            "success",
            "detector_version",
            "evidence_type",
            "fraud_category",
            "fraud_categories",
            "category_details",
            "legacy_categories",
            "risk_score",
            "risk_level",
            "signals",
            "detected_rules",
            "indicators",
            "explanations",
            "recommendations",
            "scoring",
            "machine_learning",
            "analysis_method",
            "verification",
            "disclaimer",
        ]

        for key in required_keys:

            with self.subTest(key=key):

                self.assertIn(
                    key,
                    result,
                )

    # =====================================================
    # 43. RISK SCORE BOUNDARIES
    # =====================================================

    def test_43_risk_score_boundaries(self):

        result = self.detector.analyze(
            "Your account will be blocked. "
            "Share your OTP immediately."
        )

        self.assertGreaterEqual(
            result["risk_score"],
            0,
        )

        self.assertLessEqual(
            result["risk_score"],
            100,
        )

    # =====================================================
    # 44. RECOMMENDATIONS
    # =====================================================

    def test_44_recommendations_generation(self):

        result = self.detector.analyze(
            "Your bank account will be suspended. "
            "Share your OTP immediately."
        )

        self.assertIsInstance(
            result["recommendations"],
            list,
        )

    # =====================================================
    # 45. ANALYSIS METHOD
    # =====================================================

    def test_45_analysis_method(self):

        self.detector.model = None

        result = self.detector.analyze(
            "Sample suspicious evidence."
        )

        self.assertEqual(
            result["analysis_method"],
            "rule_based",
        )

    # =====================================================
    # 46. VERIFICATION DISCLAIMER
    # =====================================================

    def test_46_external_verification_disclaimer(self):

        result = self.detector.analyze(
            "Sample evidence."
        )

        self.assertEqual(
            result["verification"]["status"],
            "UNVERIFIED",
        )

        self.assertFalse(
            result["verification"]["external_verification"]
        )

    # =====================================================
    # 47. ANALYSIS CONSISTENCY
    # =====================================================

    def test_47_repeated_analysis_consistency(self):

        evidence = (
            "Your account will be blocked. "
            "Share your OTP immediately."
        )

        first = self.detector.analyze(evidence)

        second = self.detector.analyze(evidence)

        self.assertEqual(
            first["fraud_categories"],
            second["fraud_categories"],
        )

        self.assertEqual(
            first["risk_score"],
            second["risk_score"],
        )

        self.assertEqual(
            first["signals"],
            second["signals"],
        )


if __name__ == "__main__":

    print("\n" + "=" * 65)
    print("SCAMSHIELD AI - FRAUD DETECTOR REGRESSION TEST SUITE")
    print("=" * 65)

    unittest.main(verbosity=2)