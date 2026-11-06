"""
=========================================================
SCAMSHIELD AI - RISK SCORER REGRESSION TEST SUITE
=========================================================

Version: 1.0.0
Target: RiskScorer v3.0.0

Coverage:
    1. Risk level boundaries.
    2. Invalid numeric values.
    3. Signal normalization.
    4. Duplicate signal handling.
    5. Signal weights.
    6. Metadata signal exclusion.
    7. Unknown signal handling.
    8. Category normalization.
    9. Category-only scoring.
    10. Base score normalization.
    11. Risk score clamping.
    12. Indicator summarization.
    13. Category summarization.
    14. Recommendation generation.
    15. Scoring breakdown consistency.
    16. Probability calibration disclaimer.
    17. Detection adapter compatibility.
    18. Response contract validation.

Run:
    python -m pytest tests/test_risk_scorer.py -v

=========================================================
"""

import math
import unittest

from utils.risk_scorer import RiskScorer


class TestRiskScorer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        cls.scorer = RiskScorer()

        cls.valid_risk_levels = {
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        }

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

    # =====================================================
    # 1. RISK LEVEL BOUNDARIES
    # =====================================================

    def test_01_risk_level_boundaries(self):

        cases = [
            (0, "LOW"),
            (10, "LOW"),
            (24, "LOW"),
            (25, "MEDIUM"),
            (40, "MEDIUM"),
            (49, "MEDIUM"),
            (50, "HIGH"),
            (60, "HIGH"),
            (74, "HIGH"),
            (75, "CRITICAL"),
            (90, "CRITICAL"),
            (100, "CRITICAL"),
        ]

        for score, expected in cases:

            with self.subTest(score=score):

                self.assertEqual(
                    self.scorer.get_risk_level(score),
                    expected,
                )

    # =====================================================
    # 2. INVALID NUMERIC VALUES
    # =====================================================

    def test_02_invalid_numeric_values(self):

        invalid_values = [
            float("nan"),
            float("inf"),
            float("-inf"),
        ]

        for value in invalid_values:

            with self.subTest(value=value):

                result = self.scorer.get_risk_level(value)

                self.assertIn(
                    result,
                    self.valid_risk_levels,
                )

    # =====================================================
    # 3. SIGNAL NORMALIZATION
    # =====================================================

    def test_03_signal_normalization(self):

        signals = [
            "urgent_payment",
            "otp_or_credential_request",
            "urgent_payment",
        ]

        normalized = self.scorer._normalize_signals(
            signals
        )

        self.assertEqual(
            normalized.count("urgent_payment"),
            1,
        )

        self.assertIn(
            "otp_or_credential_request",
            normalized,
        )

    # =====================================================
    # 4. DICTIONARY SIGNAL NORMALIZATION
    # =====================================================

    def test_04_dictionary_signal_normalization(self):

        signals = [
            {"name": "urgent_payment"},
            {"signal": "otp_or_credential_request"},
            {"type": "threat_or_intimidation"},
        ]

        normalized = self.scorer._normalize_signals(
            signals
        )

        self.assertIn("urgent_payment", normalized)

        self.assertIn(
            "otp_or_credential_request",
            normalized,
        )

        self.assertIn(
            "threat_or_intimidation",
            normalized,
        )

    # =====================================================
    # 5. SIGNAL WEIGHT
    # =====================================================

    def test_05_otp_signal_weight(self):

        score, contributions = (
            self.scorer.calculate_signal_score(
                ["otp_or_credential_request"]
            )
        )

        self.assertEqual(score, 25)

        self.assertEqual(
            contributions["otp_or_credential_request"],
            25,
        )

    # =====================================================
    # 6. URGENT PAYMENT WEIGHT
    # =====================================================

    def test_06_urgent_payment_signal_weight(self):

        score, contributions = (
            self.scorer.calculate_signal_score(
                ["urgent_payment"]
            )
        )

        self.assertEqual(score, 15)

        self.assertEqual(
            contributions["urgent_payment"],
            15,
        )

    # =====================================================
    # 7. DUPLICATE SIGNAL HANDLING
    # =====================================================

    def test_07_duplicate_signal_handling(self):

        result = self.scorer.calculate(
            signals=[
                "urgent_payment",
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
    # 8. METADATA SIGNAL EXCLUSION
    # =====================================================

    def test_08_metadata_signal_exclusion(self):

        score, contributions = (
            self.scorer.calculate_signal_score(
                ["shortened_url_detected"]
            )
        )

        self.assertEqual(score, 0)

        self.assertEqual(contributions, {})

    # =====================================================
    # 9. UNKNOWN SIGNAL HANDLING
    # =====================================================

    def test_09_unknown_signal_handling(self):

        score, contributions = (
            self.scorer.calculate_signal_score(
                ["unknown_test_signal"]
            )
        )

        self.assertEqual(score, 0)

        self.assertEqual(contributions, {})

    # =====================================================
    # 10. MULTIPLE SIGNAL ADDITION
    # =====================================================

    def test_10_multiple_signal_addition(self):

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
    # 11. CATEGORY NORMALIZATION
    # =====================================================

    def test_11_category_normalization(self):

        categories = [
            "fraud_message",
            "url_phishing",
            "fraud_message",
            "invalid_category",
        ]

        normalized = self.scorer.normalize_categories(
            categories
        )

        self.assertIn("fraud_message", normalized)

        self.assertIn("url_phishing", normalized)

        self.assertNotIn(
            "invalid_category",
            normalized,
        )

        self.assertEqual(
            normalized.count("fraud_message"),
            1,
        )

    # =====================================================
    # 12. ALL 12 CATEGORY DEFINITIONS
    # =====================================================

    def test_12_all_categories_are_supported(self):

        normalized = self.scorer.normalize_categories(
            list(self.valid_categories)
        )

        self.assertEqual(
            set(normalized),
            self.valid_categories,
        )

    # =====================================================
    # 13. CATEGORY-ONLY SCORING
    # =====================================================

    def test_13_category_only_scoring(self):

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
    # 14. BASE SCORE NORMALIZATION
    # =====================================================

    def test_14_base_score_normalization(self):

        result = self.scorer.calculate(
            signals=[],
            indicators={},
            base_score=35,
        )

        self.assertEqual(
            result["risk_score"],
            35,
        )

    # =====================================================
    # 15. NEGATIVE BASE SCORE
    # =====================================================

    def test_15_negative_base_score(self):

        result = self.scorer.calculate(
            signals=[],
            indicators={},
            base_score=-50,
        )

        self.assertEqual(
            result["risk_score"],
            0,
        )

    # =====================================================
    # 16. BASE SCORE ABOVE 100
    # =====================================================

    def test_16_base_score_above_100(self):

        result = self.scorer.calculate(
            signals=[],
            indicators={},
            base_score=150,
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
    # 17. RISK SCORE CLAMPING
    # =====================================================

    def test_17_risk_score_clamping(self):

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
    # 18. INDICATOR SUMMARIZATION
    # =====================================================

    def test_18_indicator_summarization(self):

        indicators = {
            "urls": [
                "https://example.test",
                "https://example.org",
            ],
            "emails": [
                "test@example.test",
            ],
            "phone_numbers": [
                "9999999999",
                "8888888888",
            ],
        }

        summary = self.scorer.summarize_indicators(
            indicators
        )

        self.assertEqual(summary["urls"], 2)

        self.assertEqual(summary["emails"], 1)

        self.assertEqual(summary["phone_numbers"], 2)

    # =====================================================
    # 19. BOOLEAN INDICATOR SUMMARIZATION
    # =====================================================

    def test_19_boolean_indicator_summarization(self):

        summary = self.scorer.summarize_indicators(
            {
                "domain_suspicious": True,
                "email_verified": False,
            }
        )

        self.assertEqual(
            summary["domain_suspicious"],
            1,
        )

        self.assertEqual(
            summary["email_verified"],
            0,
        )

    # =====================================================
    # 20. NULL INDICATOR SUMMARIZATION
    # =====================================================

    def test_20_null_indicator_summarization(self):

        summary = self.scorer.summarize_indicators(
            {
                "urls": None,
            }
        )

        self.assertEqual(
            summary["urls"],
            0,
        )

    # =====================================================
    # 21. NEGATIVE INDICATOR COUNT
    # =====================================================

    def test_21_negative_indicator_count(self):

        summary = self.scorer.summarize_indicators(
            {
                "phone_numbers": -5,
            }
        )

        self.assertEqual(
            summary["phone_numbers"],
            0,
        )

    # =====================================================
    # 22. CATEGORY SUMMARIZATION
    # =====================================================

    def test_22_category_summarization(self):

        summary = self.scorer.summarize_categories(
            [
                "fraud_message",
                "url_phishing",
            ]
        )

        self.assertIsInstance(summary, list)

        self.assertGreaterEqual(
            len(summary),
            2,
        )

    # =====================================================
    # 23. RECOMMENDATION GENERATION
    # =====================================================

    def test_23_recommendation_generation(self):

        for level in self.valid_risk_levels:

            with self.subTest(level=level):

                recommendations = (
                    self.scorer.get_recommendations(
                        level
                    )
                )

                self.assertIsInstance(
                    recommendations,
                    list,
                )

                self.assertGreater(
                    len(recommendations),
                    0,
                )

    # =====================================================
    # 24. SCORING RESPONSE CONTRACT
    # =====================================================

    def test_24_scoring_response_contract(self):

        result = self.scorer.calculate(
            signals=["otp_or_credential_request"],
            indicators={},
            base_score=10,
            categories=["fraud_message"],
        )

        required_keys = [
            "risk_score",
            "risk_level",
            "detected_categories",
            "breakdown",
            "recommendations",
            "is_high_risk",
            "is_critical",
            "scoring_method",
            "probability_calibrated",
            "scorer_version",
        ]

        for key in required_keys:

            with self.subTest(key=key):

                self.assertIn(key, result)

    # =====================================================
    # 25. BREAKDOWN CONSISTENCY
    # =====================================================

    def test_25_breakdown_consistency(self):

        result = self.scorer.calculate(
            signals=[
                "urgent_payment",
                "otp_or_credential_request",
            ],
            indicators={},
            base_score=10,
        )

        breakdown = result["breakdown"]

        self.assertEqual(
            breakdown["base_score"],
            10,
        )

        self.assertEqual(
            breakdown["signal_score"],
            40,
        )

        self.assertEqual(
            breakdown["raw_score"],
            50,
        )

        self.assertEqual(
            result["risk_score"],
            50,
        )

    # =====================================================
    # 26. HEURISTIC SCORING DISCLAIMER
    # =====================================================

    def test_26_probability_is_not_calibrated(self):

        result = self.scorer.calculate(
            signals=["urgent_payment"],
            indicators={},
            base_score=0,
        )

        self.assertFalse(
            result["probability_calibrated"]
        )

        self.assertEqual(
            result["scoring_method"],
            "heuristic_signal_weighting",
        )

    # =====================================================
    # 27. HIGH RISK FLAGS
    # =====================================================

    def test_27_high_risk_flags(self):

        result = self.scorer.calculate(
            signals=["threat_or_intimidation"],
            indicators={},
            base_score=40,
        )

        self.assertTrue(
            result["is_high_risk"]
        )

    # =====================================================
    # 28. DETECTION ADAPTER COMPATIBILITY
    # =====================================================

    def test_28_detection_adapter_compatibility(self):

        detection = {
            "signals": [
                "otp_or_credential_request",
            ],
            "indicators": {},
            "base_score": 0,
            "fraud_categories": [
                "fraud_message",
            ],
        }

        result = self.scorer.calculate_from_detection(
            detection
        )

        self.assertEqual(
            result["risk_score"],
            25,
        )

        self.assertTrue(
    any(
        isinstance(category, dict)
        and category.get("category") == "fraud_message"
        for category in result["detected_categories"]
    )
)

    # =====================================================
    # 29. EMPTY INPUT SCORING
    # =====================================================

    def test_29_empty_input_scoring(self):

        result = self.scorer.calculate(
            signals=[],
            indicators={},
            base_score=0,
            categories=[],
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
    # 30. SCORER VERSION
    # =====================================================

    def test_30_scorer_version(self):

        result = self.scorer.calculate(
            signals=[],
            indicators={},
            base_score=0,
        )

        self.assertEqual(
            result["scorer_version"],
            self.scorer.VERSION,
        )


if __name__ == "__main__":

    print("\n" + "=" * 65)
    print("SCAMSHIELD AI - RISK SCORER REGRESSION TEST SUITE")
    print("=" * 65)

    unittest.main(verbosity=2)