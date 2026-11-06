"""
=========================================================
SCAMSHIELD AI - ADVANCED RISK SCORER
=========================================================

Version: 3.1.1

Responsibilities:
    1. Calculate fraud risk scores.
    2. Evaluate category-specific fraud signals.
    3. Classify risk levels.
    4. Generate safety recommendations.
    5. Provide transparent scoring breakdown.
    6. Support all 12 fraud categories.
    7. Classify recognized and unsupported signals.
    8. Sanitize sensitive indicator information.
    9. Support optional context-confidence scoring.
    10. Preserve backward compatibility.

IMPORTANT:
    Risk score is a heuristic indicator.
    It is NOT a calibrated fraud probability.

=========================================================
"""

import math


class RiskScorer:

    VERSION = "3.1.1"

    # =====================================================
    # RISK CONFIGURATION
    # =====================================================

    RISK_LEVELS = {
        "LOW": (0, 24),
        "MEDIUM": (25, 49),
        "HIGH": (50, 74),
        "CRITICAL": (75, 100),
    }

    # =====================================================
    # SIGNAL WEIGHTS
    # =====================================================

    SIGNAL_WEIGHTS = {

        # COMMON FRAUD SIGNALS
        "urgent_payment": 15,
        "threat_or_intimidation": 20,
        "otp_or_credential_request": 25,
        "impersonation": 15,
        "suspicious_link": 15,
        "unrealistic_reward": 10,
        "financial_pressure": 15,
        "remote_access_request": 20,
        "identity_document_request": 10,
        "investment_guarantee": 20,

        # UPI AND BANKING
        "upi_payment_manipulation": 25,
        "account_takeover": 25,
        "fake_customer_support": 20,
        "unauthorized_payment_request": 25,
        "fake_bank_verification": 25,
        "bank_account_suspension_threat": 20,
        "payment_approval_manipulation": 25,
        "sensitive_financial_information": 15,

        # CARD FRAUD
        "card_details_request": 20,
        "cvv_request": 25,
        "card_pin_request": 25,
        "card_blocking_threat": 20,
        "card_verification_phishing": 20,

        # URL AND PHISHING
        "shortened_url_detected": 5,
        "suspicious_domain": 20,
        "domain_impersonation": 25,
        "fake_login_page": 25,
        "credential_harvesting": 25,
        "phishing_url_detected": 20,
        "malicious_redirect": 25,

        # EMAIL SCAMS
        "email_spoofing": 25,
        "suspicious_reply_to": 15,
        "email_credential_request": 20,
        "email_attachment_threat": 20,
        "email_phishing_link": 20,

        # CALL FRAUD
        "suspicious_call": 15,
        "fake_bank_call": 20,
        "fake_police_call": 25,
        "voice_impersonation": 20,
        "call_based_otp_request": 25,
        "video_call_extortion": 25,

        # INVESTMENT SCAMS
        "unrealistic_investment_return": 25,
        "ponzi_scheme_indicator": 25,
        "fake_trading_platform": 20,
        "investment_withdrawal_fee": 25,
        "crypto_investment_scam": 20,

        # DIGITAL ARREST
        "digital_arrest_threat": 30,
        "fake_cbi_impersonation": 25,
        "fake_police_impersonation": 25,
        "fake_government_officer": 20,
        "forced_video_call": 20,
        "fake_court_case": 20,
        "threatened_immediate_arrest": 25,

        # E-COMMERCE
        "fake_seller": 15,
        "fake_shopping_website": 20,
        "advance_payment_scam": 20,
        "fake_delivery_message": 15,
        "fake_refund_request": 20,
        "payment_before_delivery": 15,

        # JOB AND LOAN
        "fake_job_offer": 20,
        "job_registration_fee": 20,
        "fake_job_placement": 20,
        "loan_fee_scam": 20,
        "advance_loan_fee": 20,
        "fake_loan_approval": 20,
        "loan_disbursement_fee": 20,

        # SEXTORTION
        "sextortion_or_blackmail": 30,
        "intimate_image_threat": 25,
        "private_video_blackmail": 25,
        "threat_to_expose_content": 25,
        "extortion_payment_demand": 25,

        # SOCIAL MEDIA
        "fake_social_media_profile": 15,
        "social_media_impersonation": 20,
        "fake_giveaway": 15,
        "account_recovery_scam": 20,
        "social_media_phishing": 20,
        "fake_influencer_account": 15,

        # ADDITIONAL SIGNALS
        "fake_job_recruiter": 20,
        "fake_loan_agent": 20,
        "fake_bank_employee": 20,
        "fake_investment_advisor": 20,
        "fake_customer_care_number": 20,
        "fake_technical_support": 20,
        "money_mule_request": 25,
        "qr_code_payment_manipulation": 20,
        "collect_request_manipulation": 25,
        "screen_sharing_request": 20,
        "remote_access_app_installation": 20,
        "sim_swap_suspicion": 25,

    }

    # =====================================================
    # FRAUD CATEGORIES
    # =====================================================

    FRAUD_CATEGORIES = {

        "fraud_message": "Fraud Message Detection",
        "fraud_call": "Fraud Call Detection",
        "url_phishing": "URL & Phishing Detection",
        "email_scam": "Email Scam Detection",
        "investment_scam": "Investment Scam Detection",
        "digital_arrest": "Digital Arrest Detection",
        "upi_banking_fraud": "UPI & Banking Fraud Detection",
        "card_fraud": "Credit/Debit Card Fraud Detection",
        "ecommerce_scam": "E-commerce Scam Detection",
        "job_loan_scam": "Job & Loan Scam Detection",
        "sextortion_blackmail": "Sextortion & Blackmail Detection",
        "social_media_scam": "Social Media Scam Detection",

    }

    # =====================================================
    # INFORMATIONAL SIGNALS
    # =====================================================

    NON_RISK_SIGNALS = {

        "financial_transaction_reference",
        "shortened_url_detected",
        "call_related_evidence",
        "email_header_or_template_detected",

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
    # NEUTRAL INDICATORS
    # =====================================================

    NEUTRAL_INDICATORS = {

        "urls",
        "emails",
        "phone_numbers",
        "upi_ids",

    }

    # =====================================================
    # SENSITIVE INDICATOR KEYS
    # =====================================================

    SENSITIVE_INDICATOR_KEYWORDS = {

        "phone",
        "mobile",
        "email",
        "upi",
        "account",
        "card",
        "cvv",
        "pin",
        "password",
        "passwd",
        "otp",
        "token",
        "secret",
        "credential",
        "authorization",
        "session",
        "cookie",
        "private_key",
        "api_key",

    }

    # =====================================================
    # SAFETY RECOMMENDATIONS
    # =====================================================

    RECOMMENDATIONS = {

        "LOW": [
            "No strong scam indicators were detected.",
            "Continue using normal online safety precautions.",
            "Verify unexpected requests through official channels.",
        ],

        "MEDIUM": [
            "Be cautious before responding to this communication.",
            "Do not share OTPs, passwords, PINs or banking details.",
            "Verify the sender using an independently obtained contact number.",
            "Avoid making payments until the request is verified.",
        ],

        "HIGH": [
            "Do not click suspicious links or download unknown attachments.",
            "Do not transfer money or share confidential information.",
            "Verify the communication directly with the relevant organization.",
            "Preserve screenshots and transaction evidence if needed.",
            "Block and report suspicious contacts when appropriate.",
        ],

        "CRITICAL": [
            "Stop interacting with the suspected scammer.",
            "Do not share OTPs, PINs, passwords or financial details.",
            "Do not transfer additional money.",
            "Contact your bank immediately if financial information was exposed.",
            "In India, report financial cyber fraud by calling 1930.",
            "Report cybercrime through the official cybercrime portal.",
            "Preserve messages, call details, screenshots and transaction records.",
        ],

    }

    # =====================================================
    # SIGNAL NORMALIZATION
    # =====================================================

    @staticmethod
    def _normalize_signals(signals):

        if signals is None:
            return []

        normalized = []

        if isinstance(signals, dict):

            for key, value in signals.items():

                if value and isinstance(key, str):

                    name = key.strip().lower()

                    if name:
                        normalized.append(name)

        elif isinstance(signals, (list, tuple, set)):

            for signal in signals:

                if isinstance(signal, dict):

                    name = (
                        signal.get("name")
                        or signal.get("signal")
                        or signal.get("type")
                    )

                    if isinstance(name, str) and name.strip():

                        normalized.append(
                            name.strip().lower()
                        )

                elif isinstance(signal, str) and signal.strip():

                    normalized.append(
                        signal.strip().lower()
                    )

        return list(dict.fromkeys(normalized))

    # =====================================================
    # SIGNAL INTELLIGENCE
    # =====================================================

    @classmethod
    def analyze_signals(cls, signals):

        normalized = cls._normalize_signals(signals)

        recognized = []
        informational = []
        unsupported = []
        invalid = []

        if signals is None:
            pass

        elif isinstance(signals, dict):

            for key, value in signals.items():

                if not isinstance(key, str) or not key.strip():
                    invalid.append(repr(key))
                    continue

                if not value:
                    continue

                name = key.strip().lower()

                if name in cls.NON_RISK_SIGNALS:
                    informational.append(name)

                elif name in cls.SIGNAL_WEIGHTS:
                    recognized.append(name)

                else:
                    unsupported.append(name)

        elif isinstance(signals, (list, tuple, set)):

            for item in signals:

                name = None

                if isinstance(item, str):

                    name = item.strip().lower()

                elif isinstance(item, dict):

                    candidate = (
                        item.get("name")
                        or item.get("signal")
                        or item.get("type")
                    )

                    if isinstance(candidate, str):
                        name = candidate.strip().lower()

                if not name:

                    invalid.append(type(item).__name__)
                    continue

                if name in cls.NON_RISK_SIGNALS:
                    informational.append(name)

                elif name in cls.SIGNAL_WEIGHTS:
                    recognized.append(name)

                else:
                    unsupported.append(name)

        else:

            invalid.append(type(signals).__name__)

        recognized = list(dict.fromkeys(recognized))
        informational = list(dict.fromkeys(informational))
        unsupported = list(dict.fromkeys(unsupported))

        return {

            "recognized": recognized,
            "informational": informational,
            "unsupported": unsupported,
            "invalid": invalid,

            "recognized_count": len(recognized),
            "informational_count": len(informational),
            "unsupported_count": len(unsupported),
            "invalid_count": len(invalid),

        }

    # =====================================================
    # INDICATOR NORMALIZATION
    # =====================================================

    @staticmethod
    def _normalize_indicators(indicators):

        if not isinstance(indicators, dict):
            return {}

        return {

            str(key).strip().lower(): value

            for key, value in indicators.items()

        }

    # =====================================================
    # RISK LEVEL CLASSIFICATION
    # =====================================================

    @classmethod
    def get_risk_level(cls, score):

        try:

            score = float(score)

            if not math.isfinite(score):
                score = 0

        except (TypeError, ValueError, OverflowError):

            score = 0

        score = max(
            0,
            min(100, int(round(score))),
        )

        for level, (minimum, maximum) in cls.RISK_LEVELS.items():

            if minimum <= score <= maximum:
                return level

        return "UNKNOWN"

    # =====================================================
    # CATEGORY NORMALIZATION
    # =====================================================

    @classmethod
    def normalize_categories(cls, categories):

        if isinstance(categories, str):
            categories = [categories]

        if not isinstance(categories, (list, tuple, set)):
            return []

        normalized = []

        for category in categories:

            if not isinstance(category, str):
                continue

            category = category.strip().lower()

            if category in cls.FRAUD_CATEGORIES:
                normalized.append(category)

        return list(dict.fromkeys(normalized))

    # =====================================================
    # CONTEXT CONFIDENCE
    # =====================================================

    @classmethod
    def _normalize_signal_context(
        cls,
        signal_context,
        signals,
    ):

        normalized = {}
        invalid = []

        if signal_context is None:
            return normalized, invalid

        if not isinstance(signal_context, dict):

            return normalized, [
                "signal_context_must_be_dictionary"
            ]

        for signal, confidence in signal_context.items():

            if not isinstance(signal, str):

                invalid.append("invalid_signal_name")
                continue

            signal = signal.strip().lower()

            if signal not in signals:

                invalid.append(
                    "context_signal_not_present:" + signal
                )

                continue

            try:

                confidence = float(confidence)

                if not math.isfinite(confidence):
                    raise ValueError

            except (TypeError, ValueError, OverflowError):

                invalid.append(
                    "invalid_confidence:" + signal
                )

                continue

            normalized[signal] = max(
                0.0,
                min(1.0, confidence),
            )

        return normalized, invalid

    # =====================================================
    # SIGNAL SCORING
    # =====================================================

    @classmethod
    def calculate_signal_score(
        cls,
        signals,
        signal_context=None,
        detailed=False,
    ):

        intelligence = cls.analyze_signals(signals)

        normalized_signals = cls._normalize_signals(
            signals
        )

        context, invalid_context = (
            cls._normalize_signal_context(
                signal_context,
                normalized_signals,
            )
        )

        breakdown = {}
        total_score = 0
        context_adjustments = {}

        for signal in normalized_signals:

            if signal in cls.NON_RISK_SIGNALS:
                continue

            weight = cls.SIGNAL_WEIGHTS.get(signal, 0)

            if weight <= 0:
                continue

            confidence = context.get(signal, 1.0)

            contribution = int(
                round(weight * confidence)
            )

            breakdown[signal] = contribution
            total_score += contribution

            if signal in context:

                context_adjustments[signal] = {

                    "original_weight": weight,
                    "confidence": confidence,
                    "adjusted_weight": contribution,

                }

        # Backward-compatible public API.
        if not detailed:
            return total_score, breakdown

        # Extended internal API.
        return {

            "total_score": total_score,

            "signal_contributions": breakdown,

            "context_adjustments": context_adjustments,

            "intelligence": intelligence,

            "invalid_context": invalid_context,

        }

    # =====================================================
    # PRIVACY HELPERS
    # =====================================================

    @classmethod
    def _is_sensitive_indicator(cls, key):

        normalized = str(key).strip().lower()

        return any(

            keyword in normalized

            for keyword in cls.SENSITIVE_INDICATOR_KEYWORDS

        )

    # =====================================================
    # RECURSIVE PRIVACY SANITIZATION
    # =====================================================

    @classmethod
    def _sanitize_value(cls, key, value):

        if cls._is_sensitive_indicator(key):

            return "[REDACTED]", 1

        if isinstance(value, dict):

            sanitized = {}
            redacted = 0

            for child_key, child_value in value.items():

                child_key = str(child_key)

                clean_value, count = cls._sanitize_value(
                    child_key,
                    child_value,
                )

                sanitized[child_key] = clean_value
                redacted += count

            return sanitized, redacted

        if isinstance(value, list):

            sanitized = []
            redacted = 0

            for item in value:

                clean_value, count = cls._sanitize_value(
                    key,
                    item,
                )

                sanitized.append(clean_value)
                redacted += count

            return sanitized, redacted

        if isinstance(value, tuple):

            sanitized = []
            redacted = 0

            for item in value:

                clean_value, count = cls._sanitize_value(
                    key,
                    item,
                )

                sanitized.append(clean_value)
                redacted += count

            return tuple(sanitized), redacted

        if isinstance(value, set):

            sanitized = set()
            redacted = 0

            for item in value:

                clean_value, count = cls._sanitize_value(
                    key,
                    item,
                )

                try:
                    sanitized.add(clean_value)

                except TypeError:
                    sanitized.add(str(clean_value))

                redacted += count

            return sanitized, redacted

        return value, 0

    # =====================================================
    # INDICATOR REPORTING
    # =====================================================

    @classmethod
    def summarize_indicators(
        cls,
        indicators,
        include_metadata=False,
    ):

        normalized = cls._normalize_indicators(
            indicators
        )

        summary = {}
        redacted_count = 0

        for indicator, value in normalized.items():

                        # Boolean metadata contains no secret value.
            # Preserve it as an integer before privacy checks.
            if isinstance(value, bool):

                summary[indicator] = int(value)
                continue

            # Neutral indicators expose counts only.
            if indicator in cls.NEUTRAL_INDICATORS:

                if isinstance(value, (list, tuple, set)):
                    summary[indicator] = len(value)

                elif isinstance(value, bool):
                    summary[indicator] = int(value)

                elif isinstance(value, int):
                    summary[indicator] = max(0, value)

                elif value is None:
                    summary[indicator] = 0

                else:
                    summary[indicator] = 1

                continue

            sanitized, count = cls._sanitize_value(
                indicator,
                value,
            )

            summary[indicator] = sanitized
            redacted_count += count

        # Backward-compatible public API.
        if not include_metadata:
            return summary

        return summary, redacted_count

    # =====================================================
    # CATEGORY REPORTING
    # =====================================================

    @classmethod
    def summarize_categories(cls, categories):

        normalized = cls.normalize_categories(
            categories
        )

        return [

            {
                "category": category,
                "name": cls.FRAUD_CATEGORIES[category],
            }

            for category in normalized

        ]

    # =====================================================
    # RECOMMENDATION GENERATION
    # =====================================================

    @classmethod
    def get_recommendations(cls, risk_level):

        return list(
            cls.RECOMMENDATIONS.get(
                risk_level,
                cls.RECOMMENDATIONS["LOW"],
            )
        )

    # =====================================================
    # BASE SCORE NORMALIZATION
    # =====================================================

    @staticmethod
    def _normalize_base_score(base_score):

        try:

            base_score = float(base_score)

            if not math.isfinite(base_score):
                return 0

        except (TypeError, ValueError, OverflowError):

            return 0

        return max(
            0,
            min(100, base_score),
        )

    # =====================================================
    # MAIN RISK CALCULATION
    # =====================================================

    @classmethod
    def calculate(
        cls,
        signals=None,
        indicators=None,
        base_score=0,
        categories=None,
        signal_context=None,
    ):

        base_score = cls._normalize_base_score(
            base_score
        )

        normalized_categories = cls.normalize_categories(
            categories
        )

        signal_result = cls.calculate_signal_score(
            signals,
            signal_context=signal_context,
            detailed=True,
        )

        signal_score = signal_result["total_score"]

        signal_breakdown = signal_result[
            "signal_contributions"
        ]

        raw_score = base_score + signal_score

        final_score = max(
            0,
            min(100, int(round(raw_score))),
        )

        risk_level = cls.get_risk_level(
            final_score
        )

        indicator_summary, redacted_count = (
            cls.summarize_indicators(
                indicators,
                include_metadata=True,
            )
        )

        recommendations = cls.get_recommendations(
            risk_level
        )

        intelligence = signal_result["intelligence"]

        return {

            "risk_score": final_score,

            "risk_level": risk_level,

            "detected_categories": cls.summarize_categories(
                normalized_categories
            ),

            "breakdown": {

                "base_score": round(base_score, 2),

                "signal_score": signal_score,

                "raw_score": round(raw_score, 2),

                "signal_contributions": signal_breakdown,

                "indicator_summary": indicator_summary,

                "category_count": len(
                    normalized_categories
                ),

                "signal_intelligence": intelligence,

                "context_adjustments": signal_result[
                    "context_adjustments"
                ],

                "invalid_context": signal_result[
                    "invalid_context"
                ],

                "privacy": {

                    "sensitive_values_redacted": redacted_count,

                    "indicator_values_sanitized": True,

                },

            },

            "recommendations": recommendations,

            "is_high_risk": risk_level in {
                "HIGH",
                "CRITICAL",
            },

            "is_critical": risk_level == "CRITICAL",

            "scoring_method": "heuristic_signal_weighting",

            "probability_calibrated": False,

            "scorer_version": cls.VERSION,

        }

    # =====================================================
    # DETECTOR ADAPTER
    # =====================================================

    @classmethod
    def calculate_from_detection(
        cls,
        detection_result,
    ):

        if not isinstance(detection_result, dict):
            detection_result = {}

        signals = detection_result.get(
            "signals",
            [],
        )

        indicators = detection_result.get(
            "indicators",
            {},
        )

        base_score = detection_result.get(
            "base_score",
            0,
        )

        categories = detection_result.get(
            "fraud_categories",
            detection_result.get("categories", []),
        )

        signal_context = detection_result.get(
            "signal_context",
            None,
        )

        return cls.calculate(

            signals=signals,

            indicators=indicators,

            base_score=base_score,

            categories=categories,

            signal_context=signal_context,

        )


# =========================================================
# MODULE-LEVEL INSTANCE
# =========================================================

risk_scorer = RiskScorer()


# =========================================================
# CONVENIENCE FUNCTION
# =========================================================

def calculate_risk_score(
    signals=None,
    indicators=None,
    base_score=0,
    categories=None,
    signal_context=None,
):

    return RiskScorer.calculate(

        signals=signals,

        indicators=indicators,

        base_score=base_score,

        categories=categories,

        signal_context=signal_context,

    )