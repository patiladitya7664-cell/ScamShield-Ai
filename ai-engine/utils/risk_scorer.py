
"""
=========================================================
SCAMSHIELD AI - RISK SCORER
=========================================================

Responsibilities:
    1. Calculate fraud risk scores.
    2. Evaluate detected scam signals.
    3. Classify risk levels.
    4. Generate safety recommendations.
    5. Provide transparent scoring breakdown.

Important:
    Risk score is a heuristic indicator.
    It is NOT a calibrated fraud probability.

Risk levels:
    LOW      : 0 - 24
    MEDIUM   : 25 - 49
    HIGH     : 50 - 74
    CRITICAL : 75 - 100
=========================================================
"""


class RiskScorer:

    # =====================================================
    # CONFIGURATION
    # =====================================================

    RISK_LEVELS = {
        "LOW": (0, 24),
        "MEDIUM": (25, 49),
        "HIGH": (50, 74),
        "CRITICAL": (75, 100),
    }

    SIGNAL_WEIGHTS = {
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
    }

    # Contact indicators alone are NOT fraud signals.
    NEUTRAL_INDICATORS = {
        "urls",
        "emails",
        "phone_numbers",
        "upi_ids",
    }

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
        ],

        "HIGH": [
            "Do not click suspicious links or download unknown attachments.",
            "Do not transfer money or share confidential information.",
            "Verify the communication directly with the relevant organization.",
            "Preserve screenshots and transaction evidence if needed.",
        ],

        "CRITICAL": [
            "Stop interacting with the suspected scammer.",
            "Do not share OTPs, PINs, passwords or financial details.",
            "Do not transfer additional money.",
            "Contact your bank immediately if financial information was exposed.",
            "In India, report financial cyber fraud by calling 1930 or using the official cybercrime portal.",
        ],
    }

    # =====================================================
    # SIGNAL NORMALIZATION
    # =====================================================

    @staticmethod
    def _normalize_signals(signals):

        if signals is None:
            return []

        if isinstance(signals, dict):

            return [
                str(key).strip().lower()
                for key, value in signals.items()
                if value
            ]

        if isinstance(signals, (list, tuple, set)):

            normalized = []

            for signal in signals:

                if isinstance(signal, dict):

                    name = (
                        signal.get("name")
                        or signal.get("signal")
                        or signal.get("type")
                    )

                    if name:
                        normalized.append(
                            str(name).strip().lower()
                        )

                elif signal:

                    normalized.append(
                        str(signal).strip().lower()
                    )

            return normalized

        return []

    # =====================================================
    # INDICATOR NORMALIZATION
    # =====================================================

    @staticmethod
    def _normalize_indicators(indicators):

        if not isinstance(indicators, dict):
            return {}

        normalized = {}

        for key, value in indicators.items():

            normalized[str(key).strip().lower()] = value

        return normalized

    # =====================================================
    # RISK LEVEL CLASSIFICATION
    # =====================================================

    @classmethod
    def get_risk_level(cls, score):

        score = max(
            0,
            min(100, int(round(score))),
        )

        for level, (minimum, maximum) in cls.RISK_LEVELS.items():

            if minimum <= score <= maximum:
                return level

        return "UNKNOWN"

    # =====================================================
    # SIGNAL SCORING
    # =====================================================

    @classmethod
    def calculate_signal_score(cls, signals):

        normalized_signals = cls._normalize_signals(
            signals
        )

        breakdown = {}
        total_score = 0

        for signal in set(normalized_signals):

            weight = cls.SIGNAL_WEIGHTS.get(
                signal,
                0,
            )

            if weight <= 0:
                continue

            breakdown[signal] = weight

            total_score += weight

        return total_score, breakdown

    # =====================================================
    # INDICATOR REPORTING
    # =====================================================

    @classmethod
    def summarize_indicators(cls, indicators):

        normalized = cls._normalize_indicators(
            indicators
        )

        summary = {}

        for indicator, value in normalized.items():

            if indicator in cls.NEUTRAL_INDICATORS:

                if isinstance(value, (list, tuple, set)):

                    summary[indicator] = len(value)

                elif isinstance(value, bool):

                    summary[indicator] = int(value)

                elif isinstance(value, int):

                    summary[indicator] = value

                elif value is None:

                    summary[indicator] = 0

                else:

                    summary[indicator] = 1

            else:

                summary[indicator] = value

        return summary

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
    # MAIN RISK CALCULATION
    # =====================================================

    @classmethod
    def calculate(
        cls,
        signals=None,
        indicators=None,
        base_score=0,
    ):

        try:

            base_score = float(base_score)

        except (TypeError, ValueError):

            base_score = 0

        base_score = max(
            0,
            min(100, base_score),
        )

        signal_score, signal_breakdown = (
            cls.calculate_signal_score(signals)
        )

        # Add signal contributions to the optional base score.
        raw_score = base_score + signal_score

        # Final score is always between 0 and 100.
        final_score = max(
            0,
            min(100, int(round(raw_score))),
        )

        risk_level = cls.get_risk_level(
            final_score
        )

        indicator_summary = cls.summarize_indicators(
            indicators
        )

        recommendations = cls.get_recommendations(
            risk_level
        )

        return {
            "risk_score": final_score,

            "risk_level": risk_level,

            "breakdown": {
                "base_score": round(base_score, 2),
                "signal_score": signal_score,
                "signal_contributions": signal_breakdown,
                "indicator_summary": indicator_summary,
            },

            "recommendations": recommendations,

            "is_high_risk": risk_level in {
                "HIGH",
                "CRITICAL",
            },

            "is_critical": risk_level == "CRITICAL",

            "scoring_method": "heuristic_signal_weighting",

            "probability_calibrated": False,
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

        return cls.calculate(
            signals=signals,
            indicators=indicators,
            base_score=base_score,
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
):

    return RiskScorer.calculate(
        signals=signals,
        indicators=indicators,
        base_score=base_score,
    )
