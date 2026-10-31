
"""
=========================================================
SCAMSHIELD AI - HYBRID FRAUD DETECTOR
=========================================================

Components:
    1. Text preprocessing
    2. Evidence extraction
    3. Rule-based detection
    4. Heuristic risk scoring
    5. Optional ML prediction

ML predictions are advisory.
Risk score is not a calibrated probability.
=========================================================
"""

import re
from pathlib import Path

import joblib

from utils.text_preprocessor import TextPreprocessor
from utils.risk_scorer import RiskScorer
from extraction.evidence_extractor import EvidenceExtractor
from utils.logger import logger


class FraudDetector:

    VERSION = "1.1.0"
    MAX_EVIDENCE_LENGTH = 20000

    MODEL_PATH = (
        Path(__file__).resolve().parents[1]
        / "models"
        / "fraud_model.joblib"
    )

    # =====================================================
    # DETECTION RULES
    # =====================================================

    RULES = {
        "urgent_payment": {
            "patterns": [
                r"\bpay immediately\b",
                r"\bpay now\b",
                r"\burgent payment\b",
                r"\btransfer money now\b",
                r"\bmake an instant payment\b",
                r"\bpayment required immediately\b",
            ],
            "signal": "urgent_payment",
            "description": "Urgent payment language detected.",
        },

        "threat_or_intimidation": {
            "patterns": [
                r"\barrest\b",
                r"\bpolice case\b",
                r"\blegal action\b",
                r"\baccount will be blocked\b",
                r"\bconnection will be disconnected\b",
                r"\byou will be arrested\b",
            ],
            "signal": "threat_or_intimidation",
            "description": "Threat or intimidation language detected.",
        },

        "otp_or_credential_request": {
            "patterns": [
                r"\bshare your otp\b",
                r"\bsend your otp\b",
                r"\bprovide your otp\b",
                r"\bshare your password\b",
                r"\bshare your pin\b",
                r"\bcard details\b",
                r"\bbanking password\b",
            ],
            "signal": "otp_or_credential_request",
            "description": "Sensitive credential request detected.",
        },

        "impersonation": {
            "patterns": [
                r"\bwe are from your bank\b",
                r"\bi am calling from the bank\b",
                r"\bpolice officer\b",
                r"\bgovernment officer\b",
                r"\bcustoms department\b",
                r"\bincome tax department\b",
            ],
            "signal": "impersonation",
            "description": "Possible organization impersonation detected.",
        },

        "suspicious_link": {
            "patterns": [
                r"\bclick this link\b",
                r"\bverify through this link\b",
                r"\bopen this link immediately\b",
                r"\bunknown payment link\b",
                r"\bsuspicious payment link\b",
            ],
            "signal": "suspicious_link",
            "description": "Suspicious link-related language detected.",
        },

        "unrealistic_reward": {
            "patterns": [
                r"\byou have won\b",
                r"\bfree cash prize\b",
                r"\bclaim your reward\b",
                r"\blottery winner\b",
                r"\bprocessing fee\b",
                r"\bguaranteed prize\b",
            ],
            "signal": "unrealistic_reward",
            "description": "Possible fake reward or prize tactic detected.",
        },

        "financial_pressure": {
            "patterns": [
                r"\bpay a fee to unlock\b",
                r"\btransfer money to avoid\b",
                r"\bsend money immediately\b",
                r"\bpay registration fee\b",
                r"\bpay to release\b",
            ],
            "signal": "financial_pressure",
            "description": "Financial pressure tactic detected.",
        },

        "remote_access_request": {
            "patterns": [
                r"\binstall remote access\b",
                r"\binstall anydesk\b",
                r"\binstall teamviewer\b",
                r"\bgrant remote access\b",
                r"\bshare your screen\b",
            ],
            "signal": "remote_access_request",
            "description": "Remote access request detected.",
        },

        "identity_document_request": {
            "patterns": [
                r"\bsend your aadhaar\b",
                r"\bshare your pan card\b",
                r"\bupload identity proof\b",
                r"\bsend your identity document\b",
            ],
            "signal": "identity_document_request",
            "description": "Identity document request detected.",
        },

        "investment_guarantee": {
            "patterns": [
                r"\bguaranteed returns\b",
                r"\bguaranteed profit\b",
                r"\bno risk investment\b",
                r"\bdouble your money\b",
                r"\bhigh returns guaranteed\b",
            ],
            "signal": "investment_guarantee",
            "description": "Unrealistic investment promise detected.",
        },
    }

    # =====================================================
    # CATEGORY RULES
    # =====================================================

    CATEGORY_PATTERNS = {
        "digitalArrest": [
            r"\bdigital arrest\b",
            r"\bpolice officer\b",
            r"\bcbi officer\b",
            r"\bcustoms department\b",
            r"\bvideo call.*arrest\b",
        ],

        "investment": [
            r"\binvestment\b",
            r"\bguaranteed returns\b",
            r"\btrading profit\b",
            r"\bdouble your money\b",
            r"\bstock tips\b",
        ],

        "creditCard": [
            r"\bcredit card\b",
            r"\bcard details\b",
            r"\bcard limit\b",
            r"\bcard blocked\b",
        ],

        "sextortion": [
            r"\bsextortion\b",
            r"\bprivate photos\b",
            r"\bintimate video\b",
            r"\bblackmail.*video\b",
            r"\bshare your private video\b",
        ],

        "ecommerce": [
            r"\bparcel\b",
            r"\bdelivery charge\b",
            r"\border refund\b",
            r"\bonline shopping\b",
            r"\bproduct delivery\b",
        ],
    }

    # =====================================================
    # INITIALIZATION
    # =====================================================

    def __init__(self):

        self.preprocessor = TextPreprocessor()
        self.extractor = EvidenceExtractor()
        self.risk_scorer = RiskScorer()

        self.model = None
        self.model_metadata = {}

        self.model = self._load_model()

        logger.info(
            "FraudDetector initialized | ML available=%s",
            self.model is not None,
        )

    # =====================================================
    # LOAD OPTIONAL ML MODEL
    # =====================================================

    def _load_model(self):

        if not self.MODEL_PATH.exists():

            logger.warning(
                "Trained ML model not found. "
                "Rule-based detection will remain available."
            )

            return None

        try:

            artifact = joblib.load(self.MODEL_PATH)

            # New training artifact format
            if isinstance(artifact, dict):

                model = artifact.get("pipeline")

                metadata = artifact.get("metadata", {})

                if not isinstance(metadata, dict):
                    metadata = {}

                self.model_metadata = metadata

            else:
                # Backward compatibility with legacy model files
                model = artifact
                self.model_metadata = {
                    "artifact_format": "legacy",
                }

            if model is None or not callable(
                getattr(model, "predict", None)
            ):

                logger.error(
                    "Invalid ML model artifact: predict() unavailable."
                )

                return None

            logger.info(
                "ML model loaded successfully | metadata=%s",
                self.model_metadata,
            )

            return model

        except Exception:

            logger.exception(
                "Could not load ML model."
            )

            self.model_metadata = {}

            return None

    # =====================================================
    # TEXT PREPROCESSING
    # =====================================================

    def _preprocess(self, evidence):

        methods = [
            "preprocess_text",
            "process_evidence",
            "process",
            "clean_text",
        ]

        for method_name in methods:

            method = getattr(
                self.preprocessor,
                method_name,
                None,
            )

            if not callable(method):
                continue

            try:

                result = method(evidence)

                if isinstance(result, dict):

                    processed = (
                        result.get("processed_text")
                        or result.get("text")
                    )

                    if isinstance(processed, str):
                        return processed

                elif isinstance(result, str):

                    return result

            except Exception:

                logger.exception(
                    "Preprocessing method failed: %s",
                    method_name,
                )

        logger.warning(
            "No compatible preprocessing method succeeded."
        )

        return evidence.lower()

    # =====================================================
    # RULE DETECTION
    # =====================================================

    def _detect_rules(self, text):

        detected_rules = []
        signals = []

        for rule_name, rule_data in self.RULES.items():

            matched = any(
                re.search(pattern, text, re.IGNORECASE)
                for pattern in rule_data["patterns"]
            )

            if matched:

                detected_rules.append({
                    "rule": rule_name,
                    "description": rule_data["description"],
                })

                signals.append(rule_data["signal"])

        return detected_rules, signals

    # =====================================================
    # CATEGORY CLASSIFICATION
    # =====================================================

    def _classify_category(self, text):

        for category, patterns in self.CATEGORY_PATTERNS.items():

            for pattern in patterns:

                if re.search(pattern, text, re.IGNORECASE):
                    return category

        return "unknown"

    # =====================================================
    # ML PREDICTION
    # =====================================================

    def _predict_ml(self, text):

        if self.model is None:

            return {
                "available": False,
                "prediction": None,
                "confidence": None,
                "method": "not_available",
                "metadata": {},
            }

        try:

            prediction = self.model.predict([text])[0]

            confidence = None

            if callable(
                getattr(self.model, "predict_proba", None)
            ):

                probabilities = self.model.predict_proba(
                    [text]
                )[0]

                confidence = round(
                    float(max(probabilities)),
                    4,
                )

            return {
                "available": True,
                "prediction": str(prediction),
                "confidence": confidence,
                "method": "tfidf_logistic_regression",
                "metadata": {
                    "model_version": self.model_metadata.get(
                        "model_version"
                    ),
                    "advisory_only": self.model_metadata.get(
                        "advisory_only",
                        True,
                    ),
                    "production_ready": self.model_metadata.get(
                        "production_ready",
                        False,
                    ),
                },
                "confidence_note": (
                    "Model confidence is not necessarily "
                    "a calibrated fraud probability."
                ),
            }

        except Exception:

            logger.exception(
                "ML prediction failed."
            )

            return {
                "available": False,
                "prediction": None,
                "confidence": None,
                "method": "prediction_error",
                "metadata": {},
            }

    # =====================================================
    # EVIDENCE EXTRACTION
    # =====================================================

    def _extract_indicators(self, evidence):

        try:

            extracted = self.extractor.extract(evidence)

            if not isinstance(extracted, dict):
                return {}

            indicators = extracted.get(
                "indicators",
                extracted,
            )

            return (
                indicators
                if isinstance(indicators, dict)
                else {}
            )

        except Exception:

            logger.exception(
                "Evidence extraction failed."
            )

            return {}

    # =====================================================
    # RISK SCORING
    # =====================================================

    def _calculate_risk(self, signals, indicators):

        result = self.risk_scorer.calculate(
            signals=signals,
            indicators=indicators,
            base_score=0,
        )

        if not isinstance(result, dict):
            raise RuntimeError(
                "Invalid risk scorer response."
            )

        required_keys = [
            "risk_score",
            "risk_level",
            "recommendations",
            "breakdown",
        ]

        missing = [
            key for key in required_keys
            if key not in result
        ]

        if missing:

            raise RuntimeError(
                "Risk scorer response missing: "
                + ", ".join(missing)
            )

        return result

    # =====================================================
    # MAIN ANALYSIS
    # =====================================================

    def analyze(self, evidence):

        if not isinstance(evidence, str):
            raise ValueError(
                "Evidence must be a string."
            )

        evidence = evidence.strip()

        if not evidence:
            raise ValueError(
                "Evidence cannot be empty."
            )

        if len(evidence) > self.MAX_EVIDENCE_LENGTH:
            raise ValueError(
                "Evidence exceeds maximum length."
            )

        # 1. PREPROCESSING
        processed_text = self._preprocess(evidence)

        if not isinstance(processed_text, str):
            processed_text = evidence.lower()

        processed_text = processed_text.lower()

        # 2. RULE DETECTION
        detected_rules, signals = self._detect_rules(
            processed_text
        )

        # 3. EVIDENCE EXTRACTION
        indicators = self._extract_indicators(
            evidence
        )

        # 4. RISK SCORING
        risk_result = self._calculate_risk(
            signals,
            indicators,
        )

        # 5. CATEGORY CLASSIFICATION
        category = self._classify_category(
            processed_text
        )

        # 6. OPTIONAL ML PREDICTION
        ml_result = self._predict_ml(
            processed_text
        )

        # 7. EXPLANATIONS
        explanations = [
            rule["description"]
            for rule in detected_rules
        ]

        if not explanations:

            explanations.append(
                "No configured scam rules matched this evidence."
            )

        # 8. FINAL RESPONSE
        return {
            "success": True,
            "detector_version": self.VERSION,
            "fraud_category": category,
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "signals": signals,
            "detected_rules": detected_rules,
            "indicators": indicators,
            "explanations": explanations,
            "recommendations": risk_result["recommendations"],
            "scoring": risk_result["breakdown"],
            "machine_learning": ml_result,
            "analysis_method": (
                "rules_with_ml_advisory"
                if ml_result["available"]
                else "rule_based"
            ),
            "verification": {
                "status": "UNVERIFIED",
                "external_verification": False,
            },
            "disclaimer": (
                "This result is an AI-generated risk assessment. "
                "It is not proof of fraud or legitimacy. "
                "Verify suspicious claims through official channels."
            ),
        }


# =========================================================
# SHARED DETECTOR INSTANCE
# =========================================================

fraud_detector = FraudDetector()


# =========================================================
# CONVENIENCE FUNCTION
# =========================================================

def analyze_evidence(evidence):

    return fraud_detector.analyze(evidence)
