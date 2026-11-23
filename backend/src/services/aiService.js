
"use strict";

const crypto = require("crypto");
const axios = require("axios");

// =====================================================
// SCAMSHIELD AI - PYTHON AI ENGINE SERVICE
// Version: 4.0.0
//
// Flow:
// Node.js -> Python FastAPI -> AI Pipeline
//
// Responsibilities:
// 1. Evidence validation
// 2. Python AI Engine communication
// 3. Guardian result normalization
// 4. Intelligence indicators
// 5. Victim Safety recommendations
// 6. Decoy status preservation
// 7. Gemini advisory-only metadata
// 8. Machine learning metadata
//
// Raw evidence is never returned or persisted here.
// =====================================================


// =====================================================
// 1. CONFIGURATION
// =====================================================

const MAX_EVIDENCE_LENGTH = 20000;
const MAX_INDICATORS = 50;
const MAX_DETECTED_RULES = 100;
const MAX_RESPONSE_SIZE = 1024 * 1024;

const ALLOWED_EVIDENCE_TYPES = [
    "message",
    "url",
    "call",
    "transaction",
    "screenshot",
    "email",
];

const DETECTION_CATEGORIES = [
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
];

const FRAUD_MODULES = [
    "investment",
    "digitalArrest",
    "creditCard",
    "sextortion",
    "ecommerce",
    "other",
    "unclassified",
];

const RISK_LEVELS = [
    "low",
    "medium",
    "high",
    "critical",
];

const AI_ENGINE_URL = (
    process.env.AI_ENGINE_URL ||
    "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const AI_ENGINE_TIMEOUT = Number(
    process.env.AI_ENGINE_TIMEOUT || 30000
);

if (
    !Number.isFinite(AI_ENGINE_TIMEOUT) ||
    AI_ENGINE_TIMEOUT < 1000 ||
    AI_ENGINE_TIMEOUT > 120000
) {
    throw new Error(
        "Invalid AI_ENGINE_TIMEOUT configuration."
    );
}


// =====================================================
// 2. CATEGORY MAPPING
// =====================================================

const CATEGORY_TO_MODULE = {
    investment_scam: "investment",
    digital_arrest: "digitalArrest",
    card_fraud: "creditCard",
    sextortion_blackmail: "sextortion",
    ecommerce_scam: "ecommerce",

    fraud_message: "other",
    fraud_call: "other",
    url_phishing: "other",
    email_scam: "other",
    upi_banking_fraud: "other",
    job_loan_scam: "other",
    social_media_scam: "other",
};

const MODULE_ALIASES = {
    digital_arrest: "digitalArrest",
    digitalarrest: "digitalArrest",

    credit_card: "creditCard",
    creditcard: "creditCard",

    credit_card_fraud: "creditCard",
};


// =====================================================
// 3. GENERAL HELPERS
// =====================================================

const createError = (message, statusCode = 502) => {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
};

const safeObject = (value) => {
    return (
        value &&
        typeof value === "object" &&
        !Array.isArray(value)
    )
        ? value
        : {};
};

const safeArray = (value) => {
    return Array.isArray(value) ? value : [];
};

const safeString = (value, fallback = "") => {
    return typeof value === "string"
        ? value.trim()
        : fallback;
};

const firstNonEmptyArray = (...values) => {
    for (const value of values) {
        if (Array.isArray(value) && value.length > 0) {
            return value;
        }
    }

    return [];
};

const firstAvailable = (...values) => {
    for (const value of values) {
        if (
            value !== undefined &&
            value !== null
        ) {
            return value;
        }
    }

    return null;
};


// =====================================================
// 4. RISK VALIDATION
// =====================================================

const getExpectedRiskLevel = (score) => {
    if (score <= 24) return "low";
    if (score <= 49) return "medium";
    if (score <= 74) return "high";

    return "critical";
};

const normalizeRiskLevel = (value, score) => {
    const level = String(value || "")
        .trim()
        .toLowerCase();

    if (!RISK_LEVELS.includes(level)) {
        throw createError(
            "Python AI Engine returned an invalid risk level."
        );
    }

    const expectedLevel = getExpectedRiskLevel(score);

    if (level !== expectedLevel) {
        throw createError(
            "Python AI Engine returned inconsistent risk assessment data."
        );
    }

    return level;
};


// =====================================================
// 5. EVIDENCE VALIDATION
// =====================================================

const validateEvidence = ({
    evidenceType,
    evidence,
}) => {
    if (typeof evidenceType !== "string") {
        throw createError(
            "Invalid evidence type.",
            400
        );
    }

    const normalizedType = evidenceType
        .trim()
        .toLowerCase();

    if (
        !ALLOWED_EVIDENCE_TYPES.includes(
            normalizedType
        )
    ) {
        throw createError(
            "Invalid evidence type.",
            400
        );
    }

    if (typeof evidence !== "string") {
        throw createError(
            "Evidence must be provided as text.",
            400
        );
    }

    const normalizedEvidence = evidence.trim();

    if (!normalizedEvidence) {
        throw createError(
            "Evidence cannot be empty.",
            400
        );
    }

    if (
        normalizedEvidence.length >
        MAX_EVIDENCE_LENGTH
    ) {
        throw createError(
            `Evidence must not exceed ${MAX_EVIDENCE_LENGTH} characters.`,
            400
        );
    }

    return normalizedEvidence;
};


// =====================================================
// 6. DETECTION CATEGORY NORMALIZATION
// =====================================================

const normalizeDetectionCategory = (value) => {
    const category = String(value || "")
        .trim()
        .toLowerCase();

    return DETECTION_CATEGORIES.includes(category)
        ? category
        : null;
};


// =====================================================
// 7. FRAUD MODULE NORMALIZATION
// =====================================================

const normalizeFraudModule = (
    value,
    detectionCategory
) => {
    if (detectionCategory) {
        return CATEGORY_TO_MODULE[
            detectionCategory
        ];
    }

    const category = String(value || "")
        .trim()
        .toLowerCase();

    const normalized =
        MODULE_ALIASES[category] || category;

    if (FRAUD_MODULES.includes(normalized)) {
        return normalized;
    }

    return "unclassified";
};


// =====================================================
// 8. INDICATOR NORMALIZATION
// =====================================================

const normalizeIndicators = (indicators) => {
    let normalized = [];

    if (Array.isArray(indicators)) {
        normalized = indicators
            .filter(
                (item) =>
                    item &&
                    typeof item === "object" &&
                    !Array.isArray(item)
            )
            .map((item) => ({
                type: safeString(
                    item.type ||
                    item.indicator_type ||
                    item.indicatorType,
                    "unknown"
                ).slice(0, 30),

                value: String(
                    item.value ??
                    item.indicator ??
                    ""
                )
                    .trim()
                    .slice(0, 500),

                // Never assume an indicator is verified.
                verified: item.verified === true,
            }))
            .filter((item) => item.value);

    } else {
        const source = safeObject(indicators);

        for (
            const [type, values]
            of Object.entries(source)
        ) {
            const items = Array.isArray(values)
                ? values
                : [values];

            for (const value of items) {
                if (
                    typeof value === "string" ||
                    typeof value === "number"
                ) {
                    const normalizedValue = String(value)
                        .trim()
                        .slice(0, 500);

                    if (!normalizedValue) continue;

                    normalized.push({
                        type: type.slice(0, 30),
                        value: normalizedValue,
                        verified: false,
                    });
                }
            }
        }
    }

    if (normalized.length > MAX_INDICATORS) {
        throw createError(
            "Python AI Engine returned too many indicators."
        );
    }

    return normalized;
};


// =====================================================
// 9. DETECTED RULE NORMALIZATION
// =====================================================

const normalizeDetectedRules = (rules) => {
    if (!Array.isArray(rules)) {
        throw createError(
            "Python AI Engine returned invalid detected rules."
        );
    }

    if (rules.length > MAX_DETECTED_RULES) {
        throw createError(
            "Python AI Engine returned too many detected rules."
        );
    }

    return rules.map((item) => {
        if (
            !item ||
            typeof item !== "object" ||
            Array.isArray(item)
        ) {
            throw createError(
                "Python AI Engine returned malformed detection rules."
            );
        }

        const rawCategory = safeString(
            item.category,
            "unclassified"
        ).toLowerCase();

        const detectionCategory =
            normalizeDetectionCategory(rawCategory);

        const moduleCategory =
            normalizeFraudModule(
                rawCategory,
                detectionCategory
            );

        const weight = Number(item.weight ?? 0);

        if (
            !Number.isFinite(weight) ||
            weight < 0 ||
            weight > 100
        ) {
            throw createError(
                "Python AI Engine returned an invalid rule weight."
            );
        }

        return {
            category:
                detectionCategory || moduleCategory,

            label: safeString(
                item.label ||
                item.name ||
                item.message,
                "Suspicious indicator detected."
            ).slice(0, 200),

            weight,
        };
    });
};


// =====================================================
// 10. SENSITIVE INFORMATION NORMALIZATION
// =====================================================

const normalizeSensitiveInformation = (signals) => {
    return safeArray(signals)
        .filter(
            (item) =>
                item &&
                typeof item === "object" &&
                !Array.isArray(item)
        )
        .filter((item) => {
            const text = JSON.stringify(item)
                .toLowerCase();

            return (
                text.includes("sensitive") ||
                text.includes("credential") ||
                text.includes("otp") ||
                text.includes("password") ||
                text.includes("pin") ||
                text.includes("cvv")
            );
        })
        .slice(0, 50)
        .map((item) => ({
            type: safeString(
                item.type || item.code,
                "potential_sensitive_information"
            ).slice(0, 100),

            message:
                "Potentially sensitive information detected. Do not share passwords, PINs, OTPs or card security codes.",
        }));
};


// =====================================================
// 11. GEMINI ADVISORY NORMALIZATION
// =====================================================

const normalizeGeminiAdvisory = (advisory) => {
    const source = safeObject(advisory);

    if (Object.keys(source).length === 0) {
        return {
            available: false,
            advisory_only: true,
            status: "not_available",
            version: "",
            model: "",
            summary: "",
            recommendations: [],
        };
    }

    return {
        available: source.available === true,

        // Gemini cannot modify Guardian classification.
        advisory_only: true,

        status: safeString(
            source.status,
            "unknown"
        ).slice(0, 50),

        version: safeString(
            source.version
        ).slice(0, 50),

        model: safeString(
            source.model
        ).slice(0, 100),

        summary: safeString(
            source.summary
        ).slice(0, 2000),

        recommendations: safeArray(
            source.recommendations
        )
            .filter(
                (item) => typeof item === "string"
            )
            .slice(0, 20)
            .map((item) => item.trim().slice(0, 500)),
    };
};


// =====================================================
// 12. RECOMMENDATION NORMALIZATION
// =====================================================

const normalizeRecommendations = (
    result,
    victimSafety
) => {
    const recommendations = firstNonEmptyArray(
        result.recommendations,
        victimSafety.recommendations,
        victimSafety.safety_recommendations
    );

    return recommendations
        .filter(
            (item) => typeof item === "string"
        )
        .slice(0, 30)
        .map((item) => item.trim().slice(0, 1000))
        .filter(Boolean);
};


// =====================================================
// 13. PYTHON AI ENGINE REQUEST
// =====================================================

const callPythonAIEngine = async ({
    evidenceType,
    evidence,
}) => {
    let response;

    try {
        response = await axios.post(
            `${AI_ENGINE_URL}/api/ai/analyze`,
            {
                evidence,
                evidence_type: evidenceType,
            },
            {
                timeout: AI_ENGINE_TIMEOUT,

                headers: {
                    "Content-Type": "application/json",
                    Accept: "application/json",
                },

                maxBodyLength:
                    MAX_EVIDENCE_LENGTH + 10000,

                maxContentLength: MAX_RESPONSE_SIZE,
            }
        );

    } catch (error) {
        if (error.response) {
            throw createError(
                "Python AI Engine could not process the request.",
                502
            );
        }

        if (
            error.code === "ECONNABORTED" ||
            error.code === "ETIMEDOUT"
        ) {
            throw createError(
                "Python AI Engine request timed out.",
                503
            );
        }

        throw createError(
            "Python AI Engine is unavailable.",
            503
        );
    }

    if (
        !response.data ||
        typeof response.data !== "object" ||
        Array.isArray(response.data) ||
        response.data.success !== true
    ) {
        throw createError(
            "Python AI Engine returned an invalid response."
        );
    }

    return response.data;
};


// =====================================================
// 14. PYTHON RESPONSE NORMALIZATION
// =====================================================

const normalizePythonResult = ({
    pythonResult,
    evidenceType,
}) => {
    const result = safeObject(
        pythonResult.result
    );

    if (Object.keys(result).length === 0) {
        throw createError(
            "Python AI Engine did not return an analysis result."
        );
    }

    const intelligence = safeObject(
        pythonResult.intelligence
    );

    const victimSafety = safeObject(
        pythonResult.victim_safety ||
        pythonResult.victimSafety
    );

    const agentResults = safeObject(
        pythonResult.agent_results ||
        pythonResult.agentResults
    );

    const ml = safeObject(
        pythonResult.machine_learning ||
        pythonResult.machineLearning
    );


    // -----------------------------------------------
    // GUARDIAN RISK ASSESSMENT
    // -----------------------------------------------

    const riskScore = Number(
        result.risk_score ??
        result.riskScore
    );

    if (
        !Number.isFinite(riskScore) ||
        riskScore < 0 ||
        riskScore > 100
    ) {
        throw createError(
            "Python AI Engine returned an invalid risk score."
        );
    }

    const normalizedRiskScore = Math.round(riskScore);

    const riskLevel = normalizeRiskLevel(
        result.risk_level ??
        result.riskLevel,
        normalizedRiskScore
    );


    // -----------------------------------------------
    // GUARDIAN CLASSIFICATION
    // -----------------------------------------------

    const rawCategory =
        result.category ??
        result.fraud_category ??
        result.fraudCategory;

    const detectionCategory =
        normalizeDetectionCategory(rawCategory);

    const fraudCategory =
        normalizeFraudModule(
            rawCategory,
            detectionCategory
        );


    // -----------------------------------------------
    // INTELLIGENCE INDICATORS
    // -----------------------------------------------

    const indicatorSource = firstNonEmptyArray(
        result.indicators,
        intelligence.indicators,
        agentResults.intelligence?.indicators
    );

    const indicators = normalizeIndicators(
        indicatorSource
    );


    // -----------------------------------------------
    // DETECTED RULES
    // -----------------------------------------------

    const detectedRules = normalizeDetectedRules(
        firstAvailable(
            result.detected_rules,
            result.detectedRules,
            []
        )
    );


    // -----------------------------------------------
    // SENSITIVE INFORMATION
    // -----------------------------------------------

    const sensitiveInformation =
        normalizeSensitiveInformation(
            result.signals
        );


    // -----------------------------------------------
    // VICTIM SAFETY RECOMMENDATIONS
    // -----------------------------------------------

    const recommendations =
        normalizeRecommendations(
            result,
            victimSafety
        );


    // -----------------------------------------------
    // EXPLANATIONS
    // -----------------------------------------------

    const rawExplanations = firstAvailable(
        result.explanations,
        result.explanation,
        []
    );

    const explanations = Array.isArray(
        rawExplanations
    )
        ? rawExplanations
        : typeof rawExplanations === "string"
            ? [rawExplanations]
            : [];


    // -----------------------------------------------
    // AGENT RESULTS
    // -----------------------------------------------

    const guardian = safeObject(
        agentResults.guardian
    );

    const intelligenceAgent = safeObject(
        agentResults.intelligence ||
        intelligence
    );

    const victimSafetyAgent = safeObject(
        agentResults.victim_safety ||
        agentResults.victimSafety ||
        victimSafety
    );

    const decoySource = safeObject(
        agentResults.decoy
    );

    const decoy =
        Object.keys(decoySource).length > 0
            ? decoySource
            : {
                status: "not_started",
                simulationEnabled: false,
                simulationOnly: true,
                message:
                    "Decoy simulation requires separate user-controlled activation.",
            };


    // -----------------------------------------------
    // SUMMARY
    // -----------------------------------------------

    const summary = safeString(
        result.summary,
        "Evidence analysis completed."
    );

    if (summary.length > 2000) {
        throw createError(
            "Python AI Engine returned an oversized summary."
        );
    }


    // -----------------------------------------------
    // TIMESTAMP
    // -----------------------------------------------

    const analyzedAt = new Date();


    // -----------------------------------------------
    // GEMINI ADVISORY
    // -----------------------------------------------

    const geminiAdvisory =
        normalizeGeminiAdvisory(
            pythonResult.gemini_advisory ||
            pythonResult.geminiAdvisory
        );


    // -----------------------------------------------
    // MACHINE LEARNING METADATA
    // -----------------------------------------------

    const machineLearning = {
        available: ml.available === true,

        prediction: firstAvailable(
            ml.prediction,
            null
        ),

        confidence:
            typeof ml.confidence === "number" &&
            Number.isFinite(ml.confidence)
                ? ml.confidence
                : null,

        method: safeString(
            ml.method,
            "not_available"
        ).slice(0, 100),

        probabilityCalibrated:
            ml.probability_calibrated === true ||
            ml.probabilityCalibrated === true,
    };


    // -----------------------------------------------
    // FINAL NORMALIZED RESULT
    // -----------------------------------------------

    return {
        evidenceId: crypto.randomUUID(),

        evidenceType,

        // Major module and individual category
        // are intentionally separate.
        fraudCategory,

        detectionCategory,

        // Guardian remains authoritative.
        riskScore: normalizedRiskScore,

        riskLevel,

        summary,

        explanation: explanations,

        indicators,

        sensitiveInformation,

        detectedRules,

        recommendations,

        agents: {
            guardian,
            intelligence: intelligenceAgent,
            victimSafety: victimSafetyAgent,
            decoy,
        },

        machineLearning,

        geminiAdvisory,

        analysisMethod: safeString(
            ml.method,
            ml.available
                ? "hybrid"
                : "python_rule_based"
        ),

        aiEngineUsed: true,

        orchestration: safeObject(
            pythonResult.orchestration
        ),

        verification: safeObject(
            pythonResult.verification
        ),

        disclaimer: safeString(
            pythonResult.disclaimer,
            "Automated analysis is advisory and does not independently prove fraud."
        ),

        analyzedAt,
    };
};


// =====================================================
// 15. MAIN ANALYSIS FUNCTION
// =====================================================

const analyzeEvidence = async ({
    evidenceType,
    evidence,
}) => {
    const normalizedEvidence = validateEvidence({
        evidenceType,
        evidence,
    });

    const normalizedEvidenceType = evidenceType
        .trim()
        .toLowerCase();

    const pythonResult = await callPythonAIEngine({
        evidenceType: normalizedEvidenceType,
        evidence: normalizedEvidence,
    });

    return normalizePythonResult({
        pythonResult,
        evidenceType: normalizedEvidenceType,
    });
};


// =====================================================
// 16. DISABLED LEGACY HELPERS
// =====================================================

const classifyFraud = () => {
    throw new Error(
        "Local classification is disabled. Use the Python AI Engine."
    );
};

const extractIndicators = () => {
    throw new Error(
        "Local indicator extraction is disabled. Use the Python AI Engine."
    );
};

const calculateRisk = () => {
    throw new Error(
        "Local risk calculation is disabled. Use the Python AI Engine."
    );
};


// =====================================================
// 17. EXPORTS
// =====================================================

module.exports = {
    analyzeEvidence,

    validateEvidence,

    normalizePythonResult,

    classifyFraud,

    extractIndicators,

    calculateRisk,

    ALLOWED_EVIDENCE_TYPES,

    DETECTION_CATEGORIES,

    FRAUD_MODULES,

    RISK_LEVELS,
};
