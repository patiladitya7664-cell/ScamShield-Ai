"use strict";

/*
=========================================================
SCAMSHIELD AI - ANALYSIS CONTROLLER
Version: 3.0.0

Responsibilities:
1. Authenticate user.
2. Validate evidence.
3. Execute centralized analysis service.
4. Validate AI results.
5. Save analysis securely.
6. Preserve four agent results.
7. Return structured frontend response.

SECURITY:
- Raw evidence is never stored.
- User ownership is enforced.
- AI output is validated.
- Internal errors are passed to error middleware.
=========================================================
*/

const Analysis = require("../models/analysis");

const {
    executeAnalysis,
} = require("../services/analysisService");

// =====================================================
// CONSTANTS
// =====================================================

const MAX_EVIDENCE_LENGTH = 20000;
const MAX_INDICATORS = 50;
const MAX_DETECTED_RULES = 100;

const ALLOWED_EVIDENCE_TYPES = [
    "message",
    "url",
    "call",
    "transaction",
    "screenshot",
    "email",
];

const ALLOWED_FRAUD_MODULES = [
    "investment",
    "digitalArrest",
    "creditCard",
    "sextortion",
    "ecommerce",
    "other",
    "unclassified",
];

const ALLOWED_DETECTION_CATEGORIES = [
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

const RISK_THRESHOLDS = [
    { level: "low", min: 0, max: 24 },
    { level: "medium", min: 25, max: 49 },
    { level: "high", min: 50, max: 74 },
    { level: "critical", min: 75, max: 100 },
];

// =====================================================
// HELPERS
// =====================================================

const isPlainObject = (value) =>
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date);

const safeObject = (value) =>
    isPlainObject(value) ? value : {};

const safeArray = (value) =>
    Array.isArray(value) ? value : [];

const safeString = (value, maxLength = 2000) =>
    typeof value === "string"
        ? value.slice(0, maxLength)
        : "";

const createAIValidationError = (message) => {
    const error = new Error(message);
    error.statusCode = 502;
    return error;
};

// =====================================================
// RISK VALIDATION
// =====================================================

const validateRisk = (score, level) => {
    if (
        typeof score !== "number" ||
        !Number.isInteger(score) ||
        score < 0 ||
        score > 100
    ) {
        throw createAIValidationError(
            "AI Engine returned an invalid risk score."
        );
    }

    const expected = RISK_THRESHOLDS.find(
        (item) =>
            score >= item.min &&
            score <= item.max
    );

    if (!expected || level !== expected.level) {
        throw createAIValidationError(
            "AI Engine returned inconsistent risk assessment."
        );
    }

    return {
        riskScore: score,
        riskLevel: expected.level,
    };
};

// =====================================================
// INDICATOR VALIDATION
// =====================================================

const validateIndicators = (indicators) => {
    if (
        !Array.isArray(indicators) ||
        indicators.length > MAX_INDICATORS
    ) {
        throw createAIValidationError(
            "AI Engine returned invalid indicators."
        );
    }

    return indicators.map((indicator) => {
        if (
            !isPlainObject(indicator) ||
            typeof indicator.type !== "string" ||
            typeof indicator.value !== "string" ||
            typeof indicator.verified !== "boolean" ||
            indicator.type.length > 30 ||
            indicator.value.length > 500
        ) {
            throw createAIValidationError(
                "AI Engine returned malformed indicator data."
            );
        }

        return {
            type: indicator.type,
            value: indicator.value,
            verified: indicator.verified,
        };
    });
};

// =====================================================
// DETECTED RULE VALIDATION
// =====================================================

const validateDetectedRules = (rules) => {
    if (
        !Array.isArray(rules) ||
        rules.length > MAX_DETECTED_RULES
    ) {
        throw createAIValidationError(
            "AI Engine returned invalid detection rules."
        );
    }

    return rules.map((rule) => {
        if (
            !isPlainObject(rule) ||
            typeof rule.category !== "string" ||
            typeof rule.label !== "string" ||
            !Number.isFinite(rule.weight) ||
            rule.weight < 0 ||
            rule.weight > 100
        ) {
            throw createAIValidationError(
                "AI Engine returned malformed detection rules."
            );
        }

        return {
            category: rule.category.slice(0, 100),
            label: rule.label.slice(0, 200),
            weight: rule.weight,
        };
    });
};

// =====================================================
// AGENT VALIDATION
// =====================================================

const validateAgentResults = (agents) => {
    if (!isPlainObject(agents)) {
        throw createAIValidationError(
            "AI Engine returned invalid agent results."
        );
    }

    const allowedAgents = [
        "guardian",
        "intelligence",
        "victimSafety",
        "decoy",
    ];

    const result = {};

    for (const name of allowedAgents) {
        const agent = agents[name];

        if (agent === null || agent === undefined) {
            result[name] = null;
            continue;
        }

        if (!isPlainObject(agent)) {
            throw createAIValidationError(
                `AI Engine returned invalid ${name} agent data.`
            );
        }

        // Agent service is responsible for producing
        // normalized, safe agent objects.
        result[name] = agent;
    }

    return result;
};

// =====================================================
// ANALYZE USER EVIDENCE
// =====================================================

/*
POST /api/analysis/analyze

Protected route.
*/

const analyzeUserEvidence = async (req, res, next) => {
    try {
        // ---------------------------------------------
        // AUTHENTICATION
        // ---------------------------------------------

        if (!req.user || !req.user._id) {
            return res.status(401).json({
                success: false,
                message: "Authentication required.",
            });
        }

        // ---------------------------------------------
        // REQUEST VALIDATION
        // ---------------------------------------------

        const {
            evidenceType,
            evidence,
        } = req.body || {};

        if (typeof evidenceType !== "string") {
            return res.status(400).json({
                success: false,
                message: "Invalid evidence type.",
            });
        }

        const normalizedEvidenceType =
            evidenceType.trim().toLowerCase();

        if (
            !ALLOWED_EVIDENCE_TYPES.includes(
                normalizedEvidenceType
            )
        ) {
            return res.status(400).json({
                success: false,
                message: "Unsupported evidence type.",
            });
        }

        if (
            typeof evidence !== "string" ||
            !evidence.trim()
        ) {
            return res.status(400).json({
                success: false,
                message: "Evidence must be a non-empty text value.",
            });
        }

        const normalizedEvidence = evidence.trim();

        if (
            normalizedEvidence.length >
            MAX_EVIDENCE_LENGTH
        ) {
            return res.status(400).json({
                success: false,
                message:
                    `Evidence must not exceed ${MAX_EVIDENCE_LENGTH} characters.`,
            });
        }

        // ---------------------------------------------
        // CENTRALIZED ANALYSIS SERVICE
        // ---------------------------------------------

        const analysisResult = await executeAnalysis({
            evidenceType: normalizedEvidenceType,
            evidence: normalizedEvidence,
        });

        if (!isPlainObject(analysisResult)) {
            throw createAIValidationError(
                "Analysis service returned an invalid response."
            );
        }

        // ---------------------------------------------
        // EVIDENCE ID
        // ---------------------------------------------

        if (
            typeof analysisResult.evidenceId !== "string" ||
            !analysisResult.evidenceId.trim() ||
            analysisResult.evidenceId.length > 100
        ) {
            throw createAIValidationError(
                "Analysis service returned an invalid evidence identifier."
            );
        }

        // ---------------------------------------------
        // FRAUD CLASSIFICATION
        // ---------------------------------------------

        const fraudCategory =
            analysisResult.fraudCategory;

        const detectionCategory =
            analysisResult.detectionCategory ?? null;

        if (
            !ALLOWED_FRAUD_MODULES.includes(fraudCategory)
        ) {
            throw createAIValidationError(
                "Analysis service returned an invalid fraud module."
            );
        }

        if (
            detectionCategory !== null &&
            !ALLOWED_DETECTION_CATEGORIES.includes(
                detectionCategory
            )
        ) {
            throw createAIValidationError(
                "Analysis service returned an invalid detection category."
            );
        }

        // ---------------------------------------------
        // RISK VALIDATION
        // ---------------------------------------------

        const risk = validateRisk(
            analysisResult.riskScore,
            analysisResult.riskLevel
        );

        // ---------------------------------------------
        // SUMMARY
        // ---------------------------------------------

        const summary = safeString(
            analysisResult.summary,
            2000
        );

        // ---------------------------------------------
        // INDICATORS AND RULES
        // ---------------------------------------------

        const indicators = validateIndicators(
            analysisResult.indicators
        );

        const detectedRules = validateDetectedRules(
            analysisResult.detectedRules
        );

        // ---------------------------------------------
        // AGENTS
        // ---------------------------------------------

        const agents = validateAgentResults(
            analysisResult.agents
        );

        // ---------------------------------------------
        // TIMESTAMP
        // ---------------------------------------------

        const analyzedAt = analysisResult.analyzedAt
            ? new Date(analysisResult.analyzedAt)
            : new Date();

        if (Number.isNaN(analyzedAt.getTime())) {
            throw createAIValidationError(
                "Analysis service returned an invalid timestamp."
            );
        }

        // ---------------------------------------------
        // PERSISTENCE
        // ---------------------------------------------

        const savedAnalysis = await Analysis.create({
            user: req.user._id,

            evidenceId: analysisResult.evidenceId.trim(),

            evidenceType: normalizedEvidenceType,

            fraudCategory,

            detectionCategory,

            riskScore: risk.riskScore,

            riskLevel: risk.riskLevel,

            status: "completed",

            summary,

            indicators,

            detectedRules,

            agents,

            analyzedAt,
        });

        // ---------------------------------------------
        // FRONTEND RESPONSE
        // ---------------------------------------------

        const explanations = safeArray(
            analysisResult.explanations ||
            analysisResult.explanation
        );

        const recommendations = safeArray(
            analysisResult.recommendations
        );

        return res.status(201).json({
            success: true,

            message:
                "Evidence analysis completed successfully.",

            result: {
                id: savedAnalysis._id,

                evidenceId: savedAnalysis.evidenceId,

                evidenceType: savedAnalysis.evidenceType,

                fraudCategory: savedAnalysis.fraudCategory,

                detectionCategory:
                    savedAnalysis.detectionCategory,

                riskScore: savedAnalysis.riskScore,

                riskLevel: savedAnalysis.riskLevel,

                riskDescription: savedAnalysis.summary,

                explanation: explanations,

                indicators: savedAnalysis.indicators,

                detectedRules: savedAnalysis.detectedRules,

                recommendations,

                agents: savedAnalysis.agents,

                machineLearning: safeObject(
                    analysisResult.machineLearning
                ),

                geminiAdvisory: safeObject(
                    analysisResult.geminiAdvisory
                ),

                analysisMethod: safeString(
                    analysisResult.analysisMethod,
                    100
                ) || "unknown",

                aiEngineUsed:
                    analysisResult.aiEngineUsed === true,

                orchestration: safeObject(
                    analysisResult.orchestration
                ),

                verification: safeObject(
                    analysisResult.verification
                ),

                disclaimer: safeString(
                    analysisResult.disclaimer,
                    1000
                ) || "Automated analysis is advisory and does not independently prove fraud.",

                analyzedAt: savedAnalysis.analyzedAt,
            },
        });

    } catch (error) {
        // Do not log evidence, passwords or tokens.

        console.error(
            "Evidence Analysis Controller Error:",
            error.message
        );

        return next(error);
    }
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    analyzeUserEvidence,
};