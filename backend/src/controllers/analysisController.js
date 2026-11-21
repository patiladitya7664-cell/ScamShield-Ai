"use strict";

/*
=========================================================
SCAMSHIELD AI - ANALYSIS CONTROLLER
Version: 2.1.0
=========================================================

Responsibilities:

1. Authenticate user.
2. Validate incoming evidence.
3. Call Python AI Engine through aiService.
4. Validate normalized AI results.
5. Save analysis securely in MongoDB.
6. Preserve fraud module and detection category.
7. Store four AI agent results.
8. Return structured frontend response.

SECURITY:
- Raw evidence is NEVER stored in MongoDB.
- User ownership is enforced.
- AI response values are validated before persistence.
=========================================================
*/

const Analysis = require("../models/analysis");

const {
    analyzeEvidence,
} = require("../services/aiService");

// =====================================================
// CONSTANTS
// =====================================================

const MAX_EVIDENCE_LENGTH = 20000;

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

const ALLOWED_RISK_LEVELS = [
    "low",
    "medium",
    "high",
    "critical",
];

const MAX_INDICATORS = 50;
const MAX_DETECTED_RULES = 100;

// =====================================================
// SAFE HELPERS
// =====================================================

const safeObject = (value) => {
    return value &&
        typeof value === "object" &&
        !Array.isArray(value)
        ? value
        : {};
};

const safeNullableObject = (value) => {
    return value &&
        typeof value === "object" &&
        !Array.isArray(value)
        ? value
        : null;
};

const safeArray = (value) => {
    return Array.isArray(value)
        ? value
        : [];
};

const createValidationError = (message) => {
    const error = new Error(message);
    error.statusCode = 502;
    return error;
};

const validateIndicators = (indicators) => {
    if (
        !Array.isArray(indicators) ||
        indicators.length > MAX_INDICATORS
    ) {
        throw createValidationError(
            "AI Engine returned invalid indicators."
        );
    }

    for (const indicator of indicators) {
        if (
            !indicator ||
            typeof indicator !== "object" ||
            typeof indicator.type !== "string" ||
            typeof indicator.value !== "string" ||
            indicator.type.length > 30 ||
            indicator.value.length > 500 ||
            typeof indicator.verified !== "boolean"
        ) {
            throw createValidationError(
                "AI Engine returned malformed indicator data."
            );
        }
    }

    return indicators;
};

const validateDetectedRules = (rules) => {
    if (
        !Array.isArray(rules) ||
        rules.length > MAX_DETECTED_RULES
    ) {
        throw createValidationError(
            "AI Engine returned invalid detected rules."
        );
    }

    for (const rule of rules) {
        if (
            !rule ||
            typeof rule !== "object" ||
            typeof rule.category !== "string" ||
            typeof rule.label !== "string" ||
            !Number.isFinite(Number(rule.weight)) ||
            Number(rule.weight) < 0 ||
            Number(rule.weight) > 100
        ) {
            throw createValidationError(
                "AI Engine returned malformed detection rules."
            );
        }
    }

    return rules.map((rule) => ({
        category: rule.category,
        label: rule.label,
        weight: Number(rule.weight),
    }));
};

const validateAgentResults = (agents) => {
    const source = safeObject(agents);

    return {
        guardian: safeNullableObject(source.guardian),

        intelligence: safeNullableObject(
            source.intelligence
        ),

        victimSafety: safeNullableObject(
            source.victimSafety
        ),

        decoy: safeNullableObject(source.decoy),
    };
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
        // -----------------------------------------------
        // AUTHENTICATION
        // -----------------------------------------------

        if (!req.user || !req.user._id) {
            return res.status(401).json({
                success: false,
                message: "Authentication required.",
            });
        }

        // -----------------------------------------------
        // REQUEST VALIDATION
        // -----------------------------------------------

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
                message:
                    "Evidence must be a non-empty text value.",
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

        // -----------------------------------------------
        // PYTHON AI ENGINE
        // -----------------------------------------------

        const analysisResult = await analyzeEvidence({
            evidenceType: normalizedEvidenceType,
            evidence: normalizedEvidence,
        });

        if (
            !analysisResult ||
            typeof analysisResult !== "object"
        ) {
            throw createValidationError(
                "AI Engine returned an invalid response."
            );
        }

        // -----------------------------------------------
        // EVIDENCE ID VALIDATION
        // -----------------------------------------------

        if (
            typeof analysisResult.evidenceId !== "string" ||
            !analysisResult.evidenceId.trim() ||
            analysisResult.evidenceId.length > 100
        ) {
            throw createValidationError(
                "AI Engine returned an invalid evidence identifier."
            );
        }

        // -----------------------------------------------
        // FRAUD CLASSIFICATION VALIDATION
        // -----------------------------------------------

        const fraudCategory =
            analysisResult.fraudCategory;

        const detectionCategory =
            analysisResult.detectionCategory ?? null;

        if (
            !ALLOWED_FRAUD_MODULES.includes(
                fraudCategory
            )
        ) {
            throw createValidationError(
                "AI Engine returned an invalid fraud module."
            );
        }

        if (
            detectionCategory !== null &&
            !ALLOWED_DETECTION_CATEGORIES.includes(
                detectionCategory
            )
        ) {
            throw createValidationError(
                "AI Engine returned an invalid detection category."
            );
        }

        // -----------------------------------------------
        // RISK VALIDATION
        // -----------------------------------------------

        const riskScore = Number(
            analysisResult.riskScore
        );

        const riskLevel = String(
            analysisResult.riskLevel || ""
        ).toLowerCase();

        if (
            !Number.isFinite(riskScore) ||
            riskScore < 0 ||
            riskScore > 100
        ) {
            throw createValidationError(
                "AI Engine returned an invalid risk score."
            );
        }

        if (
            !ALLOWED_RISK_LEVELS.includes(riskLevel)
        ) {
            throw createValidationError(
                "AI Engine returned an invalid risk level."
            );
        }

        // -----------------------------------------------
        // SUMMARY VALIDATION
        // -----------------------------------------------

        const summary =
            typeof analysisResult.summary === "string"
                ? analysisResult.summary
                : "";

        if (summary.length > 2000) {
            throw createValidationError(
                "AI Engine returned an oversized summary."
            );
        }

        // -----------------------------------------------
        // INDICATORS AND RULES
        // -----------------------------------------------

        const indicators = validateIndicators(
            safeArray(analysisResult.indicators)
        );

        const detectedRules = validateDetectedRules(
            safeArray(analysisResult.detectedRules)
        );

        // -----------------------------------------------
        // AGENT RESULTS
        // -----------------------------------------------

        const agents = validateAgentResults(
            analysisResult.agents
        );

        // -----------------------------------------------
        // TIMESTAMP VALIDATION
        // -----------------------------------------------

        const analyzedAt = analysisResult.analyzedAt
            ? new Date(analysisResult.analyzedAt)
            : new Date();

        if (Number.isNaN(analyzedAt.getTime())) {
            throw createValidationError(
                "AI Engine returned an invalid analysis timestamp."
            );
        }

        // -----------------------------------------------
        // SAVE ANALYSIS
        // -----------------------------------------------

        const savedAnalysis = await Analysis.create({
            user: req.user._id,

            evidenceId:
                analysisResult.evidenceId.trim(),

            // Always use the validated request type.
            evidenceType: normalizedEvidenceType,

            // Major fraud module.
            fraudCategory,

            // Individual detection category.
            detectionCategory,

            // Risk assessment.
            riskScore: Math.round(riskScore),
            riskLevel,

            status: "completed",

            summary,

            indicators,

            detectedRules,

            // Guardian, Intelligence, Victim Safety, Decoy.
            agents,

            analyzedAt,
        });

        // -----------------------------------------------
        // FRONTEND RESPONSE
        // -----------------------------------------------

        return res.status(201).json({
            success: true,

            message:
                "Evidence analysis completed successfully.",

            result: {
                id: savedAnalysis._id,

                evidenceId:
                    savedAnalysis.evidenceId,

                evidenceType:
                    savedAnalysis.evidenceType,

                // Fraud classification.
                fraudCategory:
                    savedAnalysis.fraudCategory,

                detectionCategory:
                    savedAnalysis.detectionCategory,

                // Risk assessment.
                riskScore:
                    savedAnalysis.riskScore,

                riskLevel:
                    savedAnalysis.riskLevel,

                riskDescription:
                    savedAnalysis.summary,

                explanation: safeArray(
                    analysisResult.explanation
                ),

                // Intelligence.
                indicators:
                    savedAnalysis.indicators,

                sensitiveInformation: safeArray(
                    analysisResult.sensitiveInformation
                ),

                detectedRules:
                    savedAnalysis.detectedRules,

                recommendations: safeArray(
                    analysisResult.recommendations
                ),

                // Four AI agents.
                agents:
                    savedAnalysis.agents,

                // Machine learning.
                machineLearning: safeObject(
                    analysisResult.machineLearning
                ),

                analysisMethod:
                    analysisResult.analysisMethod ||
                    "unknown",

                aiEngineUsed:
                    analysisResult.aiEngineUsed === true,

                // Additional metadata.
                orchestration: safeObject(
                    analysisResult.orchestration
                ),

                verification: safeObject(
                    analysisResult.verification
                ),

                disclaimer:
                    typeof analysisResult.disclaimer === "string"
                        ? analysisResult.disclaimer
                        : "Automated analysis is advisory and does not independently prove fraud.",

                analyzedAt:
                    savedAnalysis.analyzedAt,
            },
        });

    } catch (error) {
        // Never log raw evidence or credentials.

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