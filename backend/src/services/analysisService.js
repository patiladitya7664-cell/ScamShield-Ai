
"use strict";

// =====================================================
// SCAMSHIELD AI - CENTRAL ANALYSIS SERVICE
// Version: 2.0.0
//
// Flow:
// Controller
//    |
// Analysis Service
//    |
// Python AI Service
//    |
// Multi-Agent Result Preparation
//    |
// Unified Response
//
// MongoDB persistence remains in the controller.
//
// Guardian remains authoritative.
// Gemini remains advisory-only.
// Decoy is never automatically activated.
// =====================================================

const { analyzeEvidence } = require("./aiService");
const { executeAgents } = require("./agentsService");

// =====================================================
// 1. CONSTANTS
// =====================================================

const SUPPORTED_EVIDENCE_TYPES = Object.freeze([
    "message",
    "url",
    "call",
    "transaction",
    "screenshot",
    "email",
]);

const DETECTION_CATEGORIES = Object.freeze([
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
]);

const RISK_LEVELS = Object.freeze([
    "low",
    "medium",
    "high",
    "critical",
]);

const MAX_EVIDENCE_LENGTH = 20000;


// =====================================================
// 2. ERROR HELPER
// =====================================================

const createError = (message, statusCode = 400) => {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
};


// =====================================================
// 3. GENERAL HELPERS
// =====================================================

const safeArray = (value) => {
    return Array.isArray(value) ? value : [];
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

const safeString = (value, fallback = "") => {
    return typeof value === "string"
        ? value.trim()
        : fallback;
};


// =====================================================
// 4. EVIDENCE VALIDATION
// =====================================================

const validateEvidence = ({ evidenceType, evidence } = {}) => {
    if (
        typeof evidenceType !== "string" ||
        !evidenceType.trim()
    ) {
        throw createError(
            "Evidence type is required."
        );
    }

    const normalizedType = evidenceType
        .trim()
        .toLowerCase();

    if (
        !SUPPORTED_EVIDENCE_TYPES.includes(
            normalizedType
        )
    ) {
        throw createError(
            "Unsupported evidence type."
        );
    }

    if (typeof evidence !== "string") {
        throw createError(
            "Evidence must be provided as text."
        );
    }

    const normalizedEvidence = evidence.trim();

    if (!normalizedEvidence) {
        throw createError(
            "Evidence cannot be empty."
        );
    }

    if (
        normalizedEvidence.length >
        MAX_EVIDENCE_LENGTH
    ) {
        throw createError(
            `Evidence must not exceed ${MAX_EVIDENCE_LENGTH} characters.`
        );
    }

    return {
        evidenceType: normalizedType,
        evidence: normalizedEvidence,
    };
};


// =====================================================
// 5. RISK VALIDATION
// =====================================================

const validateRiskAssessment = (analysis) => {
    if (
        typeof analysis.riskScore !== "number" ||
        !Number.isFinite(analysis.riskScore) ||
        analysis.riskScore < 0 ||
        analysis.riskScore > 100
    ) {
        throw createError(
            "AI Engine returned an invalid risk score.",
            502
        );
    }

    const riskLevel = safeString(
        analysis.riskLevel
    ).toLowerCase();

    if (!RISK_LEVELS.includes(riskLevel)) {
        throw createError(
            "AI Engine returned an invalid risk level.",
            502
        );
    }

    const expectedRiskLevel =
        analysis.riskScore <= 24
            ? "low"
            : analysis.riskScore <= 49
                ? "medium"
                : analysis.riskScore <= 74
                    ? "high"
                    : "critical";

    if (riskLevel !== expectedRiskLevel) {
        throw createError(
            "AI Engine returned inconsistent risk assessment data.",
            502
        );
    }

    return riskLevel;
};


// =====================================================
// 6. ANALYSIS RESPONSE VALIDATION
// =====================================================

const validateAnalysisResult = (analysis) => {
    if (
        !analysis ||
        typeof analysis !== "object" ||
        Array.isArray(analysis)
    ) {
        throw createError(
            "AI Engine returned an invalid analysis result.",
            502
        );
    }

    validateRiskAssessment(analysis);

    const detectionCategory = safeString(
        analysis.detectionCategory
    ).toLowerCase();

    if (
        !DETECTION_CATEGORIES.includes(
            detectionCategory
        )
    ) {
        throw createError(
            "AI Engine returned an invalid detection category.",
            502
        );
    }

    if (
        !safeString(analysis.fraudCategory)
    ) {
        throw createError(
            "AI Engine did not return a fraud module.",
            502
        );
    }

    if (
        analysis.indicators !== undefined &&
        !Array.isArray(analysis.indicators)
    ) {
        throw createError(
            "AI Engine returned invalid indicators.",
            502
        );
    }

    if (
        analysis.detectedRules !== undefined &&
        !Array.isArray(analysis.detectedRules)
    ) {
        throw createError(
            "AI Engine returned invalid detection rules.",
            502
        );
    }

    if (
        analysis.agents !== undefined &&
        (
            !analysis.agents ||
            typeof analysis.agents !== "object" ||
            Array.isArray(analysis.agents)
        )
    ) {
        throw createError(
            "AI Engine returned invalid agent results.",
            502
        );
    }

    return analysis;
};


// =====================================================
// 7. MAIN ANALYSIS EXECUTION
// =====================================================

const executeAnalysis = async (input) => {

    // -----------------------------------------------
    // STEP 1: VALIDATE INPUT
    // -----------------------------------------------

    const validatedInput = validateEvidence(input);


    // -----------------------------------------------
    // STEP 2: EXECUTE PYTHON AI PIPELINE
    // -----------------------------------------------

    const rawAnalysis = await analyzeEvidence(
        validatedInput
    );


    // -----------------------------------------------
    // STEP 3: VALIDATE GUARDIAN RESULT
    // -----------------------------------------------

    const analysis = validateAnalysisResult(
        rawAnalysis
    );


    // -----------------------------------------------
    // STEP 4: PREPARE FOUR AGENT RESULTS
    // -----------------------------------------------

    const agents = await executeAgents(analysis);


    // -----------------------------------------------
    // STEP 5: NORMALIZE EXPLANATION
    // -----------------------------------------------

    const explanation = Array.isArray(
        analysis.explanation
    )
        ? analysis.explanation
        : typeof analysis.explanation === "string"
            ? analysis.explanation
            : "";


    // -----------------------------------------------
    // STEP 6: UNIFIED RESULT
    // -----------------------------------------------

    return {
        evidenceId: analysis.evidenceId || null,

        evidenceType: validatedInput.evidenceType,

        // Guardian classification
        fraudCategory: analysis.fraudCategory,

        detectionCategory: analysis.detectionCategory,

        // Guardian authoritative risk assessment
        riskScore: analysis.riskScore,

        riskLevel: analysis.riskLevel,

        summary: safeString(
            analysis.summary
        ),

        explanation,

        indicators: safeArray(
            analysis.indicators
        ),

        sensitiveInformation: safeArray(
            analysis.sensitiveInformation
        ),

        detectedRules: safeArray(
            analysis.detectedRules
        ),

        recommendations: safeArray(
            analysis.recommendations
        ),

        // Four-agent result
        agents,

        // Gemini cannot modify Guardian's result.
        geminiAdvisory: safeObject(
            analysis.geminiAdvisory
        ),

        // ML metadata
        machineLearning: safeObject(
            analysis.machineLearning
        ),

        analysisMethod: safeString(
            analysis.analysisMethod,
            "python_rule_based"
        ),

        aiEngineUsed: analysis.aiEngineUsed === true,

        // Pipeline metadata
        orchestration: safeObject(
            analysis.orchestration
        ),

        verification: safeObject(
            analysis.verification
        ),

        analyzedAt:
            analysis.analyzedAt instanceof Date &&
            !Number.isNaN(analysis.analyzedAt.getTime())
                ? analysis.analyzedAt
                : new Date(),

        disclaimer: safeString(
            analysis.disclaimer,
            "Automated analysis is advisory and does not independently prove fraud."
        ),
    };
};


// =====================================================
// 8. EXPORTS
// =====================================================

module.exports = {
    SUPPORTED_EVIDENCE_TYPES,

    DETECTION_CATEGORIES,

    RISK_LEVELS,

    validateEvidence,

    validateAnalysisResult,

    validateRiskAssessment,

    executeAnalysis,
};
