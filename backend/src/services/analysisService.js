"use strict";

// =====================================================
// SCAMSHIELD AI - ANALYSIS SERVICE
// Central analysis orchestration layer
//
// Responsibilities:
// 1. Validate incoming evidence.
// 2. Execute the existing AI analysis service.
// 3. Validate AI analysis response.
// 4. Execute the four-agent system.
// 5. Return a unified analysis result.
//
// MongoDB persistence is handled by the controller.
// =====================================================

const { analyzeEvidence } = require("./aiService");
const { executeAgents } = require("./agentsService");

// =====================================================
// SUPPORTED EVIDENCE TYPES
// =====================================================

const SUPPORTED_EVIDENCE_TYPES = Object.freeze([
    "message",
    "url",
    "phone",
    "call",
    "transaction",
    "upi",
    "email",
    "screenshot",
]);

// =====================================================
// VALIDATE EVIDENCE INPUT
// =====================================================

const validateEvidence = ({ evidenceType, evidence }) => {
    if (!evidenceType || typeof evidenceType !== "string") {
        throw new Error("Evidence type is required.");
    }

    const normalizedType = evidenceType.trim().toLowerCase();

    if (!SUPPORTED_EVIDENCE_TYPES.includes(normalizedType)) {
        throw new Error("Unsupported evidence type.");
    }

    if (typeof evidence !== "string" || !evidence.trim()) {
        throw new Error("Valid evidence is required.");
    }

    if (evidence.length > 20000) {
        throw new Error("Evidence exceeds the maximum allowed length.");
    }

    return {
        evidenceType: normalizedType,
        evidence: evidence.trim(),
    };
};

// =====================================================
// VALIDATE AI ANALYSIS RESPONSE
// =====================================================

const validateAnalysisResult = (analysis) => {
    if (!analysis || typeof analysis !== "object") {
        throw new Error("AI Engine returned an invalid analysis result.");
    }

    if (
        typeof analysis.riskScore !== "number" ||
        !Number.isFinite(analysis.riskScore) ||
        analysis.riskScore < 0 ||
        analysis.riskScore > 100
    ) {
        throw new Error("AI Engine returned an invalid risk score.");
    }

    if (!analysis.riskLevel || !analysis.fraudCategory) {
        throw new Error(
            "AI Engine response is missing fraud category or risk level."
        );
    }

    if (
        analysis.indicators !== undefined &&
        !Array.isArray(analysis.indicators)
    ) {
        throw new Error("Invalid indicators returned by AI Engine.");
    }

    if (
        analysis.detectedRules !== undefined &&
        !Array.isArray(analysis.detectedRules)
    ) {
        throw new Error("Invalid detected rules returned by AI Engine.");
    }

    return analysis;
};

// =====================================================
// EXECUTE ANALYSIS
// =====================================================

const executeAnalysis = async (input) => {
    // 1. Validate input.
    const validatedInput = validateEvidence(input);

    // 2. Execute existing AI detection service.
    const rawAnalysis = await analyzeEvidence(validatedInput);

    // 3. Validate AI response.
    const analysis = validateAnalysisResult(rawAnalysis);

    // 4. Execute multi-agent system.
    const agents = await executeAgents(analysis);

    // 5. Return unified result.
    return {
        evidenceId: analysis.evidenceId || null,

        evidenceType: validatedInput.evidenceType,

        fraudCategory: analysis.fraudCategory,

        riskScore: analysis.riskScore,

        riskLevel: analysis.riskLevel,

        summary: analysis.summary || "",

        explanation: analysis.explanation || "",

        indicators: analysis.indicators || [],

        detectedRules: analysis.detectedRules || [],

        agents,

        analyzedAt: analysis.analyzedAt || new Date(),

        disclaimer: analysis.disclaimer || "",
    };
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    SUPPORTED_EVIDENCE_TYPES,
    validateEvidence,
    validateAnalysisResult,
    executeAnalysis,
};