"use strict";

// =====================================================
// SCAMSHIELD AI - MULTI AGENT CONTROLLER
// Version: 3.0.0
//
// Processing:
// Node.js -> Analysis Service -> Python AI Pipeline
//
// Responsibilities:
// 1. Validate authenticated requests.
// 2. Execute centralized analysis pipeline.
// 3. Preserve Python agent execution metadata.
// 4. Persist normalized analysis results.
// 5. Never store raw evidence.
// 6. Preserve frontend response compatibility.
// =====================================================

const Analysis = require("../models/analysis");
const { executeAnalysis } = require("../services/analysisService");

// =====================================================
// 1. RESPONSE HELPERS
// =====================================================

const sendError = (res, statusCode, message) => {
    return res.status(statusCode).json({
        success: false,
        message,
    });
};

const normalizeArray = (value) => {
    return Array.isArray(value) ? value : [];
};

// =====================================================
// 2. AGENT RESULT NORMALIZATION
// =====================================================

const normalizeAgentResults = (agents = {}) => {
    const guardian = agents.guardian || {};
    const intelligence = agents.intelligence || {};
    const victimSafety = agents.victimSafety || {};
    const decoy = agents.decoy || {};

    return {
        guardian: {
            agent: "Guardian Agent",
            status: guardian.status || "unknown",
            fraudCategory: guardian.fraudCategory || null,
            detectionCategory: guardian.detectionCategory || null,
            riskScore: guardian.riskScore ?? null,
            riskLevel: guardian.riskLevel || null,
            detectedRules: normalizeArray(guardian.detectedRules),
            summary: guardian.summary || "",
            analysisMethod: guardian.analysisMethod || null,
        },

        intelligence: {
            agent: "Intelligence Agent",
            status: intelligence.status || "unknown",
            totalIndicators: normalizeArray(
                intelligence.indicators
            ).length,
            indicators: normalizeArray(
                intelligence.indicators
            ).map((indicator) => ({
                type: indicator.type || "unknown",
                value: indicator.value || "",
                verified: false,
            })),
            verificationStatus: "unverified",
            message:
                "Extracted indicators are clues only and have not been independently verified.",
        },

        victimSafety: {
            agent: "Victim Safety Agent",
            status: victimSafety.status || "unknown",
            safetyLevel: victimSafety.safetyLevel || null,
            recommendations: normalizeArray(
                victimSafety.recommendations
            ),
            totalRecommendations: normalizeArray(
                victimSafety.recommendations
            ).length,
        },

        decoy: {
            agent: "Decoy Agent",
            status: decoy.status || "not_started",
            message:
                decoy.message ||
                "Controlled simulation requires a separate user-controlled operation.",
            simulationEnabled: false,
            simulationOnly: true,
        },
    };
};

// =====================================================
// 3. MAIN AGENT CONTROLLER
// =====================================================

const runAgents = async (req, res) => {
    try {
        // ---------------------------------------------
        // AUTHENTICATION
        // ---------------------------------------------

        if (!req.user || !req.user._id) {
            return sendError(
                res,
                401,
                "Authentication required."
            );
        }

        // ---------------------------------------------
        // REQUEST VALIDATION
        // ---------------------------------------------

        const { evidenceType, evidence } = req.body || {};

        if (
            typeof evidenceType !== "string" ||
            typeof evidence !== "string"
        ) {
            return sendError(
                res,
                400,
                "Evidence type and evidence are required."
            );
        }

        // ---------------------------------------------
        // CENTRALIZED ANALYSIS PIPELINE
        // ---------------------------------------------

        const analysis = await executeAnalysis({
            evidenceType,
            evidence,
        });

        if (!analysis || typeof analysis !== "object") {
            throw new Error(
                "Analysis service returned an invalid result."
            );
        }

        // ---------------------------------------------
        // NORMALIZE AGENT RESULTS
        // ---------------------------------------------

        const agentResults = normalizeAgentResults(
            analysis.agents
        );

        // ---------------------------------------------
        // PERSIST ANALYSIS
        // ---------------------------------------------

        const savedAnalysis = await Analysis.create({
            user: req.user._id,

            evidenceId: analysis.evidenceId,

            evidenceType: analysis.evidenceType,

            fraudCategory: analysis.fraudCategory,

            detectionCategory:
                analysis.detectionCategory || null,

            riskScore: analysis.riskScore,

            riskLevel: analysis.riskLevel,

            status: "completed",

            summary: analysis.summary || "",

            indicators: normalizeArray(
                analysis.indicators
            ),

            detectedRules: normalizeArray(
                analysis.detectedRules
            ),

            agents: agentResults,

            analyzedAt: analysis.analyzedAt || new Date(),
        });

        // ---------------------------------------------
        // SUCCESS RESPONSE
        // ---------------------------------------------

        return res.status(201).json({
            success: true,

            message:
                "ScamShield AI analysis completed successfully.",

            data: {
                analysisId: savedAnalysis._id,

                evidenceId: savedAnalysis.evidenceId,

                agents: savedAnalysis.agents,

                analysis: {
                    fraudCategory: savedAnalysis.fraudCategory,

                    detectionCategory:
                        savedAnalysis.detectionCategory,

                    riskScore: savedAnalysis.riskScore,

                    riskLevel: savedAnalysis.riskLevel,

                    summary: savedAnalysis.summary,

                    explanation: analysis.explanation || "",

                    recommendations:
                        normalizeArray(
                            analysis.recommendations
                        ),

                    analysisMethod:
                        analysis.analysisMethod || null,

                    aiEngineUsed:
                        analysis.aiEngineUsed || false,

                    machineLearning:
                        analysis.machineLearning || null,

                    geminiAdvisory:
                        analysis.geminiAdvisory || null,

                    analyzedAt: savedAnalysis.analyzedAt,
                },

                orchestration:
                    analysis.orchestration || null,

                verification:
                    analysis.verification || null,

                disclaimer:
                    analysis.disclaimer || null,
            },
        });

    } catch (error) {
        // ---------------------------------------------
        // INTERNAL ERROR LOGGING
        // ---------------------------------------------

        console.error(
            "[AGENTS CONTROLLER ERROR]",
            error.message
        );

        // ---------------------------------------------
        // SAFE ERROR RESPONSE
        // ---------------------------------------------

        const statusCode = Number.isInteger(error.statusCode) &&
            error.statusCode >= 400 &&
            error.statusCode < 500
            ? error.statusCode
            : 500;

        const message = statusCode < 500
            ? error.message
            : "Agent analysis could not be completed. Please try again.";

        return sendError(
            res,
            statusCode,
            message
        );
    }
};

// =====================================================
// 4. EXPORTS
// =====================================================

module.exports = {
    runAgents,
    normalizeAgentResults,
};