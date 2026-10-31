"use strict";

/*

# SCAMSHIELD AI - ANALYSIS CONTROLLER

Responsibilities:

1. Receive evidence from authenticated users.
2. Validate incoming request.
3. Call the analysis service.
4. Save analysis results in MongoDB.
5. Return structured results to frontend.

Raw evidence is not stored in the database.

=========================================================
*/

const Analysis = require("../models/analysis");
const { analyzeEvidence } = require("../services/aiService");

/*

# ANALYZE EVIDENCE

POST /api/analysis/analyze
Protected route
===============

*/

const analyzeUserEvidence = async (req, res, next) => {
  try {
    const { evidenceType, evidence } = req.body || {};

    // Ensure user is authenticated.
    if (!req.user || !req.user._id) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    // Validate required fields.
    if (!evidenceType || !evidence) {
      return res.status(400).json({
        success: false,
        message: "Evidence type and evidence are required.",
      });
    }

    // Run evidence analysis.
    const analysisResult = await analyzeEvidence({
      evidenceType,
      evidence,
    });

    // Save analysis result.
    // Raw evidence is intentionally not saved.
    const savedAnalysis = await Analysis.create({
      user: req.user._id,
      evidenceId: analysisResult.evidenceId,
      evidenceType: analysisResult.evidenceType,
      fraudCategory: analysisResult.fraudCategory,
      riskScore: analysisResult.riskScore,
      riskLevel: analysisResult.riskLevel,
      status: "completed",
      summary: analysisResult.summary,
      indicators: analysisResult.indicators,
      detectedRules: analysisResult.detectedRules,
      analyzedAt: analysisResult.analyzedAt,
    });

    // Return result to frontend.
    return res.status(201).json({
      success: true,
      message: "Evidence analysis completed successfully.",

      result: {
        id: savedAnalysis._id,
        evidenceId: savedAnalysis.evidenceId,
        evidenceType: savedAnalysis.evidenceType,

        fraudCategory: savedAnalysis.fraudCategory,

        riskScore: savedAnalysis.riskScore,
        riskLevel: savedAnalysis.riskLevel,

        riskDescription: analysisResult.summary,
        explanation: analysisResult.explanation,

        indicators: analysisResult.indicators,

        sensitiveInformation: analysisResult.sensitiveInformation,

        detectedRules: analysisResult.detectedRules,

        analysisMethod: analysisResult.analysisMethod,
        aiEngineUsed: analysisResult.aiEngineUsed,

        disclaimer: analysisResult.disclaimer,

        analyzedAt: savedAnalysis.analyzedAt,
      },
    });
  } catch (error) {
    console.error("Evidence Analysis Controller Error:", error.message);

    // Pass unexpected errors to global error middleware.
    return next(error);
  }
};

module.exports = {
  analyzeUserEvidence,
};
