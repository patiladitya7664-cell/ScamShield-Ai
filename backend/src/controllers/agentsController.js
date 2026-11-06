"use strict";

/*

# SCAMSHIELD AI - MULTI AGENT CONTROLLER

Agents:

1. Guardian Agent
2. Intelligence Agent
3. Victim Safety Agent
4. Decoy Agent

AI Processing:
Node.js -> Python FastAPI -> AI Pipeline

MongoDB:

* Saves analysis and all four agent results.
* Does not store raw evidence.
* Preserves existing frontend response contract.
  =========================================================
  */

const Analysis = require("../models/analysis");
const { analyzeEvidence } = require("../services/aiService");

/*

1. AGENT RESULT NORMALIZATION
   =========================================================
   */

const getAgentStatus = (agent) => {
  if (!agent || typeof agent !== "object") {
    return "failed";
  }

  if (agent.success === false) {
    return "failed";
  }

  return agent.status || "completed";
};

/*

2. GUARDIAN AGENT
   =========================================================
   */

const guardianAgent = (analysis) => {
  const pythonGuardian = analysis.agents?.guardian || {};

  return {
    agent: "Guardian Agent",

    status: getAgentStatus(pythonGuardian),

    fraudCategory: analysis.fraudCategory,

    riskScore: analysis.riskScore,

    riskLevel: analysis.riskLevel,

    detectedRules: analysis.detectedRules || [],

    summary: analysis.summary,

    analysisMethod: analysis.analysisMethod,

    machineLearning: analysis.machineLearning,
  };
};

/*

3. INTELLIGENCE AGENT
   =========================================================
   */

const intelligenceAgent = (analysis) => {
  const pythonIntelligence = analysis.agents?.intelligence || {};

  const indicators = analysis.indicators || [];

  return {
    agent: "Intelligence Agent",

    status: getAgentStatus(pythonIntelligence),

    totalIndicators: indicators.length,

    indicators,

    indicatorTypes: [...new Set(indicators.map((item) => item.type))],

    verificationStatus: "unverified",

    message:
      "Extracted indicators are clues only. They have not been independently verified.",

    pythonResult: pythonIntelligence,
  };
};

/*

4. VICTIM SAFETY AGENT
   =========================================================
   */

const victimSafetyAgent = (analysis) => {
  const pythonSafety = analysis.agents?.victimSafety || {};

  const recommendations = Array.isArray(analysis.recommendations)
    ? analysis.recommendations
    : [];

  return {
    agent: "Victim Safety Agent",

    status: getAgentStatus(pythonSafety),

    safetyLevel:
      pythonSafety.safety_level ||
      pythonSafety.safetyLevel ||
      analysis.riskLevel.toUpperCase(),

    recommendations,

    totalRecommendations: recommendations.length,

    pythonResult: pythonSafety,
  };
};

/*

5. DECOY AGENT
   =========================================================

Decoy simulation is NOT automatically started.
It requires a separate, explicit user-controlled action.
========================================================

*/

const decoyAgent = () => {
  return {
    agent: "Decoy Agent",

    status: "not_started",

    message:
      "Controlled simulation is available through the separate Decoy operation.",

    simulationEnabled: false,

    simulationOnly: true,
  };
};

/*

6. MAIN AGENT CONTROLLER
   =========================================================
   */

const runAgents = async (req, res) => {
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

    const { evidenceType, evidence } = req.body || {};

    if (!evidenceType || typeof evidence !== "string") {
      return res.status(400).json({
        success: false,
        message: "Evidence type and evidence are required.",
      });
    }

    // -----------------------------------------------
    // PYTHON AI ENGINE EXECUTION
    // -----------------------------------------------

    const analysis = await analyzeEvidence({
      evidenceType,
      evidence,
    });

    // -----------------------------------------------
    // EXECUTE AGENT RESULT MAPPERS
    // -----------------------------------------------

    const guardian = guardianAgent(analysis);

    const intelligence = intelligenceAgent(analysis);

    const victimSafety = victimSafetyAgent(analysis);

    const decoy = decoyAgent();

    // -----------------------------------------------
    // COMBINE AGENT RESULTS
    // -----------------------------------------------

    const agentResults = {
      guardian,
      intelligence,
      victimSafety,
      decoy,
    };

    // -----------------------------------------------
    // SAVE RESULTS IN MONGODB
    // -----------------------------------------------

    const savedAnalysis = await Analysis.create({
      user: req.user._id,

      evidenceId: analysis.evidenceId,

      evidenceType: analysis.evidenceType,

      fraudCategory: analysis.fraudCategory,

      riskScore: analysis.riskScore,

      riskLevel: analysis.riskLevel,

      status: "completed",

      summary: analysis.summary,

      indicators: analysis.indicators || [],

      detectedRules: analysis.detectedRules || [],

      agents: agentResults,

      analyzedAt: analysis.analyzedAt || new Date(),
    });

    // -----------------------------------------------
    // SUCCESS RESPONSE
    // -----------------------------------------------

    return res.status(201).json({
      success: true,

      message:
        "Python AI Engine analysis and agent execution completed successfully.",

      data: {
        analysisId: savedAnalysis._id,

        evidenceId: savedAnalysis.evidenceId,

        agents: savedAnalysis.agents,

        analysis: {
          fraudCategory: savedAnalysis.fraudCategory,

          riskScore: savedAnalysis.riskScore,

          riskLevel: savedAnalysis.riskLevel,

          summary: savedAnalysis.summary,

          explanation: analysis.explanation,

          analysisMethod: analysis.analysisMethod,

          aiEngineUsed: analysis.aiEngineUsed,

          machineLearning: analysis.machineLearning,

          analyzedAt: savedAnalysis.analyzedAt,
        },

        orchestration: analysis.orchestration,

        verification: analysis.verification,

        disclaimer: analysis.disclaimer,
      },
    });
  } catch (error) {
    console.error("Agents Controller Error:", error.message);

    const statusCode = error.statusCode || 500;

    return res.status(statusCode).json({
      success: false,

      message: error.message || "Agent execution failed.",
    });
  }
};

/*

# EXPORTS

*/

module.exports = {
  runAgents,
};
