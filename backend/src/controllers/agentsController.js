"use strict";

/*

# SCAMSHIELD AI - MULTI AGENT CONTROLLER

Agents:

1. Guardian Agent       - Scam detection and risk scoring
2. Intelligence Agent   - Indicator extraction
3. Victim Safety Agent  - Safety recommendations
4. Decoy Agent          - Controlled simulation status

MongoDB Integration:

* Saves analysis in Analysis collection.
* Saves all four agent results inside the same document.
* Does not store raw evidence.
  =========================================================
  */

const Analysis = require("../models/analysis");
const { analyzeEvidence } = require("../services/aiService");

/*

1. GUARDIAN AGENT
   =========================================================
   */

const guardianAgent = (analysis) => {
  return {
    agent: "Guardian Agent",
    status: "completed",

    fraudCategory: analysis.fraudCategory,
    riskScore: analysis.riskScore,
    riskLevel: analysis.riskLevel,

    detectedRules: analysis.detectedRules,

    summary: analysis.summary,
  };
};

/*

2. INTELLIGENCE AGENT
   =========================================================
   */

const intelligenceAgent = (analysis) => {
  const indicators = analysis.indicators || [];

  return {
    agent: "Intelligence Agent",
    status: "completed",

    totalIndicators: indicators.length,

    indicators,

    indicatorTypes: [...new Set(indicators.map((item) => item.type))],

    verificationStatus: "unverified",

    message:
      "Extracted indicators are clues only. They have not been independently verified.",
  };
};

/*

3. VICTIM SAFETY AGENT
   =========================================================
   */

const victimSafetyAgent = (analysis) => {
  const recommendations = [];

  recommendations.push(
    "Do not share OTP, PIN, CVV, passwords or banking credentials.",
  );

  recommendations.push("Do not transfer money under pressure or urgency.");

  recommendations.push(
    "Verify suspicious messages through official websites or customer support.",
  );

  if (analysis.fraudCategory === "digitalArrest") {
    recommendations.push(
      "Real law enforcement agencies do not conduct digital arrest through video calls or demand payments.",
    );
  }

  if (analysis.fraudCategory === "investment") {
    recommendations.push(
      "Avoid guaranteed-return investment offers. Verify the organization and its regulatory registration independently.",
    );
  }

  if (analysis.fraudCategory === "creditCard") {
    recommendations.push(
      "Never share card credentials or banking verification codes with callers or unknown websites.",
    );
  }

  if (analysis.fraudCategory === "sextortion") {
    recommendations.push(
      "Do not make payments under blackmail threats. Preserve evidence and report the incident.",
    );
  }

  if (analysis.fraudCategory === "ecommerce") {
    recommendations.push(
      "Use trusted shopping platforms and avoid payments outside their official payment systems.",
    );
  }

  if (analysis.riskLevel === "high" || analysis.riskLevel === "critical") {
    recommendations.push(
      "Stop interacting with the suspicious source and report the incident to the appropriate authorities.",
    );
  }

  return {
    agent: "Victim Safety Agent",
    status: "completed",

    recommendations,
    totalRecommendations: recommendations.length,
  };
};

/*

4. DECOY AGENT
   =========================================================
   */

const decoyAgent = () => {
  return {
    agent: "Decoy Agent",

    status: "not_configured",

    message: "Controlled scam simulation is not configured yet.",

    simulationEnabled: false,
  };
};

/*

5. MAIN AGENT ORCHESTRATOR
   =========================================================
   */

const runAgents = async (req, res) => {
  try {
    const { evidenceType, evidence } = req.body;

    // -----------------------------------------------
    // AUTHENTICATION CHECK
    // -----------------------------------------------

    if (!req.user || !req.user._id) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    // -----------------------------------------------
    // RUN EXISTING ANALYSIS SERVICE
    // -----------------------------------------------

    const analysis = await analyzeEvidence({
      evidenceType,
      evidence,
    });

    // -----------------------------------------------
    // EXECUTE FOUR AGENTS
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
    // SAVE ANALYSIS + AGENTS IN MONGODB
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

      message: "ScamShield AI agents executed and results saved successfully.",

      data: {
        // Actual MongoDB document ID.
        analysisId: savedAnalysis._id,

        // Unique evidence reference.
        evidenceId: savedAnalysis.evidenceId,

        agents: savedAnalysis.agents,

        analysis: {
          fraudCategory: savedAnalysis.fraudCategory,

          riskScore: savedAnalysis.riskScore,

          riskLevel: savedAnalysis.riskLevel,

          summary: savedAnalysis.summary,

          explanation: analysis.explanation,

          analyzedAt: savedAnalysis.analyzedAt,
        },

        disclaimer: analysis.disclaimer,
      },
    });
  } catch (error) {
    console.error("Agents Controller Error:", error);

    return res.status(400).json({
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
