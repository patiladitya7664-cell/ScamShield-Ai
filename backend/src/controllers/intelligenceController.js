"use strict";

const Analysis = require("../models/analysis");

const ALLOWED_TYPES = new Set(["phone", "url", "upi", "keyword"]);

const analyzeIndicator = async (req, res, next) => {
  try {
    const indicatorType = String(req.body?.indicatorType || "").trim().toLowerCase();
    const indicator = String(req.body?.indicator || "").trim();

    if (!ALLOWED_TYPES.has(indicatorType)) {
      return res.status(400).json({
        success: false,
        message: "Choose a supported indicator type.",
      });
    }

    if (!indicator || indicator.length > 250) {
      return res.status(400).json({
        success: false,
        message: "Enter an indicator between 1 and 250 characters.",
      });
    }

    // Search only this user's saved analyses. The match is an unverified clue,
    // not a confirmation that an identifier belongs to a criminal.
    const matchPattern = { $regex: `^${escapeRegex(indicator)}$`, $options: "i" };
    const searchFilter =
      indicatorType === "keyword"
        ? { user: req.user._id, "detectedRules.label": matchPattern }
        : {
            user: req.user._id,
            indicators: {
              $elemMatch: {
                type: indicatorType,
                value: matchPattern,
              },
            },
          };

    const matchingAnalyses = await Analysis.find(searchFilter)
      .select("evidenceId fraudCategory riskScore riskLevel analyzedAt")
      .sort({ analyzedAt: -1 })
      .limit(10)
      .lean();

    return res.status(200).json({
      success: true,
      result: {
        indicator,
        indicatorType,
        status: matchingAnalyses.length
          ? "Previously observed in your cases"
          : "No match in your saved cases",
        relatedEvidence: matchingAnalyses.length,
        explanation: matchingAnalyses.length
          ? "This unverified clue appeared in prior analyses belonging to your account. Review the linked case evidence before drawing conclusions."
          : "No matching clue was found in your saved analyses. This does not establish that the indicator is safe or unsafe.",
        matches: matchingAnalyses.map((analysis) => ({
          evidenceId: analysis.evidenceId,
          fraudCategory: analysis.fraudCategory,
          riskScore: analysis.riskScore,
          riskLevel: analysis.riskLevel,
          analyzedAt: analysis.analyzedAt,
        })),
      },
    });
  } catch (error) {
    return next(error);
  }
};

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

module.exports = { analyzeIndicator };
