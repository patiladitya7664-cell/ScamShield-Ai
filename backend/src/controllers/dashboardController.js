"use strict";

const Analysis = require("../models/analysis");

// ======================================================
// SCAMSHIELD AI - DASHBOARD CONTROLLER
// Version: 2.0.0
//
// Features:
// 1. User-specific dashboard statistics
// 2. Risk-level distribution
// 3. All 12 fraud detection categories
// 4. Five major detection modules
// 5. Recent analysis activity
// 6. MongoDB aggregation
// ======================================================

// All 12 individual detection categories.
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

// Five major detection modules.
const FRAUD_MODULES = [
  "investment",
  "digitalArrest",
  "creditCard",
  "sextortion",
  "ecommerce",
];

// ======================================================
// GET DASHBOARD OVERVIEW
// GET /api/dashboard/overview
// ======================================================

const getDashboardOverview = async (req, res) => {
  try {
    const userId = req.user?._id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    // Only completed analyses contribute to statistics.
    const completedFilter = {
      user: userId,
      status: "completed",
    };

    const [
      totalAnalyses,
      threatsDetected,
      lowRiskResults,
      highRiskResults,
      riskDistribution,
      categoryDistribution,
      moduleDistribution,
      recentActivity,
    ] = await Promise.all([

      // 1. Total completed analyses.
      Analysis.countDocuments(completedFilter),

      // 2. High + Critical threats.
      Analysis.countDocuments({
        ...completedFilter,
        riskLevel: {
          $in: ["high", "critical"],
        },
      }),

      // 3. Low-risk analyses.
      Analysis.countDocuments({
        ...completedFilter,
        riskLevel: "low",
      }),

      // 4. High-risk analyses (Critical excluded).
      Analysis.countDocuments({
        ...completedFilter,
        riskLevel: "high",
      }),

      // 5. Risk-level distribution.
      Analysis.aggregate([
        {
          $match: completedFilter,
        },
        {
          $group: {
            _id: "$riskLevel",
            count: {
              $sum: 1,
            },
          },
        },
      ]),

      // 6. Individual 12-category distribution.
      Analysis.aggregate([
        {
          $match: completedFilter,
        },
        {
          $group: {
            _id: "$detectionCategory",
            count: {
              $sum: 1,
            },
          },
        },
      ]),

      // 7. Five major fraud modules.
      Analysis.aggregate([
        {
          $match: completedFilter,
        },
        {
          $group: {
            _id: "$fraudCategory",
            count: {
              $sum: 1,
            },
          },
        },
      ]),

      // 8. Latest 10 user activities.
      Analysis.find({
        user: userId,
      })
        .sort({
          createdAt: -1,
        })
        .limit(10)
        .select(
          "evidenceType fraudCategory detectionCategory riskScore riskLevel status createdAt"
        )
        .lean(),
    ]);

    // ==================================================
    // RISK DISTRIBUTION
    // ==================================================

    const riskCounts = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    riskDistribution.forEach((item) => {
      if (
        Object.prototype.hasOwnProperty.call(
          riskCounts,
          item._id
        )
      ) {
        riskCounts[item._id] = item.count;
      }
    });

    // ==================================================
    // 12 DETECTION CATEGORIES
    // ==================================================

    const categoryCounts = {};

    DETECTION_CATEGORIES.forEach((category) => {
      categoryCounts[category] = 0;
    });

    let unclassifiedCategories = 0;

    categoryDistribution.forEach((item) => {
      if (
        item._id &&
        Object.prototype.hasOwnProperty.call(
          categoryCounts,
          item._id
        )
      ) {
        categoryCounts[item._id] = item.count;
      } else {
        // Includes old records without detectionCategory.
        unclassifiedCategories += item.count;
      }
    });

    // ==================================================
    // FIVE MAJOR DETECTION MODULES
    // ==================================================

    const moduleCounts = {};

    FRAUD_MODULES.forEach((module) => {
      moduleCounts[module] = 0;
    });

    moduleDistribution.forEach((item) => {
      if (
        Object.prototype.hasOwnProperty.call(
          moduleCounts,
          item._id
        )
      ) {
        moduleCounts[item._id] = item.count;
      }
    });

    // ==================================================
    // RESPONSE
    // ==================================================

    return res.status(200).json({
      success: true,

      message: "Dashboard overview fetched successfully.",

      data: {
        statistics: {
          totalAnalyses,
          threatsDetected,
          lowRiskResults,
          highRiskResults,
        },

        riskDistribution: riskCounts,

        fraudCategories: categoryCounts,

        fraudModules: moduleCounts,

        unclassifiedCategories,

        recentActivity,
      },
    });

  } catch (error) {
    console.error(
      "Dashboard Overview Error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Unable to fetch dashboard overview.",
    });
  }
};

// ======================================================
// EXPORTS
// ======================================================

module.exports = {
  getDashboardOverview,
};