"use strict";

const Analysis = require("../models/analysis");

const getDashboardOverview = async (req, res) => {
  try {
    const userId = req.user?._id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    // Only completed analyses are included in statistics.
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
      fraudCategories,
      recentActivity,
    ] = await Promise.all([
      // Total completed analyses
      Analysis.countDocuments(completedFilter),

      // High + Critical risk detections
      Analysis.countDocuments({
        ...completedFilter,
        riskLevel: { $in: ["high", "critical"] },
      }),

      // Low-risk analyses
      Analysis.countDocuments({
        ...completedFilter,
        riskLevel: "low",
      }),

      // High-risk only (Critical excluded)
      Analysis.countDocuments({
        ...completedFilter,
        riskLevel: "high",
      }),

      // Risk-level distribution
      Analysis.aggregate([
        {
          $match: completedFilter,
        },
        {
          $group: {
            _id: "$riskLevel",
            count: { $sum: 1 },
          },
        },
      ]),

      // Fraud-category distribution
      Analysis.aggregate([
        {
          $match: completedFilter,
        },
        {
          $group: {
            _id: "$fraudCategory",
            count: { $sum: 1 },
          },
        },
      ]),

      // Latest 10 activities (all statuses)
      Analysis.find({ user: userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .select(
          "evidenceType fraudCategory riskScore riskLevel status createdAt",
        )
        .lean(),
    ]);

    // Initialize risk distribution
    const riskCounts = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    riskDistribution.forEach((item) => {
      if (Object.prototype.hasOwnProperty.call(riskCounts, item._id)) {
        riskCounts[item._id] = item.count;
      }
    });

    // Initialize fraud category distribution
    const categoryCounts = {
      investment: 0,
      digitalArrest: 0,
      creditCard: 0,
      sextortion: 0,
      ecommerce: 0,
      other: 0,
      unclassified: 0,
    };

    fraudCategories.forEach((item) => {
      if (Object.prototype.hasOwnProperty.call(categoryCounts, item._id)) {
        categoryCounts[item._id] = item.count;
      }
    });

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

        recentActivity,
      },
    });
  } catch (error) {
    console.error("Dashboard Overview Error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to fetch dashboard overview.",
    });
  }
};

module.exports = {
  getDashboardOverview,
};
