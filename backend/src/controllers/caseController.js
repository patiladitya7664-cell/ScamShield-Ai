"use strict";

const mongoose = require("mongoose");
const Case = require("../models/Case");
const Analysis = require("../models/analysis");

const ALLOWED_CATEGORIES = [
  "investment",
  "digitalArrest",
  "creditCard",
  "sextortion",
  "ecommerce",
  "other",
  "unclassified",
];

const ALLOWED_RISK_LEVELS = ["low", "medium", "high", "critical"];

const ALLOWED_STATUSES = ["open", "investigating", "resolved", "closed"];

const ALLOWED_PRIORITIES = ["low", "medium", "high", "urgent"];

const getUserId = (req) => req.user?._id;

const isValidId = (id) => mongoose.Types.ObjectId.isValid(id);

/*
=========================================================
 CREATE CASE
 POST /api/cases
=========================================================
*/

const createCase = async (req, res, next) => {
  try {
    const userId = getUserId(req);

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const {
      title,
      description,
      analysisId,
      fraudCategory,
      riskLevel,
      priority,
      indicators,
    } = req.body || {};

    if (!title || typeof title !== "string" || title.trim().length < 3) {
      return res.status(400).json({
        success: false,
        message: "A valid case title of at least 3 characters is required.",
      });
    }

    if (title.trim().length > 150) {
      return res.status(400).json({
        success: false,
        message: "Case title cannot exceed 150 characters.",
      });
    }

    if (
      description !== undefined &&
      (typeof description !== "string" || description.length > 5000)
    ) {
      return res.status(400).json({
        success: false,
        message: "Description must be text and cannot exceed 5000 characters.",
      });
    }

    let linkedAnalysis = null;

    if (analysisId) {
      if (!isValidId(analysisId)) {
        return res.status(400).json({
          success: false,
          message: "Invalid analysis identifier.",
        });
      }

      linkedAnalysis = await Analysis.findOne({
        _id: analysisId,
        user: userId,
      });

      if (!linkedAnalysis) {
        return res.status(404).json({
          success: false,
          message: "Analysis not found.",
        });
      }
    }

    const selectedCategory =
      fraudCategory || linkedAnalysis?.fraudCategory || "unclassified";

    const selectedRisk = riskLevel || linkedAnalysis?.riskLevel || "medium";

    if (!ALLOWED_CATEGORIES.includes(selectedCategory)) {
      return res.status(400).json({
        success: false,
        message: "Invalid fraud category.",
      });
    }

    if (!ALLOWED_RISK_LEVELS.includes(selectedRisk)) {
      return res.status(400).json({
        success: false,
        message: "Invalid risk level.",
      });
    }

    if (priority !== undefined && !ALLOWED_PRIORITIES.includes(priority)) {
      return res.status(400).json({
        success: false,
        message: "Invalid case priority.",
      });
    }

    const safeIndicators =
      indicators === undefined ? linkedAnalysis?.indicators || [] : indicators;

    if (!Array.isArray(safeIndicators) || safeIndicators.length > 50) {
      return res.status(400).json({
        success: false,
        message: "Indicators must be an array containing at most 50 items.",
      });
    }

    const caseIndicators = safeIndicators.map((item) => {
      if (
        !item ||
        typeof item.type !== "string" ||
        typeof item.value !== "string" ||
        item.type.length > 30 ||
        item.value.length > 300
      ) {
        throw Object.assign(new Error("Invalid indicator information."), {
          statusCode: 400,
        });
      }

      return {
        type: item.type,
        value: item.value,
        // Indicators are unverified by default.
        verified: false,
      };
    });

    const newCase = await Case.create({
      user: userId,
      analysis: linkedAnalysis?._id || null,
      title: title.trim(),
      description: description?.trim() || "",
      fraudCategory: selectedCategory,
      riskLevel: selectedRisk,
      priority: priority || "medium",
      indicators: caseIndicators,
    });

    return res.status(201).json({
      success: true,
      message: "Case created successfully.",
      data: newCase,
    });
  } catch (error) {
    return next(error);
  }
};

/*
=========================================================
 GET ALL USER CASES
 GET /api/cases
=========================================================
*/

const getUserCases = async (req, res, next) => {
  try {
    const userId = getUserId(req);

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const { status, riskLevel, page = 1, limit = 10 } = req.query;

    const pageNumber = Math.max(1, Number.parseInt(page, 10) || 1);
    const pageSize = Math.min(
      50,
      Math.max(1, Number.parseInt(limit, 10) || 10),
    );

    const filter = { user: userId };

    if (status) {
      if (!ALLOWED_STATUSES.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid case status filter.",
        });
      }

      filter.status = status;
    }

    if (riskLevel) {
      if (!ALLOWED_RISK_LEVELS.includes(riskLevel)) {
        return res.status(400).json({
          success: false,
          message: "Invalid risk level filter.",
        });
      }

      filter.riskLevel = riskLevel;
    }

    const [cases, total] = await Promise.all([
      Case.find(filter)
        .sort({ createdAt: -1 })
        .skip((pageNumber - 1) * pageSize)
        .limit(pageSize)
        .populate(
          "analysis",
          "fraudCategory riskScore riskLevel evidenceType summary evidenceId indicators detectedRules analyzedAt",
        ),

      Case.countDocuments(filter),
    ]);

    return res.status(200).json({
      success: true,
      data: cases,
      pagination: {
        total,
        page: pageNumber,
        limit: pageSize,
        totalPages: Math.ceil(total / pageSize),
      },
    });
  } catch (error) {
    return next(error);
  }
};

/*
=========================================================
 GET SINGLE CASE
 GET /api/cases/:id
=========================================================
*/

const getCaseById = async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const { id } = req.params;

    if (!isValidId(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid case identifier.",
      });
    }

    const caseRecord = await Case.findOne({
      _id: id,
      user: userId,
    }).populate("analysis", "fraudCategory riskScore riskLevel summary");

    if (!caseRecord) {
      return res.status(404).json({
        success: false,
        message: "Case not found.",
      });
    }

    return res.status(200).json({
      success: true,
      data: caseRecord,
    });
  } catch (error) {
    return next(error);
  }
};

/*
=========================================================
 UPDATE CASE
 PATCH /api/cases/:id
=========================================================
*/

const updateCase = async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const { id } = req.params;

    if (!isValidId(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid case identifier.",
      });
    }

    const allowedFields = [
      "title",
      "description",
      "status",
      "priority",
      "resolution",
      "classificationFeedback",
    ];

    const updates = {};

    for (const field of allowedFields) {
      if (Object.prototype.hasOwnProperty.call(req.body || {}, field)) {
        updates[field] = req.body[field];
      }
    }

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({
        success: false,
        message: "No valid update fields provided.",
      });
    }

    if (
      updates.title !== undefined &&
      (typeof updates.title !== "string" ||
        updates.title.trim().length < 3 ||
        updates.title.trim().length > 150)
    ) {
      return res.status(400).json({
        success: false,
        message: "Title must contain between 3 and 150 characters.",
      });
    }

    if (
      updates.description !== undefined &&
      (typeof updates.description !== "string" ||
        updates.description.length > 5000)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid description.",
      });
    }

    if (
      updates.status !== undefined &&
      !ALLOWED_STATUSES.includes(updates.status)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid case status.",
      });
    }

    if (
      updates.priority !== undefined &&
      !ALLOWED_PRIORITIES.includes(updates.priority)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid case priority.",
      });
    }

    if (
      updates.classificationFeedback !== undefined &&
      ![
        "none",
        "needs_review",
        "possible_false_positive",
        "category_correction_requested",
      ].includes(updates.classificationFeedback)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid classification feedback option.",
      });
    }

    if (
      updates.resolution !== undefined &&
      (typeof updates.resolution !== "string" ||
        updates.resolution.length > 3000)
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid resolution.",
      });
    }

    if (updates.title !== undefined) {
      updates.title = updates.title.trim();
    }

    if (updates.description !== undefined) {
      updates.description = updates.description.trim();
    }

    if (updates.resolution !== undefined) {
      updates.resolution = updates.resolution.trim();
    }

    if (updates.status === "resolved" || updates.status === "closed") {
      updates.resolvedAt = new Date();
    } else if (
      updates.status &&
      ["open", "investigating"].includes(updates.status)
    ) {
      updates.resolvedAt = null;
    }

    const updatedCase = await Case.findOneAndUpdate(
      { _id: id, user: userId },
      { $set: updates },
      {
        new: true,
        runValidators: true,
      },
    );

    if (!updatedCase) {
      return res.status(404).json({
        success: false,
        message: "Case not found.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Case updated successfully.",
      data: updatedCase,
    });
  } catch (error) {
    return next(error);
  }
};

/*
=========================================================
 DELETE CASE
 DELETE /api/cases/:id
=========================================================
*/

const deleteCase = async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const { id } = req.params;

    if (!isValidId(id)) {
      return res.status(400).json({
        success: false,
        message: "Invalid case identifier.",
      });
    }

    const deletedCase = await Case.findOneAndDelete({
      _id: id,
      user: userId,
    });

    if (!deletedCase) {
      return res.status(404).json({
        success: false,
        message: "Case not found.",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Case deleted successfully.",
    });
  } catch (error) {
    return next(error);
  }
};

module.exports = {
  createCase,
  getUserCases,
  getCaseById,
  updateCase,
  deleteCase,
};
