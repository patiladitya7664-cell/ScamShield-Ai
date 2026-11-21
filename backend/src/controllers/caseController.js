"use strict";

const mongoose = require("mongoose");
const Case = require("../models/Case");
const Analysis = require("../models/analysis");

/* =========================================
   CONSTANTS
========================================= */

const ALLOWED_CATEGORIES = [
    "investment",
    "digitalArrest",
    "creditCard",
    "sextortion",
    "ecommerce",
    "other",
    "unclassified",
];

const ALLOWED_RISK_LEVELS = [
    "low",
    "medium",
    "high",
    "critical",
];

const ALLOWED_STATUSES = [
    "open",
    "investigating",
    "resolved",
    "closed",
];

const ALLOWED_PRIORITIES = [
    "low",
    "medium",
    "high",
    "urgent",
];

const ALLOWED_FEEDBACK = [
    "none",
    "needs_review",
    "possible_false_positive",
    "category_correction_requested",
];

const MAX_PAGE_SIZE = 50;

/* =========================================
   HELPERS
========================================= */

const getUserId = (req) => req.user?._id;

const isValidId = (id) =>
    mongoose.isObjectIdOrHexString(id);

const sendError = (res, statusCode, message) =>
    res.status(statusCode).json({
        success: false,
        message,
    });

const normalizeIndicators = (indicators) => {
    if (!Array.isArray(indicators) || indicators.length > 50) {
        const error = new Error(
            "Indicators must be an array containing at most 50 items."
        );

        error.statusCode = 400;
        throw error;
    }

    return indicators.map((item) => {
        if (
            !item ||
            typeof item.type !== "string" ||
            typeof item.value !== "string" ||
            !item.type.trim() ||
            !item.value.trim() ||
            item.type.length > 30 ||
            item.value.length > 300
        ) {
            const error = new Error(
                "Invalid indicator information."
            );

            error.statusCode = 400;
            throw error;
        }

        return {
            type: item.type.trim(),
            value: item.value.trim(),
            verified: false,
        };
    });
};

const parsePagination = (page, limit) => {
    const isPositiveInteger = (value) =>
        /^\d+$/.test(String(value)) &&
        Number.isSafeInteger(Number(value)) &&
        Number(value) >= 1;

    if (
        !isPositiveInteger(page) ||
        !isPositiveInteger(limit)
    ) {
        return null;
    }

    const pageNumber = Number(page);
    const pageSize = Math.min(
        Number(limit),
        MAX_PAGE_SIZE
    );

    const skip = (pageNumber - 1) * pageSize;

    if (!Number.isSafeInteger(skip)) {
        return null;
    }

    return {
        pageNumber,
        pageSize,
        skip,
    };
};

/* =========================================
   CREATE CASE
   POST /api/cases
========================================= */

const createCase = async (req, res, next) => {
    try {
        const userId = getUserId(req);

        if (!userId) {
            return sendError(
                res,
                401,
                "Authentication required."
            );
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

        // Title validation
        if (
            typeof title !== "string" ||
            title.trim().length < 3 ||
            title.trim().length > 150
        ) {
            return sendError(
                res,
                400,
                "Case title must contain between 3 and 150 characters."
            );
        }

        // Description validation
        if (
            description !== undefined &&
            (
                typeof description !== "string" ||
                description.length > 5000
            )
        ) {
            return sendError(
                res,
                400,
                "Description must be text and cannot exceed 5000 characters."
            );
        }

        // Priority validation
        if (
            priority !== undefined &&
            !ALLOWED_PRIORITIES.includes(priority)
        ) {
            return sendError(
                res,
                400,
                "Invalid case priority."
            );
        }

        // Load linked analysis only if it belongs to this user
        let linkedAnalysis = null;

        if (analysisId !== undefined && analysisId !== null) {
            if (!isValidId(analysisId)) {
                return sendError(
                    res,
                    400,
                    "Invalid analysis identifier."
                );
            }

            linkedAnalysis = await Analysis.findOne({
                _id: analysisId,
                user: userId,
                status: "completed",
            }).select(
                "fraudCategory riskLevel indicators"
            );

            if (!linkedAnalysis) {
                return sendError(
                    res,
                    404,
                    "Completed analysis not found."
                );
            }
        }

        /*
         * Linked analysis is authoritative.
         * Never allow client values to override
         * its category, risk or indicators.
         */

        const selectedCategory = linkedAnalysis
            ? linkedAnalysis.fraudCategory
            : fraudCategory || "unclassified";

        const selectedRisk = linkedAnalysis
            ? linkedAnalysis.riskLevel
            : riskLevel || "medium";

        if (!ALLOWED_CATEGORIES.includes(selectedCategory)) {
            return sendError(
                res,
                400,
                "Invalid fraud category."
            );
        }

        if (!ALLOWED_RISK_LEVELS.includes(selectedRisk)) {
            return sendError(
                res,
                400,
                "Invalid risk level."
            );
        }

        // Use trusted analysis indicators when linked.
        const sourceIndicators = linkedAnalysis
            ? linkedAnalysis.indicators || []
            : indicators || [];

        const caseIndicators = normalizeIndicators(
            sourceIndicators
        );

        const newCase = await Case.create({
            user: userId,
            analysis: linkedAnalysis?._id || null,

            title: title.trim(),

            description: description
                ? description.trim()
                : "",

            fraudCategory: selectedCategory,
            riskLevel: selectedRisk,

            priority: priority || "medium",

            indicators: caseIndicators,

            status: "open",
            classificationFeedback: "none",
            resolution: "",
            resolvedAt: null,
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

/* =========================================
   GET ALL USER CASES
   GET /api/cases
========================================= */

const getUserCases = async (req, res, next) => {
    try {
        const userId = getUserId(req);

        if (!userId) {
            return sendError(
                res,
                401,
                "Authentication required."
            );
        }

        const {
            status,
            riskLevel,
            page = "1",
            limit = "10",
        } = req.query;

        const pagination = parsePagination(page, limit);

        if (!pagination) {
            return sendError(
                res,
                400,
                "Invalid pagination parameters."
            );
        }

        const filter = {
            user: userId,
        };

        if (status !== undefined) {
            if (!ALLOWED_STATUSES.includes(status)) {
                return sendError(
                    res,
                    400,
                    "Invalid case status filter."
                );
            }

            filter.status = status;
        }

        if (riskLevel !== undefined) {
            if (!ALLOWED_RISK_LEVELS.includes(riskLevel)) {
                return sendError(
                    res,
                    400,
                    "Invalid risk level filter."
                );
            }

            filter.riskLevel = riskLevel;
        }

        const [cases, total] = await Promise.all([
            Case.find(filter)
                .sort({ createdAt: -1 })
                .skip(pagination.skip)
                .limit(pagination.pageSize)
                .populate(
                    "analysis",
                    "fraudCategory riskScore riskLevel evidenceType summary evidenceId indicators detectedRules analyzedAt"
                )
                .lean(),

            Case.countDocuments(filter),
        ]);

        return res.status(200).json({
            success: true,
            data: cases,
            pagination: {
                total,
                page: pagination.pageNumber,
                limit: pagination.pageSize,
                totalPages: Math.ceil(
                    total / pagination.pageSize
                ),
            },
        });

    } catch (error) {
        return next(error);
    }
};

/* =========================================
   GET SINGLE CASE
   GET /api/cases/:id
========================================= */

const getCaseById = async (req, res, next) => {
    try {
        const userId = getUserId(req);
        const { id } = req.params;

        if (!userId) {
            return sendError(
                res,
                401,
                "Authentication required."
            );
        }

        if (!isValidId(id)) {
            return sendError(
                res,
                400,
                "Invalid case identifier."
            );
        }

        const caseRecord = await Case.findOne({
            _id: id,
            user: userId,
        }).populate(
            "analysis",
            "fraudCategory riskScore riskLevel evidenceType summary indicators detectedRules analyzedAt"
        );

        if (!caseRecord) {
            return sendError(
                res,
                404,
                "Case not found."
            );
        }

        return res.status(200).json({
            success: true,
            data: caseRecord,
        });

    } catch (error) {
        return next(error);
    }
};

/* =========================================
   UPDATE CASE
   PATCH /api/cases/:id
========================================= */

const updateCase = async (req, res, next) => {
    try {
        const userId = getUserId(req);
        const { id } = req.params;

        if (!userId) {
            return sendError(
                res,
                401,
                "Authentication required."
            );
        }

        if (!isValidId(id)) {
            return sendError(
                res,
                400,
                "Invalid case identifier."
            );
        }

        const allowedFields = [
            "title",
            "description",
            "status",
            "priority",
            "resolution",
            "classificationFeedback",
        ];

        const body = req.body || {};
        const updates = {};

        for (const field of allowedFields) {
            if (
                Object.prototype.hasOwnProperty.call(
                    body,
                    field
                )
            ) {
                updates[field] = body[field];
            }
        }

        if (Object.keys(updates).length === 0) {
            return sendError(
                res,
                400,
                "No valid update fields provided."
            );
        }

        // Title validation
        if (updates.title !== undefined) {
            if (
                typeof updates.title !== "string" ||
                updates.title.trim().length < 3 ||
                updates.title.trim().length > 150
            ) {
                return sendError(
                    res,
                    400,
                    "Title must contain between 3 and 150 characters."
                );
            }

            updates.title = updates.title.trim();
        }

        // Description validation
        if (updates.description !== undefined) {
            if (
                typeof updates.description !== "string" ||
                updates.description.length > 5000
            ) {
                return sendError(
                    res,
                    400,
                    "Invalid description."
                );
            }

            updates.description = updates.description.trim();
        }

        // Status validation
        if (
            updates.status !== undefined &&
            !ALLOWED_STATUSES.includes(updates.status)
        ) {
            return sendError(
                res,
                400,
                "Invalid case status."
            );
        }

        // Priority validation
        if (
            updates.priority !== undefined &&
            !ALLOWED_PRIORITIES.includes(updates.priority)
        ) {
            return sendError(
                res,
                400,
                "Invalid case priority."
            );
        }

        // Feedback validation
        if (
            updates.classificationFeedback !== undefined &&
            !ALLOWED_FEEDBACK.includes(
                updates.classificationFeedback
            )
        ) {
            return sendError(
                res,
                400,
                "Invalid classification feedback option."
            );
        }

        // Resolution validation
        if (updates.resolution !== undefined) {
            if (
                typeof updates.resolution !== "string" ||
                updates.resolution.length > 3000
            ) {
                return sendError(
                    res,
                    400,
                    "Invalid resolution."
                );
            }

            updates.resolution = updates.resolution.trim();
        }

        // Manage resolution timestamp
        if (
            updates.status === "resolved" ||
            updates.status === "closed"
        ) {
            updates.resolvedAt = new Date();
        } else if (
            updates.status === "open" ||
            updates.status === "investigating"
        ) {
            updates.resolvedAt = null;
        }

        const updatedCase = await Case.findOneAndUpdate(
            {
                _id: id,
                user: userId,
            },
            {
                $set: updates,
            },
            {
                new: true,
                runValidators: true,
            }
        );

        if (!updatedCase) {
            return sendError(
                res,
                404,
                "Case not found."
            );
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

/* =========================================
   DELETE CASE
   DELETE /api/cases/:id
========================================= */

const deleteCase = async (req, res, next) => {
    try {
        const userId = getUserId(req);
        const { id } = req.params;

        if (!userId) {
            return sendError(
                res,
                401,
                "Authentication required."
            );
        }

        if (!isValidId(id)) {
            return sendError(
                res,
                400,
                "Invalid case identifier."
            );
        }

        const deletedCase = await Case.findOneAndDelete({
            _id: id,
            user: userId,
        });

        if (!deletedCase) {
            return sendError(
                res,
                404,
                "Case not found."
            );
        }

        return res.status(200).json({
            success: true,
            message: "Case deleted successfully.",
        });

    } catch (error) {
        return next(error);
    }
};

/* =========================================
   EXPORT CONTROLLERS
========================================= */

module.exports = {
    createCase,
    getUserCases,
    getCaseById,
    updateCase,
    deleteCase,
};