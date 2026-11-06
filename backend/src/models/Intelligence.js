"use strict";

// =====================================================
// SCAMSHIELD AI - INTELLIGENCE MODEL
// Stores threat intelligence and suspicious indicators
// =====================================================

const mongoose = require("mongoose");

const { FRAUD_CATEGORIES } = require("../constants/fraudCategories");
const { RISK_LEVELS } = require("../constants/riskLevels");

// =====================================================
// INTELLIGENCE SCHEMA
// =====================================================

const intelligenceSchema = new mongoose.Schema(
    {
        // -------------------------------------------------
        // INDICATOR INFORMATION
        // -------------------------------------------------

        indicator: {
            type: String,
            required: [true, "Intelligence indicator is required"],
            trim: true,
            maxlength: 2048,
        },

        indicatorType: {
            type: String,
            required: [true, "Indicator type is required"],
            enum: [
                "phone",
                "email",
                "url",
                "upi",
                "ip",
                "domain",
                "account",
                "keyword",
                "wallet",
                "other",
            ],
            lowercase: true,
            trim: true,
        },

        normalizedIndicator: {
            type: String,
            trim: true,
            lowercase: true,
            index: true,
        },

        // -------------------------------------------------
        // THREAT CLASSIFICATION
        // -------------------------------------------------

        fraudCategory: {
            type: String,
            enum: Object.values(FRAUD_CATEGORIES),
            default: FRAUD_CATEGORIES.UNKNOWN,
            lowercase: true,
        },

        riskLevel: {
            type: String,
            enum: Object.values(RISK_LEVELS),
            default: RISK_LEVELS.UNKNOWN,
            lowercase: true,
        },

        riskScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },

        confidenceScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },

        // -------------------------------------------------
        // INTELLIGENCE SOURCE
        // -------------------------------------------------

        source: {
            type: String,
            trim: true,
            default: "internal",
            maxlength: 200,
        },

        sourceType: {
            type: String,
            enum: [
                "internal_analysis",
                "user_report",
                "external_feed",
                "manual_entry",
                "ai_detection",
                "other",
            ],
            default: "internal_analysis",
        },

        sourceReference: {
            type: String,
            trim: true,
            default: null,
        },

        // -------------------------------------------------
        // DESCRIPTION AND EVIDENCE
        // -------------------------------------------------

        description: {
            type: String,
            trim: true,
            maxlength: 3000,
            default: "",
        },

        evidence: [
            {
                type: String,
                trim: true,
                maxlength: 1000,
            },
        ],

        tags: [
            {
                type: String,
                trim: true,
                lowercase: true,
                maxlength: 50,
            },
        ],

        // -------------------------------------------------
        // VERIFICATION STATUS
        // -------------------------------------------------

        status: {
            type: String,
            enum: [
                "pending",
                "verified",
                "rejected",
                "expired",
                "under_review",
            ],
            default: "pending",
            index: true,
        },

        isActive: {
            type: Boolean,
            default: true,
            index: true,
        },

        verifiedAt: {
            type: Date,
            default: null,
        },

        expiresAt: {
            type: Date,
            default: null,
            index: true,
        },

        // -------------------------------------------------
        // RELATIONSHIPS
        // -------------------------------------------------

        reportedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null,
        },

        verifiedBy: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            default: null,
        },

        relatedAnalysis: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "Analysis",
            default: null,
        },

        // -------------------------------------------------
        // TRACKING
        // -------------------------------------------------

        lastSeenAt: {
            type: Date,
            default: Date.now,
        },

        firstSeenAt: {
            type: Date,
            default: Date.now,
        },

        occurrenceCount: {
            type: Number,
            default: 1,
            min: 0,
        },
    },
    {
        timestamps: true,
        versionKey: false,
    }
);

// =====================================================
// INDEXES
// =====================================================

intelligenceSchema.index({
    indicatorType: 1,
    normalizedIndicator: 1,
});

intelligenceSchema.index({
    riskLevel: 1,
    status: 1,
});

intelligenceSchema.index({
    fraudCategory: 1,
    createdAt: -1,
});

intelligenceSchema.index({
    isActive: 1,
    expiresAt: 1,
});

// =====================================================
// INSTANCE METHODS
// =====================================================

intelligenceSchema.methods.markVerified = function (userId) {
    this.status = "verified";
    this.verifiedBy = userId;
    this.verifiedAt = new Date();

    return this.save();
};

// =====================================================
// STATIC METHODS
// =====================================================

intelligenceSchema.statics.findActiveIndicators = function (filters = {}) {
    return this.find({
        ...filters,
        isActive: true,
        status: "verified",
        $or: [
            { expiresAt: null },
            { expiresAt: { $gt: new Date() } },
        ],
    }).sort({ riskScore: -1, lastSeenAt: -1 });
};

// =====================================================
// EXPORT MODEL
// =====================================================

module.exports = mongoose.model(
    "Intelligence",
    intelligenceSchema
);