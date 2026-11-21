"use strict";

const mongoose = require("mongoose");

// ================================================
// CONSTANTS
// ================================================

const FRAUD_MODULES = [
    "investment",
    "digitalArrest",
    "creditCard",
    "sextortion",
    "ecommerce",
    "other",
    "unclassified",
];

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

const EVIDENCE_TYPES = [
    "message",
    "url",
    "call",
    "transaction",
    "screenshot",
    "email",
];

const RISK_LEVELS = [
    "low",
    "medium",
    "high",
    "critical",
];

const ANALYSIS_STATUSES = [
    "pending",
    "processing",
    "completed",
    "failed",
];

// ================================================
// AGENT RESULTS SCHEMA
// ================================================

const agentsSchema = new mongoose.Schema(
    {
        guardian: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },

        intelligence: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },

        victimSafety: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },

        decoy: {
            type: mongoose.Schema.Types.Mixed,
            default: null,
        },
    },
    {
        _id: false,
    }
);

// ================================================
// INDICATOR SCHEMA
// ================================================

const indicatorSchema = new mongoose.Schema(
    {
        type: {
            type: String,
            trim: true,
            maxlength: 30,
            default: "unknown",
        },

        value: {
            type: String,
            trim: true,
            maxlength: 500,
            default: "",
        },

        verified: {
            type: Boolean,
            default: false,
        },
    },
    {
        _id: false,
    }
);

// ================================================
// DETECTED RULE SCHEMA
// ================================================

const detectedRuleSchema = new mongoose.Schema(
    {
        category: {
            type: String,
            trim: true,
            maxlength: 50,
            default: "unclassified",
        },

        label: {
            type: String,
            trim: true,
            maxlength: 200,
            default: "",
        },

        weight: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },
    },
    {
        _id: false,
    }
);

// ================================================
// ANALYSIS SCHEMA
// ================================================

const analysisSchema = new mongoose.Schema(
    {
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: "User",
            required: true,
        },

        evidenceId: {
            type: String,
            unique: true,
            required: true,
            trim: true,
            maxlength: 100,
        },

        evidenceType: {
            type: String,
            enum: EVIDENCE_TYPES,
            required: true,
        },

        // Major fraud detection module

        fraudCategory: {
            type: String,
            enum: FRAUD_MODULES,
            default: "unclassified",
        },

        // Individual fraud detection category

        detectionCategory: {
            type: String,
            enum: [
                ...DETECTION_CATEGORIES,
                null,
            ],
            default: null,
        },

        // Risk assessment

        riskScore: {
            type: Number,
            min: 0,
            max: 100,
            default: 0,
        },

        riskLevel: {
            type: String,
            enum: RISK_LEVELS,
            default: "low",
        },

        // Analysis status

        status: {
            type: String,
            enum: ANALYSIS_STATUSES,
            default: "pending",
        },

        // Analysis summary

        summary: {
            type: String,
            trim: true,
            maxlength: 2000,
            default: "",
        },

        // Intelligence indicators

        indicators: {
            type: [indicatorSchema],
            default: [],
            validate: {
                validator: (value) => value.length <= 50,
                message: "Maximum 50 indicators are allowed.",
            },
        },

        // Detection rules

        detectedRules: {
            type: [detectedRuleSchema],
            default: [],
            validate: {
                validator: (value) => value.length <= 100,
                message: "Maximum 100 detected rules are allowed.",
            },
        },

        // Four AI agents

        agents: {
            type: agentsSchema,
            default: undefined,
        },

        // Analysis timestamp

        analyzedAt: {
            type: Date,
            default: null,
        },
    },
    {
        timestamps: true,
        versionKey: false,
        strict: true,
    }
);

// ================================================
// DATABASE INDEXES
// ================================================

analysisSchema.index(
    { user: 1, createdAt: -1 },
    { name: "user_analysis_history" }
);

analysisSchema.index(
    { user: 1, status: 1 },
    { name: "user_analysis_status" }
);

analysisSchema.index(
    { user: 1, riskLevel: 1 },
    { name: "user_analysis_risk" }
);

analysisSchema.index(
    { user: 1, fraudCategory: 1 },
    { name: "user_fraud_module" }
);

analysisSchema.index(
    { user: 1, detectionCategory: 1 },
    { name: "user_detection_category" }
);

// ================================================
// EXPORT MODEL
// ================================================

const Analysis = mongoose.model(
    "Analysis",
    analysisSchema
);

module.exports = Analysis;

// Export constants for reuse and testing

module.exports.FRAUD_MODULES = FRAUD_MODULES;
module.exports.DETECTION_CATEGORIES = DETECTION_CATEGORIES;
module.exports.EVIDENCE_TYPES = EVIDENCE_TYPES;
module.exports.RISK_LEVELS = RISK_LEVELS;
module.exports.ANALYSIS_STATUSES = ANALYSIS_STATUSES;