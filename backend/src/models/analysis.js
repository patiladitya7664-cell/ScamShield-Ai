"use strict";

const mongoose = require("mongoose");

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
  },
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
      index: true,
    },

    evidenceId: {
      type: String,
      unique: true,
      required: true,
      trim: true,
    },

    evidenceType: {
      type: String,
      enum: ["message", "url", "call", "transaction", "screenshot", "email"],
      required: true,
    },

    fraudCategory: {
      type: String,
      enum: [
        "investment",
        "digitalArrest",
        "creditCard",
        "sextortion",
        "ecommerce",
        "other",
        "unclassified",
      ],
      default: "unclassified",
    },

    riskScore: {
      type: Number,
      min: 0,
      max: 100,
      default: 0,
    },

    riskLevel: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "low",
    },

    status: {
      type: String,
      enum: ["pending", "processing", "completed", "failed"],
      default: "pending",
    },

    summary: {
      type: String,
      maxlength: 2000,
      default: "",
    },

    // Extracted clues remain explicitly unverified.
    indicators: [
      {
        type: {
          type: String,
          trim: true,
        },

        value: {
          type: String,
          trim: true,
        },

        verified: {
          type: Boolean,
          default: false,
        },
      },
    ],

    detectedRules: [
      {
        category: String,
        label: String,
        weight: Number,
      },
    ],

    // ============================================
    // FOUR AI AGENTS RESULTS
    // ============================================

    agents: {
      type: agentsSchema,
      default: undefined,
    },

    analyzedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

// ================================================
// DASHBOARD QUERY OPTIMIZATION
// ================================================

analysisSchema.index({
  user: 1,
  createdAt: -1,
});

analysisSchema.index({
  user: 1,
  riskLevel: 1,
});

analysisSchema.index({
  user: 1,
  fraudCategory: 1,
});

// ================================================
// EXPORT MODEL
// ================================================

module.exports = mongoose.model("Analysis", analysisSchema);
