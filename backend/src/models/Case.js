"use strict";

const mongoose = require("mongoose");

const caseSchema = new mongoose.Schema(
  {
    // User who created the case
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    // Optional linked evidence analysis
    analysis: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Analysis",
      default: null,
    },

    title: {
      type: String,
      required: [true, "Case title is required."],
      trim: true,
      minlength: 3,
      maxlength: 150,
    },

    description: {
      type: String,
      trim: true,
      maxlength: 5000,
      default: "",
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

    riskLevel: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "medium",
    },

    status: {
      type: String,
      enum: ["open", "investigating", "resolved", "closed"],
      default: "open",
    },

    classificationFeedback: {
      type: String,
      enum: [
        "none",
        "needs_review",
        "possible_false_positive",
        "category_correction_requested",
      ],
      default: "none",
    },

    priority: {
      type: String,
      enum: ["low", "medium", "high", "urgent"],
      default: "medium",
    },

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

    resolution: {
      type: String,
      trim: true,
      maxlength: 3000,
      default: "",
    },

    resolvedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
  },
);

// Useful query indexes
caseSchema.index({ user: 1, createdAt: -1 });
caseSchema.index({ user: 1, status: 1 });
caseSchema.index({ user: 1, riskLevel: 1 });

module.exports = mongoose.model("Case", caseSchema);
