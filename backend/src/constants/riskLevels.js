"use strict";

// =====================================================
// SCAMSHIELD AI - RISK LEVELS
// Centralized risk classification and scoring
// =====================================================

const RISK_LEVELS = Object.freeze({
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical",
    UNKNOWN: "unknown",
});

// =====================================================
// RISK SCORE CONFIGURATION
// Score range: 0–100
// =====================================================

const RISK_SCORE_RANGES = Object.freeze({
    [RISK_LEVELS.LOW]: Object.freeze({
        min: 0,
        max: 24,
        label: "Low Risk",
        description: "No significant fraud indicators detected.",
        severity: 1,
    }),

    [RISK_LEVELS.MEDIUM]: Object.freeze({
        min: 25,
        max: 49,
        label: "Medium Risk",
        description: "Some suspicious indicators detected. Further verification is recommended.",
        severity: 2,
    }),

    [RISK_LEVELS.HIGH]: Object.freeze({
        min: 50,
        max: 74,
        label: "High Risk",
        description: "Multiple suspicious indicators detected. Avoid interacting until verified.",
        severity: 3,
    }),

    [RISK_LEVELS.CRITICAL]: Object.freeze({
        min: 75,
        max: 100,
        label: "Critical Risk",
        description: "Strong fraud indicators detected. Stop interaction and take protective action.",
        severity: 4,
    }),
});

// =====================================================
// RISK LEVEL VALUES
// =====================================================

const RISK_LEVEL_VALUES = Object.freeze(
    Object.values(RISK_LEVELS)
);

// =====================================================
// HELPER FUNCTIONS
// =====================================================

/**
 * Validate risk level.
 */
const isValidRiskLevel = (level) => {
    return RISK_LEVEL_VALUES.includes(level);
};

/**
 * Get risk level from numeric score.
 */
const getRiskLevelFromScore = (score) => {
    if (
        typeof score !== "number" ||
        !Number.isFinite(score) ||
        score < 0 ||
        score > 100
    ) {
        return RISK_LEVELS.UNKNOWN;
    }

    if (score <= 24) return RISK_LEVELS.LOW;
    if (score <= 49) return RISK_LEVELS.MEDIUM;
    if (score <= 74) return RISK_LEVELS.HIGH;

    return RISK_LEVELS.CRITICAL;
};

/**
 * Get risk level metadata.
 */
const getRiskLevelDetails = (level) => {
    return (
        RISK_SCORE_RANGES[level] || {
            min: null,
            max: null,
            label: "Unknown Risk",
            description: "Risk level could not be determined.",
            severity: 0,
        }
    );
};

/**
 * Get risk details directly from score.
 */
const getRiskDetailsFromScore = (score) => {
    const level = getRiskLevelFromScore(score);

    return {
        score,
        level,
        ...getRiskLevelDetails(level),
    };
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    RISK_LEVELS,
    RISK_SCORE_RANGES,
    RISK_LEVEL_VALUES,
    isValidRiskLevel,
    getRiskLevelFromScore,
    getRiskLevelDetails,
    getRiskDetailsFromScore,
};