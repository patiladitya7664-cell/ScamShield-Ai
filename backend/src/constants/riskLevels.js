"use strict";

// =====================================================
// SCAMSHIELD AI - RISK LEVELS
// Version: 2.0.0
//
// Centralized risk classification.
// Synchronized with Python RiskScorer.
//
// LOW      : 0–24
// MEDIUM   : 25–49
// HIGH     : 50–74
// CRITICAL : 75–100
// =====================================================

// =====================================================
// 1. CANONICAL RISK LEVELS
// =====================================================

const RISK_LEVELS = Object.freeze({
    LOW: "low",
    MEDIUM: "medium",
    HIGH: "high",
    CRITICAL: "critical",
});

// =====================================================
// 2. RISK SCORE CONFIGURATION
// =====================================================

const RISK_SCORE_RANGES = Object.freeze({
    [RISK_LEVELS.LOW]: Object.freeze({
        min: 0,
        max: 24,
        label: "Low Risk",
        description:
            "No significant fraud indicators detected.",
        severity: 1,
    }),

    [RISK_LEVELS.MEDIUM]: Object.freeze({
        min: 25,
        max: 49,
        label: "Medium Risk",
        description:
            "Some suspicious indicators detected. Further verification is recommended.",
        severity: 2,
    }),

    [RISK_LEVELS.HIGH]: Object.freeze({
        min: 50,
        max: 74,
        label: "High Risk",
        description:
            "Multiple suspicious indicators detected. Avoid interacting until verified.",
        severity: 3,
    }),

    [RISK_LEVELS.CRITICAL]: Object.freeze({
        min: 75,
        max: 100,
        label: "Critical Risk",
        description:
            "Strong fraud indicators detected. Stop interaction and take protective action.",
        severity: 4,
    }),
});

// =====================================================
// 3. CANONICAL RISK LEVEL VALUES
// =====================================================

const RISK_LEVEL_VALUES = Object.freeze(
    Object.values(RISK_LEVELS)
);

// =====================================================
// 4. VALIDATE RISK LEVEL
// =====================================================

const isValidRiskLevel = (level) => {
    return RISK_LEVEL_VALUES.includes(level);
};

// =====================================================
// 5. VALIDATE RISK SCORE
// =====================================================

const isValidRiskScore = (score) => {
    return (
        typeof score === "number" &&
        Number.isFinite(score) &&
        Number.isInteger(score) &&
        score >= 0 &&
        score <= 100
    );
};

// =====================================================
// 6. GET RISK LEVEL FROM SCORE
// =====================================================

const getRiskLevelFromScore = (score) => {
    if (!isValidRiskScore(score)) {
        return null;
    }

    if (score <= 24) return RISK_LEVELS.LOW;
    if (score <= 49) return RISK_LEVELS.MEDIUM;
    if (score <= 74) return RISK_LEVELS.HIGH;

    return RISK_LEVELS.CRITICAL;
};

// =====================================================
// 7. GET RISK LEVEL METADATA
// =====================================================

const getRiskLevelDetails = (level) => {
    return (
        RISK_SCORE_RANGES[level] || {
            min: null,
            max: null,
            label: "Unknown Risk",
            description:
                "Risk level could not be determined.",
            severity: 0,
        }
    );
};

// =====================================================
// 8. GET RISK DETAILS FROM SCORE
// =====================================================

const getRiskDetailsFromScore = (score) => {
    const level = getRiskLevelFromScore(score);

    if (level === null) {
        return {
            score: null,
            level: null,
            ...getRiskLevelDetails(null),
        };
    }

    return {
        score,
        level,
        ...getRiskLevelDetails(level),
    };
};

// =====================================================
// 9. EXPORTS
// =====================================================

module.exports = {
    RISK_LEVELS,
    RISK_SCORE_RANGES,
    RISK_LEVEL_VALUES,

    isValidRiskLevel,
    isValidRiskScore,

    getRiskLevelFromScore,
    getRiskLevelDetails,
    getRiskDetailsFromScore,
};