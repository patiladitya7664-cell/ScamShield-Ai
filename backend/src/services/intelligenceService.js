"use strict";

// =====================================================
// SCAMSHIELD AI - INTELLIGENCE SERVICE
// Threat Intelligence Management
//
// Responsibilities:
// 1. Normalize suspicious indicators.
// 2. Search existing intelligence records.
// 3. Create intelligence records.
// 4. Update indicator occurrence information.
// 5. Retrieve verified active threats.
// 6. Verify and reject intelligence records.
//
// No duplicate AI detection logic.
// =====================================================

const Intelligence = require("../models/Intelligence");

const {
    FRAUD_CATEGORIES,
} = require("../constants/fraudCategories");

const {
    RISK_LEVELS,
} = require("../constants/riskLevels");

// =====================================================
// 1. NORMALIZE INDICATOR
// =====================================================

const normalizeIndicator = (indicator, indicatorType) => {
    if (typeof indicator !== "string" || !indicator.trim()) {
        throw new Error("Valid intelligence indicator is required.");
    }

    const value = indicator.trim();

    switch (indicatorType) {
        case "email":
        case "domain":
        case "url":
            return value.toLowerCase();

        case "phone":
            return value.replace(/[\s\-()]/g, "");

        case "upi":
            return value.toLowerCase();

        case "ip":
        case "account":
        case "wallet":
            return value.toLowerCase();

        case "keyword":
            return value.toLowerCase().replace(/\s+/g, " ");

        default:
            return value.toLowerCase();
    }
};

// =====================================================
// 2. FIND EXISTING INDICATOR
// =====================================================

const findIndicator = async (indicator, indicatorType) => {
    const normalizedIndicator = normalizeIndicator(
        indicator,
        indicatorType
    );

    return Intelligence.findOne({
        indicatorType,
        normalizedIndicator,
    });
};

// =====================================================
// 3. CREATE INTELLIGENCE RECORD
// =====================================================

const createIntelligence = async (data) => {
    const {
        indicator,
        indicatorType,
        fraudCategory = FRAUD_CATEGORIES.UNKNOWN,
        riskLevel = RISK_LEVELS.UNKNOWN,
        riskScore = 0,
        confidenceScore = 0,
        source = "internal",
        sourceType = "internal_analysis",
        sourceReference = null,
        description = "",
        evidence = [],
        tags = [],
        reportedBy = null,
        relatedAnalysis = null,
    } = data || {};

    if (!indicator || !indicatorType) {
        throw new Error(
            "Indicator and indicator type are required."
        );
    }

    const normalizedIndicator = normalizeIndicator(
        indicator,
        indicatorType
    );

    const existing = await Intelligence.findOne({
        indicatorType,
        normalizedIndicator,
    });

    if (existing) {
        return updateIndicatorOccurrence(existing);
    }

    const intelligence = await Intelligence.create({
        indicator: indicator.trim(),
        indicatorType,
        normalizedIndicator,

        fraudCategory,
        riskLevel,
        riskScore,
        confidenceScore,

        source,
        sourceType,
        sourceReference,

        description,
        evidence,
        tags,

        reportedBy,
        relatedAnalysis,

        status: "pending",
        isActive: true,

        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        occurrenceCount: 1,
    });

    return intelligence;
};

// =====================================================
// 4. UPDATE INDICATOR OCCURRENCE
// =====================================================

const updateIndicatorOccurrence = async (intelligence) => {
    intelligence.occurrenceCount =
        (intelligence.occurrenceCount || 0) + 1;

    intelligence.lastSeenAt = new Date();

    return intelligence.save();
};

// =====================================================
// 5. PROCESS ANALYSIS INDICATORS
// =====================================================

const processAnalysisIndicators = async (
    indicators,
    analysisData = {}
) => {
    if (!Array.isArray(indicators)) {
        throw new Error("Indicators must be an array.");
    }

    const results = [];

    for (const item of indicators) {
        if (!item || !item.value || !item.type) {
            continue;
        }

        const result = await createIntelligence({
            indicator: item.value,
            indicatorType: item.type,

            fraudCategory:
                analysisData.fraudCategory ||
                FRAUD_CATEGORIES.UNKNOWN,

            riskLevel:
                analysisData.riskLevel ||
                RISK_LEVELS.UNKNOWN,

            riskScore: analysisData.riskScore || 0,

            confidenceScore: item.confidence || 0,

            source: "ScamShield AI",

            sourceType: "internal_analysis",

            sourceReference: analysisData.evidenceId || null,

            description:
                item.description ||
                "Indicator extracted during fraud analysis.",

            reportedBy: analysisData.userId || null,

            relatedAnalysis: analysisData.analysisId || null,
        });

        results.push(result);
    }

    return results;
};

// =====================================================
// 6. GET VERIFIED ACTIVE INTELLIGENCE
// =====================================================

const getActiveIntelligence = async (filters = {}) => {
    const query = {};

    if (filters.indicatorType) {
        query.indicatorType = filters.indicatorType;
    }

    if (filters.fraudCategory) {
        query.fraudCategory = filters.fraudCategory;
    }

    if (filters.riskLevel) {
        query.riskLevel = filters.riskLevel;
    }

    return Intelligence.findActiveIndicators(query);
};

// =====================================================
// 7. GET INTELLIGENCE BY ID
// =====================================================

const getIntelligenceById = async (id) => {
    if (!id) {
        throw new Error("Intelligence ID is required.");
    }

    const intelligence = await Intelligence.findById(id);

    if (!intelligence) {
        const error = new Error("Intelligence record not found.");
        error.statusCode = 404;
        throw error;
    }

    return intelligence;
};

// =====================================================
// 8. VERIFY INTELLIGENCE
// =====================================================

const verifyIntelligence = async (id, userId) => {
    if (!userId) {
        throw new Error("Verifier user ID is required.");
    }

    const intelligence = await getIntelligenceById(id);

    intelligence.status = "verified";
    intelligence.verifiedBy = userId;
    intelligence.verifiedAt = new Date();
    intelligence.isActive = true;

    return intelligence.save();
};

// =====================================================
// 9. REJECT INTELLIGENCE
// =====================================================

const rejectIntelligence = async (id, userId) => {
    const intelligence = await getIntelligenceById(id);

    intelligence.status = "rejected";
    intelligence.verifiedBy = userId;
    intelligence.verifiedAt = new Date();
    intelligence.isActive = false;

    return intelligence.save();
};

// =====================================================
// 10. DEACTIVATE EXPIRED INTELLIGENCE
// =====================================================

const deactivateExpiredIntelligence = async () => {
    return Intelligence.updateMany(
        {
            isActive: true,
            expiresAt: {
                $ne: null,
                $lte: new Date(),
            },
        },
        {
            $set: {
                isActive: false,
                status: "expired",
            },
        }
    );
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    normalizeIndicator,
    findIndicator,
    createIntelligence,
    updateIndicatorOccurrence,
    processAnalysisIndicators,
    getActiveIntelligence,
    getIntelligenceById,
    verifyIntelligence,
    rejectIntelligence,
    deactivateExpiredIntelligence,
};