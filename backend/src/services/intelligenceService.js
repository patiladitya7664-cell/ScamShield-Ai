
"use strict";

// =====================================================
// SCAMSHIELD AI - INTELLIGENCE SERVICE
// Version: 2.0.0
//
// Responsibilities:
// 1. Normalize indicators.
// 2. Find existing intelligence records.
// 3. Create pending intelligence records.
// 4. Update indicator occurrences.
// 5. Retrieve verified active intelligence.
// 6. Verify or reject intelligence records.
// 7. Deactivate expired records.
//
// IMPORTANT:
// Extracted indicators are UNVERIFIED by default.
// Repeated occurrence does not establish legitimacy.
// Internal analysis does not independently verify threats.
// =====================================================

const mongoose = require("mongoose");

const Intelligence = require("../models/Intelligence");

const {
    FRAUD_CATEGORIES,
} = require("../constants/fraudCategories");

const {
    RISK_LEVELS,
} = require("../constants/riskLevels");

// =====================================================
// 1. CONSTANTS
// =====================================================

const INDICATOR_TYPES = Object.freeze([
    "email",
    "domain",
    "url",
    "phone",
    "upi",
    "ip",
    "account",
    "wallet",
    "keyword",
]);

const INTELLIGENCE_STATUSES = Object.freeze([
    "pending",
    "verified",
    "rejected",
    "expired",
]);

const MAX_INDICATOR_LENGTH = 500;
const MAX_DESCRIPTION_LENGTH = 2000;
const MAX_TAGS = 30;
const MAX_EVIDENCE_ITEMS = 20;


// =====================================================
// 2. ERROR HELPER
// =====================================================

const createError = (message, statusCode = 400) => {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
};


// =====================================================
// 3. VALIDATION HELPERS
// =====================================================

const isPlainObject = (value) => {
    return (
        value !== null &&
        typeof value === "object" &&
        !Array.isArray(value)
    );
};

const validateIdentifier = (value, label) => {
    if (!value || !mongoose.Types.ObjectId.isValid(value)) {
        throw createError(`Valid ${label} is required.`);
    }

    return value;
};

const validateScore = (value, label) => {
    const score = Number(value);

    if (
        !Number.isFinite(score) ||
        score < 0 ||
        score > 100
    ) {
        throw createError(
            `${label} must be between 0 and 100.`
        );
    }

    return score;
};

const validateIndicatorType = (indicatorType) => {
    if (typeof indicatorType !== "string") {
        throw createError("Invalid indicator type.");
    }

    const normalizedType = indicatorType
        .trim()
        .toLowerCase();

    if (!INDICATOR_TYPES.includes(normalizedType)) {
        throw createError("Unsupported indicator type.");
    }

    return normalizedType;
};


// =====================================================
// 4. NORMALIZE INDICATOR
// =====================================================

const normalizeIndicator = (indicator, indicatorType) => {
    if (
        typeof indicator !== "string" ||
        !indicator.trim()
    ) {
        throw createError(
            "Valid intelligence indicator is required."
        );
    }

    const type = validateIndicatorType(indicatorType);

    const value = indicator.trim();

    if (value.length > MAX_INDICATOR_LENGTH) {
        throw createError(
            "Intelligence indicator is too long."
        );
    }

    switch (type) {
        case "email":
        case "domain":
        case "upi":
        case "ip":
        case "account":
        case "wallet":
            return value.toLowerCase();

        case "url": {
            try {
                const parsed = new URL(
                    /^[a-z][a-z0-9+.-]*:\/\//i.test(value)
                        ? value
                        : `https://${value}`
                );

                if (
                    !["http:", "https:"].includes(parsed.protocol) ||
                    !parsed.hostname
                ) {
                    throw new Error("Invalid URL");
                }

                // Do not include credentials or fragments
                // in the normalized intelligence key.
                parsed.username = "";
                parsed.password = "";
                parsed.hash = "";

                return parsed.toString().toLowerCase();
            } catch {
                throw createError(
                    "Invalid URL intelligence indicator."
                );
            }
        }

        case "phone":
            return value.replace(/[\s\-()]/g, "");

        case "keyword":
            return value
                .toLowerCase()
                .replace(/\s+/g, " ")
                .trim();

        default:
            throw createError("Unsupported indicator type.");
    }
};


// =====================================================
// 5. FIND EXISTING INDICATOR
// =====================================================

const findIndicator = async (indicator, indicatorType) => {
    const normalizedType = validateIndicatorType(
        indicatorType
    );

    const normalizedIndicator = normalizeIndicator(
        indicator,
        normalizedType
    );

    return Intelligence.findOne({
        indicatorType: normalizedType,
        normalizedIndicator,
    });
};


// =====================================================
// 6. UPDATE INDICATOR OCCURRENCE
// =====================================================

const updateIndicatorOccurrence = async (intelligence) => {
    if (!intelligence) {
        throw createError(
            "Intelligence record is required."
        );
    }

    // Update only occurrence information.
    // Never change verification status automatically.

    intelligence.occurrenceCount =
        Math.max(
            0,
            Number(intelligence.occurrenceCount) || 0
        ) + 1;

    intelligence.lastSeenAt = new Date();

    return intelligence.save();
};


// =====================================================
// 7. CREATE INTELLIGENCE RECORD
// =====================================================

const createIntelligence = async (data = {}) => {
    if (!isPlainObject(data)) {
        throw createError(
            "Invalid intelligence data."
        );
    }

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
    } = data;

    const normalizedType = validateIndicatorType(
        indicatorType
    );

    const normalizedIndicator = normalizeIndicator(
        indicator,
        normalizedType
    );

    const normalizedRiskScore = validateScore(
        riskScore,
        "Risk score"
    );

    const normalizedConfidenceScore = validateScore(
        confidenceScore,
        "Confidence score"
    );

    if (
        typeof fraudCategory !== "string" ||
        !fraudCategory.trim()
    ) {
        throw createError(
            "Invalid fraud category."
        );
    }

    if (
        typeof riskLevel !== "string" ||
        !riskLevel.trim()
    ) {
        throw createError(
            "Invalid risk level."
        );
    }

    if (
        !Object.values(FRAUD_CATEGORIES).includes(
            fraudCategory
        )
    ) {
        throw createError(
            "Unsupported fraud category."
        );
    }

    if (
        !Object.values(RISK_LEVELS).includes(
            riskLevel
        )
    ) {
        throw createError(
            "Unsupported risk level."
        );
    }

    if (
        !Array.isArray(evidence) ||
        evidence.length > MAX_EVIDENCE_ITEMS
    ) {
        throw createError(
            "Invalid intelligence evidence."
        );
    }

    if (
        !Array.isArray(tags) ||
        tags.length > MAX_TAGS
    ) {
        throw createError(
            "Invalid intelligence tags."
        );
    }

    const normalizedDescription =
        typeof description === "string"
            ? description.trim().slice(
                0,
                MAX_DESCRIPTION_LENGTH
            )
            : "";

    const normalizedTags = tags
        .filter((tag) => typeof tag === "string")
        .map((tag) => tag.trim().toLowerCase())
        .filter(Boolean)
        .slice(0, MAX_TAGS);

    const existing = await Intelligence.findOne({
        indicatorType: normalizedType,
        normalizedIndicator,
    });

    if (existing) {
        return updateIndicatorOccurrence(existing);
    }

    try {
        return await Intelligence.create({
            indicator: indicator.trim(),

            indicatorType: normalizedType,

            normalizedIndicator,

            fraudCategory,

            riskLevel,

            riskScore: normalizedRiskScore,

            confidenceScore: normalizedConfidenceScore,

            source:
                typeof source === "string"
                    ? source.trim().slice(0, 100)
                    : "internal",

            sourceType:
                typeof sourceType === "string"
                    ? sourceType.trim().slice(0, 100)
                    : "internal_analysis",

            sourceReference,

            description: normalizedDescription,

            evidence,

            tags: normalizedTags,

            reportedBy,

            relatedAnalysis,

            // Internal extraction is never verification.
            status: "pending",

            isActive: false,

            verifiedBy: null,

            verifiedAt: null,

            firstSeenAt: new Date(),

            lastSeenAt: new Date(),

            occurrenceCount: 1,
        });

    } catch (error) {
        // Handle a concurrent duplicate insert only
        // when the database reports a duplicate key.
        if (error.code === 11000) {
            const existingRecord = await Intelligence.findOne({
                indicatorType: normalizedType,
                normalizedIndicator,
            });

            if (existingRecord) {
                return updateIndicatorOccurrence(
                    existingRecord
                );
            }
        }

        throw error;
    }
};


// =====================================================
// 8. PROCESS ANALYSIS INDICATORS
// =====================================================

const processAnalysisIndicators = async (
    indicators,
    analysisData = {}
) => {
    if (!Array.isArray(indicators)) {
        throw createError(
            "Indicators must be an array."
        );
    }

    if (indicators.length > 50) {
        throw createError(
            "Too many indicators were supplied."
        );
    }

    const results = [];

    for (const item of indicators) {
        if (
            !isPlainObject(item) ||
            typeof item.value !== "string" ||
            !item.value.trim() ||
            typeof item.type !== "string"
        ) {
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

            riskScore:
                analysisData.riskScore ?? 0,

            // Confidence is not independent verification.
            confidenceScore:
                item.confidence ?? 0,

            source: "ScamShield AI",

            sourceType: "internal_analysis",

            sourceReference:
                analysisData.evidenceId || null,

            description:
                item.description ||
                "Indicator extracted during automated analysis. Verification is pending.",

            reportedBy:
                analysisData.userId || null,

            relatedAnalysis:
                analysisData.analysisId || null,
        });

        results.push(result);
    }

    return results;
};


// =====================================================
// 9. GET VERIFIED ACTIVE INTELLIGENCE
// =====================================================

const getActiveIntelligence = async (filters = {}) => {
    if (!isPlainObject(filters)) {
        throw createError(
            "Invalid intelligence filters."
        );
    }

    const query = {
        status: "verified",
        isActive: true,
    };

    if (filters.indicatorType) {
        query.indicatorType = validateIndicatorType(
            filters.indicatorType
        );
    }

    if (filters.fraudCategory) {
        if (
            !Object.values(FRAUD_CATEGORIES).includes(
                filters.fraudCategory
            )
        ) {
            throw createError(
                "Invalid fraud category filter."
            );
        }

        query.fraudCategory = filters.fraudCategory;
    }

    if (filters.riskLevel) {
        if (
            !Object.values(RISK_LEVELS).includes(
                filters.riskLevel
            )
        ) {
            throw createError(
                "Invalid risk level filter."
            );
        }

        query.riskLevel = filters.riskLevel;
    }

    return Intelligence.findActiveIndicators(query);
};


// =====================================================
// 10. GET INTELLIGENCE BY ID
// =====================================================

const getIntelligenceById = async (id) => {
    validateIdentifier(id, "intelligence ID");

    const intelligence = await Intelligence.findById(id);

    if (!intelligence) {
        throw createError(
            "Intelligence record not found.",
            404
        );
    }

    return intelligence;
};


// =====================================================
// 11. VERIFY INTELLIGENCE
// =====================================================

const verifyIntelligence = async (id, userId) => {
    validateIdentifier(userId, "verifier user ID");

    const intelligence = await getIntelligenceById(id);

    if (intelligence.status === "rejected") {
        throw createError(
            "Rejected intelligence cannot be verified."
        );
    }

    if (intelligence.status === "expired") {
        throw createError(
            "Expired intelligence cannot be verified."
        );
    }

    intelligence.status = "verified";

    intelligence.verifiedBy = userId;

    intelligence.verifiedAt = new Date();

    intelligence.isActive = true;

    return intelligence.save();
};


// =====================================================
// 12. REJECT INTELLIGENCE
// =====================================================

const rejectIntelligence = async (id, userId) => {
    validateIdentifier(userId, "reviewer user ID");

    const intelligence = await getIntelligenceById(id);

    if (intelligence.status === "expired") {
        throw createError(
            "Expired intelligence cannot be rejected."
        );
    }

    intelligence.status = "rejected";

    intelligence.verifiedBy = userId;

    intelligence.verifiedAt = new Date();

    intelligence.isActive = false;

    return intelligence.save();
};


// =====================================================
// 13. DEACTIVATE EXPIRED INTELLIGENCE
// =====================================================

const deactivateExpiredIntelligence = async () => {
    return Intelligence.updateMany(
        {
            isActive: true,

            status: "verified",

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
// 14. EXPORTS
// =====================================================

module.exports = {
    INDICATOR_TYPES,

    INTELLIGENCE_STATUSES,

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
