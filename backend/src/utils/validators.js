"use strict";

// =====================================================
// SCAMSHIELD AI - VALIDATION UTILITIES
// Common Request Data Validators
// =====================================================

const mongoose = require("mongoose");

// =====================================================
// 1. CHECK EMPTY VALUE
// =====================================================

const isRequired = (value) => {
    if (value === undefined || value === null) {
        return false;
    }

    if (typeof value === "string" && !value.trim()) {
        return false;
    }

    return true;
};

// =====================================================
// 2. VALIDATE EMAIL
// =====================================================

const isValidEmail = (email) => {
    if (typeof email !== "string") {
        return false;
    }

    const normalizedEmail = email.trim();

    if (normalizedEmail.length > 254) {
        return false;
    }

    const emailRegex =
        /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

    return emailRegex.test(normalizedEmail);
};

// =====================================================
// 3. VALIDATE PASSWORD
// =====================================================

const isValidPassword = (password) => {
    if (typeof password !== "string") {
        return false;
    }

    return (
        password.length >= 8 &&
        password.length <= 128 &&
        /[A-Za-z]/.test(password) &&
        /[0-9]/.test(password)
    );
};

// =====================================================
// 4. VALIDATE MONGODB OBJECT ID
// =====================================================

const isValidObjectId = (id) => {
    if (typeof id !== "string") {
        return false;
    }

    return mongoose.Types.ObjectId.isValid(id);
};

// =====================================================
// 5. VALIDATE PHONE NUMBER
// =====================================================

const isValidPhone = (phone) => {
    if (typeof phone !== "string") {
        return false;
    }

    const normalizedPhone = phone.replace(/[\s()-]/g, "");

    return /^\+?[0-9]{10,15}$/.test(normalizedPhone);
};

// =====================================================
// 6. VALIDATE URL
// =====================================================

const isValidUrl = (value) => {
    if (typeof value !== "string") {
        return false;
    }

    try {
        const parsedUrl = new URL(value);

        return (
            parsedUrl.protocol === "http:" ||
            parsedUrl.protocol === "https:"
        );
    } catch {
        return false;
    }
};

// =====================================================
// 7. VALIDATE EVIDENCE
// =====================================================

const isValidEvidence = (evidence) => {
    if (typeof evidence !== "string") {
        return false;
    }

    const normalizedEvidence = evidence.trim();

    return (
        normalizedEvidence.length >= 1 &&
        normalizedEvidence.length <= 20000
    );
};

// =====================================================
// 8. VALIDATE EVIDENCE TYPE
// =====================================================

const SUPPORTED_EVIDENCE_TYPES = Object.freeze([
    "message",
    "url",
    "phone",
    "call",
    "transaction",
    "upi",
    "email",
    "screenshot",
]);

const isValidEvidenceType = (evidenceType) => {
    if (typeof evidenceType !== "string") {
        return false;
    }

    return SUPPORTED_EVIDENCE_TYPES.includes(
        evidenceType.trim().toLowerCase()
    );
};

// =====================================================
// 9. VALIDATE PAGINATION
// =====================================================

const validatePagination = (page, limit) => {
    const parsedPage = Number(page) || 1;
    const parsedLimit = Number(limit) || 20;

    return {
        page: Math.max(1, Math.floor(parsedPage)),
        limit: Math.min(
            100,
            Math.max(1, Math.floor(parsedLimit))
        ),
    };
};

// =====================================================
// 10. VALIDATE RISK SCORE
// =====================================================

const isValidRiskScore = (score) => {
    return (
        typeof score === "number" &&
        Number.isFinite(score) &&
        score >= 0 &&
        score <= 100
    );
};

// =====================================================
// 11. VALIDATE ARRAY
// =====================================================

const isValidArray = (value) => {
    return Array.isArray(value);
};

// =====================================================
// 12. VALIDATE ENUM VALUE
// =====================================================

const isValidEnumValue = (value, allowedValues) => {
    if (
        typeof value !== "string" ||
        !Array.isArray(allowedValues)
    ) {
        return false;
    }

    return allowedValues.includes(value.trim());
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    isRequired,
    isValidEmail,
    isValidPassword,
    isValidObjectId,
    isValidPhone,
    isValidUrl,
    isValidEvidence,
    isValidEvidenceType,
    validatePagination,
    isValidRiskScore,
    isValidArray,
    isValidEnumValue,
    SUPPORTED_EVIDENCE_TYPES,
};