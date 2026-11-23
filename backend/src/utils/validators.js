
"use strict";

// =====================================================
// SCAMSHIELD AI - VALIDATION UTILITIES
// Version: 2.0.0
//
// Responsibilities:
// 1. Required field validation.
// 2. Email validation.
// 3. Password validation.
// 4. MongoDB ObjectId validation.
// 5. Phone number validation.
// 6. URL validation.
// 7. Evidence validation.
// 8. Evidence type validation.
// 9. Pagination validation.
// 10. Risk score validation.
// 11. Array validation.
// 12. Enum validation.
//
// IMPORTANT:
// Phone and UPI are intelligence indicator types,
// not supported evidence types.
// =====================================================

const mongoose = require("mongoose");


// =====================================================
// 1. CONSTANTS
// =====================================================

const MAX_EVIDENCE_LENGTH = 20000;

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;

const SUPPORTED_EVIDENCE_TYPES = Object.freeze([
    "message",
    "url",
    "call",
    "transaction",
    "screenshot",
    "email",
]);


// =====================================================
// 2. CHECK REQUIRED VALUE
// =====================================================

const isRequired = (value) => {
    if (
        value === undefined ||
        value === null
    ) {
        return false;
    }

    if (typeof value === "string") {
        return value.trim().length > 0;
    }

    if (Array.isArray(value)) {
        return value.length > 0;
    }

    return true;
};


// =====================================================
// 3. VALIDATE EMAIL
// =====================================================

const isValidEmail = (email) => {
    if (
        typeof email !== "string" ||
        !email.trim()
    ) {
        return false;
    }

    const normalizedEmail = email.trim();

    if (
        normalizedEmail.length > 254 ||
        /\s/.test(normalizedEmail)
    ) {
        return false;
    }

    const emailRegex =
        /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

    if (!emailRegex.test(normalizedEmail)) {
        return false;
    }

    const [localPart, domain] =
        normalizedEmail.split("@");

    if (
        !localPart ||
        localPart.length > 64 ||
        !domain ||
        domain.length > 253
    ) {
        return false;
    }

    return true;
};


// =====================================================
// 4. VALIDATE PASSWORD
// =====================================================

const isValidPassword = (password) => {
    if (typeof password !== "string") {
        return false;
    }

    return (
        password.length >= MIN_PASSWORD_LENGTH &&
        password.length <= MAX_PASSWORD_LENGTH &&
        /[A-Za-z]/.test(password) &&
        /[0-9]/.test(password)
    );
};


// =====================================================
// 5. VALIDATE MONGODB OBJECT ID
// =====================================================

const isValidObjectId = (id) => {
    if (typeof id !== "string") {
        return false;
    }

    const normalizedId = id.trim();

    if (!/^[a-fA-F0-9]{24}$/.test(normalizedId)) {
        return false;
    }

    return mongoose.isValidObjectId(normalizedId);
};


// =====================================================
// 6. VALIDATE PHONE NUMBER
// =====================================================

const isValidPhone = (phone) => {
    if (
        typeof phone !== "string" ||
        !phone.trim()
    ) {
        return false;
    }

    const normalizedPhone = phone.replace(
        /[\s()-]/g,
        ""
    );

    return /^\+?[0-9]{10,15}$/.test(
        normalizedPhone
    );
};


// =====================================================
// 7. VALIDATE URL
// =====================================================

const isValidUrl = (value) => {
    if (
        typeof value !== "string" ||
        !value.trim() ||
        value.length > 2048
    ) {
        return false;
    }

    try {
        const parsedUrl = new URL(value.trim());

        return (
            ["http:", "https:"].includes(
                parsedUrl.protocol
            ) &&
            Boolean(parsedUrl.hostname) &&
            !parsedUrl.username &&
            !parsedUrl.password
        );
    } catch {
        return false;
    }
};


// =====================================================
// 8. VALIDATE EVIDENCE
// =====================================================

const isValidEvidence = (evidence) => {
    if (typeof evidence !== "string") {
        return false;
    }

    const normalizedEvidence = evidence.trim();

    return (
        normalizedEvidence.length >= 1 &&
        normalizedEvidence.length <= MAX_EVIDENCE_LENGTH
    );
};


// =====================================================
// 9. VALIDATE EVIDENCE TYPE
// =====================================================

const isValidEvidenceType = (evidenceType) => {
    if (typeof evidenceType !== "string") {
        return false;
    }

    return SUPPORTED_EVIDENCE_TYPES.includes(
        evidenceType.trim().toLowerCase()
    );
};


// =====================================================
// 10. VALIDATE PAGINATION
// =====================================================

const validatePagination = (page, limit) => {
    const parsedPage = Number(page);
    const parsedLimit = Number(limit);

    const normalizedPage =
        Number.isSafeInteger(parsedPage) &&
        parsedPage > 0
            ? parsedPage
            : DEFAULT_PAGE;

    const normalizedLimit =
        Number.isSafeInteger(parsedLimit) &&
        parsedLimit > 0
            ? Math.min(parsedLimit, MAX_LIMIT)
            : DEFAULT_LIMIT;

    return {
        page: normalizedPage,
        limit: normalizedLimit,
    };
};


// =====================================================
// 11. VALIDATE RISK SCORE
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
// 12. VALIDATE ARRAY
// =====================================================

const isValidArray = (value) => {
    return Array.isArray(value);
};


// =====================================================
// 13. VALIDATE ENUM VALUE
// =====================================================

const isValidEnumValue = (
    value,
    allowedValues
) => {
    if (
        typeof value !== "string" ||
        !Array.isArray(allowedValues)
    ) {
        return false;
    }

    return allowedValues.includes(
        value.trim()
    );
};


// =====================================================
// 14. EXPORTS
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
