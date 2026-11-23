"use strict";

// =====================================================
// SCAMSHIELD AI - FRAUD CATEGORIES
// Version: 2.0.0
//
// Canonical detection categories synchronized with
// the Python AI engine and MongoDB Analysis model.
//
// IMPORTANT:
// Detection categories and major fraud modules are
// separate concepts.
// =====================================================

// =====================================================
// 1. CANONICAL DETECTION CATEGORIES
// =====================================================

const FRAUD_CATEGORIES = Object.freeze({

    FRAUD_MESSAGE: "fraud_message",
    FRAUD_CALL: "fraud_call",
    URL_PHISHING: "url_phishing",
    EMAIL_SCAM: "email_scam",

    INVESTMENT_SCAM: "investment_scam",
    DIGITAL_ARREST: "digital_arrest",

    UPI_BANKING_FRAUD: "upi_banking_fraud",
    CARD_FRAUD: "card_fraud",

    ECOMMERCE_SCAM: "ecommerce_scam",
    JOB_LOAN_SCAM: "job_loan_scam",

    SEXTORTION_BLACKMAIL: "sextortion_blackmail",
    SOCIAL_MEDIA_SCAM: "social_media_scam",

    // Compatibility values.
    // These are NOT canonical detection categories.
    OTHER: "other",
    UNKNOWN: "unclassified",
});

// =====================================================
// 2. CANONICAL CATEGORY VALUES
// =====================================================

const FRAUD_CATEGORY_VALUES = Object.freeze([
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
]);

// =====================================================
// 3. CATEGORY METADATA
// =====================================================

const FRAUD_CATEGORY_DETAILS = Object.freeze({

    [FRAUD_CATEGORIES.FRAUD_MESSAGE]: {
        label: "Fraud Message",
        description:
            "Suspicious messages designed to deceive users or obtain money or sensitive information.",
    },

    [FRAUD_CATEGORIES.FRAUD_CALL]: {
        label: "Fraud Call",
        description:
            "Suspicious calls involving impersonation, manipulation, threats or fraudulent requests.",
    },

    [FRAUD_CATEGORIES.URL_PHISHING]: {
        label: "URL Phishing",
        description:
            "Suspicious links that may lead to phishing or fraudulent websites.",
    },

    [FRAUD_CATEGORIES.EMAIL_SCAM]: {
        label: "Email Scam",
        description:
            "Fraudulent emails designed to steal information, request payments or impersonate organizations.",
    },

    [FRAUD_CATEGORIES.INVESTMENT_SCAM]: {
        label: "Investment Scam",
        description:
            "Fake investment opportunities, Ponzi schemes and unrealistic return promises.",
    },

    [FRAUD_CATEGORIES.DIGITAL_ARREST]: {
        label: "Digital Arrest Scam",
        description:
            "Threat-based scams involving fake police, CBI or government officials.",
    },

    [FRAUD_CATEGORIES.UPI_BANKING_FRAUD]: {
        label: "UPI and Banking Fraud",
        description:
            "Fraud involving UPI payments, banking impersonation, collect requests or payment manipulation.",
    },

    [FRAUD_CATEGORIES.CARD_FRAUD]: {
        label: "Card Fraud",
        description:
            "Credit or debit card phishing, unauthorized transactions and payment credential theft.",
    },

    [FRAUD_CATEGORIES.ECOMMERCE_SCAM]: {
        label: "E-commerce Scam",
        description:
            "Fake shopping websites, deceptive sellers and fraudulent online offers.",
    },

    [FRAUD_CATEGORIES.JOB_LOAN_SCAM]: {
        label: "Job and Loan Scam",
        description:
            "Fake employment opportunities, fraudulent loan offers and advance-fee requests.",
    },

    [FRAUD_CATEGORIES.SEXTORTION_BLACKMAIL]: {
        label: "Sextortion and Blackmail",
        description:
            "Threats involving private or intimate material used to extort victims.",
    },

    [FRAUD_CATEGORIES.SOCIAL_MEDIA_SCAM]: {
        label: "Social Media Scam",
        description:
            "Fraud involving fake profiles, account impersonation and deceptive social media interactions.",
    },

    [FRAUD_CATEGORIES.OTHER]: {
        label: "Other",
        description:
            "A classification outside the canonical detection categories.",
    },

    [FRAUD_CATEGORIES.UNKNOWN]: {
        label: "Unclassified",
        description:
            "The available evidence is insufficient to determine a detection category.",
    },
});

// =====================================================
// 4. VALIDATION HELPERS
// =====================================================

const isValidFraudCategory = (category) => {
    return FRAUD_CATEGORY_VALUES.includes(category);
};

// =====================================================
// 5. CATEGORY METADATA HELPER
// =====================================================

const getFraudCategoryDetails = (category) => {
    return (
        FRAUD_CATEGORY_DETAILS[category] ||
        FRAUD_CATEGORY_DETAILS[FRAUD_CATEGORIES.UNKNOWN]
    );
};

// =====================================================
// 6. EXPORTS
// =====================================================

module.exports = {
    FRAUD_CATEGORIES,
    FRAUD_CATEGORY_DETAILS,
    FRAUD_CATEGORY_VALUES,
    isValidFraudCategory,
    getFraudCategoryDetails,
};