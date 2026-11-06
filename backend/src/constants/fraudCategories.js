"use strict";

// =====================================================
// SCAMSHIELD AI - FRAUD CATEGORIES
// Centralized fraud category definitions
// =====================================================

const FRAUD_CATEGORIES = Object.freeze({
    PHISHING: "phishing",
    UPI_FRAUD: "upi_fraud",
    BANKING_FRAUD: "banking_fraud",
    CREDIT_CARD_FRAUD: "credit_card_fraud",
    DEBIT_CARD_FRAUD: "debit_card_fraud",
    OTP_FRAUD: "otp_fraud",
    KYC_FRAUD: "kyc_fraud",
    IDENTITY_THEFT: "identity_theft",
    DIGITAL_ARREST: "digital_arrest",
    INVESTMENT_SCAM: "investment_scam",
    CRYPTOCURRENCY_SCAM: "cryptocurrency_scam",
    JOB_SCAM: "job_scam",
    LOAN_SCAM: "loan_scam",
    LOTTERY_SCAM: "lottery_scam",
    ONLINE_SHOPPING_FRAUD: "online_shopping_fraud",
    PAYMENT_FRAUD: "payment_fraud",
    QR_CODE_SCAM: "qr_code_scam",
    REMOTE_ACCESS_SCAM: "remote_access_scam",
    TECH_SUPPORT_SCAM: "tech_support_scam",
    SEXTORTION: "sextortion",
    SOCIAL_ENGINEERING: "social_engineering",
    IMPERSONATION: "impersonation",
    ROMANCE_SCAM: "romance_scam",
    MONEY_MULE: "money_mule",
    MALICIOUS_URL: "malicious_url",
    MALWARE: "malware",
    DATA_THEFT: "data_theft",
    OTHER: "other",
    UNKNOWN: "unknown",
});

// =====================================================
// CATEGORY METADATA
// =====================================================

const FRAUD_CATEGORY_DETAILS = Object.freeze({
    [FRAUD_CATEGORIES.PHISHING]: {
        label: "Phishing",
        description: "Fraudulent messages or websites designed to steal sensitive information.",
    },

    [FRAUD_CATEGORIES.UPI_FRAUD]: {
        label: "UPI Fraud",
        description: "Fraud involving UPI payments, collect requests or payment manipulation.",
    },

    [FRAUD_CATEGORIES.BANKING_FRAUD]: {
        label: "Banking Fraud",
        description: "Unauthorized banking transactions or deceptive banking communication.",
    },

    [FRAUD_CATEGORIES.CREDIT_CARD_FRAUD]: {
        label: "Credit Card Fraud",
        description: "Unauthorized use or theft of credit card information.",
    },

    [FRAUD_CATEGORIES.DEBIT_CARD_FRAUD]: {
        label: "Debit Card Fraud",
        description: "Unauthorized debit card usage or transaction manipulation.",
    },

    [FRAUD_CATEGORIES.OTP_FRAUD]: {
        label: "OTP Fraud",
        description: "Attempts to obtain or misuse one-time passwords.",
    },

    [FRAUD_CATEGORIES.KYC_FRAUD]: {
        label: "KYC Fraud",
        description: "Fraudulent requests involving identity verification or KYC updates.",
    },

    [FRAUD_CATEGORIES.IDENTITY_THEFT]: {
        label: "Identity Theft",
        description: "Unauthorized use of another person's personal identity.",
    },

    [FRAUD_CATEGORIES.DIGITAL_ARREST]: {
        label: "Digital Arrest Scam",
        description: "Threat-based scams involving fake law enforcement or government officials.",
    },

    [FRAUD_CATEGORIES.INVESTMENT_SCAM]: {
        label: "Investment Scam",
        description: "Fraudulent investment opportunities promising unrealistic returns.",
    },

    [FRAUD_CATEGORIES.CRYPTOCURRENCY_SCAM]: {
        label: "Cryptocurrency Scam",
        description: "Fraud involving fake crypto investments, wallets or exchanges.",
    },

    [FRAUD_CATEGORIES.JOB_SCAM]: {
        label: "Job Scam",
        description: "Fake employment offers involving fees or deceptive requests.",
    },

    [FRAUD_CATEGORIES.LOAN_SCAM]: {
        label: "Loan Scam",
        description: "Fraudulent loan offers, advance-fee requests or fake lenders.",
    },

    [FRAUD_CATEGORIES.LOTTERY_SCAM]: {
        label: "Lottery Scam",
        description: "Fake lottery, prize or reward claims used to extract money.",
    },

    [FRAUD_CATEGORIES.ONLINE_SHOPPING_FRAUD]: {
        label: "Online Shopping Fraud",
        description: "Fraudulent online sellers, stores or shopping transactions.",
    },

    [FRAUD_CATEGORIES.PAYMENT_FRAUD]: {
        label: "Payment Fraud",
        description: "Deceptive or unauthorized payment requests and transactions.",
    },

    [FRAUD_CATEGORIES.QR_CODE_SCAM]: {
        label: "QR Code Scam",
        description: "Malicious QR codes used to redirect payments or steal information.",
    },

    [FRAUD_CATEGORIES.REMOTE_ACCESS_SCAM]: {
        label: "Remote Access Scam",
        description: "Attempts to gain unauthorized control of a victim's device.",
    },

    [FRAUD_CATEGORIES.TECH_SUPPORT_SCAM]: {
        label: "Tech Support Scam",
        description: "Fake technical support messages or calls used to deceive victims.",
    },

    [FRAUD_CATEGORIES.SEXTORTION]: {
        label: "Sextortion",
        description: "Threats to expose private or intimate material to extort victims.",
    },

    [FRAUD_CATEGORIES.SOCIAL_ENGINEERING]: {
        label: "Social Engineering",
        description: "Psychological manipulation used to obtain information or money.",
    },

    [FRAUD_CATEGORIES.IMPERSONATION]: {
        label: "Impersonation",
        description: "Fraudsters pretending to be trusted individuals or organizations.",
    },

    [FRAUD_CATEGORIES.ROMANCE_SCAM]: {
        label: "Romance Scam",
        description: "Relationship-based deception used to obtain money or sensitive information.",
    },

    [FRAUD_CATEGORIES.MONEY_MULE]: {
        label: "Money Mule Scam",
        description: "Recruitment or misuse of accounts to transfer illicit funds.",
    },

    [FRAUD_CATEGORIES.MALICIOUS_URL]: {
        label: "Malicious URL",
        description: "Suspicious links leading to phishing, malware or fraudulent websites.",
    },

    [FRAUD_CATEGORIES.MALWARE]: {
        label: "Malware",
        description: "Malicious software intended to compromise devices or data.",
    },

    [FRAUD_CATEGORIES.DATA_THEFT]: {
        label: "Data Theft",
        description: "Unauthorized acquisition of confidential or personal information.",
    },

    [FRAUD_CATEGORIES.OTHER]: {
        label: "Other Fraud",
        description: "Fraud activity that does not match a defined category.",
    },

    [FRAUD_CATEGORIES.UNKNOWN]: {
        label: "Unknown",
        description: "Fraud category could not be determined.",
    },
});

// =====================================================
// HELPER FUNCTIONS
// =====================================================

const FRAUD_CATEGORY_VALUES = Object.freeze(
    Object.values(FRAUD_CATEGORIES)
);

const isValidFraudCategory = (category) => {
    return FRAUD_CATEGORY_VALUES.includes(category);
};

const getFraudCategoryDetails = (category) => {
    return FRAUD_CATEGORY_DETAILS[category] || FRAUD_CATEGORY_DETAILS[FRAUD_CATEGORIES.UNKNOWN];
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    FRAUD_CATEGORIES,
    FRAUD_CATEGORY_DETAILS,
    FRAUD_CATEGORY_VALUES,
    isValidFraudCategory,
    getFraudCategoryDetails,
};