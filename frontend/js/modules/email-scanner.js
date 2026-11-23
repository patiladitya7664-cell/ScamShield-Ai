"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * EMAIL FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Detects potential indicators:
 * 1. Credential requests
 * 2. Urgent account suspension threats
 * 3. Unexpected payment requests
 * 4. Prize and lottery scams
 * 5. Suspicious attachment instructions
 * 6. Secrecy and approval bypass requests
 * 7. Suspicious sender identity claims
 *
 * IMPORTANT:
 * - Local rule-based indicator analysis only.
 * - Does not verify sender identity or email authenticity.
 * - Does not inspect attachment contents.
 * - Does not verify URLs or domains.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_EMAIL_FIELD_LENGTH = 15000;
const MAX_EMAIL_TOTAL_LENGTH = 20000;

const EMAIL_RULES = [
    {
        id: "credential_request",
        label: "Request for password, OTP or account credentials",
        severity: "critical",
        patterns: [
            /\b(password|otp|one.time.password|pin|login details|credentials)\b.{0,50}\b(send|share|confirm|verify|provide|reply|enter)\b/i,

            /\b(send|share|confirm|verify|provide|reply|enter)\b.{0,50}\b(password|otp|one.time.password|pin|login details|credentials)\b/i
        ]
    },

    {
        id: "urgent_threat",
        label: "Urgent account suspension or deactivation warning",
        severity: "high",
        patterns: [
            /\b(account|mailbox|subscription|payment)\b.{0,45}\b(suspended|blocked|closed|deactivated|expire|disabled)\b/i,

            /\b(action required|urgent action|final notice|within \d+ hours?)\b/i,

            /\b(account|access)\b.{0,40}\b(will be terminated|will be suspended|will be blocked)\b/i
        ]
    },

    {
        id: "unexpected_payment",
        label: "Unexpected invoice, payment or refund request",
        severity: "high",
        patterns: [
            /\b(unpaid invoice|payment failed|refund approved|you owe|outstanding balance|wire transfer)\b/i,

            /\b(pay now|make a payment|confirm payment|claim your refund)\b/i,

            /\b(bank transfer|urgent payment|processing fee)\b/i
        ]
    },

    {
        id: "prize_or_reward",
        label: "Unexpected prize, lottery or reward claim",
        severity: "medium",
        patterns: [
            /\b(you have won|winner|lottery|claim your prize|claim your reward|gift card)\b/i,

            /\b(congratulations.{0,40}(selected|winner|prize|reward))\b/i
        ]
    },

    {
        id: "sensitive_attachment",
        label: "Instruction to open or enable unexpected attachment content",
        severity: "medium",
        patterns: [
            /\b(open|download|enable content|enable macros)\b.{0,40}\b(attachment|document|invoice|file)\b/i,

            /\b(attachment|document|invoice|file)\b.{0,40}\b(enable macros|enable content|open immediately)\b/i
        ]
    },

    {
        id: "secrecy_or_bypass",
        label: "Request to keep communication secret or bypass approval",
        severity: "high",
        patterns: [
            /\b(keep this confidential|do not tell anyone|bypass approval|don't contact your manager)\b/i,

            /\b(keep this between us|do not discuss this|skip the usual approval)\b/i
        ]
    },

    {
        id: "sender_brand_mismatch",
        label: "Sender display name may not match the claimed brand",
        severity: "medium",
        custom: true
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeEmailField(value) {
    if (typeof value !== "string") {
        return "";
    }

    return value.trim();
}

function normalizeEmailInput(email) {
    if (!email || typeof email !== "object" || Array.isArray(email)) {
        throw new TypeError(
            "Email details object ke roop mein dein."
        );
    }

    const subject = normalizeEmailField(email.subject);
    const sender = normalizeEmailField(email.sender);
    const senderName = normalizeEmailField(email.senderName);
    const body = normalizeEmailField(email.body);

    if (!body) {
        throw new TypeError(
            "Scan karne ke liye email body enter karein."
        );
    }

    for (const [field, value] of Object.entries({
        subject,
        sender,
        senderName,
        body
    })) {
        if (value.length > MAX_EMAIL_FIELD_LENGTH) {
            throw new RangeError(
                `${field} maximum ${MAX_EMAIL_FIELD_LENGTH} characters ka ho sakta hai.`
            );
        }
    }

    const totalLength =
        subject.length +
        sender.length +
        senderName.length +
        body.length;

    if (totalLength > MAX_EMAIL_TOTAL_LENGTH) {
        throw new RangeError(
            `Email content maximum ${MAX_EMAIL_TOTAL_LENGTH} characters ka ho sakta hai.`
        );
    }

    return {
        subject,
        sender,
        senderName,
        body
    };
}

/* =========================================================
   SENDER FORMAT VALIDATION
========================================================= */

function extractSenderAddress(sender) {
    const value = normalizeEmailField(sender);

    const match = value.match(/<([^<>]+)>/);

    const address = match
        ? match[1].trim()
        : value;

    if (
        !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(address)
    ) {
        return null;
    }

    return address;
}

/* =========================================================
   SENDER BRAND MISMATCH INDICATOR
========================================================= */

function detectSenderBrandMismatch(email) {
    const senderAddress = extractSenderAddress(email.sender);

    if (!senderAddress || !email.senderName) {
        return null;
    }

    const domain = senderAddress
        .split("@")[1]
        .toLowerCase();

    const displayName = email.senderName
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");

    const knownBrands = [
        "google",
        "microsoft",
        "apple",
        "amazon",
        "paypal",
        "netflix",
        "facebook",
        "instagram",
        "sbi",
        "hdfc",
        "icici"
    ];

    const claimedBrand = knownBrands.find((brand) =>
        displayName.includes(brand)
    );

    if (!claimedBrand) {
        return null;
    }

    const domainParts = domain.split(".");

    const registeredDomain = domainParts.length >= 2
        ? domainParts.slice(-2).join(".")
        : domain;

    if (registeredDomain.includes(claimedBrand)) {
        return null;
    }

    return {
        id: "sender_brand_mismatch",
        label: "Sender display name may not match the claimed brand",
        severity: "medium",
        evidence: `Display name: ${email.senderName}; sender domain: ${domain}`
    };
}

/* =========================================================
   EVIDENCE EXTRACTION
========================================================= */

function extractEmailEvidence(text, patterns) {
    for (const pattern of patterns) {
        const match = text.match(pattern);

        if (match) {
            return match[0].trim().slice(0, 300);
        }
    }

    return null;
}

/* =========================================================
   SAFETY RECOMMENDATIONS
========================================================= */

function generateEmailAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "Sender ka complete email address aur domain independently check karein.",
        "Email ke link se login karne ke bajay official website khud open karein.",
        "Unexpected attachments ko sender se independent channel par confirm kiye bina na kholen."
    ];

    if (ids.has("credential_request")) {
        advice.push(
            "Password, OTP, PIN ya recovery credentials email reply mein share na karein."
        );
    }

    if (ids.has("urgent_threat")) {
        advice.push(
            "Account suspension warning ko email ke link se verify na karein; official application ya website use karein."
        );
    }

    if (ids.has("unexpected_payment")) {
        advice.push(
            "Unexpected invoice, payment ya refund request ko known official contact channel se verify karein."
        );
    }

    if (ids.has("prize_or_reward")) {
        advice.push(
            "Unexpected prize claim karne ke liye advance payment ya confidential banking details na dein."
        );
    }

    if (ids.has("sender_brand_mismatch")) {
        advice.push(
            "Sender domain ko claimed organization ke independently verified official domain se compare karein."
        );
    }

    if (ids.has("secrecy_or_bypass")) {
        advice.push(
            "Financial ya account-related requests ke liye normal organizational approval process bypass na karein."
        );
    }

    return advice;
}

/* =========================================================
   MAIN EMAIL INDICATOR ANALYZER
========================================================= */

/**
 * @param {{
 *   subject?: string,
 *   sender?: string,
 *   senderName?: string,
 *   body: string
 * }} email
 *
 * @returns {Object}
 */

function scanEmail(email) {
    const normalized = normalizeEmailInput(email);

    const content = [
        normalized.subject,
        normalized.body
    ]
        .filter(Boolean)
        .join("\n");

    const findings = [];

    for (const rule of EMAIL_RULES) {
        if (rule.custom) {
            const customFinding = detectSenderBrandMismatch(
                normalized
            );

            if (customFinding) {
                findings.push(customFinding);
            }

            continue;
        }

        const evidence = extractEmailEvidence(
            content,
            rule.patterns
        );

        if (!evidence) {
            continue;
        }

        findings.push({
            id: rule.id,
            label: rule.label,
            severity: rule.severity,
            evidence
        });
    }

    return {
        type: "indicator_analysis",

        categoryHint: "email_scam",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential email fraud indicators identified.`
            : "No matching email fraud indicators identified.",

        advice: generateEmailAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield Email Fraud Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "email",
            rulesChecked: EMAIL_RULES.length,
            senderIdentityVerified: false,
            emailAuthenticityVerified: false,
            attachmentInspected: false,
            urlReputationVerified: false,
            analyzedAt: new Date().toISOString()
        }
    };
}

/* =========================================================
   EXPORTS
========================================================= */

if (
    typeof module !== "undefined" &&
    module.exports
) {
    module.exports = {
        scanEmail,
        normalizeEmailInput,
        extractSenderAddress,
        detectSenderBrandMismatch,
        generateEmailAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldEmailScanner = {
        scanEmail,
        normalizeEmailInput,
        extractSenderAddress,
        detectSenderBrandMismatch,
        generateEmailAdvice
    };
}