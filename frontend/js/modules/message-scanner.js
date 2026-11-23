"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * MESSAGE FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Supported message sources:
 * - SMS
 * - WhatsApp
 * - Telegram
 * - Other pasted text messages
 *
 * Detects potential indicators:
 * 1. OTP and credential requests
 * 2. Urgent threats
 * 3. Unexpected payment demands
 * 4. Prize and refund claims
 * 5. Account and KYC threats
 * 6. Suspicious link instructions
 * 7. Secrecy requests
 *
 * IMPORTANT:
 * - Rule-based indicator analysis only.
 * - Does not verify sender identity.
 * - Does not verify URLs or payment accounts.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_MESSAGE_LENGTH = 15000;

const MESSAGE_RULES = [
    {
        id: "otp_request",
        label: "Request for OTP, PIN, password or CVV",
        severity: "critical",
        patterns: [
            /\b(otp|one.time.password|pin|password|cvv)\b.{0,50}\b(send|share|tell|confirm|verify|provide|enter)\b/i,

            /\b(send|share|tell|confirm|verify|provide|enter)\b.{0,50}\b(otp|one.time.password|pin|password|cvv)\b/i,

            /\b(otp|pin|password|cvv)\b.{0,40}\b(bhejo|batao|share karo|confirm karo)\b/i
        ]
    },

    {
        id: "urgent_threat",
        label: "Urgent action pressure or account-related threat",
        severity: "medium",
        patterns: [
            /\b(act now|immediately|urgent|final warning|within \d+ hours?|account will be blocked|account will be suspended)\b/i,

            /\b(abhi|turant|jaldi|aaj hi|account band ho jayega|block ho jayega|suspend ho jayega)\b/i
        ]
    },

    {
        id: "payment_demand",
        label: "Unexpected payment, fee or money transfer request",
        severity: "high",
        patterns: [
            /\b(pay|transfer|send)\b.{0,45}\b(fee|fine|tax|deposit|charge|money|amount)\b/i,

            /\b(upi|payment|collect request)\b.{0,35}\b(request|approve|accept|pay)\b/i,

            /\b(paise bhejo|payment karo|fine bharo|deposit karo|request approve karo)\b/i
        ]
    },

    {
        id: "prize_refund",
        label: "Unexpected prize, lottery, cashback or refund claim",
        severity: "medium",
        patterns: [
            /\b(you have won|winner|lottery|cashback|refund approved|claim your prize|claim reward)\b/i,

            /\b(aap jeet|inaam|lottery|cashback|refund mil|reward claim)\b/i
        ]
    },

    {
        id: "account_kyc",
        label: "Account, SIM or KYC suspension warning",
        severity: "high",
        patterns: [
            /\b(account|bank account|sim|card|connection)\b.{0,40}\b(block|suspend|expire|close|deactivate)\b/i,

            /\b(kyc|pan|aadhaar)\b.{0,45}\b(update|verify|blocked|suspended|expired)\b/i
        ]
    },

    {
        id: "suspicious_link_instruction",
        label: "Instruction to open an unexpected website link",
        severity: "medium",
        patterns: [
            /\b(click|tap|open|visit)\b.{0,25}\b(link|here|below|website)\b/i,

            /\b(update|verify|unlock|claim|confirm)\b.{0,35}\b(through this link|using this link|on this website)\b/i
        ]
    },

    {
        id: "secrecy",
        label: "Request to keep communication secret",
        severity: "high",
        patterns: [
            /\b(do not tell anyone|keep this secret|don't inform anyone|do not discuss)\b/i,

            /\b(kisi ko mat batao|secret rakho|kisi se share mat karo)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeMessageInput(message) {
    if (typeof message !== "string") {
        return "";
    }

    return message.trim();
}

/* =========================================================
   EVIDENCE EXTRACTION
========================================================= */

function extractMessageEvidence(text, patterns) {
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

function generateMessageAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "OTP, PIN, password ya CVV kisi ke saath share na karein.",
        "Unexpected payment request ko bank ya sambandhit company ke official contact number se verify karein.",
        "Unknown sender ke instructions par turant action lene se pehle message independently verify karein."
    ];

    if (ids.has("suspicious_link_instruction")) {
        advice.push(
            "Unknown message link par click karne ke bajay official website ka address khud type karke kholen."
        );
    }

    if (ids.has("account_kyc")) {
        advice.push(
            "Account ya KYC suspension warning ko official application ya verified customer-support channel se check karein."
        );
    }

    if (ids.has("payment_demand")) {
        advice.push(
            "UPI collect request ya payment approval ko samajhe bina approve na karein."
        );
    }

    if (ids.has("secrecy")) {
        advice.push(
            "Financial ya personal information se related suspicious request ko trusted person ke saath discuss karein."
        );
    }

    if (ids.has("prize_refund")) {
        advice.push(
            "Prize ya refund claim karne ke liye advance payment ya confidential banking credentials share na karein."
        );
    }

    return advice;
}

/* =========================================================
   MAIN MESSAGE INDICATOR ANALYZER
========================================================= */

/**
 * @param {string} message
 * @returns {Object}
 */

function scanMessage(message) {
    const text = normalizeMessageInput(message);

    if (!text) {
        throw new TypeError(
            "Scan karne ke liye message text enter karein."
        );
    }

    if (text.length > MAX_MESSAGE_LENGTH) {
        throw new RangeError(
            `Message maximum ${MAX_MESSAGE_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of MESSAGE_RULES) {
        const evidence = extractMessageEvidence(
            text,
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

        categoryHint: "fraud_message",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential message fraud indicators identified.`
            : "No matching message fraud indicators identified.",

        advice: generateMessageAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield Message Fraud Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "message",
            rulesChecked: MESSAGE_RULES.length,
            senderIdentityVerified: false,
            urlReputationVerified: false,
            paymentAccountVerified: false,
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
        scanMessage,
        normalizeMessageInput,
        extractMessageEvidence,
        generateMessageAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldMessageScanner = {
        scanMessage,
        normalizeMessageInput,
        extractMessageEvidence,
        generateMessageAdvice
    };
}