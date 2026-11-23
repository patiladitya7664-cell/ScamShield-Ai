"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * CREDIT CARD FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Capabilities:
 * 1. CVV / PIN / OTP theft indicators
 * 2. Card blocking threats
 * 3. Unauthorized transaction claims
 * 4. Fake refund / reversal requests
 * 5. Remote access requests
 * 6. Urgency pressure
 * 7. Suspicious card verification links
 *
 * IMPORTANT:
 * - Local rule-based indicator analysis only.
 * - Does not verify cards or bank transactions.
 * - Does not verify URLs or payment links.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_CARD_INPUT_LENGTH = 15000;

const CARD_RULES = [
    {
        id: "cvv_or_pin_request",
        label: "CVV, card PIN, OTP or password disclosure request",
        severity: "critical",
        patterns: [
            /\b(cvv|card pin|debit pin|credit card pin|otp|one.time.password|password)\b.{0,45}\b(share|tell|send|read|confirm|provide)\b/i,

            /\b(share|tell|send|read|confirm|provide)\b.{0,45}\b(cvv|card pin|debit pin|credit card pin|otp|password)\b/i,

            /\b(cvv|card pin|otp)\b.{0,35}\b(batao|bhejo|share karo|padho)\b/i
        ]
    },

    {
        id: "card_block_threat",
        label: "Card blocking or suspension threat",
        severity: "high",
        patterns: [
            /\b(card|credit card|debit card)\b.{0,40}\b(block|suspend|deactivate|close|expire)\b/i,

            /\b(block|suspend|deactivate)\b.{0,35}\b(card|credit card|debit card)\b/i
        ]
    },

    {
        id: "unknown_transaction",
        label: "Unknown or suspicious transaction claim",
        severity: "high",
        patterns: [
            /\b(unknown|unauthorized|suspicious|unusual)\b.{0,40}\b(transaction|charge|purchase|payment)\b/i,

            /\b(transaction|charge|purchase|payment)\b.{0,40}\b(unknown|unauthorized|suspicious|unusual)\b/i
        ]
    },

    {
        id: "refund_or_reversal",
        label: "Card details requested for refund or charge reversal",
        severity: "high",
        patterns: [
            /\b(refund|chargeback|reversal)\b.{0,45}\b(card number|cvv|otp|pin|link|details)\b/i,

            /\b(card number|cvv|otp|pin)\b.{0,40}\b(refund|chargeback|reversal)\b/i
        ]
    },

    {
        id: "remote_access",
        label: "Remote access application requested under bank support pretext",
        severity: "high",
        patterns: [
            /\b(install|download)\b.{0,45}\b(anydesk|teamviewer|remote access|screen sharing)\b/i,

            /\b(anydesk|teamviewer|remote access|screen sharing)\b.{0,45}\b(card|bank|transaction)\b/i
        ]
    },

    {
        id: "urgent_action",
        label: "Urgent action or deadline pressure",
        severity: "medium",
        patterns: [
            /\b(act now|immediately|urgent|within \d+ minutes?|final warning)\b/i,

            /\b(abhi|turant|jaldi action|warna card band)\b/i
        ]
    },

    {
        id: "payment_link",
        label: "Link presented for card verification or refund",
        severity: "medium",
        patterns: [
            /\b(click|open|visit)\b.{0,30}\b(verify|refund|card|payment)\b/i,

            /\b(card|payment|refund)\b.{0,40}\b(verification link|verify link|refund link)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeCardInput(input) {
    if (typeof input === "string") {
        return input.trim();
    }

    if (input && typeof input === "object") {
        return [
            input.message,
            input.transcript,
            input.details
        ]
            .filter((part) => typeof part === "string")
            .join("\n")
            .trim();
    }

    return "";
}

/* =========================================================
   EVIDENCE EXTRACTION
========================================================= */

function extractCardEvidence(text, patterns) {
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

function generateCardAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "Never share CVV, card PIN, OTP or passwords through calls, SMS or email.",
        "Verify transactions through your bank's official application or the contact number printed on your card.",
        "If a transaction appears unauthorized, contact your bank immediately and follow its official card-blocking or dispute process."
    ];

    if (ids.has("payment_link")) {
        advice.push(
            "Do not enter card details through an unsolicited link. Open your bank's official application or website independently."
        );
    }

    if (ids.has("remote_access")) {
        advice.push(
            "Do not install remote-access or screen-sharing applications at an unknown caller's request."
        );
    }

    if (ids.has("refund_or_reversal")) {
        advice.push(
            "Do not disclose CVV, PIN or OTP to receive a refund. Verify refund requests directly with your bank or merchant."
        );
    }

    if (ids.has("unknown_transaction")) {
        advice.push(
            "Check the transaction in your official bank statement and report unauthorized activity through your bank's official channel."
        );
    }

    return advice;
}

/* =========================================================
   MAIN CARD INDICATOR ANALYZER
========================================================= */

/**
 * Analyze card-related messages or supplied call transcripts.
 *
 * @param {string|object} input
 * @returns {Object}
 */
function scanCardFraud(input) {
    const text = normalizeCardInput(input);

    if (!text) {
        throw new TypeError(
            "Card-related message ya call transcript enter karein."
        );
    }

    if (text.length > MAX_CARD_INPUT_LENGTH) {
        throw new RangeError(
            `Input maximum ${MAX_CARD_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of CARD_RULES) {
        const evidence = extractCardEvidence(
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

        categoryHint: "card_fraud",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential card fraud indicators identified.`
            : "No matching card fraud indicators identified.",

        advice: generateCardAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield Card Fraud Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "message_or_call_transcript",
            rulesChecked: CARD_RULES.length,
            bankVerified: false,
            transactionVerified: false,
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
        scanCardFraud,
        normalizeCardInput,
        extractCardEvidence,
        generateCardAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldCardScanner = {
        scanCardFraud,
        normalizeCardInput,
        extractCardEvidence,
        generateCardAdvice
    };
}