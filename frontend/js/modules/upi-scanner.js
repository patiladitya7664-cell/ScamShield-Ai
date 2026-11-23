"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * UPI & BANKING FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Detects potential indicators:
 * 1. Suspicious UPI collect requests
 * 2. UPI PIN / OTP / banking credential requests
 * 3. Fake receive-money PIN instructions
 * 4. Remote access application requests
 * 5. Account blocking / KYC threats
 * 6. Unexpected refund / cashback claims
 * 7. Urgent money transfer pressure
 * 8. Suspicious payment / verification links
 *
 * IMPORTANT:
 * - Rule-based indicator analysis only.
 * - Does not verify bank accounts.
 * - Does not verify UPI IDs.
 * - Does not verify transactions.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_UPI_INPUT_LENGTH = 15000;

const UPI_RULES = [
    {
        id: "collect_request",
        label: "Potential UPI collect request approval instruction",
        severity: "high",
        patterns: [
            /\b(collect request|payment request|upi request)\b/i,

            /\b(approve|accept|authorize)\b.{0,40}\b(upi|collect|payment request)\b/i,

            /\b(collect request|upi request)\b.{0,40}\b(approve|accept|authorize)\b/i
        ]
    },

    {
        id: "upi_pin_request",
        label: "Request for UPI PIN, OTP or banking password",
        severity: "critical",
        patterns: [
            /\b(upi pin|otp|banking password|transaction pin|debit card pin)\b.{0,45}\b(share|tell|send|enter|confirm|provide)\b/i,

            /\b(share|tell|send|enter|confirm|provide)\b.{0,45}\b(upi pin|otp|banking password|transaction pin|debit card pin)\b/i,

            /\b(upi pin|otp|pin)\b.{0,35}\b(batao|bhejo|share karo|daalo)\b/i
        ]
    },

    {
        id: "receive_money_pin",
        label: "Instruction to enter PIN for receiving money",
        severity: "critical",
        patterns: [
            /\b(receive|get|accept)\b.{0,35}\b(money|payment|refund)\b.{0,50}\b(enter|type|use)\b.{0,20}\b(pin|upi pin)\b/i,

            /\b(paise receive|refund receive)\b.{0,40}\b(pin daalo|upi pin daalo)\b/i,

            /\b(receive money|receive payment)\b.{0,40}\b(enter|provide)\b.{0,15}\bupi pin\b/i
        ]
    },

    {
        id: "remote_access",
        label: "Request to install remote access or screen sharing software",
        severity: "critical",
        patterns: [
            /\b(install|download)\b.{0,45}\b(anydesk|teamviewer|remote access|screen sharing)\b/i,

            /\b(anydesk|teamviewer|remote access|screen sharing)\b.{0,45}\b(bank|upi|payment|banking)\b/i,

            /\b(bank|upi|payment|banking)\b.{0,45}\b(anydesk|teamviewer|remote access|screen sharing)\b/i
        ]
    },

    {
        id: "account_block_threat",
        label: "Bank account blocking, freezing or KYC suspension threat",
        severity: "high",
        patterns: [
            /\b(bank account|account|kyc|debit card)\b.{0,45}\b(will be blocked|block|suspend|freeze|expire|deactivate)\b/i,

            /\b(kyc|account)\b.{0,40}\b(update|verify)\b.{0,35}\b(block|suspend|freeze)\b/i,

            /\b(account blocked|account frozen|kyc expired|bank account suspended)\b/i
        ]
    },

    {
        id: "unexpected_refund",
        label: "Unexpected refund, cashback or reward claim",
        severity: "medium",
        patterns: [
            /\b(refund|cashback|reward)\b.{0,40}\b(approved|pending|claim|receive|credited)\b/i,

            /\b(claim|receive)\b.{0,30}\b(refund|cashback|reward)\b/i
        ]
    },

    {
        id: "urgent_transfer",
        label: "Urgent pressure to transfer or send money",
        severity: "high",
        patterns: [
            /\b(transfer|send|pay)\b.{0,35}\b(now|immediately|urgent|within \d+ minutes?)\b/i,

            /\b(abhi paise bhejo|turant transfer|payment karo warna)\b/i,

            /\b(urgent payment|immediate payment required|send money immediately)\b/i
        ]
    },

    {
        id: "unfamiliar_payment_link",
        label: "Instruction to open a link for banking, payment or KYC verification",
        severity: "medium",
        patterns: [
            /\b(click|open|visit|tap)\b.{0,30}\b(link|bank|upi|payment|kyc|verification)\b/i,

            /\b(verify|update|reactivate)\b.{0,35}\b(bank account|kyc|upi account)\b.{0,35}\b(link|website)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeUpiInput(input) {
    if (typeof input === "string") {
        return input.trim();
    }

    if (
        input &&
        typeof input === "object" &&
        !Array.isArray(input)
    ) {
        return [
            input.message,
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

function extractUpiEvidence(text, patterns) {
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

function generateUpiAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "UPI PIN sirf apne UPI app mein payment authorize karne ke liye enter karein; ise kisi person ke saath share na karein.",
        "OTP, banking password aur PIN kisi caller, message ya supposed support agent ko na batayein.",
        "Bank se contact karne ke liye official banking app, card ya verified bank website ka contact channel use karein."
    ];

    if (ids.has("collect_request")) {
        advice.push(
            "UPI request approve karne se pehle amount, recipient aur transaction details carefully check karein. Money receive karne ke naam par anjaan collect request approve na karein."
        );
    }

    if (ids.has("receive_money_pin")) {
        advice.push(
            "Paise receive karne ke liye UPI PIN enter karne ki zaroorat nahi hoti. Aisi instruction ko suspicious samjhein."
        );
    }

    if (ids.has("remote_access")) {
        advice.push(
            "Banking assistance ke naam par unknown remote access application install na karein aur screen sharing enable na karein."
        );
    }

    if (ids.has("account_block_threat")) {
        advice.push(
            "Account blocking ya KYC warning ko message ke link se nahi, official bank channel se independently verify karein."
        );
    }

    if (ids.has("unexpected_refund")) {
        advice.push(
            "Unexpected refund ya cashback claim ko apne bank statement aur official payment application mein independently check karein."
        );
    }

    if (ids.has("urgent_transfer")) {
        advice.push(
            "Urgent payment pressure mein transaction karne se pehle recipient aur payment purpose independently verify karein."
        );
    }

    if (ids.has("unfamiliar_payment_link")) {
        advice.push(
            "Unknown payment ya KYC links par banking credentials, card details ya OTP enter na karein."
        );
    }

    return advice;
}

/* =========================================================
   MAIN UPI & BANKING INDICATOR ANALYZER
========================================================= */

/**
 * @param {
 *   string |
 *   {
 *     message?: string,
 *     details?: string
 *   }
 * } input
 *
 * @returns {Object}
 */

function scanUpiBanking(input) {
    const text = normalizeUpiInput(input);

    if (!text) {
        throw new TypeError(
            "Scan karne ke liye UPI ya banking message enter karein."
        );
    }

    if (text.length > MAX_UPI_INPUT_LENGTH) {
        throw new RangeError(
            `Input maximum ${MAX_UPI_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of UPI_RULES) {
        const evidence = extractUpiEvidence(
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

        categoryHint: "upi_banking_fraud",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential UPI or banking fraud indicators identified.`
            : "No matching UPI or banking fraud indicators identified.",

        advice: generateUpiAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield UPI & Banking Fraud Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "upi_banking_message",
            rulesChecked: UPI_RULES.length,
            bankAccountVerified: false,
            upiIdVerified: false,
            transactionVerified: false,
            externalReputationChecked: false,
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
        scanUpiBanking,
        normalizeUpiInput,
        extractUpiEvidence,
        generateUpiAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldUpiScanner = {
        scanUpiBanking,
        normalizeUpiInput,
        extractUpiEvidence,
        generateUpiAdvice
    };
}