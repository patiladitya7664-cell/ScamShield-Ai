"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * DIGITAL ARREST INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Detects potential indicators:
 * 1. Digital arrest claims
 * 2. Authority impersonation
 * 3. Video-call surveillance pressure
 * 4. Arrest and criminal case threats
 * 5. Money demands for case clearance
 * 6. Bank transfer instructions
 * 7. Secrecy instructions
 * 8. Sensitive information requests
 *
 * IMPORTANT:
 * - Rule-based indicator analysis only.
 * - Does not verify police or government identity.
 * - Does not independently establish criminal activity.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_DIGITAL_ARREST_INPUT_LENGTH = 15000;

const DIGITAL_ARREST_RULES = [
    {
        id: "digital_arrest_claim",
        label: "Digital arrest or online custody claim",
        severity: "critical",
        patterns: [
            /\b(digital arrest|online arrest|virtual arrest|under digital custody)\b/i,
            /\b(digital giraftari|online giraftar|video call par arrest)\b/i
        ]
    },

    {
        id: "authority_impersonation",
        label: "Police, CBI, court or government agency impersonation claim",
        severity: "high",
        patterns: [
            /\b(police|cbi|cyd|customs|court|supreme court|enforcement directorate|government agency)\b.{0,50}\b(speaking|calling|bol raha|bol rahi|ki taraf se)\b/i,

            /\b(main|hum)\b.{0,30}\b(police|cbi|court|customs|sarkari agency)\b.{0,30}\b(se|ki taraf se|department se)\b/i
        ]
    },

    {
        id: "video_call_surveillance",
        label: "Instruction to remain on video call or keep camera on",
        severity: "high",
        patterns: [
            /\b(stay on the video call|do not disconnect|keep your camera on|video surveillance)\b/i,

            /\b(video call mat kaato|camera on rakho|call par bane raho)\b/i
        ]
    },

    {
        id: "arrest_or_case_threat",
        label: "Arrest or criminal case threat",
        severity: "critical",
        patterns: [
            /\b(arrest warrant|you will be arrested|criminal case|custody|police will come)\b/i,

            /\b(giraftar|arrest warrant|criminal case|police ghar aayegi|custody)\b/i
        ]
    },

    {
        id: "money_for_clearance",
        label: "Money demanded for case clearance or verification",
        severity: "critical",
        patterns: [
            /\b(pay|transfer|deposit|send)\b.{0,50}\b(security deposit|clearance fee|verification fee|case settlement|bail)\b/i,

            /\b(case khatam|verification|bail|clearance)\b.{0,40}\b(paise|payment|deposit|transfer)\b/i
        ]
    },

    {
        id: "bank_transfer_instruction",
        label: "Instruction to transfer money to another account",
        severity: "critical",
        patterns: [
            /\b(transfer|move|send)\b.{0,45}\b(money|funds|savings|bank balance)\b/i,

            /\b(account safe|verification account|government account)\b.{0,40}\b(transfer|deposit|send)\b/i
        ]
    },

    {
        id: "secret_instruction",
        label: "Instruction to avoid contacting family, bank or police",
        severity: "high",
        patterns: [
            /\b(do not tell your family|do not contact your bank|keep this confidential|tell no one)\b/i,

            /\b(family ko mat batao|bank ko phone mat karo|kisi ko mat batao|secret rakho)\b/i
        ]
    },

    {
        id: "identity_details_request",
        label: "Sensitive personal or banking information request",
        severity: "critical",
        patterns: [
            /\b(share|tell|send|confirm|provide)\b.{0,45}\b(otp|pin|password|aadhaar|pan|bank details|cvv)\b/i,

            /\b(otp|pin|password|aadhaar|pan|bank details|cvv)\b.{0,45}\b(bhejo|batao|share karo|provide karo)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeDigitalArrestInput(input) {
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

function extractDigitalArrestEvidence(text, patterns) {
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

function generateDigitalArrestAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "Do not panic or transfer money because of threats made during a call or message.",
        "Never share OTPs, PINs, passwords or banking credentials.",
        "Independently contact the relevant organization using its official contact details.",
        "Inform a trusted family member or person.",
        "Preserve messages, phone numbers, call details and payment evidence."
    ];

    if (ids.has("video_call_surveillance")) {
        advice.push(
            "Do not allow an unknown caller to control your actions through video-call surveillance or intimidation."
        );
    }

    if (
        ids.has("money_for_clearance") ||
        ids.has("bank_transfer_instruction")
    ) {
        advice.push(
            "If money has already been transferred in India, contact your bank immediately and report suspected financial cyber fraud through helpline 1930."
        );
    }

    if (ids.has("identity_details_request")) {
        advice.push(
            "Do not disclose sensitive identity or banking information to an unverified caller."
        );
    }

    return advice;
}

/* =========================================================
   MAIN DIGITAL ARREST INDICATOR ANALYZER
========================================================= */

/**
 * Analyze a supplied message or call transcript.
 *
 * @param {string|object} input
 * @returns {Object}
 */
function scanDigitalArrest(input) {
    const text = normalizeDigitalArrestInput(input);

    if (!text) {
        throw new TypeError(
            "Digital arrest analysis ke liye message ya call transcript enter karein."
        );
    }

    if (text.length > MAX_DIGITAL_ARREST_INPUT_LENGTH) {
        throw new RangeError(
            `Input maximum ${MAX_DIGITAL_ARREST_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of DIGITAL_ARREST_RULES) {
        const evidence = extractDigitalArrestEvidence(
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

        categoryHint: "digital_arrest",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential digital arrest scam indicators identified.`
            : "No matching digital arrest indicators identified.",

        advice: generateDigitalArrestAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield Digital Arrest Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "message_or_call_transcript",
            rulesChecked: DIGITAL_ARREST_RULES.length,
            authorityIdentityVerified: false,
            externallyVerified: false,
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
        scanDigitalArrest,
        normalizeDigitalArrestInput,
        generateDigitalArrestAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldDigitalArrestScanner = {
        scanDigitalArrest,
        normalizeDigitalArrestInput,
        generateDigitalArrestAdvice
    };
}