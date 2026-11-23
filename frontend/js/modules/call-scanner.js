"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI - CALL FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Capabilities:
 * 1. Authority impersonation indicators
 * 2. Digital arrest threats
 * 3. OTP / PIN / password theft attempts
 * 4. Remote access requests
 * 5. Money transfer pressure
 * 6. Urgency and intimidation
 * 7. Secrecy instructions
 * 8. Fake KYC / account blocking
 * 9. UPI collect request manipulation
 *
 * IMPORTANT:
 * - Transcript/text analysis only.
 * - No automatic call recording.
 * - No automatic speech transcription.
 * - No caller identity verification.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_CALL_INPUT_LENGTH = 15000;

const CALL_RULES = [
    {
        id: "authority_impersonation",
        label: "Police, government or bank impersonation claim",
        severity: "medium",
        patterns: [
            /\b(police|cbi|court|customs|income tax|rbi|bank officer|government officer)\b/i,

            /\b(speaking|calling|bol raha|bol rahi)\b.{0,50}\b(police|cbi|bank|court|customs)\b/i,

            /\b(main|hum)\b.{0,30}\b(police|cbi|bank|government|customs)\b.{0,30}\b(se|ki taraf se|department se)\b/i,

            /\b(sarkari adhikari|police adhikari|bank adhikari)\b/i
        ]
    },

    {
        id: "digital_arrest_threat",
        label: "Digital arrest or physical arrest threat",
        severity: "critical",
        patterns: [
            /\b(digital arrest|you are under arrest|arrest warrant|police case against you)\b/i,

            /\b(you will be arrested|arrest kar liya jayega|giraftar kar lenge)\b/i,

            /\b(video call|online)\b.{0,50}\b(arrest|giraftar|investigation)\b/i,

            /\b(aapke khilaf)\b.{0,40}\b(case|warrant|arrest)\b/i,

            /\b(court order|police custody|investigation officer)\b/i
        ]
    },

    {
        id: "otp_or_pin",
        label: "OTP, PIN, password or CVV disclosure request",
        severity: "critical",
        patterns: [
            /\b(otp|one.time.password|pin|password|cvv)\b.{0,60}\b(tell|share|read|send|confirm|provide|batao|padho|bhejo)\b/i,

            /\b(tell|share|read|send|confirm|provide|batao|padho|bhejo)\b.{0,60}\b(otp|one.time.password|pin|password|cvv)\b/i,

            /\b(otp|pin|password|cvv)\b.{0,40}\b(batao|padho|bhejo|share karo)\b/i,

            /\b(otp bataiye|otp boliye|secret code batao)\b/i
        ]
    },

    {
        id: "remote_access",
        label: "Remote access or screen-sharing application request",
        severity: "high",
        patterns: [
            /\b(install|download)\b.{0,60}\b(anydesk|teamviewer|remote access|screen sharing|quick support)\b/i,

            /\b(anydesk|teamviewer|remote access|screen sharing|quick support)\b.{0,60}\b(install|download|open|allow|permission)\b/i,

            /\b(screen share|screen sharing|remote control)\b.{0,50}\b(phone|mobile|device|karna|karo)\b/i
        ]
    },

    {
        id: "money_transfer",
        label: "Money transfer or payment approval pressure",
        severity: "high",
        patterns: [
            /\b(transfer|send|pay|deposit)\b.{0,50}\b(money|funds|amount|fee|fine|tax|account)\b/i,

            /\b(approve|accept)\b.{0,40}\b(upi|collect|payment|request)\b/i,

            /\b(paise bhejo|amount transfer|payment approve|collect request accept)\b/i,

            /\b(account mein)\b.{0,40}\b(paise|amount|money)\b.{0,30}\b(transfer|bhejo|jama)\b/i,

            /\b(safe account|verification account)\b.{0,50}\b(transfer|money|paise)\b/i
        ]
    },

    {
        id: "urgent_threat",
        label: "Urgent action demand or intimidation",
        severity: "medium",
        patterns: [
            /\b(immediately|right now|within \d+ minutes?|last chance|otherwise you will be arrested)\b/i,

            /\b(abhi|turant|isi waqt|warna giraftar|case darj ho jayega)\b/i,

            /\b(within \d+ hours?|account will be blocked immediately)\b/i,

            /\b(10 minute|15 minute|30 minute)\b.{0,40}\b(transfer|pay|share|confirm)\b/i
        ]
    },

    {
        id: "secrecy",
        label: "Instruction to keep the call or investigation secret",
        severity: "high",
        patterns: [
            /\b(do not tell anyone|keep this confidential|do not disconnect|don't contact your bank)\b/i,

            /\b(kisi ko mat batao|call mat kaato|bank ko phone mat karo|secret rakho)\b/i,

            /\b(family|friend|relative)\b.{0,40}\b(do not tell|mat batao|contact mat karo)\b/i
        ]
    },

    {
        id: "fake_kyc",
        label: "Fake KYC or account suspension claim",
        severity: "high",
        patterns: [
            /\b(kyc|know your customer)\b.{0,50}\b(expire|expired|update|block|suspend|verify)\b/i,

            /\b(account|bank account)\b.{0,50}\b(block|freeze|suspend|बंद|band)\b/i,

            /\b(kyc update karo|account band ho jayega|bank account block ho jayega)\b/i,

            /\b(pan card|aadhaar card)\b.{0,50}\b(update|verify|link|share)\b/i
        ]
    },

    {
        id: "upi_collect_scam",
        label: "UPI collect request or payment approval manipulation",
        severity: "high",
        patterns: [
            /\b(upi collect request|collect request|payment request)\b/i,

            /\b(upi pin)\b.{0,40}\b(enter|dalna|batao|share|confirm)\b/i,

            /\b(request accept|payment approve)\b.{0,40}\b(upi|phonepe|google pay|paytm)\b/i,

            /\b(paise receive karne)\b.{0,50}\b(upi pin|payment approve|request accept)\b/i
        ]
    }
];

/* =========================================================
   INPUT VALIDATION
========================================================= */

function normalizeCallInput(input) {
    if (typeof input !== "string") {
        return "";
    }

    return input.trim();
}

/* =========================================================
   EVIDENCE EXTRACTION
========================================================= */

function extractEvidence(text, patterns) {
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

function generateCallAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "Never share OTPs, UPI PINs, CVV or passwords with callers.",
        "Do not transfer money because of an unexpected phone call.",
        "Disconnect suspicious calls and independently verify the organization using its official contact details.",
        "Preserve relevant call details, phone numbers, messages and other available evidence."
    ];

    if (ids.has("remote_access")) {
        advice.push(
            "Do not install AnyDesk, TeamViewer or other remote-access applications at an unknown caller's request."
        );
    }

    if (ids.has("digital_arrest_threat")) {
        advice.push(
            "Do not trust digital-arrest threats. Independently contact the relevant official authorities."
        );
    }

    if (ids.has("upi_collect_scam")) {
        advice.push(
            "Receiving money through UPI does not require entering your UPI PIN."
        );
    }

    if (ids.has("fake_kyc")) {
        advice.push(
            "Update KYC only through your bank's official application, website or branch."
        );
    }

    if (ids.has("money_transfer")) {
        advice.push(
            "If money has already been transferred in India, contact your bank immediately and report suspected financial cyber fraud through helpline 1930."
        );
    }

    return advice;
}

/* =========================================================
   MAIN CALL INDICATOR ANALYZER
========================================================= */

/**
 * Analyze supplied call transcript or notes.
 *
 * @param {string} transcript
 * @returns {Object}
 */
function scanCallTranscript(transcript) {
    const text = normalizeCallInput(transcript);

    if (!text) {
        throw new TypeError(
            "Call transcript ya notes enter karein."
        );
    }

    if (text.length > MAX_CALL_INPUT_LENGTH) {
        throw new RangeError(
            `Call transcript maximum ${MAX_CALL_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of CALL_RULES) {
        const evidence = extractEvidence(
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

        categoryHint: "fraud_call",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential suspicious call indicators identified.`
            : "No matching call fraud indicators identified.",

        advice: generateCallAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield Call Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            rulesChecked: CALL_RULES.length,
            evidenceType: "call_transcript",
            callerIdentityVerified: false,
            automaticTranscription: false,
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
        scanCallTranscript,
        normalizeCallInput,
        extractEvidence,
        generateCallAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldCallScanner = {
        scanCallTranscript,
        normalizeCallInput,
        extractEvidence,
        generateCallAdvice
    };
}