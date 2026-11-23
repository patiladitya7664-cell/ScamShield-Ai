"use strict";

/* =========================================================
   SCAMSHIELD AI
   SEXTORTION & BLACKMAIL INDICATOR ANALYZER

   Version: 3.0.0

   IMPORTANT:
   - Local indicator examination only.
   - Not an authoritative fraud detector.
   - Guardian Agent determines final category and risk.
   - No automatic reporting or external verification.
========================================================= */

const BLACKMAIL_RULES = [
    {
        id: "intimate_content_threat",
        label: "Private or intimate content exposure threat",
        severity: "critical",
        patterns: [
            /\b(leak|publish|post|share|send|expose|release)\b.{0,60}\b(your\s+)?(private|intimate|explicit|nude|personal)\s+(photo|picture|video|image|content)\b/i,

            /\b(your\s+)?(private|intimate|explicit|nude|personal)\s+(photo|picture|video|image|content)\b.{0,60}\b(leak|publish|post|share|expose|release)\b/i,

            /\b(nudes?|private photos?|intimate videos?)\b.{0,50}\b(leak|share|publish|send)\b/i,

            /\b(photo|video|nude)\s+(leak|viral)\s+(karunga|kar dunga|kar denge|bhej dunga|share karunga)\b/i,

            /\b(tumhari|teri)\s+(private|personal|nude)\s+(photo|video)\b.{0,50}\b(leak|viral|share)\b/i
        ]
    },

    {
        id: "payment_demand",
        label: "Payment demand associated with a threat",
        severity: "critical",
        patterns: [
            /\b(pay|send|transfer)\b.{0,45}\b(money|bitcoin|crypto|gift card|ransom|payment)\b/i,

            /\b(money|bitcoin|crypto|gift card|ransom)\b.{0,45}\b(or i will|otherwise i will|warna|nahi to)\b/i,

            /\b(paise bhejo|payment karo|paisa transfer karo|crypto bhejo)\b/i
        ]
    },

    {
        id: "exposure_threat",
        label: "Threat to expose information to family or public",
        severity: "high",
        patterns: [
            /\b(send|show|share|expose|contact|inform)\b.{0,45}\b(your family|your friends|your employer|everyone|the public|your contacts)\b/i,

            /\b(tumhare family|tumhare doston|tumhare office|sabko|gharwalon ko)\b.{0,45}\b(bata|bhej|dikha|share|contact)\b/i,

            /\b(viral kar dunga|sabko bhej dunga|family ko bata dunga)\b/i
        ]
    },

    {
        id: "account_hacking_claim",
        label: "Device or account compromise claim",
        severity: "high",
        patterns: [
            /\b(i hacked|we hacked|access to your device|your camera is|your account is compromised)\b/i,

            /\b(hacked|camera access|device access|phone access)\b.{0,45}\b(pay|send|money|bitcoin|crypto)\b/i,

            /\b(tumhara phone hack|camera hack|account hack|device hack)\b/i
        ]
    },

    {
        id: "deadline_pressure",
        label: "Urgent deadline or countdown pressure",
        severity: "high",
        patterns: [
            /\b(within \d+ hours?|within \d+ minutes?|you have \d+ hours?|deadline|pay now|immediately)\b/i,

            /\b(24 hours|48 hours|one hour|aaj raat tak|abhi payment|turant paise)\b/i,

            /\b(last warning|final warning|time is running out)\b/i
        ]
    },

    {
        id: "secrecy",
        label: "Victim discouraged from seeking help",
        severity: "medium",
        patterns: [
            /\b(do not tell anyone|don't contact police|keep this secret|tell no one)\b/i,

            /\b(kisi ko mat batao|police ko mat batao|secret rakho|madad mat lo)\b/i,

            /\b(don't inform your family|do not seek help)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeInput(input) {
    if (typeof input === "string") {
        return input.trim();
    }

    if (input && typeof input === "object") {
        return [
            input.message,
            input.email,
            input.details,
            input.transcript,
            input.extractedText
        ]
            .filter((value) => typeof value === "string")
            .join("\n")
            .trim();
    }

    return "";
}

/* =========================================================
   INDICATOR ANALYSIS
========================================================= */

function scanBlackmail(input) {
    const text = normalizeInput(input);

    if (!text) {
        throw new TypeError(
            "Blackmail analysis ke liye text evidence required hai."
        );
    }

    if (text.length > 15000) {
        throw new RangeError(
            "Input maximum 15000 characters ka ho sakta hai."
        );
    }

    const findings = [];

    for (const rule of BLACKMAIL_RULES) {
        const matchedPattern = rule.patterns.find(
            (pattern) => pattern.test(text)
        );

        if (!matchedPattern) {
            continue;
        }

        const matchedText = text.match(matchedPattern);

        findings.push({
            id: rule.id,
            label: rule.label,
            severity: rule.severity,

            matchedText: matchedText
                ? matchedText[0].slice(0, 300)
                : null
        });
    }

    const advice = [
        "Do not send money or cryptocurrency in response to threats.",
        "Do not share OTPs, passwords, PINs or additional personal information.",
        "Preserve relevant messages, emails, usernames and payment details.",
        "Avoid opening suspicious links or downloading unknown attachments.",
        "Seek help from a trusted person or appropriate reporting service."
    ];

    if (
        findings.some(
            (finding) =>
                finding.id === "intimate_content_threat"
        )
    ) {
        advice.push(
            "Do not forward or repost intimate images.",
            "Preserve evidence of the threat and report it through appropriate channels."
        );
    }

    if (
        findings.some(
            (finding) =>
                finding.id === "account_hacking_claim"
        )
    ) {
        advice.push(
            "Access your accounts through official websites or applications.",
            "Change compromised passwords and enable two-factor authentication.",
            "Review active account sessions and revoke unfamiliar sessions."
        );
    }

    if (
        findings.some(
            (finding) =>
                finding.id === "payment_demand"
        )
    ) {
        advice.push(
            "If money has already been transferred in India, contact your bank immediately and report financial cyber fraud through helpline 1930."
        );
    }

    return {
        type: "indicator_analysis",

        categoryHint: "sextortion_blackmail",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential sextortion or blackmail indicators identified.`
            : "No matching sextortion or blackmail indicators identified.",

        advice,

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            engine: "ScamShield Blackmail Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "Local Rule-Based Pattern Matching",
            evidenceLength: text.length,
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
        scanBlackmail,
        normalizeInput
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldBlackmailScanner = {
        scanBlackmail,
        normalizeInput
    };
}