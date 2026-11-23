"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * SOCIAL MEDIA FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Supported input:
 * - Social media messages
 * - Public posts
 * - Profile descriptions
 *
 * Detects potential indicators:
 * 1. Brand or support impersonation claims
 * 2. Account suspension threats
 * 3. Credential requests
 * 4. Fake giveaway and prize claims
 * 5. Advance payment requests
 * 6. Suspicious investment promotions
 * 7. Urgent private-contact requests
 * 8. Suspicious link instructions
 * 9. Secrecy requests
 *
 * IMPORTANT:
 * - Rule-based indicator analysis only.
 * - Does not verify social media accounts.
 * - Does not verify profile ownership.
 * - Does not verify URLs or brands.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_SOCIAL_MEDIA_INPUT_LENGTH = 15000;

const SOCIAL_MEDIA_RULES = [
    {
        id: "impersonation",
        label: "Claim of representing a known person, brand or support team",
        severity: "medium",
        patterns: [
            /\b(official support|customer support|admin team|platform support)\b/i,

            /\b(i am|we are|this is)\b.{0,35}\b(your friend|your relative|platform support|bank support)\b/i,

            /\b(main|hum)\b.{0,35}\b(official support|customer care|admin team)\b/i
        ]
    },

    {
        id: "account_threat",
        label: "Account ban, verification failure or suspension threat",
        severity: "high",
        patterns: [
            /\b(your account|profile|page)\b.{0,45}\b(will be banned|suspended|disabled|restricted)\b/i,

            /\b(verify your account|appeal now|account violation|copyright violation)\b/i,

            /\b(account|profile)\b.{0,35}\b(urgent verification required|permanently disabled)\b/i
        ]
    },

    {
        id: "credential_request",
        label: "Request for password, login code or OTP",
        severity: "critical",
        patterns: [
            /\b(password|login code|verification code|otp|two.factor code)\b.{0,45}\b(send|share|tell|reply|confirm|provide)\b/i,

            /\b(send|share|tell|reply|confirm|provide)\b.{0,45}\b(password|login code|verification code|otp)\b/i
        ]
    },

    {
        id: "giveaway_or_prize",
        label: "Unexpected giveaway, prize or lottery winning claim",
        severity: "medium",
        patterns: [
            /\b(you have won|winner|giveaway|claim your prize|free gift|lottery winner)\b/i,

            /\b(aap jeet gaye|inaam jeeta|free gift|prize claim)\b/i
        ]
    },

    {
        id: "advance_payment",
        label: "Advance payment request for a prize, promotion or collaboration",
        severity: "high",
        patterns: [
            /\b(pay|send|transfer)\b.{0,45}\b(processing fee|release fee|delivery fee|collaboration fee|verification fee)\b/i,

            /\b(prize|giveaway|brand deal)\b.{0,40}\b(fee|deposit|payment)\b/i
        ]
    },

    {
        id: "investment_promotion",
        label: "Guaranteed investment profit or suspicious trading promotion",
        severity: "high",
        patterns: [
            /\b(guaranteed|risk.free|sure)\b.{0,35}\b(profit|returns|income|crypto gains)\b/i,

            /\b(double your money|daily profit|crypto signals)\b/i,

            /\b(investment opportunity)\b.{0,40}\b(guaranteed|risk.free|fixed return)\b/i
        ]
    },

    {
        id: "urgent_private_contact",
        label: "Pressure to move communication to private chat urgently",
        severity: "medium",
        patterns: [
            /\b(message me privately|dm me now|move to whatsapp|contact me urgently)\b/i,

            /\b(private mein message|abhi dm karo|whatsapp par aao|turant contact karo)\b/i
        ]
    },

    {
        id: "suspicious_link",
        label: "Instruction to open a link for login, verification or prize claims",
        severity: "medium",
        patterns: [
            /\b(click|tap|open|visit)\b.{0,30}\b(link|bio|here|website)\b/i,

            /\b(login|verify|claim|recover)\b.{0,35}\b(through this link|using this link)\b/i
        ]
    },

    {
        id: "secrecy",
        label: "Request to keep an offer or conversation secret",
        severity: "high",
        patterns: [
            /\b(keep this between us|do not tell anyone|private offer|secret deal)\b/i,

            /\b(kisi ko mat batao|secret deal|sirf tumhare liye)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeSocialMediaInput(input) {
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
            input.post,
            input.profileText
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

function extractSocialMediaEvidence(text, patterns) {
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

function generateSocialMediaAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "Profile username aur contact details independently verify karein.",
        "Password, OTP ya login code kisi DM, comment ya unknown contact ke saath share na karein.",
        "Prize, giveaway ya promotion ke liye advance payment karne se pehle brand ke official contact se confirm karein."
    ];

    if (ids.has("account_threat")) {
        advice.push(
            "Account suspension warning ko message link se nahi, platform ki official application ya website par check karein."
        );
    }

    if (ids.has("suspicious_link")) {
        advice.push(
            "Unknown links par login details, OTP ya personal information enter na karein."
        );
    }

    if (ids.has("advance_payment")) {
        advice.push(
            "Prize ya collaboration release karne ke naam par unexpected advance payment maangne wale contact ko independently verify karein."
        );
    }

    if (ids.has("investment_promotion")) {
        advice.push(
            "Social media investment claims ko independent sources se verify karein; guaranteed profit claims par bina verification bharosa na karein."
        );
    }

    if (ids.has("impersonation")) {
        advice.push(
            "Claimed person, organization ya support team ko independently verified contact channel se confirm karein."
        );
    }

    if (ids.has("secrecy")) {
        advice.push(
            "Suspicious financial ya personal requests ko trusted person ke saath discuss karein."
        );
    }

    return advice;
}

/* =========================================================
   MAIN SOCIAL MEDIA INDICATOR ANALYZER
========================================================= */

/**
 * @param {
 *   string |
 *   {
 *     message?: string,
 *     post?: string,
 *     profileText?: string
 *   }
 * } input
 *
 * @returns {Object}
 */

function scanSocialMedia(input) {
    const text = normalizeSocialMediaInput(input);

    if (!text) {
        throw new TypeError(
            "Scan karne ke liye social media message ya post enter karein."
        );
    }

    if (text.length > MAX_SOCIAL_MEDIA_INPUT_LENGTH) {
        throw new RangeError(
            `Input maximum ${MAX_SOCIAL_MEDIA_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of SOCIAL_MEDIA_RULES) {
        const evidence = extractSocialMediaEvidence(
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

        categoryHint: "social_media_scam",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential social media fraud indicators identified.`
            : "No matching social media fraud indicators identified.",

        advice: generateSocialMediaAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield Social Media Fraud Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "social_media_message_post_or_profile",
            rulesChecked: SOCIAL_MEDIA_RULES.length,
            accountIdentityVerified: false,
            profileOwnershipVerified: false,
            brandVerified: false,
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
        scanSocialMedia,
        normalizeSocialMediaInput,
        extractSocialMediaEvidence,
        generateSocialMediaAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldSocialMediaScanner = {
        scanSocialMedia,
        normalizeSocialMediaInput,
        extractSocialMediaEvidence,
        generateSocialMediaAdvice
    };
}