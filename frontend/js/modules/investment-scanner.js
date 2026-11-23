"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * INVESTMENT FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Detects potential indicators:
 * 1. Guaranteed or risk-free returns
 * 2. Unrealistic profit promises
 * 3. Urgent investment pressure
 * 4. Recruitment-based income schemes
 * 5. Suspicious crypto/trading claims
 * 6. Personal account payment requests
 * 7. Withdrawal and release fee requests
 * 8. Unclear registration and documentation claims
 *
 * IMPORTANT:
 * - Rule-based indicator analysis only.
 * - Does not verify investment legitimacy.
 * - Does not verify financial registration.
 * - Does not provide financial advice.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_INVESTMENT_INPUT_LENGTH = 15000;

const INVESTMENT_RULES = [
    {
        id: "guaranteed_returns",
        label: "Guaranteed or risk-free profit promises",
        severity: "high",
        patterns: [
            /\b(guaranteed|guarantee|risk.free|no risk|fixed return|assured return)\b.{0,50}\b(profit|return|income|growth)\b/i,

            /\b(double|triple|10x|100%)\b.{0,30}\b(your money|investment|capital|returns)\b/i,

            /\b(pakka munafa|guaranteed profit|bina risk|fixed return)\b/i
        ]
    },

    {
        id: "unrealistic_returns",
        label: "Unusually high or rapid return promises",
        severity: "high",
        patterns: [
            /\b\d{1,3}\s*%\s*(daily|weekly|monthly|per month|every day)\b/i,

            /\b(double your money|quick profits|instant returns|high returns)\b/i,

            /\b(rozana|har din|har mahine)\b.{0,30}\b(munafa|return|profit)\b/i
        ]
    },

    {
        id: "urgent_investment",
        label: "Pressure to invest immediately",
        severity: "medium",
        patterns: [
            /\b(invest now|limited time|offer expires|last chance|only today|act immediately)\b/i,

            /\b(abhi invest|sirf aaj|mauka haath se|turant paisa lagao)\b/i
        ]
    },

    {
        id: "recruitment_scheme",
        label: "Income claims based on recruiting new members",
        severity: "medium",
        patterns: [
            /\b(refer|recruit|bring|add)\b.{0,40}\b(members|people|investors|friends)\b/i,

            /\b(downline|referral income|multi.level|pyramid scheme)\b/i,

            /\b(log jodo|member banao|referral se kamai)\b/i
        ]
    },

    {
        id: "crypto_or_trading_claim",
        label: "Guaranteed profit claims involving crypto or trading",
        severity: "high",
        patterns: [
            /\b(crypto|bitcoin|forex|trading bot|signals)\b.{0,50}\b(guaranteed|risk.free|fixed profit|sure returns)\b/i,

            /\b(crypto|bitcoin|forex)\b.{0,50}\b(double your money|daily income|assured return)\b/i
        ]
    },

    {
        id: "personal_account_payment",
        label: "Request to transfer investment money to a personal account or wallet",
        severity: "high",
        patterns: [
            /\b(send|transfer|deposit|pay)\b.{0,50}\b(personal account|private wallet|individual account|personal upi)\b/i,

            /\b(personal upi|private wallet|personal account)\b.{0,40}\b(paisa|payment|transfer|deposit)\b/i
        ]
    },

    {
        id: "withdrawal_fee",
        label: "Additional payment requested to release investment funds",
        severity: "high",
        patterns: [
            /\b(pay|deposit|send)\b.{0,40}\b(withdrawal fee|release fee|unlock fee|tax to withdraw)\b/i,

            /\b(withdraw|release|unlock)\b.{0,40}\b(fee|tax|charge|deposit)\b/i
        ]
    },

    {
        id: "unregistered_claim",
        label: "Investment offer with unclear registration or documentation",
        severity: "medium",
        patterns: [
            /\b(no paperwork|no documents|no registration|secret investment|private investment group)\b/i,

            /\b(no need for documents|without registration|no legal formalities)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeInvestmentInput(input) {
    if (typeof input === "string") {
        return input.trim();
    }

    if (input && typeof input === "object" && !Array.isArray(input)) {
        return [
            input.message,
            input.offer,
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

function extractInvestmentEvidence(text, patterns) {
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

function generateInvestmentAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "Investment company aur product ko relevant official regulator ke records mein independently verify karein.",
        "Promised returns ke saath fees, withdrawal conditions aur risk disclosures bhi carefully check karein.",
        "Payment karne se pehle beneficiary aur payment details ko official company channels se verify karein.",
        "Sirf screenshots, testimonials ya social media claims par bharosa karke investment na karein."
    ];

    if (ids.has("guaranteed_returns") || ids.has("unrealistic_returns")) {
        advice.push(
            "Guaranteed ya unusually high returns ke claims ko independently verify kiye bina accept na karein."
        );
    }

    if (ids.has("recruitment_scheme")) {
        advice.push(
            "Agar earning primarily naye members recruit karne par depend karti hai, toh scheme ki structure aur legality carefully examine karein."
        );
    }

    if (ids.has("crypto_or_trading_claim")) {
        advice.push(
            "Trading bots aur crypto profit claims ko verified performance records aur independent sources se check karein."
        );
    }

    if (ids.has("personal_account_payment")) {
        advice.push(
            "Unknown personal UPI IDs, bank accounts ya private wallets mein investment transfer karne se pehle extra verification karein."
        );
    }

    if (ids.has("withdrawal_fee")) {
        advice.push(
            "Funds release karne ke naam par additional payment maangne par transaction rok kar official provider se independently confirm karein."
        );
    }

    if (ids.has("unregistered_claim")) {
        advice.push(
            "Relevant financial regulator ke official records aur applicable registration requirements check karein."
        );
    }

    return advice;
}

/* =========================================================
   MAIN INVESTMENT INDICATOR ANALYZER
========================================================= */

/**
 * @param {string|{message?:string,offer?:string,details?:string}} input
 * @returns {Object}
 */

function scanInvestment(input) {
    const text = normalizeInvestmentInput(input);

    if (!text) {
        throw new TypeError(
            "Scan karne ke liye investment offer ya message enter karein."
        );
    }

    if (text.length > MAX_INVESTMENT_INPUT_LENGTH) {
        throw new RangeError(
            `Input maximum ${MAX_INVESTMENT_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of INVESTMENT_RULES) {
        const evidence = extractInvestmentEvidence(
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

        categoryHint: "investment_scam",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential investment fraud indicators identified.`
            : "No matching investment fraud indicators identified.",

        advice: generateInvestmentAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield Investment Fraud Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "investment_offer_or_message",
            rulesChecked: INVESTMENT_RULES.length,
            financialRegistrationVerified: false,
            investmentLegitimacyVerified: false,
            financialAdviceProvided: false,
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
        scanInvestment,
        normalizeInvestmentInput,
        extractInvestmentEvidence,
        generateInvestmentAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldInvestmentScanner = {
        scanInvestment,
        normalizeInvestmentInput,
        extractInvestmentEvidence,
        generateInvestmentAdvice
    };
}