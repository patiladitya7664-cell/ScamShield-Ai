"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * E-COMMERCE FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Detects potential indicators:
 * 1. Unrealistic discounts
 * 2. Off-platform payment requests
 * 3. Suspicious advance fees
 * 4. Unexpected delivery links
 * 5. OTP / PIN / CVV requests
 * 6. Urgent purchase pressure
 * 7. Fake refund requests
 *
 * IMPORTANT:
 * - Local rule-based indicator analysis only.
 * - Does not verify sellers or products.
 * - Does not verify marketplace accounts.
 * - Does not verify website reputation.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_ECOMMERCE_INPUT_LENGTH = 15000;

const ECOMMERCE_RULES = [
    {
        id: "unrealistic_discount",
        label: "Unusually large discount or unrealistic price claim",
        severity: "medium",
        patterns: [
            /\b(up to )?(90|95|99)\s*%\s*(off|discount)\b/i,

            /\b(too good to be true|lowest price ever|almost free|unbelievable deal)\b/i,

            /\b(90|95|99)\s*%\s*(chhoot|discount)\b/i
        ]
    },

    {
        id: "off_platform_payment",
        label: "Request to make payment outside the marketplace",
        severity: "high",
        patterns: [
            /\b(pay|transfer|send)\b.{0,45}\b(outside the platform|directly to my account|personal account|personal upi)\b/i,

            /\b(platform ke bahar|personal upi|direct account)\b.{0,40}\b(payment|paise|bhejo)\b/i,

            /\b(whatsapp|telegram)\b.{0,40}\b(send payment|pay me|transfer money|personal upi)\b/i
        ]
    },

    {
        id: "advance_fee",
        label: "Unexpected additional delivery, customs or insurance fee",
        severity: "high",
        patterns: [
            /\b(pay|send|transfer)\b.{0,40}\b(delivery fee|customs fee|insurance fee|release fee|parcel charge)\b/i,

            /\b(delivery|parcel|package)\b.{0,40}\b(customs|insurance|release)\b.{0,30}\b(fee|payment|charge)\b/i
        ]
    },

    {
        id: "fake_delivery_link",
        label: "Unexpected delivery or parcel confirmation request",
        severity: "medium",
        patterns: [
            /\b(delivery|parcel|package|shipment)\b.{0,45}\b(track|reschedule|confirm address|delivery fee)\b/i,

            /\b(click|open|visit)\b.{0,35}\b(delivery link|parcel link|tracking link)\b/i,

            /\b(address confirmation|parcel release|delivery confirmation)\b.{0,40}\b(link|payment|otp)\b/i
        ]
    },

    {
        id: "payment_or_otp_request",
        label: "OTP, card PIN, CVV or UPI PIN disclosure request",
        severity: "critical",
        patterns: [
            /\b(otp|one.time.password|cvv|card pin|upi pin)\b.{0,45}\b(share|send|tell|confirm|provide)\b/i,

            /\b(share|send|tell|confirm|provide)\b.{0,45}\b(otp|one.time.password|cvv|card pin|upi pin)\b/i,

            /\b(otp|upi pin|cvv)\b.{0,35}\b(batao|bhejo|share karo)\b/i
        ]
    },

    {
        id: "urgent_offer",
        label: "Pressure to order or make payment immediately",
        severity: "medium",
        patterns: [
            /\b(only today|limited time|pay now|last chance|offer expires soon|hurry)\b/i,

            /\b(sirf aaj|abhi order|jaldi payment|offer khatam)\b/i
        ]
    },

    {
        id: "fake_refund",
        label: "Payment or banking details requested for a refund",
        severity: "high",
        patterns: [
            /\b(refund|cashback)\b.{0,45}\b(pay|fee|otp|pin|cvv|bank details|click)\b/i,

            /\b(pay|share|enter)\b.{0,40}\b(refund|cashback)\b/i,

            /\b(refund|cashback)\b.{0,45}\b(upi pin|card pin|password)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeEcommerceInput(input) {
    if (typeof input === "string") {
        return input.trim();
    }

    if (input && typeof input === "object") {
        return [
            input.message,
            input.listing,
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

function extractEcommerceEvidence(text, patterns) {
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

function generateEcommerceAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "Make payments through the marketplace's official checkout whenever possible.",
        "Independently review seller information, reviews and return policies.",
        "Never share OTP, UPI PIN, card PIN or CVV with a seller or delivery agent."
    ];

    if (ids.has("off_platform_payment")) {
        advice.push(
            "Avoid transferring money outside the marketplace because buyer protection may not apply."
        );
    }

    if (ids.has("fake_delivery_link")) {
        advice.push(
            "Check parcel status directly through the courier's official website or application."
        );
    }

    if (ids.has("advance_fee")) {
        advice.push(
            "Verify unexpected customs, insurance or parcel charges directly with the official courier."
        );
    }

    if (ids.has("fake_refund")) {
        advice.push(
            "A refund should not require disclosing your OTP, UPI PIN or card security credentials."
        );
    }

    if (ids.has("payment_or_otp_request")) {
        advice.push(
            "Stop the transaction if someone requests confidential banking credentials."
        );
    }

    return advice;
}

/* =========================================================
   MAIN E-COMMERCE INDICATOR ANALYZER
========================================================= */

/**
 * Analyze a product listing or seller message.
 *
 * @param {string|object} input
 * @returns {Object}
 */
function scanEcommerce(input) {
    const text = normalizeEcommerceInput(input);

    if (!text) {
        throw new TypeError(
            "Product listing ya seller message enter karein."
        );
    }

    if (text.length > MAX_ECOMMERCE_INPUT_LENGTH) {
        throw new RangeError(
            `Input maximum ${MAX_ECOMMERCE_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of ECOMMERCE_RULES) {
        const evidence = extractEcommerceEvidence(
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

        categoryHint: "ecommerce_scam",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential e-commerce fraud indicators identified.`
            : "No matching e-commerce fraud indicators identified.",

        advice: generateEcommerceAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield E-commerce Fraud Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "product_listing_or_seller_message",
            rulesChecked: ECOMMERCE_RULES.length,
            sellerVerified: false,
            productVerified: false,
            websiteReputationVerified: false,
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
        scanEcommerce,
        normalizeEcommerceInput,
        extractEcommerceEvidence,
        generateEcommerceAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldEcommerceScanner = {
        scanEcommerce,
        normalizeEcommerceInput,
        extractEcommerceEvidence,
        generateEcommerceAdvice
    };
}