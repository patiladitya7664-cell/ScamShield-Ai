"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * URL PHISHING INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Detects potential URL indicators:
 * 1. Non-HTTPS protocol
 * 2. IP address used as hostname
 * 3. URL credentials / userinfo
 * 4. Punycode hostname
 * 5. Multiple subdomains
 * 6. Less-common TLD
 * 7. Known URL shortener
 * 8. Known brand name in a subdomain
 *
 * IMPORTANT:
 * - Rule-based URL structure analysis only.
 * - Does not visit the website.
 * - Does not follow redirects.
 * - Does not check domain reputation.
 * - Does not verify website ownership.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_URL_INPUT_LENGTH = 2048;

const SHORTENER_HOSTS = new Set([
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly"
]);

const LESS_COMMON_TLDS = new Set([
    "zip",
    "mov",
    "top",
    "click",
    "work",
    "country",
    "gq",
    "tk",
    "ml",
    "cf"
]);

const KNOWN_BRANDS = [
    "google",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "facebook",
    "instagram",
    "whatsapp",
    "netflix",
    "telegram",
    "sbi",
    "hdfc",
    "icici",
    "axisbank",
    "paytm"
];

const URL_RULES = [
    {
        id: "non_https",
        label: "URL uses HTTP instead of HTTPS",
        severity: "low"
    },
    {
        id: "ip_address_host",
        label: "Website uses an IP address instead of a domain name",
        severity: "high"
    },
    {
        id: "userinfo_present",
        label: "URL contains embedded username or password information",
        severity: "high"
    },
    {
        id: "punycode_domain",
        label: "Hostname contains an encoded internationalized domain label",
        severity: "medium"
    },
    {
        id: "many_subdomains",
        label: "Hostname contains an unusually large number of subdomains",
        severity: "low"
    },
    {
        id: "uncommon_tld",
        label: "Hostname uses a less-common top-level domain",
        severity: "low"
    },
    {
        id: "shortened_url",
        label: "URL belongs to a known URL-shortening service",
        severity: "medium"
    },
    {
        id: "brand_in_subdomain",
        label: "Known brand name appears inside a subdomain",
        severity: "high"
    }
];

/* =========================================================
   URL NORMALIZATION
========================================================= */

function normalizeUrl(input) {
    if (typeof input !== "string") {
        throw new TypeError(
            "URL text ke roop mein enter karein."
        );
    }

    const trimmed = input.trim();

    if (!trimmed) {
        throw new TypeError(
            "Scan karne ke liye URL enter karein."
        );
    }

    if (trimmed.length > MAX_URL_INPUT_LENGTH) {
        throw new RangeError(
            `URL maximum ${MAX_URL_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    let candidate = trimmed;

    if (/^https?:\/\//i.test(candidate)) {
        // Keep the supplied HTTP or HTTPS URL.
    } else if (/^[a-z][a-z\d+.-]*:/i.test(candidate)) {
        throw new TypeError(
            "Sirf HTTP ya HTTPS links scan kiye ja sakte hain."
        );
    } else {
        candidate = `https://${candidate}`;
    }

    let parsed;

    try {
        parsed = new URL(candidate);
    } catch {
        throw new TypeError(
            "Yeh valid URL nahi lagta. URL ko dobara check karein."
        );
    }

    if (
        parsed.protocol !== "http:" &&
        parsed.protocol !== "https:"
    ) {
        throw new TypeError(
            "Sirf HTTP ya HTTPS links scan kiye ja sakte hain."
        );
    }

    if (!parsed.hostname) {
        throw new TypeError(
            "URL mein valid hostname nahi mila."
        );
    }

    return parsed;
}

/* =========================================================
   IP ADDRESS DETECTION
========================================================= */

function isIpv4(hostname) {
    const parts = hostname.split(".");

    if (parts.length !== 4) {
        return false;
    }

    return parts.every((part) => {
        if (!/^\d{1,3}$/.test(part)) {
            return false;
        }

        const value = Number(part);

        return value >= 0 && value <= 255;
    });
}

function isIpv6(hostname) {
    const value = hostname.replace(/^\[|\]$/g, "");

    if (!value.includes(":")) {
        return false;
    }

    return /^[\da-f:.]+$/i.test(value);
}

function isIpAddress(hostname) {
    return isIpv4(hostname) || isIpv6(hostname);
}

/* =========================================================
   BRAND SUBDOMAIN DETECTION
========================================================= */

function containsKnownBrandInSubdomain(labels) {
    if (labels.length < 3) {
        return false;
    }

    // Approximation only:
    // The final two labels are treated as the registered domain.
    // This is not a Public Suffix List implementation.

    const subdomainLabels = labels.slice(0, -2);

    return subdomainLabels.some((label) =>
        KNOWN_BRANDS.some((brand) => {
            return label === brand ||
                label.startsWith(`${brand}-`) ||
                label.endsWith(`-${brand}`);
        })
    );
}

/* =========================================================
   FINDING HELPERS
========================================================= */

function getRule(id) {
    return URL_RULES.find((rule) => rule.id === id);
}

function addFinding(findings, id, evidence) {
    const rule = getRule(id);

    if (!rule) {
        return;
    }

    findings.push({
        id: rule.id,
        label: rule.label,
        severity: rule.severity,
        evidence: String(evidence).slice(0, 300)
    });
}

/* =========================================================
   MAIN URL INDICATOR ANALYZER
========================================================= */

/**
 * @param {string} input
 *
 * @returns {Object}
 */

function scanUrl(input) {
    const parsed = normalizeUrl(input);

    const hostname = parsed.hostname.toLowerCase();

    const labels = hostname
        .replace(/^\[|\]$/g, "")
        .split(".")
        .filter(Boolean);

    const findings = [];

    // HTTP protocol is a security concern, not proof of phishing.
    if (parsed.protocol !== "https:") {
        addFinding(
            findings,
            "non_https",
            `${parsed.protocol}//${hostname}`
        );
    }

    // IP address as hostname.
    if (isIpAddress(hostname)) {
        addFinding(
            findings,
            "ip_address_host",
            hostname
        );
    }

    // Only actual URL credentials are considered.
    // An @ character in the path or query is not sufficient.
    if (parsed.username || parsed.password) {
        addFinding(
            findings,
            "userinfo_present",
            `${parsed.username ? "username" : ""}${parsed.password ? " and password" : ""}`
        );
    }

    // Punycode is an informational indicator, not proof of fraud.
    if (labels.some((label) => label.startsWith("xn--"))) {
        addFinding(
            findings,
            "punycode_domain",
            hostname
        );
    }

    // Avoid applying subdomain logic to IP addresses.
    if (!isIpAddress(hostname) && labels.length >= 5) {
        addFinding(
            findings,
            "many_subdomains",
            hostname
        );
    }

    const tld = labels[labels.length - 1];

    if (LESS_COMMON_TLDS.has(tld)) {
        addFinding(
            findings,
            "uncommon_tld",
            `.${tld}`
        );
    }

    if (SHORTENER_HOSTS.has(hostname)) {
        addFinding(
            findings,
            "shortened_url",
            hostname
        );
    }

    if (
        !isIpAddress(hostname) &&
        containsKnownBrandInSubdomain(labels)
    ) {
        addFinding(
            findings,
            "brand_in_subdomain",
            hostname
        );
    }

    const advice = [
        "Link open karne se pehle domain spelling aur hostname carefully check karein.",
        "Password, OTP, UPI PIN ya payment details unknown links par enter na karein.",
        "Important accounts ke liye official website ka address khud type karke open karein.",
        "HTTPS connection hona website ki legitimacy ya safety ki guarantee nahi hai."
    ];

    const findingIds = new Set(
        findings.map((finding) => finding.id)
    );

    if (findingIds.has("shortened_url")) {
        advice.push(
            "Shortened URL ka final destination is analysis mein resolve nahi kiya gaya hai."
        );
    }

    if (findingIds.has("userinfo_present")) {
        advice.push(
            "URL mein embedded username ya password information ho sakti hai. Aise link ko open karne se pehle independently inspect karein."
        );
    }

    if (findingIds.has("brand_in_subdomain")) {
        advice.push(
            "Domain ke actual registered name ko check karein. Subdomain mein kisi brand ka naam hona official affiliation prove nahi karta."
        );
    }

    if (findingIds.has("ip_address_host")) {
        advice.push(
            "IP-address based website par sensitive banking ya account credentials enter karne se bachein."
        );
    }

    return {
        type: "indicator_analysis",

        categoryHint: "url_phishing",

        input: input.trim(),

        hostname,

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential URL security indicators identified.`
            : "No matching URL structure indicators identified.",

        advice,

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield URL Phishing Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "url",
            rulesChecked: URL_RULES.length,
            websiteVisited: false,
            redirectsFollowed: false,
            domainReputationChecked: false,
            urlDestinationVerified: false,
            websiteOwnershipVerified: false,
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
        scanUrl,
        normalizeUrl,
        isIpv4,
        isIpv6,
        isIpAddress,
        containsKnownBrandInSubdomain
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldUrlScanner = {
        scanUrl,
        normalizeUrl,
        isIpv4,
        isIpv6,
        isIpAddress,
        containsKnownBrandInSubdomain
    };
}