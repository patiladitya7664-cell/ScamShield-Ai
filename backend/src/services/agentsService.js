
"use strict";

// =====================================================
// SCAMSHIELD AI - MULTI AGENT SERVICE
// Version: 2.0.0
//
// Responsibilities:
// 1. Preserve existing Guardian analysis.
// 2. Normalize Intelligence indicators.
// 3. Prepare Victim Safety recommendations.
// 4. Keep Decoy disabled by default.
//
// IMPORTANT:
// This service does not perform duplicate fraud detection.
// Guardian's Python analysis remains authoritative.
// =====================================================


// =====================================================
// 1. CONSTANTS
// =====================================================

const RISK_LEVELS = [
    "low",
    "medium",
    "high",
    "critical",
];

const DETECTION_CATEGORIES = [
    "fraud_message",
    "fraud_call",
    "url_phishing",
    "email_scam",
    "investment_scam",
    "digital_arrest",
    "upi_banking_fraud",
    "card_fraud",
    "ecommerce_scam",
    "job_loan_scam",
    "sextortion_blackmail",
    "social_media_scam",
];

const CATEGORY_TO_MODULE = {
    investment_scam: "investment",
    digital_arrest: "digitalArrest",
    card_fraud: "creditCard",
    sextortion_blackmail: "sextortion",
    ecommerce_scam: "ecommerce",

    fraud_message: "other",
    fraud_call: "other",
    url_phishing: "other",
    email_scam: "other",
    upi_banking_fraud: "other",
    job_loan_scam: "other",
    social_media_scam: "other",
};


// =====================================================
// 2. GENERAL HELPERS
// =====================================================

const safeObject = (value) => {
    return (
        value &&
        typeof value === "object" &&
        !Array.isArray(value)
    )
        ? value
        : {};
};

const safeArray = (value) => {
    return Array.isArray(value) ? value : [];
};

const safeString = (value, fallback = "") => {
    return typeof value === "string"
        ? value.trim()
        : fallback;
};

const normalizeCategory = (value) => {
    const category = safeString(value)
        .toLowerCase();

    return DETECTION_CATEGORIES.includes(category)
        ? category
        : null;
};

const normalizeRiskLevel = (value) => {
    const level = safeString(value)
        .toLowerCase();

    return RISK_LEVELS.includes(level)
        ? level
        : null;
};

const uniqueStrings = (values) => {
    return [
        ...new Set(
            values
                .filter((value) => typeof value === "string")
                .map((value) => value.trim())
                .filter(Boolean)
        ),
    ];
};


// =====================================================
// 3. ANALYSIS VALIDATION
// =====================================================

const validateAnalysis = (analysis) => {
    if (
        !analysis ||
        typeof analysis !== "object" ||
        Array.isArray(analysis)
    ) {
        throw new Error(
            "A valid AI analysis result is required."
        );
    }

    if (
        typeof analysis.riskScore !== "number" ||
        !Number.isFinite(analysis.riskScore) ||
        analysis.riskScore < 0 ||
        analysis.riskScore > 100
    ) {
        throw new Error(
            "Invalid risk score received from AI analysis."
        );
    }

    const riskLevel = normalizeRiskLevel(
        analysis.riskLevel
    );

    if (!riskLevel) {
        throw new Error(
            "Invalid risk level received from AI analysis."
        );
    }

    const detectionCategory = normalizeCategory(
        analysis.detectionCategory ||
        analysis.category ||
        analysis.guardian?.fraudCategory
    );

    if (!detectionCategory) {
        throw new Error(
            "Valid Guardian detection category is required."
        );
    }

    return {
        riskLevel,
        detectionCategory,
    };
};


// =====================================================
// 4. GUARDIAN AGENT
// =====================================================

const guardianAgent = (analysis) => {
    const {
        riskLevel,
        detectionCategory,
    } = validateAnalysis(analysis);

    const existingGuardian = safeObject(
        analysis.agents?.guardian
    );

    return {
        agent: "Guardian Agent",

        // The Guardian result is already produced
        // by the authoritative Python AI pipeline.
        status: "completed",

        fraudCategory:
            analysis.fraudCategory ||
            CATEGORY_TO_MODULE[detectionCategory],

        detectionCategory,

        riskScore: analysis.riskScore,

        riskLevel,

        detectedRules: safeArray(
            analysis.detectedRules
        ),

        summary: safeString(
            analysis.summary
        ),

        analysisMethod: safeString(
            analysis.analysisMethod,
            "python_ai_engine"
        ),

        authority: "guardian",

        authoritative: true,

        pythonResult: existingGuardian,
    };
};


// =====================================================
// 5. INTELLIGENCE AGENT
// =====================================================

const intelligenceAgent = (analysis) => {
    const existingIntelligence = safeObject(
        analysis.agents?.intelligence
    );

    const rawIndicators = safeArray(
        analysis.indicators
    );

    const indicators = rawIndicators
        .filter(
            (item) =>
                item &&
                typeof item === "object" &&
                !Array.isArray(item)
        )
        .map((item) => ({
            type: safeString(
                item.type ||
                item.indicator_type ||
                item.indicatorType,
                "unknown"
            ).slice(0, 30),

            value: safeString(
                item.value ||
                item.indicator
            ).slice(0, 500),

            // Extracted indicators are not independently verified.
            verified: false,
        }))
        .filter((item) => item.value)
        .slice(0, 50);

    const indicatorTypes = uniqueStrings(
        indicators.map((item) => item.type)
    );

    return {
        agent: "Intelligence Agent",

        status:
            Object.keys(existingIntelligence).length > 0
                ? safeString(
                    existingIntelligence.status,
                    "completed"
                )
                : "completed",

        totalIndicators: indicators.length,

        indicators,

        indicatorTypes,

        verificationStatus: "unverified",

        externallyVerified: false,

        message:
            "Extracted indicators are clues only. Their ownership, reputation and involvement have not been independently verified.",

        pythonResult: existingIntelligence,
    };
};


// =====================================================
// 6. VICTIM SAFETY AGENT
// =====================================================

const victimSafetyAgent = (analysis) => {
    const {
        riskLevel,
        detectionCategory,
    } = validateAnalysis(analysis);

    const existingSafety = safeObject(
        analysis.agents?.victimSafety ||
        analysis.agents?.victim_safety
    );

    const pythonRecommendations = safeArray(
        analysis.recommendations
    );

    const agentRecommendations = safeArray(
        existingSafety.recommendations
    );

    // Prefer recommendations already generated by Python.
    const suppliedRecommendations =
        pythonRecommendations.length > 0
            ? pythonRecommendations
            : agentRecommendations;

    let recommendations = suppliedRecommendations
        .filter(
            (item) => typeof item === "string"
        )
        .map((item) => item.trim())
        .filter(Boolean);

    // Generate basic safety guidance only when
    // Python did not provide recommendations.
    if (recommendations.length === 0) {
        recommendations = [
            "Do not share OTPs, PINs, CVV, passwords or banking credentials.",
            "Do not transfer money under pressure or urgency.",
            "Verify suspicious messages using independently obtained official contact details.",
        ];

        const categoryRecommendations = {
            digital_arrest: [
                "Do not make payments in response to threats of digital arrest. Preserve evidence and independently contact the appropriate authorities.",
            ],

            investment_scam: [
                "Do not invest based on guaranteed-return claims. Independently verify the organization and applicable regulatory registration.",
            ],

            card_fraud: [
                "Contact your bank using its official number if card details or payment credentials may have been exposed.",
            ],

            upi_banking_fraud: [
                "Never enter a UPI PIN to receive money. Contact your bank immediately if an unauthorized transaction occurs.",
            ],

            sextortion_blackmail: [
                "Do not comply with blackmail demands. Preserve relevant evidence and report the incident.",
            ],

            ecommerce_scam: [
                "Use the marketplace's official payment and dispute-resolution process. Avoid unprotected off-platform payments.",
            ],

            job_loan_scam: [
                "Verify the employer or lender independently. Be cautious of advance fees and requests for sensitive credentials.",
            ],

            url_phishing: [
                "Do not enter credentials or payment information on a suspicious website. Navigate to the official website independently.",
            ],

            email_scam: [
                "Do not open unexpected attachments or follow suspicious links. Verify the sender through a separate trusted channel.",
            ],

            fraud_call: [
                "End suspicious calls requesting money or confidential information and contact the organization using an independently verified number.",
            ],

            fraud_message: [
                "Do not follow payment or credential instructions in an unverified message.",
            ],

            social_media_scam: [
                "Verify suspicious accounts through a separate trusted channel before sending money or sharing personal information.",
            ],
        };

        recommendations.push(
            ...(categoryRecommendations[detectionCategory] || [])
        );

        if (
            riskLevel === "high" ||
            riskLevel === "critical"
        ) {
            recommendations.push(
                "Pause further interaction. If money or sensitive credentials have been exposed, contact your bank and the appropriate reporting authority promptly."
            );
        }
    }

    recommendations = uniqueStrings(
        recommendations
    ).slice(0, 30);

    return {
        agent: "Victim Safety Agent",

        status: "completed",

        safetyLevel: riskLevel,

        recommendations,

        totalRecommendations: recommendations.length,

        automaticActionTaken: false,

        pythonResult: existingSafety,
    };
};


// =====================================================
// 7. DECOY AGENT
// =====================================================

const decoyAgent = (analysis = {}) => {
    const existingDecoy = safeObject(
        analysis.agents?.decoy
    );

    // Never start a simulation from normal analysis.
    return {
        agent: "Decoy Agent",

        status: "not_started",

        message:
            "Controlled simulation requires a separate explicit user-controlled operation.",

        simulationEnabled: false,

        simulationOnly: true,

        automaticExecution: false,

        pythonResult: existingDecoy,
    };
};


// =====================================================
// 8. MAIN AGENT RESULT PREPARATION
// =====================================================

const executeAgents = async (analysis) => {
    validateAnalysis(analysis);

    const [
        guardian,
        intelligence,
        victimSafety,
        decoy,
    ] = await Promise.all([
        Promise.resolve(
            guardianAgent(analysis)
        ),

        Promise.resolve(
            intelligenceAgent(analysis)
        ),

        Promise.resolve(
            victimSafetyAgent(analysis)
        ),

        Promise.resolve(
            decoyAgent(analysis)
        ),
    ]);

    return {
        guardian,
        intelligence,
        victimSafety,
        decoy,
    };
};


// =====================================================
// 9. EXPORTS
// =====================================================

module.exports = {
    executeAgents,

    guardianAgent,

    intelligenceAgent,

    victimSafetyAgent,

    decoyAgent,

    validateAnalysis,
};
