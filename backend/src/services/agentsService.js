"use strict";

// =====================================================
// SCAMSHIELD AI - MULTI AGENT SERVICE
//
// 1. Guardian Agent
// 2. Intelligence Agent
// 3. Victim Safety Agent
// 4. Decoy Agent
//
// This service receives an existing AI analysis result.
// It does not run duplicate fraud detection.
// =====================================================

// =====================================================
// 1. GUARDIAN AGENT
// =====================================================

const guardianAgent = (analysis) => {
    return {
        agent: "Guardian Agent",
        status: "completed",

        fraudCategory: analysis.fraudCategory,
        riskScore: analysis.riskScore,
        riskLevel: analysis.riskLevel,

        detectedRules: analysis.detectedRules || [],
        summary: analysis.summary || "",
    };
};

// =====================================================
// 2. INTELLIGENCE AGENT
// =====================================================

const intelligenceAgent = (analysis) => {
    const indicators = Array.isArray(analysis.indicators)
        ? analysis.indicators
        : [];

    return {
        agent: "Intelligence Agent",
        status: "completed",

        totalIndicators: indicators.length,
        indicators,

        indicatorTypes: [
            ...new Set(
                indicators
                    .map((item) => item.type)
                    .filter(Boolean)
            ),
        ],

        verificationStatus: "unverified",

        message:
            "Extracted indicators are clues only. They have not been independently verified.",
    };
};

// =====================================================
// 3. VICTIM SAFETY AGENT
// =====================================================

const victimSafetyAgent = (analysis) => {
    const recommendations = [];

    recommendations.push(
        "Do not share OTP, PIN, CVV, passwords or banking credentials."
    );

    recommendations.push(
        "Do not transfer money under pressure or urgency."
    );

    recommendations.push(
        "Verify suspicious messages through official websites or customer support."
    );

    const fraudCategory = String(
        analysis.fraudCategory || ""
    ).toLowerCase();

    const riskLevel = String(
        analysis.riskLevel || ""
    ).toLowerCase();

    // Digital arrest
    if (
        fraudCategory === "digitalarrest" ||
        fraudCategory === "digital_arrest"
    ) {
        recommendations.push(
            "Real law enforcement agencies do not conduct digital arrest through video calls or demand payments."
        );
    }

    // Investment fraud
    if (
        fraudCategory === "investment" ||
        fraudCategory === "investment_scam"
    ) {
        recommendations.push(
            "Avoid guaranteed-return investment offers. Verify the organization and its regulatory registration independently."
        );
    }

    // Credit card fraud
    if (
        fraudCategory === "creditcard" ||
        fraudCategory === "credit_card_fraud"
    ) {
        recommendations.push(
            "Never share card credentials or banking verification codes with callers or unknown websites."
        );
    }

    // Sextortion
    if (fraudCategory === "sextortion") {
        recommendations.push(
            "Do not make payments under blackmail threats. Preserve evidence and report the incident."
        );
    }

    // E-commerce fraud
    if (
        fraudCategory === "ecommerce" ||
        fraudCategory === "online_shopping_fraud"
    ) {
        recommendations.push(
            "Use trusted shopping platforms and avoid payments outside their official payment systems."
        );
    }

    // High-risk cases
    if (
        riskLevel === "high" ||
        riskLevel === "critical"
    ) {
        recommendations.push(
            "Stop interacting with the suspicious source and report the incident to the appropriate authorities."
        );
    }

    return {
        agent: "Victim Safety Agent",
        status: "completed",

        recommendations,
        totalRecommendations: recommendations.length,
    };
};

// =====================================================
// 4. DECOY AGENT
// =====================================================

const decoyAgent = () => {
    return {
        agent: "Decoy Agent",

        status: "not_configured",

        message:
            "Controlled scam simulation is not configured yet.",

        simulationEnabled: false,
    };
};

// =====================================================
// 5. MAIN AGENT EXECUTION
// =====================================================

const executeAgents = async (analysis) => {
    if (!analysis || typeof analysis !== "object") {
        throw new Error(
            "A valid analysis result is required to execute agents."
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

    if (!analysis.riskLevel || !analysis.fraudCategory) {
        throw new Error(
            "Analysis result is missing risk level or fraud category."
        );
    }

    // Execute all four agents.
    const [
        guardian,
        intelligence,
        victimSafety,
        decoy,
    ] = await Promise.all([
        Promise.resolve(guardianAgent(analysis)),
        Promise.resolve(intelligenceAgent(analysis)),
        Promise.resolve(victimSafetyAgent(analysis)),
        Promise.resolve(decoyAgent()),
    ]);

    return {
        guardian,
        intelligence,
        victimSafety,
        decoy,
    };
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    executeAgents,

    guardianAgent,
    intelligenceAgent,
    victimSafetyAgent,
    decoyAgent,
};