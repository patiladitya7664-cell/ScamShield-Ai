"use strict";

/*
=========================================================
 SCAMSHIELD AI - ANALYSIS SERVICE
=========================================================

 Purpose:
 1. Validate submitted evidence.
 2. Detect common scam indicators.
 3. Classify potential fraud category.
 4. Calculate explainable risk score.
 5. Return structured analysis results.

 IMPORTANT:
 This is a rule-based assessment service.
 It is NOT a trained AI model.
 It does NOT prove that a person or transaction is fraudulent.

=========================================================
*/

const crypto = require("crypto");

const MAX_EVIDENCE_LENGTH = 20000;

const ALLOWED_EVIDENCE_TYPES = [
  "message",
  "url",
  "call",
  "transaction",
  "screenshot",
  "email",
];

const FRAUD_CATEGORIES = [
  "investment",
  "digitalArrest",
  "creditCard",
  "sextortion",
  "ecommerce",
  "other",
  "unclassified",
];

/*
=========================================================
 1. EVIDENCE VALIDATION
=========================================================
*/

const validateEvidence = ({ evidenceType, evidence }) => {
  if (!evidenceType || !ALLOWED_EVIDENCE_TYPES.includes(evidenceType)) {
    throw new Error("Invalid evidence type.");
  }

  if (typeof evidence !== "string") {
    throw new Error("Evidence must be provided as text.");
  }

  const normalizedEvidence = evidence.trim();

  if (!normalizedEvidence) {
    throw new Error("Evidence cannot be empty.");
  }

  if (normalizedEvidence.length > MAX_EVIDENCE_LENGTH) {
    throw new Error(
      `Evidence must not exceed ${MAX_EVIDENCE_LENGTH} characters.`,
    );
  }

  return normalizedEvidence;
};

/*
=========================================================
 2. SENSITIVE INFORMATION DETECTION
=========================================================

 Never request or expose:
 - OTP
 - PIN
 - Password
 - CVV
 - Full card credentials

 The service detects possible sensitive information and
 avoids returning the matched value.
=========================================================
*/

const detectSensitiveInformation = (text) => {
  const patterns = [
    {
      type: "possible_otp",
      regex: /\b(?:otp|one[\s-]?time password|verification code)\b/i,
    },
    {
      type: "possible_pin",
      regex: /\b(?:pin|upi pin|atm pin)\b/i,
    },
    {
      type: "possible_password",
      regex: /\bpassword\b/i,
    },
    {
      type: "possible_cvv",
      regex: /\bcvv\b|\bcvc\b/i,
    },
    {
      type: "possible_card_number",
      regex: /\b(?:\d[ -]*?){13,19}\b/,
    },
  ];

  return patterns
    .filter((item) => item.regex.test(text))
    .map((item) => ({
      type: item.type,
      message:
        "Potentially sensitive information detected. Do not share credentials or verification codes.",
    }));
};

/*
=========================================================
 3. SCAM INDICATOR DETECTION
=========================================================
*/

const SCAM_RULES = [
  {
    category: "digitalArrest",
    weight: 25,
    label: "Digital arrest threat",
    patterns: [
      /\bdigital arrest\b/i,
      /\byou are under arrest\b/i,
      /\bpolice case against you\b/i,
      /\bcbi officer\b/i,
      /\bcyber crime officer\b/i,
      /\bvideo call interrogation\b/i,
    ],
  },

  {
    category: "investment",
    weight: 20,
    label: "Unrealistic investment returns",
    patterns: [
      /\bguaranteed returns?\b/i,
      /\bdouble your money\b/i,
      /\b100% profit\b/i,
      /\brisk[- ]free investment\b/i,
      /\bquick profit\b/i,
      /\bhigh return.{0,30}low risk\b/i,
    ],
  },

  {
    category: "creditCard",
    weight: 20,
    label: "Card or banking credential request",
    patterns: [
      /\bshare.{0,20}(otp|cvv|pin)\b/i,
      /\bverify.{0,20}(card|bank account)\b/i,
      /\bcard blocked\b/i,
      /\bkyc.{0,30}(expire|update|verify)\b/i,
      /\baccount.{0,20}(blocked|suspended)\b/i,
    ],
  },

  {
    category: "sextortion",
    weight: 25,
    label: "Blackmail or intimate-content threat",
    patterns: [
      /\bsextortion\b/i,
      /\bpay.{0,30}(or|otherwise).{0,30}(leak|expose)\b/i,
      /\bshare your private photos\b/i,
      /\bleak your private video\b/i,
      /\bsend money.{0,30}(photos|video|family)\b/i,
      /\bblackmail\b/i,
    ],
  },

  {
    category: "ecommerce",
    weight: 15,
    label: "Suspicious online shopping activity",
    patterns: [
      /\bpayment successful.{0,30}no order\b/i,
      /\bpay outside the platform\b/i,
      /\badvance payment.{0,30}delivery\b/i,
      /\bfake tracking\b/i,
      /\brefund.{0,30}processing fee\b/i,
      /\bprize.{0,30}delivery charge\b/i,
    ],
  },
];

/*
=========================================================
 4. INDICATOR EXTRACTION
=========================================================
*/

const extractIndicators = (text) => {
  const indicators = [];

  const patterns = [
    {
      type: "phone",
      regex: /(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
    },
    {
      type: "email",
      regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    },
    {
      type: "url",
      regex: /\bhttps?:\/\/[^\s<>"']+/gi,
    },
    {
      type: "upi",
      regex: /\b[a-zA-Z0-9._-]+@[a-zA-Z]{2,}\b/g,
    },
  ];

  for (const pattern of patterns) {
    const matches = text.match(pattern.regex) || [];

    for (const value of matches) {
      const normalizedValue = value.replace(/[.,!?;]+$/, "");

      if (
        !indicators.some(
          (item) =>
            item.type === pattern.type && item.value === normalizedValue,
        )
      ) {
        indicators.push({
          type: pattern.type,
          value: normalizedValue,
          verified: false,
        });
      }
    }
  }

  return indicators;
};

/*
=========================================================
 5. CATEGORY CLASSIFICATION
=========================================================
*/

const classifyFraud = (text) => {
  const categoryScores = {};

  for (const category of FRAUD_CATEGORIES) {
    categoryScores[category] = 0;
  }

  const detectedRules = [];

  for (const rule of SCAM_RULES) {
    const matchedPatterns = rule.patterns.filter((pattern) =>
      pattern.test(text),
    );

    if (matchedPatterns.length > 0) {
      categoryScores[rule.category] +=
        rule.weight * Math.min(matchedPatterns.length, 2);

      detectedRules.push({
        category: rule.category,
        label: rule.label,
        weight: rule.weight,
      });
    }
  }

  const rankedCategories = Object.entries(categoryScores)
    .filter(([category, score]) => {
      return category !== "other" && category !== "unclassified" && score > 0;
    })
    .sort((a, b) => b[1] - a[1]);

  if (rankedCategories.length === 0) {
    return {
      fraudCategory: "unclassified",
      detectedRules,
      categoryScores,
    };
  }

  return {
    fraudCategory: rankedCategories[0][0],
    detectedRules,
    categoryScores,
  };
};

/*
=========================================================
 6. RISK SCORE CALCULATION
=========================================================
*/

const calculateRisk = ({ detectedRules, indicators, sensitiveInformation }) => {
  let riskScore = 0;

  const reasons = [];

  for (const rule of detectedRules) {
    riskScore += rule.weight;

    reasons.push(rule.label);
  }

  if (indicators.some((item) => item.type === "url")) {
    riskScore += 10;
    reasons.push("A URL was found in the submitted evidence.");
  }

  if (indicators.some((item) => item.type === "upi")) {
    riskScore += 8;
    reasons.push("A UPI identifier was found.");
  }

  if (sensitiveInformation.length > 0) {
    riskScore += 10;
    reasons.push("The evidence refers to potentially sensitive credentials.");
  }

  riskScore = Math.min(100, riskScore);

  let riskLevel = "low";

  if (riskScore >= 75) {
    riskLevel = "critical";
  } else if (riskScore >= 50) {
    riskLevel = "high";
  } else if (riskScore >= 25) {
    riskLevel = "medium";
  }

  return {
    riskScore,
    riskLevel,
    reasons,
  };
};

/*
=========================================================
 7. ANALYSIS SUMMARY
=========================================================
*/

const generateSummary = (fraudCategory, riskLevel) => {
  const categoryNames = {
    investment: "Investment scam",
    digitalArrest: "Digital arrest scam",
    creditCard: "Credit card or banking fraud",
    sextortion: "Sextortion or blackmail",
    ecommerce: "E-commerce fraud",
    other: "Other suspicious activity",
    unclassified: "Unclassified activity",
  };

  const categoryName = categoryNames[fraudCategory] || "Suspicious activity";

  if (riskLevel === "critical") {
    return `${categoryName} indicators detected. Immediate caution is recommended.`;
  }

  if (riskLevel === "high") {
    return `${categoryName} indicators detected. Verify the source before taking action.`;
  }

  if (riskLevel === "medium") {
    return `Some suspicious indicators were detected. Exercise caution and verify independently.`;
  }

  return "No strong scam indicators were detected by the current rules. This does not guarantee that the evidence is safe.";
};

/*
=========================================================
 8. MAIN ANALYSIS FUNCTION
=========================================================
*/

const analyzeEvidence = async ({ evidenceType, evidence }) => {
  const normalizedEvidence = validateEvidence({
    evidenceType,
    evidence,
  });

  // Use an opaque, unique reference rather than hashing user text. A stable
  // content hash can reveal repeated submissions and be guessed offline.
  const evidenceId = crypto.randomUUID();

  const sensitiveInformation = detectSensitiveInformation(normalizedEvidence);

  const classification = classifyFraud(normalizedEvidence);

  const indicators = extractIndicators(normalizedEvidence);

  const risk = calculateRisk({
    detectedRules: classification.detectedRules,
    indicators,
    sensitiveInformation,
  });

  const summary = generateSummary(classification.fraudCategory, risk.riskLevel);

  return {
    evidenceId,

    evidenceType,

    fraudCategory: classification.fraudCategory,

    riskScore: risk.riskScore,

    riskLevel: risk.riskLevel,

    summary,

    explanation: risk.reasons,

    indicators,

    sensitiveInformation,

    detectedRules: classification.detectedRules,

    analysisMethod: "rule_based",

    aiEngineUsed: false,

    disclaimer:
      "This is an automated rule-based assessment, not proof of fraud. Indicators are unverified clues. Verify independently before taking action.",

    analyzedAt: new Date(),
  };
};

/*
=========================================================
 EXPORTS
=========================================================
*/

module.exports = {
  analyzeEvidence,
  validateEvidence,
  classifyFraud,
  extractIndicators,
  calculateRisk,
};
