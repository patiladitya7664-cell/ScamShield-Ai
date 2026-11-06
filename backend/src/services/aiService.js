"use strict";

const crypto = require("crypto");
const axios = require("axios");

const MAX_EVIDENCE_LENGTH = 20000;

const ALLOWED_EVIDENCE_TYPES = [
  "message",
  "url",
  "call",
  "transaction",
  "screenshot",
  "email",
];

const AI_ENGINE_URL = (
  process.env.AI_ENGINE_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const AI_ENGINE_TIMEOUT = Number(
  process.env.AI_ENGINE_TIMEOUT || 30000,
);

// =====================================================
// VALIDATION
// =====================================================

const validateEvidence = ({ evidenceType, evidence }) => {
  if (
    typeof evidenceType !== "string" ||
    !ALLOWED_EVIDENCE_TYPES.includes(
      evidenceType.trim().toLowerCase(),
    )
  ) {
    const error = new Error("Invalid evidence type.");
    error.statusCode = 400;
    throw error;
  }

  if (typeof evidence !== "string") {
    const error = new Error("Evidence must be provided as text.");
    error.statusCode = 400;
    throw error;
  }

  const normalizedEvidence = evidence.trim();

  if (!normalizedEvidence) {
    const error = new Error("Evidence cannot be empty.");
    error.statusCode = 400;
    throw error;
  }

  if (normalizedEvidence.length > MAX_EVIDENCE_LENGTH) {
    const error = new Error(
      `Evidence must not exceed ${MAX_EVIDENCE_LENGTH} characters.`,
    );
    error.statusCode = 400;
    throw error;
  }

  return normalizedEvidence;
};

// =====================================================
// SAFE HELPERS
// =====================================================

const safeObject = (value) =>
  value && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};

const safeArray = (value) =>
  Array.isArray(value) ? value : [];

const normalizeRiskLevel = (value) => {
  const level = String(value || "").toLowerCase();

  const allowed = ["low", "medium", "high", "critical"];

  if (!allowed.includes(level)) {
    const error = new Error(
      "Python AI Engine returned an invalid risk level.",
    );
    error.statusCode = 502;
    throw error;
  }

  return level;
};

const normalizeCategory = (value) => {
  const category = String(value || "").toLowerCase();

  const categoryMap = {
    digital_arrest: "digitalArrest",
    digitalarrest: "digitalArrest",
    credit_card: "creditCard",
    creditcard: "creditCard",
  };

  const normalized = categoryMap[category] || category;

  const allowed = [
    "investment",
    "digitalArrest",
    "creditCard",
    "sextortion",
    "ecommerce",
    "other",
    "unclassified",
    "unknown",
  ];

  return allowed.includes(normalized)
    ? normalized === "unknown"
      ? "unclassified"
      : normalized
    : "unclassified";
};

// =====================================================
// INDICATORS
// =====================================================

const normalizeIndicators = (indicators) => {
  if (Array.isArray(indicators)) {
    return indicators
      .filter(
        (item) =>
          item &&
          typeof item === "object" &&
          !Array.isArray(item),
      )
      .map((item) => ({
        type: String(
          item.type ||
          item.indicator_type ||
          item.indicatorType ||
          "unknown",
        ),
        value: String(item.value || item.indicator || ""),
        verified: item.verified === true,
      }))
      .filter((item) => item.value);
  }

  // Python pipeline currently may return indicators as an object.
  const indicatorObject = safeObject(indicators);

  const normalized = [];

  for (const [type, values] of Object.entries(indicatorObject)) {
    const items = Array.isArray(values) ? values : [values];

    for (const value of items) {
      if (
        typeof value === "string" ||
        typeof value === "number"
      ) {
        normalized.push({
          type,
          value: String(value),
          verified: false,
        });
      }
    }
  }

  return normalized;
};

// =====================================================
// DETECTED RULES
// =====================================================

const normalizeDetectedRules = (rules) => {
  return safeArray(rules)
    .filter(
      (item) =>
        item &&
        typeof item === "object" &&
        !Array.isArray(item),
    )
    .map((item) => ({
      category: normalizeCategory(item.category || "other"),

      label: String(
        item.label ||
        item.name ||
        item.message ||
        "Suspicious indicator detected",
      ),

      weight: Math.max(
        0,
        Math.min(100, Number(item.weight) || 0),
      ),
    }));
};

// =====================================================
// SENSITIVE INFORMATION
// =====================================================

const normalizeSensitiveInformation = (signals) => {
  return safeArray(signals)
    .filter(
      (item) =>
        item &&
        typeof item === "object" &&
        !Array.isArray(item),
    )
    .filter((item) => {
      const text = JSON.stringify(item).toLowerCase();

      return (
        text.includes("sensitive") ||
        text.includes("credential") ||
        text.includes("otp") ||
        text.includes("password") ||
        text.includes("pin") ||
        text.includes("cvv")
      );
    })
    .map((item) => ({
      type: String(
        item.type || item.code || "potential_sensitive_information",
      ),
      message: String(
        item.message ||
        item.description ||
        "Potentially sensitive information detected. Do not share credentials or verification codes.",
      ),
    }));
};

// =====================================================
// PYTHON AI ENGINE REQUEST
// =====================================================

const callPythonAIEngine = async ({
  evidenceType,
  evidence,
}) => {
  let response;

  try {
    response = await axios.post(
      `${AI_ENGINE_URL}/api/ai/analyze`,
      {
        evidence,
        evidence_type: evidenceType,
      },
      {
        timeout: AI_ENGINE_TIMEOUT,
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        maxBodyLength: MAX_EVIDENCE_LENGTH + 10000,
      },
    );
  } catch (error) {
    const status = error.response?.status;

    if (status) {
      const serviceError = new Error(
        `Python AI Engine returned HTTP ${status}.`,
      );

      serviceError.statusCode =
        status >= 400 && status < 500 ? 400 : 502;

      throw serviceError;
    }

    const serviceError = new Error(
      error.code === "ECONNABORTED"
        ? "Python AI Engine request timed out."
        : "Python AI Engine is unavailable.",
    );

    serviceError.statusCode = 503;

    throw serviceError;
  }

  if (
    !response.data ||
    typeof response.data !== "object" ||
    response.data.success !== true
  ) {
    const serviceError = new Error(
      response.data?.message ||
      "Python AI Engine could not complete the analysis.",
    );

    serviceError.statusCode = 502;

    throw serviceError;
  }

  return response.data;
};

// =====================================================
// PYTHON RESPONSE NORMALIZATION
// =====================================================

const normalizePythonResult = ({
  pythonResult,
  evidenceType,
}) => {
  const result = safeObject(pythonResult.result);

  const intelligence = safeObject(
    pythonResult.intelligence,
  );

  const victimSafety = safeObject(
    pythonResult.victim_safety,
  );

  const agentResults = safeObject(
    pythonResult.agent_results,
  );

  const guardian = safeObject(agentResults.guardian);

  const ml = safeObject(
    pythonResult.machine_learning,
  );

  const riskScore = Number(result.risk_score);

  if (
    !Number.isFinite(riskScore) ||
    riskScore < 0 ||
    riskScore > 100
  ) {
    const error = new Error(
      "Python AI Engine returned an invalid risk score.",
    );

    error.statusCode = 502;

    throw error;
  }

  const indicators = normalizeIndicators(
    result.indicators || intelligence.indicators,
  );

  const detectedRules = normalizeDetectedRules(
    result.detected_rules,
  );

  const signals = safeArray(result.signals);

  const sensitiveInformation =
    normalizeSensitiveInformation(signals);

  const recommendations = safeArray(
    result.recommendations,
  ).filter((item) => typeof item === "string");

  const explanations = safeArray(
    result.explanations,
  );

  const analysisMethod =
    ml.available === true
      ? "hybrid"
      : "python_rule_based";

  return {
    evidenceId: crypto.randomUUID(),

    evidenceType,

    fraudCategory: normalizeCategory(
      result.category,
    ),

    riskScore: Math.round(riskScore),

    riskLevel: normalizeRiskLevel(
      result.risk_level,
    ),

    summary: String(
      result.summary || "Evidence analysis completed.",
    ),

    explanation: explanations,

    indicators,

    sensitiveInformation,

    detectedRules,

    recommendations,

    agents: {
      guardian,

      intelligence,

      victimSafety: safeObject(
        agentResults.victim_safety || victimSafety,
      ),

      decoy: {
        status: "not_started",
        message:
          "Decoy simulation requires separate user-controlled activation.",
        simulationEnabled: false,
      },
    },

    machineLearning: {
      available: ml.available === true,
      prediction: ml.prediction ?? null,
      confidence: ml.confidence ?? null,
      method: ml.method || "not_available",
    },

    analysisMethod,

    aiEngineUsed: true,

    orchestration: safeObject(
      pythonResult.orchestration,
    ),

    verification: safeObject(
      pythonResult.verification,
    ),

    disclaimer: String(
      pythonResult.disclaimer ||
      "Automated analysis is advisory and does not independently prove fraud.",
    ),

    analyzedAt: new Date(),
  };
};

// =====================================================
// MAIN ANALYSIS
// =====================================================

const analyzeEvidence = async ({
  evidenceType,
  evidence,
}) => {
  const normalizedEvidence = validateEvidence({
    evidenceType,
    evidence,
  });

  const normalizedEvidenceType = evidenceType
    .trim()
    .toLowerCase();

  const pythonResult = await callPythonAIEngine({
    evidenceType: normalizedEvidenceType,
    evidence: normalizedEvidence,
  });

  return normalizePythonResult({
    pythonResult,
    evidenceType: normalizedEvidenceType,
  });
};

// =====================================================
// LEGACY HELPERS
// =====================================================

const classifyFraud = () => {
  throw new Error(
    "Local classification is disabled. Use the Python AI Engine.",
  );
};

const extractIndicators = () => {
  throw new Error(
    "Local indicator extraction is disabled. Use the Python AI Engine.",
  );
};

const calculateRisk = () => {
  throw new Error(
    "Local risk calculation is disabled. Use the Python AI Engine.",
  );
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
  analyzeEvidence,
  validateEvidence,
  classifyFraud,
  extractIndicators,
  calculateRisk,
};