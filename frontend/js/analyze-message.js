/*
=========================================================
SCAMSHIELD AI - MESSAGE ANALYSIS
=========================================================

Version: 4.0.0

Features:
1. Message input validation.
2. Evidence metadata handling.
3. Centralized API integration.
4. Guardian-authoritative risk assessment.
5. Intelligence indicator rendering.
6. Victim Safety recommendations.
7. Gemini advisory-only rendering.
8. Controlled Decoy status.
9. Automatic case creation.
10. Classification feedback integration.
11. Safe DOM rendering.
12. Mobile navigation.
13. Duplicate request protection.
14. Robust API response normalization.

=========================================================
*/

"use strict";

(() => {
  // =====================================================
  // CONFIGURATION
  // =====================================================

  const VERSION = "4.0.0";

  const API_ENDPOINT = "/analysis/analyze";
  const CASE_ENDPOINT = "/cases";

  const MAX_EVIDENCE_LENGTH = 20000;
  const MAX_SENDER_LENGTH = 150;
  const REQUEST_TIMEOUT = 120000;

  const RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

  const ALLOWED_CATEGORIES = [
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

  const RISK_CONFIG = {
    LOW: {
      label: "Low Risk",
      priority: "low",
      className: "low",
    },

    MEDIUM: {
      label: "Medium Risk",
      priority: "medium",
      className: "medium",
    },

    HIGH: {
      label: "High Risk",
      priority: "high",
      className: "high",
    },

    CRITICAL: {
      label: "Critical Risk",
      priority: "urgent",
      className: "critical",
    },
  };

  const DEFAULT_SAFETY_GUIDANCE = {
    LOW: [
      "Continue exercising caution.",
      "Never share OTPs, PINs or passwords.",
      "Verify suspicious claims through official channels.",
    ],

    MEDIUM: [
      "Avoid responding immediately to suspicious requests.",
      "Do not click unknown links.",
      "Verify the sender independently.",
      "Never share banking credentials or OTPs.",
    ],

    HIGH: [
      "Do not transfer money based on suspicious requests.",
      "Do not disclose OTPs, PINs, CVV or passwords.",
      "Verify the communication through official channels.",
      "Preserve suspicious messages as evidence.",
    ],

    CRITICAL: [
      "Stop interacting with the suspicious sender.",
      "Do not transfer money or disclose sensitive information.",
      "Contact your bank immediately if financial information was exposed.",
      "If money was lost through cyber fraud in India, call 1930.",
      "Preserve messages and transaction evidence.",
    ],
  };

  // =====================================================
  // DOM HELPERS
  // =====================================================

  const $ = (id) => document.getElementById(id);

  function setText(id, value) {
    const element = $(id);

    if (!element) return;

    element.textContent =
      value === null || value === undefined
        ? ""
        : String(value);
  }

  function showElement(id) {
    const element = $(id);

    if (element) {
      element.hidden = false;
    }
  }

  function hideElement(id) {
    const element = $(id);

    if (element) {
      element.hidden = true;
    }
  }

  function safeObject(value) {
    return value &&
      typeof value === "object" &&
      !Array.isArray(value)
      ? value
      : {};
  }

  function safeArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function firstString(...values) {
    for (const value of values) {
      if (typeof value === "string" && value.trim()) {
        return value.trim();
      }

      if (typeof value === "number" && Number.isFinite(value)) {
        return String(value);
      }
    }

    return "";
  }

  function firstArray(...values) {
    for (const value of values) {
      if (Array.isArray(value) && value.length) {
        return value;
      }
    }

    return [];
  }

  function normalizeText(value) {
    return value === null || value === undefined
      ? ""
      : String(value).trim();
  }

  // =====================================================
  // STATE
  // =====================================================

  let isAnalyzing = false;
  let isCreatingCase = false;
  let isSubmittingFeedback = false;

  let currentAnalysisId = null;
  let currentCaseId = null;

  let currentAnalysis = null;

  // =====================================================
  // FORM ELEMENTS
  // =====================================================

  const form = $("messageAnalysisForm");

  const messageInput = $("messageContent");

  const sourceInput = $("messageSource");

  const senderInput = $("messageSender");

  const categoryInput = $("messageFraudCategory");

  const consentInput = $("messageAnalysisConsent");

  const analyzeButton = $("analyzeMessageButton");

  const clearButton = $("clearMessageForm");

  const characterCount = $("messageCharacterCount");

  const inputError = $("messageInputError");

  // =====================================================
  // INITIALIZATION
  // =====================================================

  function initialize() {
    if (!form || !messageInput || !analyzeButton) {
      console.error(
        "[ScamShield] Message Analysis initialization failed. Required form elements are missing."
      );

      return;
    }

    bindEvents();

    updateCharacterCount();

    initializeMobileNavigation();

    initializeLogout();

    resetResults();

    console.info(
      `[ScamShield Message Analysis] v${VERSION} initialized successfully.`
    );
  }

  // =====================================================
  // EVENT LISTENERS
  // =====================================================

  function bindEvents() {
    form.addEventListener("submit", handleFormSubmit);

    messageInput.addEventListener(
      "input",
      updateCharacterCount
    );

    if (clearButton) {
      clearButton.addEventListener("click", clearForm);
    }

    const helpfulButton = $("messageFeedbackHelpful");

    const reviewButton = $("messageFeedbackReview");

    if (helpfulButton) {
      helpfulButton.addEventListener("click", () => {
        handleFeedback("helpful");
      });
    }

    if (reviewButton) {
      reviewButton.addEventListener("click", () => {
        handleFeedback("needs_review");
      });
    }
  }

  // =====================================================
  // TOKEN
  // =====================================================

  function getToken() {
    try {
      const api = window.ScamShieldAPI;

      return (
        (api && typeof api.getToken === "function"
          ? api.getToken()
          : null) ||

        localStorage.getItem("scamshieldToken") ||

        sessionStorage.getItem("scamshieldToken") ||

        localStorage.getItem("scamshield_token") ||

        sessionStorage.getItem("scamshield_token") ||

        null
      );
    } catch (error) {
      console.error("[ScamShield] Token retrieval failed:", error);

      return null;
    }
  }

  // =====================================================
  // CHARACTER COUNTER
  // =====================================================

  function updateCharacterCount() {
    if (!messageInput || !characterCount) {
      return;
    }

    const length = messageInput.value.length;

    characterCount.textContent =
      `${length.toLocaleString()} / ${MAX_EVIDENCE_LENGTH.toLocaleString()}`;

    characterCount.classList.toggle(
      "limit-reached",
      length >= MAX_EVIDENCE_LENGTH
    );

    characterCount.style.color =
      length >= MAX_EVIDENCE_LENGTH * 0.9
        ? "#fbbf24"
        : "";
  }

  // =====================================================
  // INPUT VALIDATION
  // =====================================================

  function validateForm() {
    clearValidationError();

    const message = normalizeText(messageInput.value);

    if (!message) {
      showValidationError(
        "Please enter the suspicious message."
      );

      messageInput.focus();

      return null;
    }

    if (message.length > MAX_EVIDENCE_LENGTH) {
      showValidationError(
        `Message cannot exceed ${MAX_EVIDENCE_LENGTH.toLocaleString()} characters.`
      );

      messageInput.focus();

      return null;
    }

    const sender = senderInput
      ? normalizeText(senderInput.value)
      : "";

    if (sender.length > MAX_SENDER_LENGTH) {
      showValidationError(
        "Sender information exceeds the allowed length."
      );

      senderInput.focus();

      return null;
    }

    if (!consentInput || !consentInput.checked) {
      showValidationError(
        "Please confirm the consent checkbox before analysis."
      );

      consentInput?.focus();

      return null;
    }

    const allowedSources = [
      "unknown",
      "sms",
      "whatsapp",
      "telegram",
      "social_media",
      "email_message",
      "other",
    ];

    const source = sourceInput
      ? sourceInput.value
      : "unknown";

    if (!allowedSources.includes(source)) {
      showValidationError(
        "Please select a valid message source."
      );

      sourceInput?.focus();

      return null;
    }

    const category = categoryInput
      ? normalizeText(categoryInput.value)
      : "";

    if (
      category &&
      !ALLOWED_CATEGORIES.includes(category)
    ) {
      showValidationError(
        "Please select a valid fraud category."
      );

      categoryInput?.focus();

      return null;
    }

    return {
      message,
      sender,
      source,
      category,
    };
  }

  function showValidationError(message) {
    if (!inputError) return;

    inputError.textContent = message;

    inputError.hidden = false;
  }

  function clearValidationError() {
    if (!inputError) return;

    inputError.textContent = "";

    inputError.hidden = true;
  }

  // =====================================================
  // BUILD ANALYSIS PAYLOAD
  // =====================================================

  function buildPayload(validated) {
    return {
      evidenceType: "message",

      evidence: validated.message,

      selectedCategory: validated.category || "auto",

      selectedCategoryLabel: validated.category
        ? getCategoryLabel(validated.category)
        : "Automatic Fraud Detection",

      metadata: {
        source: "analyze-message-page",

        inputMethod: "manual_message_input",

        pageVersion: VERSION,

        messageSource: validated.source,

        senderInformation: validated.sender || null,
      },
    };
  }

  // =====================================================
  // API SERVICE
  // =====================================================

  function getAPI() {
    const api = window.ScamShieldAPI;

    if (!api || typeof api.post !== "function") {
      throw new Error(
        "ScamShield API service is unavailable. Please reload the page."
      );
    }

    return api;
  }

  async function requestAnalysis(payload) {
    const api = getAPI();

    return api.post(
      API_ENDPOINT,
      payload,
      {
        timeout: REQUEST_TIMEOUT,
      }
    );
  }

  async function requestCaseCreation(payload) {
    const api = getAPI();

    return api.post(
      CASE_ENDPOINT,
      payload
    );
  }

  // =====================================================
  // FORM SUBMISSION
  // =====================================================

  async function handleFormSubmit(event) {
    event.preventDefault();

    if (isAnalyzing || isCreatingCase) {
      return;
    }

    const validated = validateForm();

    if (!validated) {
      return;
    }

    if (!getToken()) {
      showAnalysisStatus(
        "Authentication required",
        "Your session may have expired. Please login again."
      );

      return;
    }

    isAnalyzing = true;

    resetResults();

    clearValidationError();

    setLoadingState(true);

    showAnalysisStatus(
      "Analysis in progress",
      "ScamShield AI is examining your submitted message."
    );

    try {
      const payload = buildPayload(validated);

      // STEP 1: ANALYZE MESSAGE

      const response = await requestAnalysis(payload);

      const normalized = normalizeResponse(response);

      if (!normalized.success) {
        throw new Error(
          normalized.message ||
          "Message analysis could not be completed."
        );
      }

      if (normalized.riskScore === null) {
        throw new Error(
          "The analysis engine did not return a valid risk score."
        );
      }

      currentAnalysis = normalized;

      currentAnalysisId = normalized.id;

      // STEP 2: DISPLAY RESULTS

      renderResults(normalized);

      showElement("messageResults");

      showAnalysisStatus(
        "Analysis completed",
        "Your message analysis report is ready."
      );

      // STEP 3: CREATE CASE

      try {
        isCreatingCase = true;

        showAnalysisStatus(
          "Saving detection case",
          "Analysis completed. Saving the result to your case records."
        );

        const savedCase = await createAnalysisCase(
          normalized,
          validated
        );

        currentCaseId = savedCase._id || savedCase.id;

        showAnalysisStatus(
          "Analysis completed",
          "Your analysis report and detection case have been saved."
        );

        console.info(
          "[ScamShield] Detection case created:",
          currentCaseId
        );
      } catch (caseError) {
        console.error(
          "[ScamShield] Case creation failed:",
          caseError
        );

        showAnalysisStatus(
          "Analysis completed - Case not saved",
          "Your analysis report is available, but the detection case could not be saved. " +
          getErrorMessage(caseError)
        );
      } finally {
        isCreatingCase = false;
      }

      console.info(
        "[ScamShield Message Analysis] Analysis completed.",
        {
          analysisId: currentAnalysisId,
          caseId: currentCaseId,
          riskScore: normalized.riskScore,
          riskLevel: normalized.riskLevel,
          category: normalized.detectionCategory,
        }
      );

      $("messageResults")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    } catch (error) {
      console.error(
        "[ScamShield Message Analysis] Analysis error:",
        error
      );

      showAnalysisStatus(
        "Analysis failed",
        getErrorMessage(error)
      );
    } finally {
      isAnalyzing = false;

      isCreatingCase = false;

      setLoadingState(false);
    }
  }

  // =====================================================
  // RESPONSE NORMALIZATION
  // =====================================================

  function normalizeResponse(response) {
    const outer = safeObject(response);

    const data = safeObject(outer.data);

    const body =
      Object.keys(data).length > 0
        ? data
        : outer;

    if (
      body.success === false ||
      outer.success === false
    ) {
      return {
        success: false,

        message: firstString(
          body.message,
          outer.message,
          body.error?.message,
          "Analysis failed."
        ),
      };
    }

    const result = safeObject(
      body.result ||
      body.analysis ||
      body.data?.result ||
      body
    );

    if (result.success === false) {
      return {
        success: false,

        message: firstString(
          result.message,
          result.error?.message,
          "Analysis failed."
        ),
      };
    }

    const agents = safeObject(
      result.agents
    );

    const agentResults = safeObject(
      result.agent_results ||
      result.agentResults
    );

    const guardian = safeObject(
      agents.guardian ||
      agentResults.guardian ||
      result.guardian ||
      result.guardian_result
    );

    const intelligence = safeObject(
      agents.intelligence ||
      agentResults.intelligence ||
      result.intelligence ||
      result.intelligence_result
    );

    const victimSafety = safeObject(
      agents.victimSafety ||
      agents.victim_safety ||
      agentResults.victim_safety ||
      agentResults.victimSafety ||
      result.victim_safety ||
      result.victimSafety
    );

    const decoy = safeObject(
      agents.decoy ||
      agentResults.decoy ||
      result.decoy ||
      result.decoy_result
    );

    const gemini = safeObject(
      result.geminiAdvisory ||
      result.gemini_advisory ||
      result.advisory ||
      body.gemini_advisory
    );

    // Guardian is the authoritative result source.
    const scoreValue =
      guardian.riskScore ??
      guardian.risk_score ??
      guardian.analysis?.riskScore ??
      guardian.analysis?.risk_score ??
      result.riskScore ??
      result.risk_score;

    const riskScore = normalizeScore(scoreValue);

    const category = firstString(
      guardian.fraudCategory,
      guardian.fraud_category,
      guardian.category,
      guardian.analysis?.fraudCategory,
      guardian.analysis?.fraud_category,
      result.fraudCategory,
      result.fraud_category,
      result.detectionCategory,
      result.detection_category,
      result.category
    );

    const riskLevel = normalizeRiskLevel(
      firstString(
        guardian.riskLevel,
        guardian.risk_level,
        guardian.analysis?.riskLevel,
        guardian.analysis?.risk_level,
        result.riskLevel,
        result.risk_level
      ),
      riskScore
    );

    const summary = firstString(
      guardian.summary,
      guardian.explanation,
      guardian.message,
      result.summary,
      result.riskDescription,
      result.risk_description,
      result.explanation,
      result.riskExplanation
    );

    return {
      success: true,

      id: firstString(
        result.id,
        result.analysisId,
        result.analysis_id,
        body.analysisId,
        body.analysis_id
      ),

      caseId: firstString(
        result.caseId,
        result.case_id
      ),

      riskScore,

      riskLevel,

      detectionCategory: category,

      summary,

      explanation: firstString(
        guardian.explanation,
        guardian.summary,
        result.explanation,
        result.riskExplanation,
        result.risk_explanation
      ),

      guardian,

      intelligence,

      victimSafety,

      decoy,

      gemini,

      indicators: normalizeIndicators(
        result.indicators ||
        result.extracted_indicators ||
        intelligence.indicators,
        intelligence
      ),

      recommendations: normalizeRecommendations(
        result.recommendations,
        victimSafety
      ),

      safetyGuidance: normalizeRecommendations(
        result.safety_guidance ||
        result.safetyGuidance,
        victimSafety
      ),

      raw: result,
    };
  }

  // =====================================================
  // SCORE NORMALIZATION
  // =====================================================

  function normalizeScore(value) {
    if (
      value === null ||
      value === undefined ||
      value === ""
    ) {
      return null;
    }

    const score = Number(value);

    if (
      !Number.isFinite(score) ||
      score < 0 ||
      score > 100
    ) {
      return null;
    }

    return Math.round(score);
  }

  // =====================================================
  // RISK LEVEL NORMALIZATION
  // =====================================================

  function normalizeRiskLevel(value, score) {
    if (typeof value === "string") {
      const normalized = value
        .trim()
        .toUpperCase()
        .replace(/\s+/g, "_");

      const aliases = {
        LOW_RISK: "LOW",
        MEDIUM_RISK: "MEDIUM",
        MODERATE: "MEDIUM",
        MODERATE_RISK: "MEDIUM",
        HIGH_RISK: "HIGH",
        CRITICAL_RISK: "CRITICAL",
      };

      const resolved = aliases[normalized] || normalized;

      if (RISK_LEVELS.includes(resolved)) {
        return resolved;
      }
    }

    if (score === null) {
      return "UNKNOWN";
    }

    if (score <= 24) return "LOW";

    if (score <= 49) return "MEDIUM";

    if (score <= 74) return "HIGH";

    return "CRITICAL";
  }

  // =====================================================
  // CATEGORY NORMALIZATION
  // =====================================================

  function getCategoryLabel(category) {
    const normalized = normalizeText(category).toLowerCase();

    if (!ALLOWED_CATEGORIES.includes(normalized)) {
      return "Not classified";
    }

    return normalized
      .split("_")
      .map(
        (word) =>
          word.charAt(0).toUpperCase() + word.slice(1)
      )
      .join(" ");
  }

  // =====================================================
  // INDICATOR NORMALIZATION
  // =====================================================

  function normalizeIndicators(resultIndicators, intelligence) {
    const items = [];

    const direct = safeArray(resultIndicators);

    direct.forEach((item) => {
      if (typeof item === "string") {
        items.push({
          type: "Indicator",
          value: item,
          verified: false,
        });

        return;
      }

      const indicator = safeObject(item);

      const value = firstString(
        indicator.value,
        indicator.indicator,
        indicator.text
      );

      if (!value) return;

      items.push({
        type: firstString(
          indicator.type,
          indicator.category,
          "Indicator"
        ),

        value,

        // Only explicit true is treated as verified.
        verified: indicator.verified === true,
      });
    });

    const intelligenceData = safeObject(
      intelligence.intelligence
    );

    const indicatorSource =
      Object.keys(intelligenceData).length
        ? intelligenceData
        : intelligence;

    const indicatorGroups = [
      ["URLs", "urls"],
      ["Phone Numbers", "phone_numbers"],
      ["Emails", "emails"],
      ["UPI IDs", "upi_ids"],
    ];

    indicatorGroups.forEach(([label, key]) => {
      safeArray(indicatorSource[key]).forEach((value) => {
        if (typeof value !== "string" || !value.trim()) {
          return;
        }

        items.push({
          type: label,
          value: value.trim(),
          verified: false,
        });
      });
    });

    const seen = new Set();

    return items
      .filter((item) => {
        const key =
          `${item.type.toLowerCase()}:${item.value.toLowerCase()}`;

        if (seen.has(key)) return false;

        seen.add(key);

        return true;
      })
      .slice(0, 50);
  }

  // =====================================================
  // RECOMMENDATION NORMALIZATION
  // =====================================================

  function normalizeRecommendations(direct, safety) {
    const items = [];

    safeArray(direct).forEach((item) => {
      if (typeof item === "string" && item.trim()) {
        items.push(item.trim());

        return;
      }

      const object = safeObject(item);

      const message = firstString(
        object.message,
        object.description,
        object.recommendation,
        object.action
      );

      if (message) {
        items.push(message);
      }
    });

    const safetyData = safeObject(
      safety.victim_safety ||
      safety.safety ||
      safety
    );

    const keys = [
      "guidance",
      "recommendations",
      "safety_guidance",
      "safety_recommendations",
      "immediate_actions",
      "actions",
    ];

    keys.forEach((key) => {
      safeArray(safetyData[key]).forEach((item) => {
        if (typeof item === "string" && item.trim()) {
          items.push(item.trim());

          return;
        }

        const object = safeObject(item);

        const message = firstString(
          object.message,
          object.description,
          object.action
        );

        if (message) {
          items.push(message);
        }
      });
    });

    return [...new Set(items)].slice(0, 30);
  }

  // =====================================================
  // RESULT RENDERING
  // =====================================================

  function renderResults(data) {
    setText(
      "messageRiskScore",
      data.riskScore
    );

    const riskInfo = RISK_CONFIG[data.riskLevel];

    setText(
      "messageRiskLevel",
      riskInfo ? riskInfo.label : "Unclassified"
    );

    setText(
      "messageFraudCategoryResult",
      getCategoryLabel(data.detectionCategory)
    );

    setText(
      "messageResultStatus",
      "Completed"
    );

    setText(
      "messageRiskDescription",
      data.summary ||
      data.explanation ||
      "Analysis completed. Review the agent findings below."
    );

    renderRiskScoreStyle(data.riskLevel);

    renderGuardian(data);

    renderIntelligence(data);

    renderVictimSafety(data);

    renderGemini(data);

    renderDecoy(data);
  }

  // =====================================================
  // RISK SCORE STYLE
  // =====================================================

  function renderRiskScoreStyle(level) {
    const circle = $("messageRiskScoreCircle");

    if (!circle) return;

    circle.classList.remove(
      "low",
      "medium",
      "high",
      "critical"
    );

    if (RISK_CONFIG[level]) {
      circle.classList.add(
        RISK_CONFIG[level].className
      );
    }
  }

  // =====================================================
  // GUARDIAN RENDERING
  // =====================================================

  function renderGuardian(data) {
    const guardian = data.guardian;

    const status = firstString(
      guardian.agent?.status,
      guardian.status
    );

    setText(
      "messageGuardianStatus",
      status
        ? status.toLowerCase() === "completed"
          ? "Completed - Authoritative"
          : status
        : "Primary Result"
    );

    const guardianAnalysis = safeObject(
      guardian.analysis
    );

    const message = firstString(
      guardian.summary,
      guardianAnalysis.summary,
      guardian.explanation,
      guardian.message,
      data.summary
    );

    setText(
      "messageGuardianResult",
      message ||
      `Guardian completed the primary assessment with a risk score of ${data.riskScore}/100.`
    );
  }

  // =====================================================
  // INTELLIGENCE RENDERING
  // =====================================================

  function renderIntelligence(data) {
    const intelligence = data.intelligence;

    const status = firstString(
      intelligence.agent?.status,
      intelligence.status
    );

    const successful =
      intelligence.success === true ||
      status.toLowerCase() === "completed";

    setText(
      "messageIntelligenceStatus",
      successful ? "Completed" : "Unavailable"
    );

    const summary = safeObject(
      intelligence.summary
    );

    const message = firstString(
      summary.message,
      intelligence.message,
      typeof intelligence.summary === "string"
        ? intelligence.summary
        : ""
    );

    setText(
      "messageIntelligenceResult",
      message ||
      (
        successful
          ? "Intelligence indicators were processed."
          : "Additional intelligence information is unavailable."
      )
    );

    renderIndicators(data.indicators);
  }

  // =====================================================
  // INDICATOR RENDERING
  // =====================================================

  function renderIndicators(indicators) {
    const container = $("messageIndicators");

    if (!container) return;

    container.replaceChildren();

    if (!indicators.length) {
      const empty = document.createElement("p");

      empty.className = "indicator-item";

      empty.textContent =
        "No supported indicators were returned.";

      container.appendChild(empty);

      return;
    }

    indicators.forEach((indicator) => {
      const item = document.createElement("div");

      item.className = indicator.verified
        ? "indicator-item"
        : "indicator-item unverified";

      const type = document.createElement("strong");

      type.textContent = indicator.type;

      const value = document.createElement("span");

      value.textContent = indicator.value;

      const verification = document.createElement("span");

      verification.textContent = indicator.verified
        ? "Verified"
        : "Unverified";

      item.append(
        type,
        value,
        verification
      );

      container.appendChild(item);
    });
  }

  // =====================================================
  // VICTIM SAFETY RENDERING
  // =====================================================

  function renderVictimSafety(data) {
    const safety = data.victimSafety;

    const status = firstString(
      safety.agent?.status,
      safety.status
    );

    const successful =
      safety.success === true ||
      status.toLowerCase() === "completed";

    setText(
      "messageVictimSafetyStatus",
      successful ? "Completed" : "Guidance Available"
    );

    let recommendations = firstArray(
      data.safetyGuidance,
      data.recommendations
    );

    if (!recommendations.length) {
      recommendations =
        DEFAULT_SAFETY_GUIDANCE[data.riskLevel] ||
        DEFAULT_SAFETY_GUIDANCE.MEDIUM;
    }

    const summary = firstString(
      safety.summary,
      safety.message,
      safety.explanation
    );

    const parts = [];

    if (summary) {
      parts.push(summary);
    }

    recommendations.forEach((item, index) => {
      parts.push(`${index + 1}. ${item}`);
    });

    setText(
      "messageVictimSafetyResult",
      parts.join("\n\n") ||
      "Follow standard safety precautions."
    );
  }

  // =====================================================
  // GEMINI ADVISORY RENDERING
  // =====================================================

  function renderGemini(data) {
    const gemini = data.gemini;

    const status = firstString(
      gemini.status
    ).toLowerCase();

    const available =
      gemini.available === true &&
      status !== "unavailable" &&
      status !== "error" &&
      status !== "failed";

    setText(
      "messageGeminiStatus",
      available
        ? "Available - Advisory Only"
        : "Unavailable - Guardian Independent"
    );

    const explanation = firstString(
      gemini.explanation,
      gemini.summary,
      gemini.advice,
      gemini.message
    );

    const tactics = safeArray(
      gemini.social_engineering_tactics
    );

    const safetyNotes = safeArray(
      gemini.safety_notes
    );

    const parts = [];

    if (explanation) {
      parts.push(explanation);
    }

    if (tactics.length) {
      parts.push(
        "Potential social engineering tactics: " +
        tactics.join(", ")
      );
    }

    if (safetyNotes.length) {
      parts.push(
        "Additional safety notes: " +
        safetyNotes.join(" ")
      );
    }

    setText(
      "messageGeminiResult",
      available
        ? parts.join("\n\n") ||
          "Gemini advisory was received."
        : firstString(
            gemini.reason,
            gemini.message,
            "Gemini advisory is unavailable. Guardian's primary assessment remains independent."
          )
    );
  }

  // =====================================================
  // DECOY RENDERING
  // =====================================================

  function renderDecoy(data) {
    const decoy = data.decoy;

    const status = firstString(
      decoy.status
    ).toLowerCase();

    const started =
      status === "completed" ||
      status === "active";

    setText(
      "messageDecoyStatus",
      started ? "Controlled Operation" : "Not Started"
    );

    setText(
      "messageDecoyResult",
      firstString(
        decoy.message,
        decoy.summary,
        "Decoy simulation is a separate controlled operation and was not started automatically."
      )
    );
  }

  // =====================================================
  // CASE CREATION
  // =====================================================

  async function createAnalysisCase(data, validated) {
    if (!data.id) {
      throw new Error(
        "Analysis ID was not returned. Case creation is unavailable."
      );
    }

    const riskInfo = RISK_CONFIG[data.riskLevel];

    if (!riskInfo) {
      throw new Error(
        "Valid risk classification is unavailable."
      );
    }

    const indicators = data.indicators
      .slice(0, 50)
      .map((item) => ({
        type: String(item.type).slice(0, 30),

        value: String(item.value).slice(0, 300),
      }));

    const payload = {
      analysisId: data.id,

      title:
        `${getCategoryLabel(data.detectionCategory)} Detection Case`,

      description:
        `Evidence type: message\n` +
        `Message source: ${validated.source}\n` +
        `Risk score: ${data.riskScore}/100\n` +
        `Risk level: ${data.riskLevel}\n` +
        `Evidence preview: ${validated.message.slice(0, 500)}`,

      fraudCategory: data.detectionCategory,

      riskLevel: data.riskLevel.toLowerCase(),

      priority: riskInfo.priority,

      indicators,
    };

    const response = await requestCaseCreation(payload);

    if (!response || response.success !== true) {
      throw new Error(
        response?.message ||
        "The detection case could not be saved."
      );
    }

    const body = safeObject(response.data);

    const savedCase = safeObject(
      body.case ||
      body.data?.case ||
      body ||
      response.case
    );

    const caseId = firstString(
      savedCase._id,
      savedCase.id,
      response.case?._id,
      response.case?.id
    );

    if (!caseId) {
      throw new Error(
        "The server did not return a valid case ID."
      );
    }

    return {
      ...savedCase,
      _id: caseId,
    };
  }

  // =====================================================
  // ANALYSIS STATUS
  // =====================================================

  function showAnalysisStatus(title, message) {
    showElement("messageAnalysisStatus");

    setText(
      "messageAnalysisStatusTitle",
      title
    );

    setText(
      "messageAnalysisStatusMessage",
      message
    );
  }

  // =====================================================
  // LOADING STATE
  // =====================================================

  function setLoadingState(isLoading) {
    if (!analyzeButton) return;

    if (isLoading) {
      if (!analyzeButton.dataset.originalHTML) {
        analyzeButton.dataset.originalHTML =
          analyzeButton.innerHTML;
      }

      analyzeButton.disabled = true;

      analyzeButton.innerHTML =
        '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...';

      if (clearButton) {
        clearButton.disabled = true;
      }

      return;
    }

    analyzeButton.disabled = false;

    analyzeButton.innerHTML =
      analyzeButton.dataset.originalHTML ||
      '<i class="fa-solid fa-shield-halved"></i> Analyze Message';

    if (clearButton) {
      clearButton.disabled = false;
    }
  }

  // =====================================================
  // ERROR HANDLING
  // =====================================================

  function getErrorMessage(error) {
    if (!error) {
      return "An unexpected error occurred.";
    }

    const status = error.response?.status;

    if (status === 401 || status === 403) {
      return "Authentication failed. Please login again.";
    }

    if (status === 413) {
      return "Submitted evidence is too large for the server.";
    }

    if (status === 429) {
      return "Too many requests. Please wait before trying again.";
    }

    if (status >= 500) {
      return "Server error. Please try again later.";
    }

    if (error.name === "AbortError") {
      return "The analysis request timed out. Please try again.";
    }

    return firstString(
      error.response?.data?.message,
      error.data?.message,
      error.message,
      "Unable to complete analysis. Please check the backend and AI engine."
    );
  }

  // =====================================================
  // RESET RESULTS
  // =====================================================

  function resetResults() {
    currentAnalysisId = null;

    currentCaseId = null;

    currentAnalysis = null;

    setText("messageRiskScore", "0");

    setText("messageRiskLevel", "Pending");

    setText(
      "messageFraudCategoryResult",
      "Not classified"
    );

    setText(
      "messageResultStatus",
      "Pending"
    );

    setText(
      "messageRiskDescription",
      "Risk explanation will appear here."
    );

    setText(
      "messageGuardianStatus",
      "Awaiting result"
    );

    setText(
      "messageGuardianResult",
      "Primary fraud detection and risk assessment."
    );

    setText(
      "messageIntelligenceStatus",
      "Awaiting result"
    );

    setText(
      "messageIntelligenceResult",
      "Extracted indicators and suspicious information."
    );

    setText(
      "messageVictimSafetyStatus",
      "Awaiting result"
    );

    setText(
      "messageVictimSafetyResult",
      "Safety recommendations will appear here."
    );

    setText(
      "messageGeminiStatus",
      "Awaiting result"
    );

    setText(
      "messageGeminiResult",
      "Additional AI advisory information."
    );

    setText(
      "messageDecoyStatus",
      "Not started"
    );

    setText(
      "messageDecoyResult",
      "Decoy simulation is not started automatically."
    );

    renderRiskScoreStyle("UNKNOWN");

    const indicators = $("messageIndicators");

    if (indicators) {
      indicators.replaceChildren();
    }

    const feedback = $("messageFeedbackStatus");

    if (feedback) {
      feedback.textContent = "";
      feedback.className = "feedback-status";
    }

    const helpful = $("messageFeedbackHelpful");

    const review = $("messageFeedbackReview");

    if (helpful) {
      helpful.disabled = true;
    }

    if (review) {
      review.disabled = true;
    }

    hideElement("messageResults");
  }

  // =====================================================
  // CLEAR FORM
  // =====================================================

  function clearForm() {
    if (isAnalyzing || isCreatingCase || isSubmittingFeedback) {
      return;
    }

    if (form) {
      form.reset();
    }

    clearValidationError();

    updateCharacterCount();

    resetResults();

    hideElement("messageAnalysisStatus");

    messageInput?.focus();
  }

  // =====================================================
  // FEEDBACK
  // =====================================================

  async function handleFeedback(type) {
    if (isSubmittingFeedback) {
      return;
    }

    const status = $("messageFeedbackStatus");

    const helpfulButton = $("messageFeedbackHelpful");

    const reviewButton = $("messageFeedbackReview");

    if (!status) return;

    if (type === "needs_review" && !currentCaseId) {
      status.textContent =
        "A saved detection case is required to submit review feedback.";

      return;
    }

    if (type === "helpful") {
      status.textContent =
        "Thank you for your feedback.";

      return;
    }

    const api = window.ScamShieldAPI;

    if (!api || typeof api.patch !== "function") {
      status.textContent =
        "Feedback service is unavailable.";

      return;
    }

    isSubmittingFeedback = true;

    const originalHTML = reviewButton?.innerHTML;

    if (helpfulButton) {
      helpfulButton.disabled = true;
    }

    if (reviewButton) {
      reviewButton.disabled = true;

      reviewButton.innerHTML =
        '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
    }

    try {
      const response = await api.patch(
        `/cases/${encodeURIComponent(currentCaseId)}`,
        {
          classificationFeedback: "needs_review",
        }
      );

      if (!response || response.success !== true) {
        throw new Error(
          response?.message ||
          "Unable to save classification feedback."
        );
      }

      status.textContent =
        "Your review feedback was saved successfully.";

      status.className =
        "feedback-status success";
    } catch (error) {
      console.error(
        "[ScamShield] Feedback submission failed:",
        error
      );

      status.textContent =
        getErrorMessage(error);

      status.className =
        "feedback-status error";
    } finally {
      isSubmittingFeedback = false;

      if (helpfulButton) {
        helpfulButton.disabled = false;
      }

      if (reviewButton) {
        reviewButton.disabled = false;

        reviewButton.innerHTML =
          originalHTML ||
          '<i class="fa-solid fa-flag"></i> Needs Review';
      }
    }
  }

  // =====================================================
  // MOBILE NAVIGATION
  // =====================================================

  function initializeMobileNavigation() {
    const toggle = $("mobileMenuToggle");

    const navigation = $("primaryNavigation");

    if (!toggle || !navigation) return;

    toggle.addEventListener("click", () => {
      const isOpen =
        navigation.classList.toggle("open");

      toggle.setAttribute(
        "aria-expanded",
        String(isOpen)
      );

      const icon = toggle.querySelector("i");

      if (icon) {
        icon.className = isOpen
          ? "fa-solid fa-xmark"
          : "fa-solid fa-bars";
      }
    });

    navigation.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        navigation.classList.remove("open");

        toggle.setAttribute(
          "aria-expanded",
          "false"
        );

        const icon = toggle.querySelector("i");

        if (icon) {
          icon.className = "fa-solid fa-bars";
        }
      });
    });
  }

  // =====================================================
  // LOGOUT
  // =====================================================

  function initializeLogout() {
    const logoutButton = $("logoutButton");

    if (!logoutButton) return;

    logoutButton.addEventListener("click", () => {
      const api = window.ScamShieldAPI;

      if (api && typeof api.logout === "function") {
        api.logout();

        return;
      }

      try {
        localStorage.removeItem("scamshieldToken");
        sessionStorage.removeItem("scamshieldToken");

        localStorage.removeItem("scamshield_token");
        sessionStorage.removeItem("scamshield_token");
      } catch (error) {
        console.error(
          "[ScamShield] Logout cleanup failed:",
          error
        );
      }

      window.location.href = "login.html";
    });
  }

  // =====================================================
  // PUBLIC API
  // =====================================================

  window.ScamShieldMessageAnalysis = {
    version: VERSION,

    clearForm,

    validateForm,

    updateCharacterCount,

    normalizeResponse,

    getCurrentAnalysis: () => currentAnalysis,

    getCurrentCaseId: () => currentCaseId,
  };

  // =====================================================
  // START APPLICATION
  // =====================================================

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      initialize,
      { once: true }
    );
  } else {
    initialize();
  }
})();