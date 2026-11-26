"use strict";

/* =========================================================
   SCAMSHIELD AI - DETECTION MODULE
   Version: 3.0.0

   Features:
   1. Six Evidence Types
   2. Twelve Fraud Categories
   3. Guardian Risk Assessment
   4. Four Agent Results
   5. Gemini Advisory
   6. Case Management
   7. Classification Feedback
========================================================= */

document.addEventListener("DOMContentLoaded", () => {

  /* =======================================================
     1. CONFIGURATION
  ======================================================= */

  const API = window.ScamShieldAPI;

  const EVIDENCE_LIMITS = {
    message: 10000,
    call: 15000,
    email: 15000,
    url: 2048,
    screenshot: 20000,
    transaction: 10000,
  };

  const FRAUD_CATEGORIES = {
    fraud_message: "Fraud Message",
    fraud_call: "Fraud Call",
    url_phishing: "URL & Phishing",
    email_scam: "Email Scam",
    investment_scam: "Investment Scam",
    digital_arrest: "Digital Arrest",
    upi_banking_fraud: "UPI & Banking Fraud",
    card_fraud: "Credit/Debit Card Fraud",
    ecommerce_scam: "E-commerce Scam",
    job_loan_scam: "Job & Loan Scam",
    sextortion_blackmail: "Sextortion & Blackmail",
    social_media_scam: "Social Media Scam",
  };

  const RISK_LEVELS = {
    low: {
      label: "Low Risk",
      description: "Limited suspicious indicators detected.",
      color: "#42a5f5",
    },

    medium: {
      label: "Medium Risk",
      description: "Some suspicious indicators require attention.",
      color: "#eab308",
    },

    high: {
      label: "High Risk",
      description: "Multiple suspicious indicators were detected.",
      color: "#f97316",
    },

    critical: {
      label: "Critical Risk",
      description: "Strong warning signs of potential fraud were detected.",
      color: "#ef4444",
    },
  };

  const SAFETY_GUIDANCE = {
    low: [
      "Continue exercising caution.",
      "Never share OTPs, PINs, passwords or banking credentials.",
      "Verify suspicious claims through official channels.",
    ],

    medium: [
      "Do not respond immediately to suspicious requests.",
      "Avoid clicking unknown links or downloading attachments.",
      "Verify the sender through an independently obtained contact.",
      "Never share OTPs, PINs or passwords.",
    ],

    high: [
      "Do not click suspicious links or transfer money.",
      "Do not share OTPs, PINs, CVV or passwords.",
      "Block and report suspicious contacts when appropriate.",
      "Verify the communication through official channels.",
    ],

    critical: [
      "Stop interacting with the suspicious sender.",
      "Do not transfer money or disclose sensitive information.",
      "Contact your bank immediately if financial details were exposed.",
      "Report financial cyber fraud through India's official 1930 helpline.",
      "Preserve relevant messages and transaction evidence.",
    ],
  };

  const VALID_RISK_LEVELS = [
    "low",
    "medium",
    "high",
    "critical",
  ];

  /* =======================================================
     2. DOM ELEMENTS
  ======================================================= */

  const elements = {
    evidenceButtons: document.querySelectorAll(".evidence-type"),
    evidenceForms: document.querySelectorAll(".evidence-form"),

    messageInput: document.getElementById("messageInput"),
    callInput: document.getElementById("callInput"),
    emailInput: document.getElementById("emailInput"),
    urlInput: document.getElementById("urlInput"),
    screenshotInput: document.getElementById("screenshotInput"),
    transactionInput: document.getElementById("transactionInput"),

    messageCount: document.getElementById("messageCount"),
    callCount: document.getElementById("callCount"),
    emailCount: document.getElementById("emailCount"),
    screenshotCount: document.getElementById("screenshotCount"),
    transactionCount: document.getElementById("transactionCount"),

    fraudCategorySelect: document.getElementById(
      "fraudCategorySelect"
    ),

    analyzeBtn: document.getElementById("analyzeBtn"),
    clearBtn: document.getElementById("clearBtn"),

    analysisPanelStatus: document.getElementById(
      "analysisPanelStatus"
    ),

    analysisMessage: document.getElementById("analysisMessage"),

    detectionResults: document.getElementById("detectionResults"),

    resultStatus: document.getElementById("resultStatus"),

    riskScoreCircle: document.getElementById("riskScoreCircle"),
    riskScore: document.getElementById("riskScore"),
    riskLevel: document.getElementById("riskLevel"),
    riskDescription: document.getElementById("riskDescription"),

    fraudCategory: document.getElementById("fraudCategory"),
    riskExplanation: document.getElementById("riskExplanation"),

    guardianAgentResult: document.getElementById(
      "guardianAgentResult"
    ),

    intelligenceAgentResult: document.getElementById(
      "intelligenceAgentResult"
    ),

    victimSafetyAgentResult: document.getElementById(
      "victimSafetyAgentResult"
    ),

    decoyAgentResult: document.getElementById(
      "decoyAgentResult"
    ),

    geminiAdvisory: document.getElementById("geminiAdvisory"),

    indicatorList: document.getElementById("indicatorList"),
    safetyGuidance: document.getElementById("safetyGuidance"),

    feedbackPanel: document.getElementById(
      "classificationFeedbackPanel"
    ),

    feedbackSelect: document.getElementById(
      "classificationFeedbackSelect"
    ),

    feedbackBtn: document.getElementById(
      "submitClassificationFeedback"
    ),

    feedbackStatus: document.getElementById(
      "classificationFeedbackStatus"
    ),
  };

  /* =======================================================
     3. STATE
  ======================================================= */

  let currentEvidenceType = "message";

  let currentAnalysisId = null;
  let currentCaseId = null;

  let isAnalyzing = false;
  let isSubmittingFeedback = false;

  /* =======================================================
     4. INITIAL VALIDATION
  ======================================================= */

  const requiredElements = [
    elements.analyzeBtn,
    elements.clearBtn,
    elements.analysisMessage,
    elements.detectionResults,
    elements.resultStatus,
    elements.riskScoreCircle,
    elements.riskScore,
    elements.riskLevel,
    elements.riskDescription,
    elements.fraudCategory,
    elements.riskExplanation,
    elements.indicatorList,
    elements.safetyGuidance,
  ];

  if (requiredElements.some((element) => !element)) {
    console.error(
      "Detection initialization failed: Required HTML elements are missing."
    );

    return;
  }

  if (!API || typeof API.post !== "function") {
    console.error("ScamShield API service is unavailable.");

    showMessage(
      "API service could not be loaded. Please refresh the page.",
      "error"
    );

    elements.analyzeBtn.disabled = true;

    return;
  }

  if (typeof API.patch !== "function") {
    console.warn(
      "API.patch is unavailable. Classification feedback will not work."
    );
  }

  /* =======================================================
     5. UTILITY FUNCTIONS
  ======================================================= */

  function normalizeText(value) {
    if (value === null || value === undefined) {
      return "";
    }

    return String(value).trim();
  }

  function getToken() {
    try {
      return (
        (typeof API.getToken === "function"
          ? API.getToken()
          : null) ||
        localStorage.getItem("scamshieldToken") ||
        sessionStorage.getItem("scamshieldToken") ||
        localStorage.getItem("scamshield_token") ||
        sessionStorage.getItem("scamshield_token") ||
        null
      );
    } catch (error) {
      console.error("Token retrieval error:", error);
      return null;
    }
  }

  function showMessage(message, type = "info") {
    elements.analysisMessage.textContent = String(message);

    elements.analysisMessage.className =
      `analysis-message ${type}`;

    elements.analysisMessage.hidden = false;
  }

  function hideMessage() {
    elements.analysisMessage.textContent = "";

    elements.analysisMessage.hidden = true;

    elements.analysisMessage.className = "analysis-message";
  }

  function setButtonLoading(button, loading) {
    if (!button) return;

    if (loading) {
      if (!button.dataset.originalHTML) {
        button.dataset.originalHTML = button.innerHTML;
      }

      button.disabled = true;

      button.innerHTML = `
        <i class="fa-solid fa-spinner fa-spin"></i>
        Processing...
      `;
    } else {
      button.disabled = false;

      if (button.dataset.originalHTML) {
        button.innerHTML = button.dataset.originalHTML;
      }
    }
  }

  function getRiskLevelFromScore(score) {
    if (score <= 24) return "low";
    if (score <= 49) return "medium";
    if (score <= 74) return "high";

    return "critical";
  }

  function normalizeRiskLevel(value, score) {
    const normalized = normalizeText(value).toLowerCase();

    if (VALID_RISK_LEVELS.includes(normalized)) {
      return normalized;
    }

    return getRiskLevelFromScore(score);
  }

  function getPriority(score) {
    if (score >= 75) return "urgent";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";

    return "low";
  }

  function getCategoryLabel(category) {
    const normalized = normalizeText(category);

    if (FRAUD_CATEGORIES[normalized]) {
      return FRAUD_CATEGORIES[normalized];
    }

    return normalized
      ? normalized
          .replace(/_/g, " ")
          .replace(/\b\w/g, (character) => character.toUpperCase())
      : "Unclassified";
  }

  function getSelectedCategory() {
    if (!elements.fraudCategorySelect) {
      return "auto";
    }

    const selected = normalizeText(
      elements.fraudCategorySelect.value
    );

    return selected || "auto";
  }

  function getSelectedCategoryLabel() {
    const category = getSelectedCategory();

    if (category === "auto") {
      return "Automatic Fraud Detection";
    }

    return getCategoryLabel(category);
  }

  function formatExplanation(explanation) {
    if (Array.isArray(explanation)) {
      return explanation
        .map((item) => {
          if (typeof item === "string") {
            return item.trim();
          }

          if (item && typeof item === "object") {
            return (
              item.message ||
              item.description ||
              item.reason ||
              ""
            );
          }

          return "";
        })
        .filter(Boolean)
        .join("\n");
    }

    if (typeof explanation === "string") {
      return explanation.trim();
    }

    if (explanation && typeof explanation === "object") {
      return (
        explanation.message ||
        explanation.description ||
        explanation.summary ||
        JSON.stringify(explanation)
      );
    }

    return "No additional explanation was provided by the analysis engine.";
  }

  function getResponseResult(response) {
    if (!response || typeof response !== "object") {
      return null;
    }

    // Standard Node backend response.
    if (response.result && typeof response.result === "object") {
      return response.result;
    }

    // Alternative response format.
    if (response.data?.result) {
      return response.data.result;
    }

    if (response.data && typeof response.data === "object") {
      return response.data;
    }

    return null;
  }

  function getAnalysisScore(result) {
    const candidates = [
      result.riskScore,
      result.risk_score,
      result.guardian?.riskScore,
      result.guardian?.risk_score,
      result.result?.riskScore,
      result.result?.risk_score,
    ];

    for (const candidate of candidates) {
      if (
        candidate !== null &&
        candidate !== undefined &&
        candidate !== ""
      ) {
        const score = Number(candidate);

        if (
          Number.isFinite(score) &&
          score >= 0 &&
          score <= 100
        ) {
          return score;
        }
      }
    }

    return null;
  }

  function getAnalysisCategory(result) {
    return (
      result.fraudCategory ||
      result.fraud_category ||
      result.category ||
      result.guardian?.fraudCategory ||
      result.guardian?.fraud_category ||
      "unclassified"
    );
  }

  function getAnalysisRiskLevel(result, score) {
    return normalizeRiskLevel(
      result.riskLevel ||
      result.risk_level ||
      result.guardian?.riskLevel ||
      result.guardian?.risk_level,
      score
    );
  }

  function getAgentResults(result) {
    return result.agent_results ||
      result.agentResults ||
      {};
  }

  function setAgentText(element, value, fallback) {
    if (!element) return;

    element.textContent =
      formatExplanation(value) || fallback;
  }

  /* =======================================================
     6. EVIDENCE SELECTION
  ======================================================= */

  function switchEvidenceType(type) {
    if (!Object.prototype.hasOwnProperty.call(
      EVIDENCE_LIMITS,
      type
    )) {
      console.warn("Unsupported evidence type:", type);
      return;
    }

    currentEvidenceType = type;

    elements.evidenceButtons.forEach((button) => {
      const active = button.dataset.evidence === type;

      button.classList.toggle("active", active);

      button.setAttribute(
        "aria-pressed",
        String(active)
      );
    });

    elements.evidenceForms.forEach((form) => {
      const active = form.dataset.form === type;

      form.classList.toggle("active", active);

      form.hidden = !active;
    });

    resetResults();

    hideMessage();
  }

  elements.evidenceButtons.forEach((button) => {
    button.addEventListener("click", () => {
      switchEvidenceType(button.dataset.evidence);
    });
  });

  /* =======================================================
     7. CHARACTER COUNTERS
  ======================================================= */

  const inputMap = {
    message: elements.messageInput,
    call: elements.callInput,
    email: elements.emailInput,
    url: elements.urlInput,
    screenshot: elements.screenshotInput,
    transaction: elements.transactionInput,
  };

  const counterMap = {
    message: elements.messageCount,
    call: elements.callCount,
    email: elements.emailCount,
    screenshot: elements.screenshotCount,
    transaction: elements.transactionCount,
  };

  function updateCounter(type) {
    const input = inputMap[type];
    const counter = counterMap[type];

    if (!input || !counter) return;

    const maximum = EVIDENCE_LIMITS[type];

    counter.textContent =
      `${input.value.length} / ${maximum}`;

    counter.classList.toggle(
      "limit-reached",
      input.value.length >= maximum
    );
  }

  Object.keys(counterMap).forEach((type) => {
    const input = inputMap[type];

    if (!input) return;

    input.addEventListener("input", () => {
      updateCounter(type);
    });

    updateCounter(type);
  });

  /* =======================================================
     8. GET EVIDENCE
  ======================================================= */

  function getEvidence() {
    const input = inputMap[currentEvidenceType];

    if (!input) {
      throw new Error(
        "Selected evidence input is unavailable."
      );
    }

    const evidence = normalizeText(input.value);

    if (!evidence) {
      throw new Error(
        "Please provide evidence before analysis."
      );
    }

    const maximum = EVIDENCE_LIMITS[currentEvidenceType];

    if (evidence.length > maximum) {
      throw new Error(
        `Evidence exceeds the maximum limit of ${maximum} characters.`
      );
    }

    if (currentEvidenceType === "url") {
      let parsedURL;

      try {
        parsedURL = new URL(evidence);
      } catch {
        throw new Error(
          "Please enter a valid website URL."
        );
      }

      if (!["http:", "https:"].includes(parsedURL.protocol)) {
        throw new Error(
          "Only HTTP and HTTPS URLs are supported."
        );
      }

      if (
        !parsedURL.hostname ||
        !parsedURL.hostname.includes(".")
      ) {
        throw new Error(
          "Please enter a valid website hostname."
        );
      }
    }

    return evidence;
  }

  /* =======================================================
     9. RESET RESULTS
  ======================================================= */

  function resetResults() {
    currentAnalysisId = null;
    currentCaseId = null;

    elements.detectionResults.hidden = true;

    elements.resultStatus.textContent = "Pending";

    elements.riskScore.textContent = "--";

    elements.riskLevel.textContent = "Awaiting Analysis";

    elements.riskDescription.textContent =
      "Submit evidence to receive an explainable risk assessment.";

    elements.fraudCategory.textContent =
      "Not classified yet.";

    elements.riskExplanation.textContent =
      "Analysis explanation will appear here.";

    elements.riskScoreCircle.style.background =
      "conic-gradient(#263746 0deg, #263746 360deg)";

    elements.indicatorList.replaceChildren();

    const emptyIndicators = document.createElement("p");

    emptyIndicators.textContent =
      "No indicators extracted yet.";

    elements.indicatorList.appendChild(emptyIndicators);

    renderSafetyGuidance("medium");

    setAgentText(
      elements.guardianAgentResult,
      null,
      "Guardian analysis is pending."
    );

    setAgentText(
      elements.intelligenceAgentResult,
      null,
      "Intelligence analysis is pending."
    );

    setAgentText(
      elements.victimSafetyAgentResult,
      null,
      "Victim Safety analysis is pending."
    );

    setAgentText(
      elements.decoyAgentResult,
      null,
      "Decoy simulation has not been started."
    );

    setAgentText(
      elements.geminiAdvisory,
      null,
      "Gemini advisory is pending."
    );

    if (elements.feedbackPanel) {
      elements.feedbackPanel.hidden = true;
    }

    if (elements.feedbackStatus) {
      elements.feedbackStatus.textContent = "";

      elements.feedbackStatus.className = "";
    }

    if (elements.feedbackSelect) {
      elements.feedbackSelect.selectedIndex = 0;
    }
  }

  /* =======================================================
     10. RENDER INDICATORS
  ======================================================= */

  function renderIndicators(indicators) {
    const container = elements.indicatorList;

    container.replaceChildren();

    if (!Array.isArray(indicators) || indicators.length === 0) {
      const empty = document.createElement("p");

      empty.textContent =
        "No suspicious indicators were extracted.";

      container.appendChild(empty);

      return;
    }

    indicators.slice(0, 50).forEach((indicator) => {
      if (!indicator || typeof indicator !== "object") {
        return;
      }

      const item = document.createElement("div");

      item.className = "indicator-item";

      const type = document.createElement("strong");

      type.textContent =
        normalizeText(indicator.type) || "Indicator";

      const value = document.createElement("span");

      value.textContent =
        normalizeText(indicator.value) || "Not available";

      const verification = document.createElement("span");

      if (indicator.verified === true) {
        verification.className = "indicator-verified";

        verification.textContent = "Verified";
      } else {
        verification.className = "indicator-unverified";

        verification.textContent = "Unverified";
      }

      item.append(type, value, verification);

      container.appendChild(item);
    });

    if (!container.children.length) {
      const empty = document.createElement("p");

      empty.textContent =
        "No valid indicators were returned.";

      container.appendChild(empty);
    }
  }

  /* =======================================================
     11. RENDER SAFETY GUIDANCE
  ======================================================= */

  function renderSafetyGuidance(level, serverGuidance = null) {
    const container = elements.safetyGuidance;

    container.replaceChildren();

    let guidance = SAFETY_GUIDANCE[level] ||
      SAFETY_GUIDANCE.medium;

    if (Array.isArray(serverGuidance)) {
      guidance = serverGuidance
        .map((item) => {
          if (typeof item === "string") {
            return item;
          }

          if (item && typeof item === "object") {
            return (
              item.message ||
              item.description ||
              ""
            );
          }

          return "";
        })
        .filter(Boolean);
    }

    guidance.forEach((message) => {
      const item = document.createElement("li");

      item.textContent = message;

      container.appendChild(item);
    });
  }

  /* =======================================================
     12. RENDER AGENT RESULTS
  ======================================================= */

  function renderAgentResults(result) {
    const agents = getAgentResults(result);

    const guardian =
      agents.guardian ||
      result.guardian ||
      result.guardian_result;

    const intelligence =
      agents.intelligence ||
      result.intelligence ||
      result.intelligence_result;

    const victimSafety =
      agents.victim_safety ||
      agents.victimSafety ||
      result.victim_safety ||
      result.victimSafety;

    const decoy =
      agents.decoy ||
      result.decoy ||
      result.decoy_result;

    setAgentText(
      elements.guardianAgentResult,
      guardian?.summary ||
      guardian?.explanation ||
      guardian?.message ||
      guardian,
      "Guardian analysis completed."
    );

    setAgentText(
      elements.intelligenceAgentResult,
      intelligence?.summary ||
      intelligence?.message ||
      intelligence?.indicators ||
      intelligence,
      "No additional intelligence information was returned."
    );

    setAgentText(
      elements.victimSafetyAgentResult,
      victimSafety?.summary ||
      victimSafety?.message ||
      victimSafety?.guidance ||
      victimSafety,
      "Victim Safety analysis completed."
    );

    setAgentText(
      elements.decoyAgentResult,
      decoy?.summary ||
      decoy?.message ||
      decoy,
      "Decoy simulation was not started during this analysis."
    );

    const advisory =
      result.gemini_advisory ||
      result.geminiAdvisory ||
      result.advisory ||
      null;

    setAgentText(
      elements.geminiAdvisory,
      advisory?.summary ||
      advisory?.advice ||
      advisory?.message ||
      advisory,
      "No Gemini advisory was returned."
    );
  }

  /* =======================================================
     13. RENDER ANALYSIS RESULTS
  ======================================================= */

  function renderResults(result) {
    if (!result || typeof result !== "object") {
      throw new Error(
        "Invalid analysis response received."
      );
    }

    const score = getAnalysisScore(result);

    if (score === null) {
      throw new Error(
        "Analysis response does not contain a valid risk score."
      );
    }

    const roundedScore = Math.round(score);

    // Preserve Guardian's returned risk classification.
    const riskLevel = getAnalysisRiskLevel(
      result,
      roundedScore
    );

    const riskInfo = RISK_LEVELS[riskLevel];

    const category = getAnalysisCategory(result);

    elements.riskScore.textContent = roundedScore;

    elements.riskLevel.textContent = riskInfo.label;

    elements.riskDescription.textContent =
      result.riskDescription ||
      result.risk_description ||
      result.summary ||
      riskInfo.description;

    elements.fraudCategory.textContent =
      getCategoryLabel(category);

    elements.riskExplanation.textContent =
      formatExplanation(
        result.explanation ||
        result.riskExplanation ||
        result.risk_explanation
      );

    elements.resultStatus.textContent =
      "Analysis Complete";

    const degrees = roundedScore * 3.6;

    elements.riskScoreCircle.style.background = `
      conic-gradient(
        ${riskInfo.color} ${degrees}deg,
        #263746 ${degrees}deg
      )
    `;

    renderIndicators(
      result.indicators ||
      result.extracted_indicators ||
      []
    );

    const victimSafety =
      result.victim_safety ||
      result.victimSafety ||
      {};

    renderSafetyGuidance(
      riskLevel,
      victimSafety.guidance ||
      victimSafety.safety_guidance ||
      result.safety_guidance
    );

    renderAgentResults(result);

    elements.detectionResults.hidden = false;

    elements.detectionResults.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });

    return {
      score: roundedScore,
      riskLevel,
      category,
    };
  }

  /* =======================================================
     14. CREATE CASE
  ======================================================= */

  async function createAnalysisCase(result, evidence) {
    const analysisId =
      result.id ||
      result.analysisId ||
      result.analysis_id;

    if (!analysisId) {
      throw new Error(
        "Analysis ID was not returned. Case cannot be created."
      );
    }

    const score = getAnalysisScore(result);

    if (score === null) {
      throw new Error(
        "Invalid risk score. Case cannot be created."
      );
    }

    const roundedScore = Math.round(score);

    const riskLevel = getAnalysisRiskLevel(
      result,
      roundedScore
    );

    const category = getAnalysisCategory(result);

    const indicators = Array.isArray(result.indicators)
      ? result.indicators
          .filter(
            (item) =>
              item &&
              typeof item === "object" &&
              item.type &&
              item.value
          )
          .slice(0, 50)
          .map((item) => ({
            type: String(item.type).slice(0, 30),
            value: String(item.value).slice(0, 300),
          }))
      : [];

    const casePayload = {
      analysisId,

      title: `${getCategoryLabel(category)} Detection Case`,

      description:
        `Evidence type: ${currentEvidenceType}\n` +
        `Risk score: ${roundedScore}/100\n` +
        `Risk level: ${riskLevel}\n` +
        `Evidence preview: ${evidence.slice(0, 500)}`,

      fraudCategory: category,

      riskLevel,

      priority: getPriority(roundedScore),

      indicators,
    };

    const response = await API.post(
      "/cases",
      casePayload
    );

    if (!response || response.success !== true) {
      throw new Error(
        response?.message ||
        "Unable to save the detection case."
      );
    }

    const savedCase =
      response.data?.case ||
      response.data ||
      response.case ||
      null;

    if (!savedCase || typeof savedCase !== "object") {
      throw new Error(
        "Case was not returned by the server."
      );
    }

    currentCaseId =
      savedCase._id ||
      savedCase.id ||
      null;

    if (!currentCaseId) {
      throw new Error(
        "Saved case ID was not returned by the server."
      );
    }

    return savedCase;
  }

  /* =======================================================
     15. ANALYZE EVIDENCE
  ======================================================= */

  async function analyzeEvidence() {
    if (isAnalyzing) return;

    hideMessage();

    let evidence;

    try {
      evidence = getEvidence();
    } catch (error) {
      showMessage(error.message, "error");
      return;
    }

    if (!getToken()) {
      showMessage(
        "Your session has expired. Please login again.",
        "error"
      );

      return;
    }

    isAnalyzing = true;

    resetResults();

    setButtonLoading(elements.analyzeBtn, true);

    elements.clearBtn.disabled = true;

    if (elements.analysisPanelStatus) {
      elements.analysisPanelStatus.textContent =
        "Analyzing evidence...";
    }

    showMessage(
      `Analyzing ${currentEvidenceType} evidence. Please wait...`,
      "info"
    );

    try {

      /* STEP 1: ANALYZE EVIDENCE */

      const payload = {
        evidenceType: currentEvidenceType,

        evidence,

        selectedCategory: getSelectedCategory(),

        selectedCategoryLabel: getSelectedCategoryLabel(),
      };

      const response = await API.post(
        "/analysis/analyze",
        payload
      );

      if (!response || response.success !== true) {
        throw new Error(
          response?.message ||
          "Evidence analysis failed."
        );
      }

      const result = getResponseResult(response);

      if (!result) {
        throw new Error(
          "Analysis server returned an empty result."
        );
      }

      currentAnalysisId =
        result.id ||
        result.analysisId ||
        result.analysis_id ||
        null;

      /* STEP 2: DISPLAY RESULTS */

      renderResults(result);

      /* STEP 3: SAVE CASE */

      try {
        await createAnalysisCase(
          result,
          evidence
        );

        if (elements.feedbackPanel) {
          elements.feedbackPanel.hidden = false;
        }

        showMessage(
          "Analysis completed successfully. Detection case saved.",
          "success"
        );

      } catch (caseError) {
        console.error(
          "Case creation error:",
          caseError
        );

        if (elements.feedbackPanel) {
          elements.feedbackPanel.hidden = true;
        }

        showMessage(
          "Analysis completed, but the case could not be saved: " +
          caseError.message,
          "warning"
        );
      }

      if (elements.analysisPanelStatus) {
        elements.analysisPanelStatus.textContent =
          "Analysis completed.";
      }

    } catch (error) {
      console.error(
        "Detection analysis error:",
        error
      );

      const message =
        error.message ||
        "Unable to analyze evidence.";

      if (
        /token|login|authentication|unauthorized|401/i.test(message)
      ) {
        showMessage(
          "Authentication failed. Please login again.",
          "error"
        );
      } else {
        showMessage(message, "error");
      }

      if (elements.analysisPanelStatus) {
        elements.analysisPanelStatus.textContent =
          "Analysis failed.";
      }

    } finally {
      isAnalyzing = false;

      setButtonLoading(elements.analyzeBtn, false);

      elements.clearBtn.disabled = false;
    }
  }

  /* =======================================================
     16. CLASSIFICATION FEEDBACK
  ======================================================= */

  async function submitClassificationFeedback() {
    if (isSubmittingFeedback) return;

    if (!currentCaseId) {
      showMessage(
        "No saved case is available for feedback.",
        "error"
      );

      return;
    }

    if (
      !elements.feedbackSelect ||
      !elements.feedbackBtn ||
      !elements.feedbackStatus
    ) {
      showMessage(
        "Classification feedback elements are unavailable.",
        "error"
      );

      return;
    }

    if (typeof API.patch !== "function") {
      showMessage(
        "Feedback API is unavailable.",
        "error"
      );

      return;
    }

    const feedback = elements.feedbackSelect.value;

    const allowedFeedback = [
      "needs_review",
      "possible_false_positive",
      "category_correction_requested",
    ];

    if (!allowedFeedback.includes(feedback)) {
      elements.feedbackStatus.textContent =
        "Please select valid feedback.";

      elements.feedbackStatus.className = "error";

      return;
    }

    isSubmittingFeedback = true;

    const originalHTML = elements.feedbackBtn.innerHTML;

    elements.feedbackBtn.disabled = true;

    elements.feedbackBtn.innerHTML = `
      <i class="fa-solid fa-spinner fa-spin"></i>
      Saving...
    `;

    elements.feedbackStatus.textContent = "";

    try {
      const response = await API.patch(
        `/cases/${encodeURIComponent(currentCaseId)}`,
        {
          classificationFeedback: feedback,
        }
      );

      if (!response || response.success !== true) {
        throw new Error(
          response?.message ||
          "Unable to save feedback."
        );
      }

      elements.feedbackStatus.textContent =
        "Feedback saved successfully.";

      elements.feedbackStatus.className = "success";

    } catch (error) {
      console.error("Feedback error:", error);

      elements.feedbackStatus.textContent =
        error.message ||
        "Failed to save feedback.";

      elements.feedbackStatus.className = "error";

    } finally {
      isSubmittingFeedback = false;

      elements.feedbackBtn.disabled = false;

      elements.feedbackBtn.innerHTML = originalHTML;
    }
  }

  /* =======================================================
     17. CLEAR FORM
  ======================================================= */

  function clearDetectionForm() {
    if (isAnalyzing || isSubmittingFeedback) {
      return;
    }

    Object.values(inputMap).forEach((input) => {
      if (input) {
        input.value = "";
      }
    });

    Object.keys(counterMap).forEach((type) => {
      updateCounter(type);
    });

    if (elements.fraudCategorySelect) {
      elements.fraudCategorySelect.value = "auto";
    }

    switchEvidenceType("message");

    resetResults();

    hideMessage();

    if (elements.analysisPanelStatus) {
      elements.analysisPanelStatus.textContent =
        "Ready for analysis.";
    }

    elements.analyzeBtn.disabled = false;

    elements.clearBtn.disabled = false;
  }

  /* =======================================================
     18. EVENT LISTENERS
  ======================================================= */

  elements.analyzeBtn.addEventListener(
    "click",
    analyzeEvidence
  );

  elements.clearBtn.addEventListener(
    "click",
    clearDetectionForm
  );

  if (elements.feedbackBtn) {
    elements.feedbackBtn.addEventListener(
      "click",
      submitClassificationFeedback
    );
  }

  /* =======================================================
     19. INITIALIZATION
  ======================================================= */

  switchEvidenceType("message");

  resetResults();

  if (elements.analysisPanelStatus) {
    elements.analysisPanelStatus.textContent =
      "Ready for analysis.";
  }

  console.log(
    "ScamShield AI Detection Module v3.0.0 initialized successfully."
  );

});