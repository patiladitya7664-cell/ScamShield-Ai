"use strict";

/* =========================================================
   SCAMSHIELD AI — CALL ANALYSIS
   Version: 3.0.0

   Features:
   - Call transcript analysis
   - Centralized ScamShieldAPI integration
   - Guardian-authoritative risk results
   - Intelligence and Victim Safety results
   - Gemini advisory-only display
   - Controlled Decoy status
   - Safe DOM rendering
   - Input validation and character counter
   - Analysis feedback
   - Responsive navigation

   Limitations:
   - Transcript text only
   - No automatic call recording
   - No live listening or caller identification
   - No automatic transcription
========================================================= */

(() => {
  const VERSION = "3.0.0";

  const API = window.ScamShieldAPI;

  const CONFIG = {
    maxLength: 20000,
    endpoint: "/analysis/analyze",
    feedbackEndpoint: "/cases"
  };

  const state = {
    isAnalyzing: false,
    lastAnalysis: null,
    lastCaseId: null,
    selectedFeedback: null
  };

  const $ = (id) => document.getElementById(id);

  const elements = {
    form: $("callAnalysisForm"),
    callerType: $("callerType"),
    transcript: $("callTranscript"),
    characterCount: $("callCharacterCount"),
    inputHelp: $("callInputHelp"),
    inputError: $("callInputError"),
    category: $("callFraudCategory"),
    consent: $("callAnalysisConsent"),
    clearButton: $("clearCallForm"),
    analyzeButton: $("analyzeCallButton"),

    status: $("callAnalysisStatus"),
    statusMessage: $("callAnalysisStatusMessage"),

    results: $("callResults"),
    riskOverview: $("callRiskOverview"),
    riskScoreCircle: $("callRiskScoreCircle"),
    riskScore: $("callRiskScore"),
    riskLevel: $("callRiskLevel"),
    fraudCategory: $("callFraudCategoryResult"),
    riskDescription: $("callRiskDescription"),

    guardianStatus: $("guardianStatus"),
    guardianResult: $("guardianResult"),

    intelligenceStatus: $("intelligenceStatus"),
    intelligenceResult: $("intelligenceResult"),

    victimSafetyStatus: $("victimSafetyStatus"),
    victimSafetyResult: $("victimSafetyResult"),

    geminiStatus: $("geminiStatus"),
    geminiResult: $("geminiResult"),

    decoyStatus: $("decoyStatus"),
    decoyResult: $("decoyResult"),

    feedbackHelpful: $("callFeedbackHelpful"),
    feedbackReview: $("callFeedbackReview"),
    feedbackStatus: $("callFeedbackStatus")
  };

  const CATEGORY_LABELS = {
    fraud_message: "Fraud Message",
    fraud_call: "Fraud Call",
    url_phishing: "URL Phishing",
    email_scam: "Email Scam",
    investment_scam: "Investment Scam",
    digital_arrest: "Digital Arrest",
    upi_banking_fraud: "UPI / Banking Fraud",
    card_fraud: "Credit / Debit Card Fraud",
    ecommerce_scam: "E-commerce Scam",
    job_loan_scam: "Job / Loan Scam",
    sextortion_blackmail: "Sextortion / Blackmail",
    social_media_scam: "Social Media Scam",
    unknown: "Not Classified"
  };

  /* =====================================================
     INITIALIZATION
  ===================================================== */

  function init() {
    console.info(`ScamShield Call Analysis v${VERSION} initialized.`);

    if (!elements.form || !elements.transcript) {
      console.error("Call analysis form elements were not found.");
      return;
    }

    bindEvents();
    updateCharacterCount();
    resetResults();
  }

  function bindEvents() {
    elements.form.addEventListener("submit", handleAnalysis);

    elements.transcript.addEventListener("input", () => {
      updateCharacterCount();
      clearInputError();
    });

    elements.clearButton?.addEventListener("click", clearForm);

    elements.feedbackHelpful?.addEventListener("click", () => {
      submitFeedback("helpful");
    });

    elements.feedbackReview?.addEventListener("click", () => {
      submitFeedback("needs_review");
    });

    setupNavigation();
  }

  /* =====================================================
     NAVIGATION
  ===================================================== */

  function setupNavigation() {
    const toggle = $("mobileMenuToggle");
    const navigation = $("primaryNavigation");

    if (toggle && navigation) {
      toggle.addEventListener("click", () => {
        const isOpen = navigation.classList.toggle("active");
        toggle.setAttribute("aria-expanded", String(isOpen));
      });
    }

    document.querySelectorAll('[data-action="logout"]').forEach((button) => {
      button.addEventListener("click", logout);
    });
  }

  function logout() {
    const keys = [
      "scamshieldToken",
      "token",
      "authToken",
      "scamshieldUser"
    ];

    keys.forEach((key) => {
      localStorage.removeItem(key);
      sessionStorage.removeItem(key);
    });

    window.location.href = "login.html";
  }

  /* =====================================================
     INPUT VALIDATION
  ===================================================== */

  function validateInput() {
    const transcript = elements.transcript.value.trim();

    if (!transcript) {
      showInputError("Please paste the suspicious call transcript.");
      elements.transcript.focus();
      return false;
    }

    if (transcript.length > CONFIG.maxLength) {
      showInputError(
        `Transcript must not exceed ${CONFIG.maxLength} characters.`
      );
      elements.transcript.focus();
      return false;
    }

    if (!elements.consent?.checked) {
      showInputError("Please confirm that you have permission to analyze this transcript.");
      elements.consent?.focus();
      return false;
    }

    return true;
  }

  function showInputError(message) {
    if (elements.inputError) {
      elements.inputError.textContent = message;
      elements.inputError.hidden = false;
    }

    elements.transcript?.setAttribute("aria-invalid", "true");
  }

  function clearInputError() {
    if (elements.inputError) {
      elements.inputError.textContent = "";
      elements.inputError.hidden = true;
    }

    elements.transcript?.removeAttribute("aria-invalid");
  }

  function updateCharacterCount() {
    if (!elements.characterCount || !elements.transcript) return;

    const length = elements.transcript.value.length;

    elements.characterCount.textContent =
      `${length.toLocaleString()} / ${CONFIG.maxLength.toLocaleString()}`;

    elements.characterCount.classList.toggle(
      "limit-reached",
      length >= CONFIG.maxLength
    );
  }

  /* =====================================================
     ANALYSIS
  ===================================================== */

  async function handleAnalysis(event) {
    event.preventDefault();

    if (state.isAnalyzing) return;
    if (!validateInput()) return;

    if (!API || typeof API.post !== "function") {
      showStatus(
        "The API service is unavailable. Please refresh the page and try again.",
        "error"
      );
      return;
    }

    const payload = buildPayload();

    state.isAnalyzing = true;
    setLoading(true);
    hideResults();

    showStatus("Analyzing the call transcript. Please wait...", "loading");

    try {
      const response = await API.post(CONFIG.endpoint, payload);

      if (!response || response.success === false) {
        throw new Error(
          response?.message || "The analysis request could not be completed."
        );
      }

      const normalized = normalizeResponse(response);

      if (!normalized.result) {
        throw new Error("The AI engine returned an incomplete analysis result.");
      }

      state.lastAnalysis = normalized;
      state.lastCaseId = normalized.caseId || null;

      renderResults(normalized);

      showStatus("Call transcript analysis completed.", "success");

      elements.results?.scrollIntoView({
        behavior: "smooth",
        block: "start"
      });

    } catch (error) {
      console.error("Call analysis failed:", error);

      showStatus(
        getErrorMessage(error),
        "error"
      );
    } finally {
      state.isAnalyzing = false;
      setLoading(false);
    }
  }

  function buildPayload() {
    return {
      evidence_type: "call",
      evidence: elements.transcript.value.trim(),
      category: elements.category?.value || undefined,
      metadata: {
        source: "analyze-call-page",
        caller_type: elements.callerType?.value || "unknown",
        input_method: "manual_transcript",
        version: VERSION
      }
    };
  }

  /* =====================================================
     RESPONSE NORMALIZATION

     Supports common API response envelopes:
     - response.data.result
     - response.result
     - response.data
     - direct result object

     Guardian's result remains authoritative.
  ===================================================== */

  function normalizeResponse(response) {
    const outer = response || {};
    const data = outer.data || outer;
    const result =
      data.result ||
      data.analysis?.result ||
      data.analysis ||
      outer.result ||
      null;

    const agents = data.agent_results || data.agents || {};
    const orchestration = data.orchestration || {};

    const guardian =
      agents.guardian ||
      data.guardian ||
      result?.guardian ||
      null;

    return {
      result,
      guardian,

      intelligence:
        data.intelligence ||
        agents.intelligence ||
        null,

      victimSafety:
        data.victim_safety ||
        data.victimSafety ||
        agents.victim_safety ||
        agents.victimSafety ||
        null,

      gemini:
        data.gemini_advisory ||
        data.gemini ||
        agents.gemini ||
        null,

      decoy:
        agents.decoy ||
        data.decoy ||
        null,

      orchestration,

      caseId:
        data.case?._id ||
        data.case?.id ||
        data.caseId ||
        data.case_id ||
        null,

      raw: outer
    };
  }

  /* =====================================================
     RESULT DISPLAY
  ===================================================== */

  function renderResults(data) {
    const result = data.result || {};

    const score = normalizeScore(
      result.risk_score ??
      result.riskScore ??
      result.score
    );

    const level = normalizeRiskLevel(
      result.risk_level ||
      result.riskLevel ||
      getRiskLevelFromScore(score)
    );

    const category =
      result.category ||
      result.fraud_category ||
      result.fraudCategory ||
      "unknown";

    const description =
      result.description ||
      result.explanation ||
      result.risk_description ||
      "Analysis completed. Review the findings carefully.";

    setText(elements.riskScore, String(score));
    setText(elements.riskLevel, level);
    setText(elements.fraudCategory, getCategoryLabel(category));
    setText(elements.riskDescription, description);

    if (elements.riskScoreCircle) {
      elements.riskScoreCircle.style.setProperty(
        "--risk-score",
        `${score}%`
      );

      elements.riskScoreCircle.setAttribute(
        "aria-label",
        `Risk score ${score} out of 100`
      );
    }

    if (elements.riskOverview) {
      elements.riskOverview.className =
        `risk-overview risk-${level.toLowerCase()}`;
    }

    if (elements.riskLevel) {
      elements.riskLevel.className =
        `risk-level ${level.toLowerCase()}`;
    }

    renderGuardian(data.guardian, result);
    renderIntelligence(data.intelligence);
    renderVictimSafety(data.victimSafety);
    renderGemini(data.gemini);
    renderDecoy(data.decoy);

    elements.results.hidden = false;
  }

  function renderGuardian(guardian, result) {
    const source = guardian || result;

    if (!source) {
      setAgent(
        elements.guardianStatus,
        elements.guardianResult,
        "Unavailable",
        "Guardian result was not included in the response."
      );
      return;
    }

    const category = source.category || result.category || "unknown";
    const score = normalizeScore(
      source.risk_score ??
      source.riskScore ??
      result.risk_score ??
      result.riskScore
    );

    const level = normalizeRiskLevel(
      source.risk_level ||
      source.riskLevel ||
      result.risk_level ||
      result.riskLevel ||
      getRiskLevelFromScore(score)
    );

    const explanation =
      source.explanation ||
      source.reason ||
      source.description ||
      result.explanation ||
      result.description ||
      "Guardian completed the primary fraud assessment.";

    setAgent(
      elements.guardianStatus,
      elements.guardianResult,
      "Completed",
      `Category: ${getCategoryLabel(category)}. Risk: ${level} (${score}/100). ${explanation}`
    );
  }

  function renderIntelligence(intelligence) {
    if (!intelligence) {
      setAgent(
        elements.intelligenceStatus,
        elements.intelligenceResult,
        "Unavailable",
        "No intelligence indicators were returned."
      );
      return;
    }

    const indicators =
      intelligence.indicators ||
      intelligence.matches ||
      intelligence.findings ||
      [];

    const summary =
      intelligence.summary ||
      intelligence.message ||
      intelligence.status_message ||
      "Intelligence assessment completed.";

    const indicatorText = Array.isArray(indicators)
      ? indicators.map((item) => {
          if (typeof item === "string") return item;
          return item.name || item.value || item.description || "Indicator found";
        }).join("; ")
      : "";

    setAgent(
      elements.intelligenceStatus,
      elements.intelligenceResult,
      intelligence.status || "Completed",
      `${summary}${indicatorText ? ` Indicators: ${indicatorText}` : ""} Treat indicators as unverified unless independently confirmed.`
    );
  }

  function renderVictimSafety(safety) {
    if (!safety) {
      setAgent(
        elements.victimSafetyStatus,
        elements.victimSafetyResult,
        "Unavailable",
        "No victim safety guidance was returned."
      );
      return;
    }

    const guidance =
      safety.guidance ||
      safety.recommendations ||
      safety.actions ||
      safety.message ||
      safety.summary ||
      "Review the guidance and contact your bank or relevant authorities if money or sensitive information was shared.";

    setAgent(
      elements.victimSafetyStatus,
      elements.victimSafetyResult,
      safety.status || "Guidance available",
      formatValue(guidance)
    );
  }

  function renderGemini(gemini) {
    if (!gemini) {
      setAgent(
        elements.geminiStatus,
        elements.geminiResult,
        "Unavailable",
        "Gemini advisory was not returned. The primary Guardian assessment remains independent."
      );
      return;
    }

    const advisory =
      gemini.advisory ||
      gemini.summary ||
      gemini.explanation ||
      gemini.message ||
      gemini;

    const status =
      gemini.status ||
      (gemini.available === false ? "Unavailable" : "Advisory");

    setAgent(
      elements.geminiStatus,
      elements.geminiResult,
      status,
      `${formatValue(advisory)} Gemini is advisory-only and does not determine or override the Guardian risk score or category.`
    );
  }

  function renderDecoy(decoy) {
    if (!decoy) {
      setAgent(
        elements.decoyStatus,
        elements.decoyResult,
        "Not started",
        "Decoy simulation was not automatically started during this analysis."
      );
      return;
    }

    const status =
      decoy.status ||
      (decoy.started ? "Active" : "Not started");

    const message =
      decoy.message ||
      decoy.summary ||
      "Decoy agent status received.";

    setAgent(
      elements.decoyStatus,
      elements.decoyResult,
      status,
      `${formatValue(message)} Decoy activity must remain controlled and explicitly initiated.`
    );
  }

  /* =====================================================
     FEEDBACK
  ===================================================== */

  async function submitFeedback(feedback) {
    if (!state.lastAnalysis) {
      setFeedbackStatus("Complete an analysis before submitting feedback.");
      return;
    }

    if (!state.lastCaseId) {
      setFeedbackStatus(
        "No case ID was returned. Feedback cannot be saved until a case is created."
      );
      return;
    }

    if (!API || typeof API.patch !== "function") {
      setFeedbackStatus("Feedback service is unavailable.");
      return;
    }

    if (state.selectedFeedback) return;

    state.selectedFeedback = feedback;

    try {
      const endpoint =
        `${CONFIG.feedbackEndpoint}/${encodeURIComponent(state.lastCaseId)}`;

      const response = await API.patch(endpoint, {
        feedback,
        source: "analyze-call-page"
      });

      if (response?.success === false) {
        throw new Error(response.message || "Feedback could not be saved.");
      }

      setFeedbackStatus("Thank you. Your feedback has been submitted.");

      if (elements.feedbackHelpful) {
        elements.feedbackHelpful.disabled = true;
      }

      if (elements.feedbackReview) {
        elements.feedbackReview.disabled = true;
      }

    } catch (error) {
      state.selectedFeedback = null;
      console.error("Feedback submission failed:", error);
      setFeedbackStatus(getErrorMessage(error));
    }
  }

  function setFeedbackStatus(message) {
    setText(elements.feedbackStatus, message);
  }

  /* =====================================================
     FORM CONTROLS
  ===================================================== */

  function clearForm() {
    if (state.isAnalyzing) return;

    elements.form.reset();

    updateCharacterCount();
    clearInputError();
    hideStatus();
    resetResults();

    state.lastAnalysis = null;
    state.lastCaseId = null;
    state.selectedFeedback = null;

    if (elements.feedbackHelpful) {
      elements.feedbackHelpful.disabled = false;
    }

    if (elements.feedbackReview) {
      elements.feedbackReview.disabled = false;
    }

    setFeedbackStatus("");
  }

  function resetResults() {
    hideResults();

    setText(elements.riskScore, "0");
    setText(elements.riskLevel, "Not assessed");
    setText(elements.fraudCategory, "Not classified");
    setText(elements.riskDescription, "Analysis results will appear here.");

    setAgent(
      elements.guardianStatus,
      elements.guardianResult,
      "Waiting",
      "Guardian assessment will appear here."
    );

    setAgent(
      elements.intelligenceStatus,
      elements.intelligenceResult,
      "Waiting",
      "Intelligence findings will appear here."
    );

    setAgent(
      elements.victimSafetyStatus,
      elements.victimSafetyResult,
      "Waiting",
      "Victim safety guidance will appear here."
    );

    setAgent(
      elements.geminiStatus,
      elements.geminiResult,
      "Waiting",
      "Optional Gemini advisory will appear here."
    );

    setAgent(
      elements.decoyStatus,
      elements.decoyResult,
      "Not started",
      "Decoy simulation will not start automatically."
    );
  }

  function setLoading(isLoading) {
    if (!elements.analyzeButton) return;

    elements.analyzeButton.disabled = isLoading;

    const label = elements.analyzeButton.querySelector(
      "[data-button-label]"
    );

    if (label) {
      label.textContent = isLoading
        ? "Analyzing..."
        : "Analyze Call";
    } else {
      elements.analyzeButton.textContent = isLoading
        ? "Analyzing..."
        : "Analyze Call";
    }

    if (elements.clearButton) {
      elements.clearButton.disabled = isLoading;
    }
  }

  /* =====================================================
     STATUS DISPLAY
  ===================================================== */

  function showStatus(message, type) {
    if (!elements.status || !elements.statusMessage) return;

    elements.status.hidden = false;
    elements.status.className =
      `call-analysis-status status-${type}`;

    elements.statusMessage.textContent = message;
  }

  function hideStatus() {
    if (!elements.status) return;

    elements.status.hidden = true;
    elements.status.className = "call-analysis-status";
  }

  function hideResults() {
    if (elements.results) {
      elements.results.hidden = true;
    }
  }

  /* =====================================================
     SAFE DOM HELPERS
  ===================================================== */

  function setText(element, value) {
    if (!element) return;

    element.textContent = String(value ?? "");
  }

  function setAgent(statusElement, resultElement, status, message) {
    setText(statusElement, status);
    setText(resultElement, message);
  }

  function formatValue(value) {
    if (value === null || value === undefined) {
      return "No details available.";
    }

    if (typeof value === "string" || typeof value === "number") {
      return String(value);
    }

    if (Array.isArray(value)) {
      return value.map(formatValue).join("; ");
    }

    if (typeof value === "object") {
      const preferredKeys = [
        "summary",
        "message",
        "description",
        "guidance",
        "recommendation",
        "reason",
        "status"
      ];

      const parts = preferredKeys
        .filter((key) => value[key] !== undefined)
        .map((key) => `${key}: ${formatValue(value[key])}`);

      return parts.length
        ? parts.join(" | ")
        : "Details received.";
    }

    return String(value);
  }

  /* =====================================================
     RISK HELPERS
  ===================================================== */

  function normalizeScore(value) {
    const score = Number(value);

    if (!Number.isFinite(score)) return 0;

    return Math.max(0, Math.min(100, Math.round(score)));
  }

  function normalizeRiskLevel(value) {
    const level = String(value || "").toLowerCase();

    if (level === "critical") return "CRITICAL";
    if (level === "high") return "HIGH";
    if (level === "medium") return "MEDIUM";
    if (level === "low") return "LOW";

    return "UNKNOWN";
  }

  function getRiskLevelFromScore(score) {
    if (score >= 75) return "CRITICAL";
    if (score >= 50) return "HIGH";
    if (score >= 25) return "MEDIUM";
    return "LOW";
  }

  function getCategoryLabel(category) {
    const normalized = String(category || "unknown").toLowerCase();

    return CATEGORY_LABELS[normalized] ||
      normalized.replace(/_/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function getErrorMessage(error) {
    if (!error) {
      return "An unexpected error occurred. Please try again.";
    }

    if (error.name === "AbortError") {
      return "The request timed out. Please try again.";
    }

    return error.message ||
      "Unable to analyze the transcript. Check your connection and try again.";
  }

  /* =====================================================
     START
  ===================================================== */

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();