"use strict";

/* =========================================================
   SCAMSHIELD AI — EMAIL ANALYSIS
   File: frontend/js/analyze-email.js
   Version: 3.1.0

   Features:
   - Email sender, subject and content validation
   - Centralized ScamShieldAPI integration
   - Guardian-authoritative risk assessment
   - Intelligence Agent results
   - Victim Safety guidance
   - Gemini advisory-only output
   - Decoy Agent status
   - Case feedback integration
   - Safe DOM rendering
   - Responsive navigation
   - Request timeout handling

   Security:
   - No unsafe innerHTML rendering
   - No automatic inbox access
   - No automatic email sending
   - No client-side risk-score fabrication
   - No automatic Decoy activation
   ========================================================= */

(() => {
  "use strict";

  const VERSION = "3.1.0";
  const API_ENDPOINT = "/analysis/analyze";

  const MAX_EMAIL_LENGTH = 20000;
  const REQUEST_TIMEOUT = 45000;

  const RISK_LEVELS = {
    LOW: { min: 0, max: 24 },
    MEDIUM: { min: 25, max: 49 },
    HIGH: { min: 50, max: 74 },
    CRITICAL: { min: 75, max: 100 },
  };

  /* =====================================================
       DOM ELEMENTS
       ===================================================== */

  const elements = {
    form: document.getElementById("emailAnalysisForm"),

    sender: document.getElementById("emailSender"),
    subject: document.getElementById("emailSubject"),
    category: document.getElementById("emailFraudCategory"),
    content: document.getElementById("emailContent"),
    consent: document.getElementById("emailAnalysisConsent"),

    characterCount: document.getElementById("emailCharacterCount"),
    inputHelp: document.getElementById("emailInputHelp"),
    inputError: document.getElementById("emailInputError"),

    clearButton: document.getElementById("clearEmailForm"),
    analyzeButton: document.getElementById("analyzeEmailButton"),

    status: document.getElementById("emailAnalysisStatus"),
    statusMessage: document.getElementById("emailAnalysisStatusMessage"),

    results: document.getElementById("emailResults"),
    riskOverview: document.getElementById("emailRiskOverview"),
    riskCircle: document.getElementById("emailRiskScoreCircle"),
    riskScore: document.getElementById("emailRiskScore"),
    riskLevel: document.getElementById("emailRiskLevel"),
    fraudCategory: document.getElementById("emailFraudCategoryResult"),
    riskDescription: document.getElementById("emailRiskDescription"),

    guardianStatus: document.getElementById("emailGuardianStatus"),
    guardianResult: document.getElementById("emailGuardianResult"),

    intelligenceStatus: document.getElementById("emailIntelligenceStatus"),
    intelligenceResult: document.getElementById("emailIntelligenceResult"),

    victimSafetyStatus: document.getElementById("emailVictimSafetyStatus"),
    victimSafetyResult: document.getElementById("emailVictimSafetyResult"),

    geminiStatus: document.getElementById("emailGeminiStatus"),
    geminiResult: document.getElementById("emailGeminiResult"),

    decoyStatus: document.getElementById("emailDecoyStatus"),
    decoyResult: document.getElementById("emailDecoyResult"),

    feedbackHelpful: document.getElementById("emailFeedbackHelpful"),
    feedbackReview: document.getElementById("emailFeedbackReview"),
    feedbackStatus: document.getElementById("emailFeedbackStatus"),

    mobileMenuToggle: document.getElementById("mobileMenuToggle"),
    primaryNavigation: document.getElementById("primaryNavigation"),
  };

  let currentCaseId = null;
  let isAnalyzing = false;
  let isSubmittingFeedback = false;

  /* =====================================================
       SAFE DOM HELPERS
       ===================================================== */

  function setText(element, value, fallback = "Not available") {
    if (!element) return;

    const text =
      value === null || value === undefined || value === ""
        ? fallback
        : String(value);

    element.textContent = text;
  }

  function showElement(element) {
    if (element) {
      element.hidden = false;
    }
  }

  function hideElement(element) {
    if (element) {
      element.hidden = true;
    }
  }

  function setStatus(message, type = "info") {
    if (!elements.status || !elements.statusMessage) return;

    elements.status.classList.remove(
      "status-success",
      "status-error",
      "status-warning",
      "status-info",
    );

    elements.status.classList.add(`status-${type}`);

    setText(elements.statusMessage, message);
    showElement(elements.status);
  }

  function clearStatus() {
    hideElement(elements.status);
  }

  function setInputError(message = "") {
    if (elements.inputError) {
      setText(elements.inputError, message, "");
      elements.inputError.hidden = !message;
    }

    if (elements.content) {
      elements.content.setAttribute("aria-invalid", message ? "true" : "false");
    }
  }

  function setLoading(loading) {
    isAnalyzing = loading;

    if (elements.analyzeButton) {
      elements.analyzeButton.disabled = loading;

      elements.analyzeButton.setAttribute(
        "aria-busy",
        loading ? "true" : "false",
      );

      setText(
        elements.analyzeButton,
        loading ? "Analyzing Email..." : "Analyze Email",
      );
    }

    if (elements.clearButton) {
      elements.clearButton.disabled = loading;
    }
  }

  function updateCharacterCount() {
    if (!elements.content || !elements.characterCount) return;

    setText(
      elements.characterCount,
      `${elements.content.value.length}/${MAX_EMAIL_LENGTH}`,
      "0",
    );
  }

  /* =====================================================
       INPUT VALIDATION
       ===================================================== */

  function validateEmailAddress(value) {
    const email = String(value || "").trim();

    if (!email) {
      return { valid: true, value: "" };
    }

    if (email.length > 254) {
      return {
        valid: false,
        message: "Sender email address is too long.",
      };
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

    if (!emailPattern.test(email)) {
      return {
        valid: false,
        message: "Please enter a valid sender email address.",
      };
    }

    return {
      valid: true,
      value: email,
    };
  }

  function validateEmailContent(value) {
    const content = String(value || "").trim();

    if (!content) {
      return {
        valid: false,
        message: "Please paste the email content you want to analyze.",
      };
    }

    if (content.length > MAX_EMAIL_LENGTH) {
      return {
        valid: false,
        message: `Email content cannot exceed ${MAX_EMAIL_LENGTH} characters.`,
      };
    }

    return {
      valid: true,
      value: content,
    };
  }

  function validateInputs() {
    const senderValidation = validateEmailAddress(elements.sender?.value);

    if (!senderValidation.valid) {
      return {
        valid: false,
        field: elements.sender,
        message: senderValidation.message,
      };
    }

    const contentValidation = validateEmailContent(elements.content?.value);

    if (!contentValidation.valid) {
      return {
        valid: false,
        field: elements.content,
        message: contentValidation.message,
      };
    }

    return {
      valid: true,
      sender: senderValidation.value,
      subject: String(elements.subject?.value || "").trim(),
      content: contentValidation.value,
    };
  }

  /* =====================================================
       API RESPONSE NORMALIZATION
       ===================================================== */

  function isObject(value) {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  }

  function firstObject(...values) {
    return values.find(isObject) || {};
  }

  function getNestedResult(response) {
    const outer = firstObject(response);

    const data = isObject(outer.data) ? outer.data : outer;

    const analysis = isObject(data.analysis) ? data.analysis : {};

    const result = firstObject(
      data.result,
      analysis.result,
      analysis,
      outer.result,
      data,
    );

    return {
      outer,
      data,
      result,
    };
  }

  function getAgentResult(result, data, agentName) {
    const agents = firstObject(result.agent_results, data.agent_results);

    const key = agentName.toLowerCase();

    return firstObject(result[key], data[key], agents[key]);
  }

  function getRiskScore(result) {
    const candidates = [result.risk_score, result.score, result.riskScore];

    for (const value of candidates) {
      if (value === undefined || value === null || value === "") {
        continue;
      }

      const score = Number(value);

      if (Number.isFinite(score) && score >= 0 && score <= 100) {
        return score;
      }
    }

    return null;
  }

  function getRiskLevel(result, score) {
    const supplied = String(
      result.risk_level || result.riskLevel || "",
    ).toUpperCase();

    if (RISK_LEVELS[supplied]) {
      return supplied;
    }

    if (score === null) {
      return "UNAVAILABLE";
    }

    if (score <= 24) return "LOW";
    if (score <= 49) return "MEDIUM";
    if (score <= 74) return "HIGH";

    return "CRITICAL";
  }

  function getCategory(result) {
    return (
      result.fraud_category ||
      result.category ||
      result.detected_category ||
      "Not classified"
    );
  }

  function getDescription(result) {
    return (
      result.description ||
      result.risk_description ||
      result.explanation ||
      result.summary ||
      "Analysis completed. Review the available findings carefully."
    );
  }

  function getAgentMessage(agent) {
    if (!isObject(agent)) {
      return "No additional information available.";
    }

    const message =
      agent.message ||
      agent.summary ||
      agent.explanation ||
      agent.description ||
      agent.recommendation ||
      agent.status_message;

    if (typeof message === "string") {
      return message;
    }

    if (isObject(message) || Array.isArray(message)) {
      return JSON.stringify(message, null, 2);
    }

    return "Agent response received.";
  }

  /* =====================================================
       RISK RESULT DISPLAY
       ===================================================== */

  function renderRiskOverview(result) {
    const score = getRiskScore(result);
    const level = getRiskLevel(result, score);

    setText(elements.riskScore, score === null ? "--" : String(score));

    setText(elements.riskLevel, level);
    setText(elements.fraudCategory, getCategory(result));
    setText(elements.riskDescription, getDescription(result));

    if (elements.riskCircle) {
      elements.riskCircle.classList.remove(
        "risk-low",
        "risk-medium",
        "risk-high",
        "risk-critical",
        "risk-unavailable",
      );

      const className =
        level === "UNAVAILABLE"
          ? "risk-unavailable"
          : `risk-${level.toLowerCase()}`;

      elements.riskCircle.classList.add(className);

      if (score !== null) {
        elements.riskCircle.style.setProperty("--risk-score", `${score}%`);
      } else {
        elements.riskCircle.style.removeProperty("--risk-score");
      }
    }

    showElement(elements.riskOverview);
  }

  function renderAgent(
    statusElement,
    resultElement,
    agent,
    unavailableMessage,
  ) {
    if (!statusElement || !resultElement) return;

    if (!isObject(agent) || Object.keys(agent).length === 0) {
      setText(statusElement, "Unavailable");
      setText(resultElement, unavailableMessage);
      return;
    }

    setText(statusElement, agent.status || "Completed");

    setText(resultElement, getAgentMessage(agent));
  }

  function renderGuardian(result, guardian) {
    const score = getRiskScore(result);
    const level = getRiskLevel(result, score);

    setText(elements.guardianStatus, "Completed");

    const message =
      getAgentMessage(guardian) !== "No additional information available."
        ? getAgentMessage(guardian)
        : `Guardian analysis completed. Risk level: ${level}. ` +
          `Risk score: ${score === null ? "Unavailable" : score + "/100"}. ` +
          `Category: ${getCategory(result)}.`;

    setText(elements.guardianResult, message);
  }

  function renderIntelligence(intelligence) {
    renderAgent(
      elements.intelligenceStatus,
      elements.intelligenceResult,
      intelligence,
      "Intelligence information is unavailable for this analysis.",
    );
  }

  function renderVictimSafety(victimSafety) {
    renderAgent(
      elements.victimSafetyStatus,
      elements.victimSafetyResult,
      victimSafety,
      "No additional safety guidance was returned.",
    );
  }

  function renderGemini(gemini) {
    if (!isObject(gemini) || Object.keys(gemini).length === 0) {
      setText(elements.geminiStatus, "Unavailable");

      setText(
        elements.geminiResult,
        "Gemini advisory is unavailable. Primary Guardian analysis remains independent.",
      );

      return;
    }

    const advisory =
      gemini.advisory ||
      gemini.message ||
      gemini.summary ||
      gemini.explanation ||
      gemini;

    setText(elements.geminiStatus, gemini.status || "Advisory received");

    if (typeof advisory === "string") {
      setText(elements.geminiResult, advisory);
    } else {
      setText(elements.geminiResult, JSON.stringify(advisory, null, 2));
    }
  }

  function renderDecoy(decoy) {
    if (!isObject(decoy) || Object.keys(decoy).length === 0) {
      setText(elements.decoyStatus, "Not started");

      setText(
        elements.decoyResult,
        "Decoy Agent is not automatically activated during normal email analysis.",
      );

      return;
    }

    renderAgent(
      elements.decoyStatus,
      elements.decoyResult,
      decoy,
      "Decoy simulation was not started.",
    );
  }

  /* =====================================================
       COMPLETE RESULT RENDERING
       ===================================================== */

  function renderResults(response) {
    const normalized = getNestedResult(response);

    const result = normalized.result;
    const data = normalized.data;

    if (!isObject(result) || Object.keys(result).length === 0) {
      throw new Error("The server returned an invalid analysis response.");
    }

    const guardian = getAgentResult(result, data, "guardian");

    /*
     * Guardian remains authoritative.
     * Gemini advisory cannot override its risk score,
     * risk level or fraud category.
     */

    const authoritativeResult =
      Object.keys(guardian).length > 0
        ? {
            ...result,

            risk_score:
              guardian.risk_score ??
              guardian.score ??
              result.risk_score ??
              result.score,

            risk_level:
              guardian.risk_level ??
              guardian.riskLevel ??
              result.risk_level ??
              result.riskLevel,

            fraud_category:
              guardian.fraud_category ??
              guardian.category ??
              result.fraud_category ??
              result.category,
          }
        : result;

    renderRiskOverview(authoritativeResult);

    renderGuardian(authoritativeResult, guardian);

    renderIntelligence(getAgentResult(result, data, "intelligence"));

    renderVictimSafety(getAgentResult(result, data, "victim_safety"));

    renderGemini(
      firstObject(
        result.gemini_advisory,
        data.gemini_advisory,
        getAgentResult(result, data, "gemini"),
      ),
    );

    renderDecoy(getAgentResult(result, data, "decoy"));

    currentCaseId =
      data.case_id || data.caseId || result.case_id || result.caseId || null;

    showElement(elements.results);

    elements.results?.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });

    return authoritativeResult;
  }

  /* =====================================================
       CENTRALIZED API INTEGRATION
       ===================================================== */

  function getAPI() {
    const api = window.ScamShieldAPI;

    if (!api || typeof api.post !== "function") {
      throw new Error(
        "ScamShield API service is unavailable. Please reload the page.",
      );
    }

    return api;
  }

  function buildPayload(validated) {
    const emailEvidence = [
      validated.sender ? `Sender: ${validated.sender}` : "",

      validated.subject ? `Subject: ${validated.subject}` : "",

      "Email Content:",

      validated.content,
    ]
      .filter(Boolean)
      .join("\n\n");

    return {
      evidenceType: "email",

      evidence: emailEvidence,

      metadata: {
        source: "analyze-email-page",
        inputMethod: "manual_email_content",
        pageVersion: VERSION,
      },
    };
  }
  /* =====================================================
       REQUEST WITH TIMEOUT
       ===================================================== */

  async function requestWithTimeout(api, payload) {
    let timeoutId;

    try {
      return await Promise.race([
        api.post(API_ENDPOINT, payload, {
          timeout: 120000,
        }),

        new Promise((_, reject) => {
          timeoutId = setTimeout(() => {
            reject(new Error("Email analysis timed out after 120 seconds."));
          }, 125000);
        }),
      ]);
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }
  }

  /* =====================================================
       EMAIL ANALYSIS
       ===================================================== */

  async function analyzeEmail(event) {
    /*
     * IMPORTANT:
     * Prevent native browser form submission immediately.
     * The form must submit through ScamShieldAPI only.
     */

    if (event) {
      event.preventDefault();
      event.stopPropagation();
    }

    if (isAnalyzing) return;

    setInputError("");
    clearStatus();

    const validation = validateInputs();

    if (!validation.valid) {
      setInputError(validation.message);

      setStatus(validation.message, "error");

      validation.field?.focus();

      return;
    }

    if (elements.consent && !elements.consent.checked) {
      setStatus(
        "Please confirm the analysis consent before continuing.",
        "warning",
      );

      elements.consent.focus();

      return;
    }

    let api;

    try {
      api = getAPI();
    } catch (error) {
      setStatus(error.message, "error");
      return;
    }

    setLoading(true);

    hideElement(elements.results);

    currentCaseId = null;

    setStatus("Analyzing the submitted email. Please wait...", "info");

    try {
      const payload = buildPayload(validation);

      const response = await requestWithTimeout(api, payload);

      if (!response || response.success === false) {
        throw new Error(
          response?.message ||
            response?.error ||
            "Email analysis could not be completed.",
        );
      }

      renderResults(response);

      setStatus(
        "Email analysis completed successfully. Review the findings below.",
        "success",
      );
    } catch (error) {
      console.error("[ScamShield Email Analysis]", error);

      setStatus(
        error.message || "An unexpected error occurred during email analysis.",
        "error",
      );
    } finally {
      setLoading(false);
    }
  }

  /* =====================================================
       CASE FEEDBACK
       ===================================================== */

  async function submitFeedback(feedbackType) {
    if (isSubmittingFeedback) return;

    if (!currentCaseId) {
      setText(
        elements.feedbackStatus,
        "Feedback is unavailable because no case ID was returned by the server.",
      );

      return;
    }

    const api = window.ScamShieldAPI;

    if (!api || typeof api.patch !== "function") {
      setText(elements.feedbackStatus, "Feedback service is unavailable.");

      return;
    }

    isSubmittingFeedback = true;

    if (elements.feedbackHelpful) {
      elements.feedbackHelpful.disabled = true;
    }

    if (elements.feedbackReview) {
      elements.feedbackReview.disabled = true;
    }

    try {
      const response = await api.patch(
        `/cases/${encodeURIComponent(currentCaseId)}`,

        {
          feedback: {
            type: feedbackType,
            source: "analyze-email-page",
            submitted_at: new Date().toISOString(),
          },
        },
      );

      if (response?.success === false) {
        throw new Error(response.message || "Feedback could not be submitted.");
      }

      setText(
        elements.feedbackStatus,
        "Thank you. Your feedback has been submitted.",
      );
    } catch (error) {
      console.error("[ScamShield Email Feedback]", error);

      setText(
        elements.feedbackStatus,
        error.message || "Unable to submit feedback. Please try again.",
      );
    } finally {
      isSubmittingFeedback = false;

      if (elements.feedbackHelpful) {
        elements.feedbackHelpful.disabled = false;
      }

      if (elements.feedbackReview) {
        elements.feedbackReview.disabled = false;
      }
    }
  }

  /* =====================================================
       CLEAR FORM
       ===================================================== */

  function clearForm() {
    if (isAnalyzing) return;

    elements.form?.reset();

    setInputError("");

    clearStatus();

    hideElement(elements.results);

    currentCaseId = null;

    updateCharacterCount();

    setText(elements.feedbackStatus, "");

    elements.content?.focus();
  }

  /* =====================================================
       MOBILE NAVIGATION
       ===================================================== */

  function initializeNavigation() {
    if (!elements.mobileMenuToggle || !elements.primaryNavigation) {
      return;
    }

    elements.mobileMenuToggle.addEventListener("click", () => {
      const isOpen = elements.primaryNavigation.classList.toggle("active");

      elements.mobileMenuToggle.setAttribute("aria-expanded", String(isOpen));
    });

    elements.primaryNavigation.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        elements.primaryNavigation.classList.remove("active");

        elements.mobileMenuToggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  /* =====================================================
       EVENT LISTENERS
       ===================================================== */

  function initializeEvents() {
    /*
     * Capture phase ensures this handler gets an early
     * opportunity to prevent native form submission.
     */

    elements.form?.addEventListener("submit", analyzeEmail, true);

    elements.content?.addEventListener("input", () => {
      updateCharacterCount();

      if (elements.inputError && !elements.inputError.hidden) {
        setInputError("");
      }
    });

    elements.sender?.addEventListener("input", () => {
      if (elements.inputError && !elements.inputError.hidden) {
        setInputError("");
      }
    });

    elements.clearButton?.addEventListener("click", (event) => {
      event.preventDefault();
      clearForm();
    });

    elements.feedbackHelpful?.addEventListener("click", (event) => {
      event.preventDefault();
      submitFeedback("helpful");
    });

    elements.feedbackReview?.addEventListener("click", (event) => {
      event.preventDefault();
      submitFeedback("needs_review");
    });

    initializeNavigation();
  }

  /* =====================================================
       INITIALIZATION
       ===================================================== */

  function initialize() {
    if (!elements.form) {
      console.warn(
        "[ScamShield Email Analysis] Email analysis form was not found. Check emailAnalysisForm ID.",
      );

      return;
    }

    updateCharacterCount();

    initializeEvents();

    hideElement(elements.results);
    hideElement(elements.status);

    console.info(
      `[ScamShield AI] Email Analysis v${VERSION} initialized successfully.`,
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
