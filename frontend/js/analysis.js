"use strict";

/* =====================================================
   SCAMSHIELD AI - EVIDENCE ANALYSIS
   File: frontend/js/analysis.js

   Features:
   1. Evidence submission
   2. Four-agent result integration
   3. Risk score visualization
   4. Intelligence indicators
   5. Accessible status feedback
   6. Character counter
   7. Form reset
   8. JWT authentication
   9. Mobile-friendly interactions
===================================================== */

(() => {
  /* =====================================================
     CONFIGURATION
  ===================================================== */

  const API_BASE_URL = (
    window.SCAMSHIELD_API_URL || "http://localhost:5000/api"
  ).replace(/\/+$/, "");

  // Single endpoint prevents duplicate Analysis creation.
  const API_ENDPOINT = `${API_BASE_URL}/agents/run`;

  const TOKEN_KEY = "scamshieldToken";

  const ALLOWED_EVIDENCE_TYPES = [
    "message",
    "url",
    "call",
    "transaction",
    "screenshot",
    "email",
  ];

  const MAX_EVIDENCE_LENGTH = 20000;

  let isAnalyzing = false;

  /* =====================================================
     DOM ELEMENTS
  ===================================================== */

  const elements = {
    form: document.querySelector(
      "#analysisForm, #evidenceAnalysisForm, [data-analysis-form]"
    ),

    evidenceType: document.querySelector(
      "#evidenceType, #analysisEvidenceType, [name='evidenceType']"
    ),

    evidence: document.querySelector(
      "#evidenceInput, #analysisEvidence, #evidence, [name='evidence']"
    ),

    characterCount: document.querySelector(
      "#characterCount, #evidenceCharacterCount"
    ),

    submitButton: document.querySelector(
      "#analyzeButton, #submitAnalysis, [data-analyze-button]"
    ),

    resetButton: document.querySelector(
      "#resetAnalysis, #clearAnalysis, [data-reset-analysis]"
    ),

    status: document.querySelector(
      "#analysisStatus, #analysisMessage, [data-analysis-status]"
    ),

    results: document.querySelector(
      "#analysisResults, #analysisResult, [data-analysis-results]"
    ),

    riskScore: document.querySelector(
      "#riskScore, #analysisRiskScore"
    ),

    riskLevel: document.querySelector(
      "#riskLevel, #analysisRiskLevel"
    ),

    fraudCategory: document.querySelector(
      "#fraudCategory, #analysisFraudCategory"
    ),

    summary: document.querySelector(
      "#analysisSummary, #riskSummary"
    ),

    explanation: document.querySelector(
      "#analysisExplanation, #explanationList"
    ),

    indicators: document.querySelector(
      "#analysisIndicators, #indicatorsList"
    ),

    disclaimer: document.querySelector(
      "#analysisDisclaimer, #disclaimer"
    ),

    analysisId: document.querySelector("#analysisId"),

    guardian: document.querySelector(
      "#guardianResults, #guardianAgentResult"
    ),

    intelligence: document.querySelector(
      "#intelligenceResults, #intelligenceAgentResult"
    ),

    victimSafety: document.querySelector(
      "#victimSafetyResults, #victimSafetyAgentResult"
    ),

    decoy: document.querySelector(
      "#decoyResults, #decoyAgentResult"
    ),
  };

  /* =====================================================
     HELPERS
  ===================================================== */

  function getToken() {
    return (
      localStorage.getItem(TOKEN_KEY) ||
      sessionStorage.getItem(TOKEN_KEY) ||
      ""
    );
  }

  function createElement(tag, className = "", text = "") {
    const element = document.createElement(tag);

    if (className) {
      element.className = className;
    }

    if (text !== null && text !== undefined) {
      element.textContent = String(text);
    }

    return element;
  }

  function clearElement(element) {
    if (element) {
      element.replaceChildren();
    }
  }

  function formatLabel(value) {
    return String(value || "Unknown")
      .replace(/([a-z])([A-Z])/g, "$1 $2")
      .replace(/[_-]/g, " ")
      .replace(/\b\w/g, (character) => character.toUpperCase());
  }

  function formatValue(value) {
    if (value === null || value === undefined || value === "") {
      return "Not available";
    }

    if (typeof value === "boolean") {
      return value ? "Yes" : "No";
    }

    if (Array.isArray(value)) {
      return value.length
        ? value.map(formatValue).join(", ")
        : "No records found";
    }

    if (typeof value === "object") {
      return Object.entries(value)
        .map(([key, item]) => {
          return `${formatLabel(key)}: ${formatValue(item)}`;
        })
        .join("\n");
    }

    return String(value);
  }

  function updateText(element, value, fallback = "--") {
    if (!element) return;

    element.textContent =
      value === null || value === undefined || value === ""
        ? fallback
        : String(value);
  }

  function normalizeRiskLevel(level) {
    const normalized = String(level || "").toLowerCase();

    const allowed = ["low", "medium", "high", "critical"];

    return allowed.includes(normalized)
      ? normalized
      : "unknown";
  }

  function getRiskLevelFromScore(score) {
    if (score >= 75) return "critical";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";

    return "low";
  }

  function getRiskScore(value) {
    if (
      value === null ||
      value === undefined ||
      value === ""
    ) {
      return null;
    }

    const score = Number(value);

    if (!Number.isFinite(score)) {
      return null;
    }

    return Math.min(100, Math.max(0, score));
  }

  function normalizeIndicators(indicators) {
    if (!indicators) return [];

    if (Array.isArray(indicators)) {
      return indicators;
    }

    if (typeof indicators === "object") {
      return Object.entries(indicators).map(([key, value]) => ({
        type: key,
        value: formatValue(value),
      }));
    }

    return [indicators];
  }

  /* =====================================================
     ACCESSIBLE STATUS
  ===================================================== */

  function showStatus(message, type = "info") {
    if (!elements.status) return;

    elements.status.textContent = message;

    elements.status.dataset.state = type;

    elements.status.setAttribute("role", "status");

    elements.status.setAttribute("aria-live", "polite");
  }

  /* =====================================================
     CHARACTER COUNTER
  ===================================================== */

  function updateCharacterCount() {
    if (!elements.evidence || !elements.characterCount) {
      return;
    }

    const count = elements.evidence.value.length;

    elements.characterCount.textContent =
      `${count.toLocaleString()} / ${MAX_EVIDENCE_LENGTH.toLocaleString()}`;

    elements.characterCount.dataset.state =
      count > MAX_EVIDENCE_LENGTH ? "error" : "normal";

    elements.characterCount.setAttribute(
      "aria-live",
      "polite"
    );
  }

  /* =====================================================
     LOADING STATE
  ===================================================== */

  function setLoading(loading) {
    isAnalyzing = loading;

    if (elements.submitButton) {
      elements.submitButton.disabled = loading;

      elements.submitButton.setAttribute(
        "aria-busy",
        String(loading)
      );

      const icon = elements.submitButton.querySelector("i");

      if (icon) {
        icon.classList.toggle("fa-spin", loading);
      }

      const textNode = [
        ...elements.submitButton.childNodes,
      ].find((node) => node.nodeType === Node.TEXT_NODE);

      if (textNode) {
        textNode.textContent = loading
          ? " Analyzing..."
          : " Analyze Evidence";
      }
    }

    if (elements.evidence) {
      elements.evidence.disabled = loading;
    }

    if (elements.evidenceType) {
      elements.evidenceType.disabled = loading;
    }

    if (elements.resetButton) {
      elements.resetButton.disabled = loading;
    }

    if (elements.form) {
      elements.form.setAttribute(
        "aria-busy",
        String(loading)
      );
    }
  }

  /* =====================================================
     VALIDATION
  ===================================================== */

  function validateEvidence() {
    if (!elements.evidenceType || !elements.evidence) {
      throw new Error(
        "Analysis form is incomplete. Please refresh the page."
      );
    }

    const evidenceType = elements.evidenceType.value.trim();

    const evidence = elements.evidence.value.trim();

    if (!ALLOWED_EVIDENCE_TYPES.includes(evidenceType)) {
      throw new Error("Please select a valid evidence type.");
    }

    if (!evidence) {
      throw new Error(
        "Please enter your message, link or other evidence first."
      );
    }

    if (evidence.length > MAX_EVIDENCE_LENGTH) {
      throw new Error(
        `Evidence cannot exceed ${MAX_EVIDENCE_LENGTH} characters.`
      );
    }

    return {
      evidenceType,
      evidence,
    };
  }

  /* =====================================================
     API REQUEST
  ===================================================== */

  async function runAnalysis(payload) {
    const token = getToken();

    if (!token) {
      throw new Error(
        "Please login before analyzing your evidence."
      );
    }

    let response;

    try {
      response = await fetch(API_ENDPOINT, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify(payload),
      });
    } catch {
      throw new Error(
        "Unable to connect to ScamShield AI. Please check your internet connection."
      );
    }

    let result;

    try {
      result = await response.json();
    } catch {
      throw new Error(
        "The server returned an invalid response."
      );
    }

    if (response.status === 401) {
      localStorage.removeItem(TOKEN_KEY);
      sessionStorage.removeItem(TOKEN_KEY);

      window.ScamShieldApp?.showScreen("login");

      throw new Error(
        "Your session has expired. Please login again."
      );
    }

    if (response.status === 403) {
      throw new Error(
        "You do not have permission to perform this analysis."
      );
    }

    if (!response.ok || result.success !== true) {
      throw new Error(
        result.message ||
        `Analysis failed. Server status: ${response.status}.`
      );
    }

    if (!result.data || typeof result.data !== "object") {
      throw new Error(
        "The server response does not contain analysis results."
      );
    }

    return result.data;
  }

  /* =====================================================
     MAIN ANALYSIS HANDLER
  ===================================================== */

  async function handleAnalysis(event) {
    if (event) {
      event.preventDefault();
    }

    if (isAnalyzing) return;

    try {
      const payload = validateEvidence();

      setLoading(true);

      showStatus(
        "Your evidence is being checked. Please wait.",
        "loading"
      );

      if (elements.results) {
        elements.results.hidden = true;
      }

      const result = await runAnalysis(payload);

      renderResults(result);

      if (elements.results) {
        elements.results.hidden = false;

        const prefersReducedMotion = window.matchMedia(
          "(prefers-reduced-motion: reduce)"
        ).matches;

        elements.results.scrollIntoView({
          behavior: prefersReducedMotion ? "auto" : "smooth",
          block: "start",
        });

        elements.results.setAttribute("tabindex", "-1");

        elements.results.focus({
          preventScroll: true,
        });
      }

      showStatus(
        "Your evidence analysis is complete.",
        "success"
      );

    } catch (error) {
      showStatus(
        error.message || "Unable to complete the analysis.",
        "error"
      );

      if (elements.evidence) {
        elements.evidence.focus();
      }

    } finally {
      setLoading(false);
    }
  }

  /* =====================================================
     MAIN RESULTS
  ===================================================== */

  function renderResults(data) {
    const analysis = data.analysis || {};

    const agents = data.agents || {};

    updateText(
      elements.analysisId,
      data.analysisId,
      "Not available"
    );

    const score = getRiskScore(analysis.riskScore);

    updateText(
      elements.riskScore,
      score === null ? "--" : `${score}/100`
    );

    // Backend riskLevel is authoritative.
    // Score is only a fallback when backend level is absent.
    const backendRisk = normalizeRiskLevel(
      analysis.riskLevel
    );

    const riskLevel =
      backendRisk !== "unknown"
        ? backendRisk
        : score !== null
          ? getRiskLevelFromScore(score)
          : "unknown";

    updateText(
      elements.riskLevel,
      riskLevel === "unknown"
        ? "Not available"
        : formatLabel(riskLevel)
    );

    if (elements.riskLevel) {
      elements.riskLevel.dataset.risk = riskLevel;
    }

    updateText(
      elements.fraudCategory,
      formatLabel(analysis.fraudCategory || "Unknown")
    );

    updateText(
      elements.summary,
      analysis.summary || "No summary is available."
    );

    renderExplanation(
      analysis.explanation ||
      analysis.explanations
    );

    const intelligenceIndicators = normalizeIndicators(
      agents.intelligence?.indicators ||
      analysis.indicators
    );

    renderIndicators(intelligenceIndicators);

    renderAgent(
      elements.guardian,
      "Guardian Agent",
      agents.guardian
    );

    renderAgent(
      elements.intelligence,
      "Intelligence Agent",
      agents.intelligence
    );

    renderAgent(
      elements.victimSafety,
      "Victim Safety Agent",
      agents.victimSafety
    );

    renderAgent(
      elements.decoy,
      "Decoy Agent",
      agents.decoy
    );

    updateText(
      elements.disclaimer,
      data.disclaimer ||
      "This automated assessment is an indication, not proof of fraud."
    );
  }

  /* =====================================================
     EXPLANATION
  ===================================================== */

  function renderExplanation(explanation) {
    if (!elements.explanation) return;

    clearElement(elements.explanation);

    const items = Array.isArray(explanation)
      ? explanation
      : explanation
        ? [explanation]
        : [];

    if (!items.length) {
      elements.explanation.appendChild(
        createElement(
          "p",
          "empty-state",
          "No explanation is available."
        )
      );

      return;
    }

    const list = createElement(
      "ul",
      "analysis-explanation-list"
    );

    items.forEach((item) => {
      list.appendChild(
        createElement(
          "li",
          "",
          formatValue(item)
        )
      );
    });

    elements.explanation.appendChild(list);
  }

  /* =====================================================
     INTELLIGENCE INDICATORS
  ===================================================== */

  function renderIndicators(indicators) {
    if (!elements.indicators) return;

    clearElement(elements.indicators);

    if (!Array.isArray(indicators) || !indicators.length) {
      elements.indicators.appendChild(
        createElement(
          "p",
          "empty-state",
          "No suspicious indicators were reported."
        )
      );

      return;
    }

    const list = createElement(
      "ul",
      "analysis-indicator-list"
    );

    indicators.forEach((indicator) => {
      const item = createElement(
        "li",
        "analysis-indicator-item"
      );

      item.textContent = formatValue(indicator);

      list.appendChild(item);
    });

    elements.indicators.appendChild(list);
  }

  /* =====================================================
     AGENT RESULT RENDERING
  ===================================================== */

  function renderAgent(container, title, agentData) {
    if (!container) return;

    clearElement(container);

    const card = createElement(
      "div",
      "agent-result-card"
    );

    card.appendChild(
      createElement(
        "h3",
        "agent-result-title",
        title
      )
    );

    if (
      !agentData ||
      typeof agentData !== "object" ||
      Array.isArray(agentData)
    ) {
      card.appendChild(
        createElement(
          "p",
          "empty-state",
          "This agent's result is not available."
        )
      );

      container.appendChild(card);

      return;
    }

    const status = agentData.status || "completed";

    const statusBadge = createElement(
      "span",
      `agent-status-badge ${String(status).toLowerCase()}`,
      formatLabel(status)
    );

    card.appendChild(statusBadge);

    const details = createElement(
      "div",
      "agent-result-details"
    );

    const ignoredFields = [
      "status",
      "agent",
      "agentName",
      "_id",
      "id",
    ];

    Object.entries(agentData).forEach(([key, value]) => {
      if (
        value === null ||
        value === undefined ||
        ignoredFields.includes(key)
      ) {
        return;
      }

      const row = createElement(
        "div",
        "agent-detail-row"
      );

      row.append(
        createElement(
          "strong",
          "agent-detail-label",
          formatLabel(key)
        ),
        createElement(
          "span",
          "agent-detail-value",
          formatValue(value)
        )
      );

      details.appendChild(row);
    });

    card.appendChild(details);

    container.appendChild(card);
  }

  /* =====================================================
     RESET RESULTS
  ===================================================== */

  function clearResults() {
    if (elements.results) {
      elements.results.hidden = true;
    }

    updateText(elements.analysisId, "", "--");

    updateText(elements.riskScore, "", "--");

    updateText(elements.riskLevel, "", "--");

    updateText(elements.fraudCategory, "", "--");

    updateText(elements.summary, "", "--");

    updateText(elements.disclaimer, "", "--");

    if (elements.riskLevel) {
      delete elements.riskLevel.dataset.risk;
    }

    clearElement(elements.explanation);

    clearElement(elements.indicators);

    clearElement(elements.guardian);

    clearElement(elements.intelligence);

    clearElement(elements.victimSafety);

    clearElement(elements.decoy);
  }

  function handleReset() {
    if (isAnalyzing) return;

    clearResults();

    updateCharacterCount();

    showStatus(
      "The previous analysis has been cleared.",
      "info"
    );
  }

  /* =====================================================
     INITIALIZATION
  ===================================================== */

  function initAnalysis() {
    if (elements.form) {
      elements.form.addEventListener(
        "submit",
        handleAnalysis
      );

      elements.form.addEventListener(
        "reset",
        () => {
          // Wait until browser performs native reset.
          setTimeout(() => {
            clearResults();
            updateCharacterCount();

            showStatus(
              "Form cleared. You can enter new evidence.",
              "info"
            );
          }, 0);
        }
      );
    } else if (elements.submitButton) {
      elements.submitButton.addEventListener(
        "click",
        handleAnalysis
      );
    }

    if (elements.resetButton) {
      elements.resetButton.addEventListener(
        "click",
        handleReset
      );
    }

    if (elements.evidence) {
      elements.evidence.addEventListener(
        "input",
        updateCharacterCount
      );

      updateCharacterCount();
    }

    if (!elements.form && !elements.submitButton) {
      console.warn(
        "[ScamShield] Analysis form or submit button was not found."
      );
    }

    if (!elements.evidence || !elements.evidenceType) {
      console.warn(
        "[ScamShield] Evidence input or evidence type selector was not found."
      );
    }

    if (elements.results) {
      elements.results.hidden = true;
    }

    console.log(
      "[ScamShield] Analysis module initialized."
    );
  }

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      initAnalysis
    );
  } else {
    initAnalysis();
  }
})();