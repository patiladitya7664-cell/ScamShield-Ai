
"use strict";

/* =========================================================
   SCAMSHIELD AI - DETECTION MODULE
   12 Fraud Categories + Evidence Analysis
   Risk Assessment + Case Management
   Classification Feedback
========================================================= */

document.addEventListener("DOMContentLoaded", () => {

  /* =======================================================
     1. CONFIGURATION
  ======================================================= */

  const API = window.ScamShieldAPI;

  const EVIDENCE_LIMITS = {
    message: 10000,
    url: 2048,
    call: 15000,
    transaction: 10000,
  };

  const FRAUD_CATEGORIES = {
    message: {
      label: "Fraud Message",
      evidenceType: "message",
    },
    call: {
      label: "Fraud Call",
      evidenceType: "call",
    },
    url: {
      label: "URL & Phishing",
      evidenceType: "url",
    },
    email: {
      label: "Email Scam",
      evidenceType: "message",
    },
    investment: {
      label: "Investment Scam",
      evidenceType: "message",
    },
    digital_arrest: {
      label: "Digital Arrest",
      evidenceType: "message",
    },
    upi: {
      label: "UPI & Banking Fraud",
      evidenceType: "transaction",
    },
    card: {
      label: "Credit/Debit Card Fraud",
      evidenceType: "transaction",
    },
    ecommerce: {
      label: "E-commerce Scam",
      evidenceType: "message",
    },
    job_loan: {
      label: "Job & Loan Scam",
      evidenceType: "message",
    },
    blackmail: {
      label: "Sextortion & Blackmail",
      evidenceType: "message",
    },
    social_media: {
      label: "Social Media Scam",
      evidenceType: "message",
    },
  };

  const RISK_LEVELS = {
    low: {
      label: "Low Risk",
      description: "Limited suspicious indicators detected.",
    },
    medium: {
      label: "Medium Risk",
      description: "Some suspicious indicators require attention.",
    },
    high: {
      label: "High Risk",
      description: "Multiple suspicious indicators were detected.",
    },
    critical: {
      label: "Critical Risk",
      description: "Strong warning signs of potential fraud were detected.",
    },
  };

  const CATEGORY_LABELS = {
    investment: "Investment Fraud",
    digitalArrest: "Digital Arrest Scam",
    digital_arrest: "Digital Arrest Scam",
    creditCard: "Credit Card Fraud",
    credit_card: "Credit Card Fraud",
    card: "Credit/Debit Card Fraud",
    sextortion: "Sextortion Scam",
    blackmail: "Sextortion & Blackmail",
    ecommerce: "E-commerce Fraud",
    upi: "UPI & Banking Fraud",
    email: "Email Scam",
    job_loan: "Job & Loan Scam",
    social_media: "Social Media Scam",
    message: "Fraud Message",
    call: "Fraud Call",
    url: "URL & Phishing",
    other: "Other Fraud",
    unclassified: "Unclassified",
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

  /* =======================================================
     2. DOM ELEMENTS
  ======================================================= */

  const elements = {
    evidenceButtons: document.querySelectorAll(".evidence-type"),
    evidenceForms: document.querySelectorAll(".evidence-form"),

    messageInput: document.getElementById("messageInput"),
    urlInput: document.getElementById("urlInput"),
    callInput: document.getElementById("callInput"),
    transactionInput: document.getElementById("transactionInput"),

    messageCount: document.getElementById("messageCount"),
    callCount: document.getElementById("callCount"),
    transactionCount: document.getElementById("transactionCount"),

    analyzeBtn: document.getElementById("analyzeBtn"),
    clearBtn: document.getElementById("clearBtn"),

    analysisMessage: document.getElementById("analysisMessage"),
    detectionResults: document.getElementById("detectionResults"),

    resultStatus: document.getElementById("resultStatus"),

    riskScoreCircle: document.getElementById("riskScoreCircle"),
    riskScore: document.getElementById("riskScore"),
    riskLevel: document.getElementById("riskLevel"),
    riskDescription: document.getElementById("riskDescription"),

    fraudCategory: document.getElementById("fraudCategory"),
    riskExplanation: document.getElementById("riskExplanation"),

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
  let currentCategory = "message";

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
      "Detection module initialization failed: Required HTML elements are missing."
    );

    return;
  }

  if (!API || typeof API.post !== "function") {
    console.error(
      "ScamShield API service not found or API.post is unavailable."
    );

    showMessage(
      "API service could not be loaded. Please refresh the page.",
      "error"
    );

    elements.analyzeBtn.disabled = true;

    return;
  }

  if (typeof API.getToken !== "function") {
    console.warn(
      "API.getToken is unavailable. Using local storage fallback."
    );
  }

  /* =======================================================
     5. UTILITY FUNCTIONS
  ======================================================= */

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
      console.error("Token Retrieval Error:", error);
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

  function setButtonLoading(button, loading, originalHTML) {
    if (!button) return;

    button.disabled = loading;

    if (loading) {
      if (!button.dataset.originalHTML) {
        button.dataset.originalHTML = button.innerHTML;
      }

      button.innerHTML = `
        <i class="fa-solid fa-spinner fa-spin"></i>
        Processing...
      `;
    } else {
      button.innerHTML =
        originalHTML ||
        button.dataset.originalHTML ||
        button.innerHTML;
    }
  }

  function normalizeText(value) {
    if (value === null || value === undefined) {
      return "";
    }

    return String(value).trim();
  }

  function getRiskLevel(score) {
    if (score <= 24) return "low";
    if (score <= 49) return "medium";
    if (score <= 74) return "high";

    return "critical";
  }

  function getPriority(score) {
    if (score >= 75) return "urgent";
    if (score >= 50) return "high";
    if (score >= 25) return "medium";

    return "low";
  }

  function getCategoryLabel(category) {
    return (
      CATEGORY_LABELS[category] ||
      CATEGORY_LABELS.unclassified
    );
  }

  function getSelectedCategoryLabel() {
    return (
      FRAUD_CATEGORIES[currentCategory]?.label ||
      "Fraud Detection"
    );
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
              JSON.stringify(item)
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

    return "No additional explanation was provided by the analysis engine.";
  }

  /* =======================================================
     6. CATEGORY & EVIDENCE SELECTION
  ======================================================= */

  function switchEvidenceType(type, category = null) {
    if (!Object.prototype.hasOwnProperty.call(
      EVIDENCE_LIMITS,
      type
    )) {
      console.warn("Unsupported evidence type:", type);
      return;
    }

    let selectedCategory = category;

    if (
      !selectedCategory ||
      !FRAUD_CATEGORIES[selectedCategory] ||
      FRAUD_CATEGORIES[selectedCategory].evidenceType !== type
    ) {
      selectedCategory = Object.keys(FRAUD_CATEGORIES).find(
        (key) =>
          FRAUD_CATEGORIES[key].evidenceType === type
      );
    }

    if (!selectedCategory) return;

    currentEvidenceType = type;
    currentCategory = selectedCategory;

    elements.evidenceButtons.forEach((button) => {
      const active =
        button.dataset.category === currentCategory;

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
      switchEvidenceType(
        button.dataset.evidence,
        button.dataset.category
      );
    });
  });

  /* =======================================================
     7. CHARACTER COUNTERS
  ======================================================= */

  function updateCounter(input, counter, maximum) {
    if (!input || !counter) return;

    const length = input.value.length;

    counter.textContent = `${length} / ${maximum}`;

    counter.classList.toggle(
      "limit-reached",
      length >= maximum
    );
  }

  const counterConfigurations = [
    {
      input: elements.messageInput,
      counter: elements.messageCount,
      maximum: EVIDENCE_LIMITS.message,
    },
    {
      input: elements.callInput,
      counter: elements.callCount,
      maximum: EVIDENCE_LIMITS.call,
    },
    {
      input: elements.transactionInput,
      counter: elements.transactionCount,
      maximum: EVIDENCE_LIMITS.transaction,
    },
  ];

  counterConfigurations.forEach((config) => {
    if (!config.input) return;

    config.input.addEventListener("input", () => {
      updateCounter(
        config.input,
        config.counter,
        config.maximum
      );
    });

    updateCounter(
      config.input,
      config.counter,
      config.maximum
    );
  });

  /* =======================================================
     8. GET EVIDENCE
  ======================================================= */

  function getEvidence() {
    const inputMap = {
      message: elements.messageInput,
      url: elements.urlInput,
      call: elements.callInput,
      transaction: elements.transactionInput,
    };

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

    elements.riskLevel.textContent =
      "Awaiting Analysis";

    elements.riskDescription.textContent =
      "Submit evidence to receive an explainable risk assessment.";

    elements.fraudCategory.textContent =
      "Not classified yet.";

    elements.riskExplanation.textContent =
      "Analysis explanation will appear here.";

    elements.indicatorList.replaceChildren();

    const emptyIndicators = document.createElement("p");

    emptyIndicators.textContent =
      "No indicators extracted yet.";

    elements.indicatorList.appendChild(emptyIndicators);

    elements.riskScoreCircle.style.background =
      "conic-gradient(#263746 0deg, #263746 360deg)";

    renderSafetyGuidance("medium");

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

    indicators.forEach((indicator) => {
      if (
        !indicator ||
        typeof indicator !== "object"
      ) {
        return;
      }

      const item = document.createElement("div");

      item.className = "indicator-item";

      const type = document.createElement("strong");

      type.textContent =
        indicator.type || "Indicator";

      const value = document.createElement("span");

      value.textContent =
        indicator.value || "Not available";

      const verification = document.createElement("span");

      if (indicator.verified === true) {
        verification.className = "indicator-verified";
        verification.textContent = "Verified";
      } else {
        verification.className = "indicator-unverified";
        verification.textContent = "Unverified";
      }

      item.append(
        type,
        value,
        verification
      );

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

  function renderSafetyGuidance(level) {
    const guidance =
      SAFETY_GUIDANCE[level] ||
      SAFETY_GUIDANCE.medium;

    const container = elements.safetyGuidance;

    container.replaceChildren();

    guidance.forEach((message) => {
      const item = document.createElement("li");

      item.textContent = message;

      container.appendChild(item);
    });
  }

  /* =======================================================
     12. RENDER ANALYSIS RESULTS
  ======================================================= */

  function renderResults(result) {
    if (!result || typeof result !== "object") {
      throw new Error(
        "Invalid analysis response received."
      );
    }

    if (
      result.riskScore === null ||
      result.riskScore === undefined ||
      result.riskScore === ""
    ) {
      throw new Error(
        "Analysis response does not contain a valid risk score."
      );
    }

    const score = Number(result.riskScore);

    if (
      !Number.isFinite(score) ||
      score < 0 ||
      score > 100
    ) {
      throw new Error(
        "The returned risk score is invalid."
      );
    }

    const roundedScore = Math.round(score);

    // UI risk classification follows the configured score thresholds.
    const riskLevel = getRiskLevel(roundedScore);

    const riskInfo = RISK_LEVELS[riskLevel];

    const category = getCategoryLabel(
      result.fraudCategory
    );

    elements.riskScore.textContent = roundedScore;

    elements.riskLevel.textContent =
      riskInfo.label;

    elements.riskDescription.textContent =
      result.riskDescription ||
      result.summary ||
      riskInfo.description;

    elements.fraudCategory.textContent =
      category;

    elements.riskExplanation.textContent =
      formatExplanation(result.explanation);

    elements.resultStatus.textContent =
      "Analysis Complete";

    const degrees = roundedScore * 3.6;

    const riskColors = {
      low: "#22c55e",
      medium: "#eab308",
      high: "#f97316",
      critical: "#ef4444",
    };

    const color = riskColors[riskLevel];

    elements.riskScoreCircle.style.background = `
      conic-gradient(
        ${color} ${degrees}deg,
        #263746 ${degrees}deg
      )
    `;

    renderIndicators(result.indicators);

    renderSafetyGuidance(riskLevel);

    elements.detectionResults.hidden = false;

    elements.detectionResults.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });

    return {
      score: roundedScore,
      riskLevel,
      category: result.fraudCategory || "unclassified",
    };
  }

  /* =======================================================
     13. CREATE CASE
  ======================================================= */

  async function createAnalysisCase(result, evidence) {
    if (!result.id) {
      throw new Error(
        "Analysis ID missing. Case cannot be created."
      );
    }

    const score = Number(result.riskScore);

    if (!Number.isFinite(score)) {
      throw new Error(
        "Invalid risk score. Case cannot be created."
      );
    }

    const riskLevel = getRiskLevel(score);

    const category =
      result.fraudCategory || "unclassified";

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
      analysisId: result.id,

      title:
        `${getSelectedCategoryLabel()} Detection Case`,

      description:
        `Selected category: ${getSelectedCategoryLabel()}\n` +
        `Evidence type: ${currentEvidenceType}\n` +
        `Risk score: ${Math.round(score)}/100\n` +
        `Risk level: ${riskLevel}\n` +
        `Evidence preview: ${evidence.slice(0, 500)}`,

      fraudCategory: category,

      riskLevel,

      priority: getPriority(score),

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

    const savedCase = response.data;

    if (!savedCase) {
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
     14. ANALYZE EVIDENCE
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

    setButtonLoading(
      elements.analyzeBtn,
      true
    );

    elements.clearBtn.disabled = true;

    showMessage(
      `Analyzing ${getSelectedCategoryLabel()} evidence. Please wait...`,
      "info"
    );

    try {

      /* STEP 1: ANALYZE EVIDENCE */

      const response = await API.post(
        "/analysis/analyze",
        {
          evidenceType: currentEvidenceType,

          evidence,

          selectedCategory: currentCategory,

          selectedCategoryLabel:
            getSelectedCategoryLabel(),
        }
      );

      if (!response || response.success !== true) {
        throw new Error(
          response?.message ||
          "Evidence analysis failed."
        );
      }

      const result = response.result;

      if (!result) {
        throw new Error(
          "Analysis server returned an empty result."
        );
      }

      currentAnalysisId = result.id || null;

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
          "Case Creation Error:",
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

    } catch (error) {
      console.error(
        "Detection Analysis Error:",
        error
      );

      const message =
        error.message ||
        "Unable to analyze evidence.";

      if (
        message.toLowerCase().includes("token") ||
        message.toLowerCase().includes("login") ||
        message.toLowerCase().includes("authentication")
      ) {
        showMessage(
          "Authentication failed. Please login again.",
          "error"
        );
      } else {
        showMessage(
          message,
          "error"
        );
      }

    } finally {
      isAnalyzing = false;

      setButtonLoading(
        elements.analyzeBtn,
        false
      );

      elements.clearBtn.disabled = false;
    }
  }

  /* =======================================================
     15. CLASSIFICATION FEEDBACK
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

    const feedback =
      elements.feedbackSelect.value;

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

    const originalHTML =
      elements.feedbackBtn.innerHTML;

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

      elements.feedbackStatus.className =
        "success";

    } catch (error) {
      console.error(
        "Feedback Error:",
        error
      );

      elements.feedbackStatus.textContent =
        error.message ||
        "Failed to save feedback.";

      elements.feedbackStatus.className =
        "error";

    } finally {
      isSubmittingFeedback = false;

      elements.feedbackBtn.disabled = false;

      elements.feedbackBtn.innerHTML =
        originalHTML;
    }
  }

  /* =======================================================
     16. CLEAR FORM
  ======================================================= */

  function clearDetectionForm() {
    if (
      isAnalyzing ||
      isSubmittingFeedback
    ) {
      return;
    }

    if (elements.messageInput) {
      elements.messageInput.value = "";
    }

    if (elements.urlInput) {
      elements.urlInput.value = "";
    }

    if (elements.callInput) {
      elements.callInput.value = "";
    }

    if (elements.transactionInput) {
      elements.transactionInput.value = "";
    }

    counterConfigurations.forEach((config) => {
      updateCounter(
        config.input,
        config.counter,
        config.maximum
      );
    });

    switchEvidenceType(
      "message",
      "message"
    );

    resetResults();

    hideMessage();

    elements.analyzeBtn.disabled = false;

    elements.clearBtn.disabled = false;
  }

  /* =======================================================
     17. EVENT LISTENERS
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
     18. INITIALIZATION
  ======================================================= */

  switchEvidenceType(
    "message",
    "message"
  );

  resetResults();

  console.log(
    "ScamShield AI Detection Module initialized successfully."
  );

});
