/* =====================================================
   SCAMSHIELD AI - THREAT INTELLIGENCE
   Indicator Explorer
   API + Authentication + MongoDB Integration
===================================================== */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // ================================================
  // DOM ELEMENTS
  // ================================================

  const indicatorTabs = document.querySelectorAll(".indicator-tab");

  const indicatorForm = document.getElementById("indicatorForm");
  const indicatorInput = document.getElementById("indicatorInput");
  const indicatorLabel = document.getElementById("indicatorLabel");
  const indicatorHint = document.getElementById("indicatorHint");
  const indicatorInputIcon = document.getElementById("indicatorInputIcon");
  const indicatorAnalyzeBtn = document.getElementById("indicatorAnalyzeBtn");

  const indicatorMessage = document.getElementById("indicatorMessage");
  const indicatorResults = document.getElementById("indicatorResults");

  const resultIndicator = document.getElementById("resultIndicator");
  const resultType = document.getElementById("resultType");

  // HTML ID is resultStatus
  const resultStatus = document.getElementById("resultStatus");

  const resultEvidence = document.getElementById("resultEvidence");
  const resultExplanation = document.getElementById("resultExplanation");

  // ================================================
  // REQUIRED ELEMENT CHECK
  // ================================================

  const requiredElements = {
    indicatorForm,
    indicatorInput,
    indicatorLabel,
    indicatorHint,
    indicatorInputIcon,
    indicatorAnalyzeBtn,
    indicatorMessage,
    indicatorResults,
    resultIndicator,
    resultType,
    resultStatus,
    resultEvidence,
    resultExplanation,
  };

  const missingElements = Object.entries(requiredElements)
    .filter(([, element]) => !element)
    .map(([name]) => name);

  if (missingElements.length > 0) {
    console.error(
      "ScamShield Intelligence: Missing HTML elements:",
      missingElements,
    );

    return;
  }

  // ================================================
  // API CONFIGURATION
  // ================================================

  const API = window.ScamShieldAPI;

  if (!API || typeof API.post !== "function") {
    console.error(
      "ScamShield Intelligence: ScamShieldAPI is unavailable.",
    );

    showMessage(
      "API service is unavailable. Please check api.js loading.",
      "error",
    );

    return;
  }

  const API_ENDPOINT = "/intelligence/analyze";

  let currentIndicatorType = "phone";

  // ================================================
  // INDICATOR CONFIGURATION
  // ================================================

  const indicatorConfig = {
    phone: {
      label: "Enter Phone Number",
      placeholder: "Example: +919876543210",
      hint: "Enter a phone number with country code if available.",
      icon: "fa-phone",
      maxLength: 20,
    },

    url: {
      label: "Enter Suspicious URL",
      placeholder: "Example: https://example.com",
      hint: "Enter a complete HTTP or HTTPS URL.",
      icon: "fa-link",
      maxLength: 250,
    },

    upi: {
      label: "Enter UPI ID",
      placeholder: "Example: username@bank",
      hint: "Enter the UPI identifier found in your evidence.",
      icon: "fa-wallet",
      maxLength: 100,
    },

    keyword: {
      label: "Enter Suspicious Keyword",
      placeholder: "Example: urgent payment",
      hint: "Enter a suspicious phrase or keyword.",
      icon: "fa-file-lines",
      maxLength: 250,
    },
  };

  // ================================================
  // AUTHENTICATION
  // ================================================

  function getToken() {
    return (
      localStorage.getItem("scamshieldToken") ||
      sessionStorage.getItem("scamshieldToken")
    );
  }

  function checkAuthentication() {
    if (!getToken()) {
      showMessage(
        "Your session has expired. Please log in again.",
        "error",
      );

      return false;
    }

    return true;
  }

  // ================================================
  // MESSAGE HANDLING
  // ================================================

  function showMessage(message, type = "info") {
    indicatorMessage.textContent = message;

    indicatorMessage.className = `indicator-message ${type}`;

    indicatorMessage.hidden = false;
  }

  function hideMessage() {
    indicatorMessage.hidden = true;
    indicatorMessage.textContent = "";
    indicatorMessage.className = "indicator-message";
  }

  // ================================================
  // CLEAR RESULTS
  // ================================================

  function clearResults() {
    indicatorResults.hidden = true;

    resultIndicator.textContent = "-";
    resultType.textContent = "-";
    resultStatus.textContent = "-";
    resultEvidence.textContent = "-";

    resultExplanation.textContent = "No analysis available.";
  }

  // ================================================
  // UPDATE INDICATOR TYPE
  // ================================================

  function updateIndicatorType(type) {
    const config = indicatorConfig[type];

    if (!config) {
      return;
    }

    currentIndicatorType = type;

    indicatorTabs.forEach((tab) => {
      const isActive = tab.dataset.indicator === type;

      tab.classList.toggle("active", isActive);

      tab.setAttribute("aria-pressed", String(isActive));
    });

    indicatorLabel.textContent = config.label;

    indicatorInput.placeholder = config.placeholder;

    indicatorInput.maxLength = config.maxLength;

    indicatorHint.textContent = config.hint;

    indicatorInputIcon.className = `fa-solid ${config.icon}`;

    indicatorInput.value = "";

    hideMessage();

    clearResults();

    indicatorInput.focus();
  }

  // ================================================
  // TAB EVENTS
  // ================================================

  indicatorTabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      updateIndicatorType(tab.dataset.indicator);
    });
  });

  // ================================================
  // INPUT VALIDATION
  // ================================================

  function validateIndicator(value, type) {
    if (!value) {
      return "Please enter an indicator.";
    }

    if (value.length > 250) {
      return "Indicator cannot exceed 250 characters.";
    }

    switch (type) {
      case "phone": {
        const cleaned = value.replace(/[\s()+-]/g, "");

        if (!/^\d{7,15}$/.test(cleaned)) {
          return "Enter a valid phone number containing 7–15 digits.";
        }

        break;
      }

      case "url": {
        try {
          const parsedURL = new URL(value);

          if (
            parsedURL.protocol !== "http:" &&
            parsedURL.protocol !== "https:"
          ) {
            return "Only HTTP and HTTPS URLs are supported.";
          }

          if (!parsedURL.hostname.includes(".")) {
            return "Enter a valid website URL.";
          }
        } catch {
          return "Please enter a valid URL.";
        }

        break;
      }

      case "upi": {
        const upiPattern =
          /^[a-zA-Z0-9._-]{2,256}@[a-zA-Z0-9.-]{2,64}$/;

        if (!upiPattern.test(value)) {
          return "Enter a valid UPI ID format.";
        }

        break;
      }

      case "keyword": {
        if (value.length < 2) {
          return "Keyword must contain at least 2 characters.";
        }

        break;
      }

      default:
        return "Invalid indicator type.";
    }

    return null;
  }

  // ================================================
  // LOADING STATE
  // ================================================

  let originalButtonHTML = indicatorAnalyzeBtn.innerHTML;

  function setLoading(isLoading) {
    indicatorAnalyzeBtn.disabled = isLoading;
    indicatorInput.disabled = isLoading;

    indicatorTabs.forEach((tab) => {
      tab.disabled = isLoading;
    });

    if (isLoading) {
      indicatorAnalyzeBtn.innerHTML = `
        <i class="fa-solid fa-spinner fa-spin"></i>
        Examining...
      `;
    } else {
      indicatorAnalyzeBtn.innerHTML = originalButtonHTML;
    }
  }

  // ================================================
  // FORMAT RELATED EVIDENCE
  // ================================================

  function formatRelatedEvidence(value) {
    if (typeof value === "number") {
      return `${value} matching record(s)`;
    }

    if (Array.isArray(value)) {
      return `${value.length} matching record(s)`;
    }

    if (typeof value === "string" && value.trim()) {
      return value;
    }

    return "No matching evidence found";
  }

  // ================================================
  // RENDER RESULTS
  // ================================================

  function renderResults(response, submittedValue, submittedType) {
    if (!response || response.success !== true || !response.result) {
      throw new Error("Invalid response received from intelligence API.");
    }

    const result = response.result;

    resultIndicator.textContent =
      result.indicator || submittedValue;

    resultType.textContent =
      result.indicatorType?.toUpperCase() ||
      submittedType.toUpperCase();

    resultStatus.textContent =
      result.status || "Pending verification";

    resultEvidence.textContent = formatRelatedEvidence(
      result.relatedEvidence,
    );

    resultExplanation.textContent =
      result.explanation ||
      response.message ||
      "No additional intelligence information is available.";

    indicatorResults.hidden = false;

    indicatorResults.scrollIntoView({
      behavior: "smooth",
      block: "nearest",
    });
  }

  // ================================================
  // API REQUEST
  // ================================================

  async function analyzeIndicator(value, type) {
    const response = await API.post(API_ENDPOINT, {
      indicatorType: type,
      indicator: value,
    });

    if (!response || response.success !== true) {
      throw new Error(
        response?.message || "Indicator examination failed.",
      );
    }

    return response;
  }

  // ================================================
  // FORM SUBMISSION
  // ================================================

  indicatorForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    hideMessage();

    clearResults();

    const value = indicatorInput.value.trim();

    const type = currentIndicatorType;

    // Authentication check

    if (!checkAuthentication()) {
      return;
    }

    // Input validation

    const validationError = validateIndicator(value, type);

    if (validationError) {
      showMessage(validationError, "error");

      indicatorInput.focus();

      return;
    }

    // Loading state

    setLoading(true);

    showMessage(
      "Searching your submitted evidence for matching indicators...",
      "info",
    );

    try {
      const response = await analyzeIndicator(value, type);

      renderResults(response, value, type);

      hideMessage();

      console.log(
        "ScamShield Intelligence: Indicator examination completed.",
        response.result,
      );
    } catch (error) {
      console.error(
        "ScamShield Intelligence Error:",
        error,
      );

      if (
        error.message?.toLowerCase().includes("unauthorized") ||
        error.message?.toLowerCase().includes("token")
      ) {
        showMessage(
          "Authentication failed. Please log in again.",
          "error",
        );
      } else if (
        error.message?.includes("Failed to fetch")
      ) {
        showMessage(
          "Unable to connect to the backend. Check whether the ScamShield API server is running.",
          "error",
        );
      } else {
        showMessage(
          error.message || "Unable to examine this indicator.",
          "error",
        );
      }
    } finally {
      setLoading(false);
    }
  });

  // ================================================
  // FOOTER YEAR
  // ================================================

  document.querySelectorAll("[data-current-year]").forEach((element) => {
    element.textContent = new Date().getFullYear();
  });

  // ================================================
  // INITIALIZATION
  // ================================================

  updateIndicatorType("phone");

  console.log(
    "ScamShield Intelligence Module Initialized Successfully.",
  );
});