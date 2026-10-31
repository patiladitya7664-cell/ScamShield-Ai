/* =====================================================
   SCAMSHIELD AI - THREAT INTELLIGENCE
   Indicator Explorer
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
  const resultStatus = document.getElementById("intelligenceResultStatus");
  const resultEvidence = document.getElementById("resultEvidence");
  const resultExplanation = document.getElementById("resultExplanation");

  if (
    !indicatorForm ||
    !indicatorInput ||
    !indicatorAnalyzeBtn ||
    !indicatorResults
  ) {
    console.error("ScamShield Intelligence: Required HTML elements not found.");
    return;
  }

  // ================================================
  // CONFIGURATION
  // ================================================

  const API_BASE_URL = window.SCAMSHIELD_API_URL || "http://localhost:5000/api";

  const API_ENDPOINT = `${API_BASE_URL}/intelligence/analyze`;

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
      const selectedType = tab.dataset.indicator;

      updateIndicatorType(selectedType);
    });
  });

  // ================================================
  // INPUT VALIDATION
  // ================================================

  function validateIndicator(value, type) {
    if (!value) {
      return "Please enter an indicator.";
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
        } catch (error) {
          return "Please enter a valid URL.";
        }

        break;
      }

      case "upi": {
        const upiPattern = /^[a-zA-Z0-9._-]{2,256}@[a-zA-Z0-9.-]{2,64}$/;

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
      indicatorAnalyzeBtn.innerHTML = `
                <i class="fa-solid fa-magnifying-glass"></i>
                Examine
            `;
    }
  }

  // ================================================
  // RENDER RESULTS
  // ================================================

  function renderResults(data, submittedValue, submittedType) {
    const result = data.result || data.data || data;

    resultIndicator.textContent = result.indicator || submittedValue;

    resultType.textContent =
      result.indicatorType || submittedType.toUpperCase();

    resultStatus.textContent = result.status || "Pending verification";

    resultEvidence.textContent = result.relatedEvidence ?? "Not available";

    resultExplanation.textContent =
      result.explanation ||
      result.message ||
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
    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, 20000);

    try {
      const response = await fetch(API_ENDPOINT, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("scamshieldToken") || sessionStorage.getItem("scamshieldToken") || ""}`,
        },

        body: JSON.stringify({
          indicatorType: type,

          indicator: value,
        }),

        signal: controller.signal,
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(data.message || `Server error (${response.status}).`);
      }

      if (data.success === false) {
        throw new Error(data.message || "Indicator examination failed.");
      }

      return data;
    } finally {
      clearTimeout(timeout);
    }
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

    // Validate input

    const validationError = validateIndicator(value, type);

    if (validationError) {
      showMessage(validationError, "error");

      indicatorInput.focus();

      return;
    }

    // Loading

    setLoading(true);

    showMessage("Submitting indicator for examination...", "info");

    try {
      const data = await analyzeIndicator(value, type);

      renderResults(data, value, type);

      hideMessage();
    } catch (error) {
      console.error("ScamShield Intelligence Error:", error);

      if (error.name === "AbortError") {
        showMessage("Request timed out. Please try again.", "error");
      } else if (error.message.includes("Failed to fetch")) {
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
  // INITIALIZATION
  // ================================================

  updateIndicatorType("phone");

  // Footer year

  document.querySelectorAll("[data-current-year]").forEach((element) => {
    element.textContent = new Date().getFullYear();
  });

  console.log("ScamShield Intelligence Module Initialized.");
});
