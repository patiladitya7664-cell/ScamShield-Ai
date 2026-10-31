"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // ==========================================
  // DOM ELEMENTS
  // ==========================================

  const evidenceButtons = document.querySelectorAll(".evidence-type");
  const evidenceForms = document.querySelectorAll(".evidence-form");

  const analyzeBtn = document.getElementById("analyzeBtn");
  const clearBtn = document.getElementById("clearBtn");

  const analysisMessage = document.getElementById("analysisMessage");
  const detectionResults = document.getElementById("detectionResults");

  const messageInput = document.getElementById("messageInput");
  const urlInput = document.getElementById("urlInput");
  const callInput = document.getElementById("callInput");
  const transactionInput = document.getElementById("transactionInput");
  const safetyGuidance = document.getElementById("safetyGuidance");
  const feedbackPanel = document.getElementById("classificationFeedbackPanel");
  const feedbackSelect = document.getElementById("classificationFeedbackSelect");
  const feedbackButton = document.getElementById("submitClassificationFeedback");
  const feedbackStatus = document.getElementById("classificationFeedbackStatus");

  let activeEvidence = "message";
  let isAnalyzing = false;
  let currentCaseId = null;

  // ==========================================
  // API CONFIGURATION
  // ==========================================

  const API_BASE_URL = window.SCAMSHIELD_API_URL || "http://localhost:5000/api";
  const TOKEN_KEY = "scamshieldToken";

  // ==========================================
  // EVIDENCE SELECTION
  // ==========================================

  evidenceButtons.forEach((button) => {
    button.addEventListener("click", () => {
      if (isAnalyzing) return;

      activeEvidence = button.dataset.evidence;

      evidenceButtons.forEach((item) => {
        item.classList.remove("active");
        item.setAttribute("aria-pressed", "false");
      });

      button.classList.add("active");
      button.setAttribute("aria-pressed", "true");

      evidenceForms.forEach((form) => {
        const isActive = form.dataset.form === activeEvidence;

        form.classList.toggle("active", isActive);
        form.hidden = !isActive;
      });

      hideMessage();
      detectionResults.hidden = true;
    });
  });

  // ==========================================
  // CHARACTER COUNTERS
  // ==========================================

  function updateCounter(input, counter, maxLength) {
    if (!input || !counter) return;

    const update = () => {
      counter.textContent = `${input.value.length} / ${maxLength}`;
    };

    input.addEventListener("input", update);
    update();
  }

  updateCounter(messageInput, document.getElementById("messageCount"), 10000);

  updateCounter(callInput, document.getElementById("callCount"), 15000);

  updateCounter(
    transactionInput,
    document.getElementById("transactionCount"),
    10000,
  );

  // ==========================================
  // MESSAGE HELPERS
  // ==========================================

  function showMessage(message, type = "success") {
    analysisMessage.textContent = message;
    analysisMessage.className = `analysis-message ${type}`;
    analysisMessage.hidden = false;
  }

  function hideMessage() {
    analysisMessage.textContent = "";
    analysisMessage.className = "analysis-message";
    analysisMessage.hidden = true;
  }

  // ==========================================
  // INPUT VALIDATION
  // ==========================================

  function getEvidenceValue() {
    switch (activeEvidence) {
      case "message":
        return messageInput.value.trim();

      case "url":
        return urlInput.value.trim();

      case "call":
        return callInput.value.trim();

      case "transaction":
        return transactionInput.value.trim();

      default:
        return "";
    }
  }

  function validateEvidence(value) {
    if (!value) {
      return "Please provide evidence before starting analysis.";
    }

    if (activeEvidence === "url") {
      try {
        const parsedURL = new URL(value);

        if (!["http:", "https:"].includes(parsedURL.protocol)) {
          return "Only HTTP and HTTPS URLs are supported.";
        }
      } catch {
        return "Please enter a valid website URL.";
      }
    }

    return null;
  }

  // ==========================================
  // LOADING STATE
  // ==========================================

  function setLoading(loading) {
    isAnalyzing = loading;

    analyzeBtn.disabled = loading;
    clearBtn.disabled = loading;

    evidenceButtons.forEach((button) => {
      button.disabled = loading;
    });

    analyzeBtn.innerHTML = loading
      ? `<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...`
      : `<i class="fa-solid fa-shield-halved"></i> Analyze Evidence`;
  }

  // ==========================================
  // RESULT HELPERS
  // ==========================================

  function getRiskLevel(score) {
    if (score <= 24) {
      return {
        name: "Low Risk",
        description: "No strong fraud indicators were identified.",
        color: "#39d98a",
      };
    }

    if (score <= 49) {
      return {
        name: "Medium Risk",
        description: "Some suspicious indicators require attention.",
        color: "#f5bd65",
      };
    }

    if (score <= 74) {
      return {
        name: "High Risk",
        description: "Multiple suspicious indicators were identified.",
        color: "#ff8b4a",
      };
    }

    return {
      name: "Critical Risk",
      description: "Strong fraud indicators require immediate caution.",
      color: "#ff5252",
    };
  }

  // ==========================================
  // SAFE RESULT RENDERING
  // ==========================================

  function renderResults(data) {
    const score = Number(data.riskScore);

    if (!Number.isFinite(score) || score < 0 || score > 100) {
      throw new Error("Invalid risk score received from the server.");
    }

    const risk = getRiskLevel(score);

    document.getElementById("riskScore").textContent = score;

    document.getElementById("riskLevel").textContent = risk.name;

    document.getElementById("riskDescription").textContent =
      data.riskDescription || risk.description;

    const categoryLabels = {
      investment: "Investment scam",
      digitalArrest: "Digital arrest / authority impersonation",
      creditCard: "Banking or credit card fraud",
      sextortion: "Sextortion or blackmail",
      ecommerce: "E-commerce fraud",
      other: "Other suspicious activity",
      unclassified: "Unclassified",
    };
    const category = String(data.fraudCategory || "unclassified");
    document.getElementById("fraudCategory").textContent =
      categoryLabels[category] || category;

    document.getElementById("riskExplanation").textContent =
      data.explanation || "No explanation provided.";

    document.getElementById("resultStatus").textContent = "Analysis Complete";

    const circle = document.getElementById("riskScoreCircle");

    circle.style.background = `conic-gradient(
            ${risk.color} ${score * 3.6}deg,
            rgba(255,255,255,0.08) ${score * 3.6}deg
        )`;

    document.getElementById("riskLevel").style.color = risk.color;

    const indicatorList = document.getElementById("indicatorList");

    indicatorList.replaceChildren();

    const indicators = Array.isArray(data.indicators) ? data.indicators : [];

    if (indicators.length === 0) {
      const empty = document.createElement("p");
      empty.textContent = "No indicators extracted.";
      indicatorList.appendChild(empty);
    } else {
      indicators.forEach((indicator) => {
        const item = document.createElement("span");

        item.className = "indicator-item";
        item.textContent =
          indicator && typeof indicator === "object"
            ? `${indicator.type || "clue"}: ${indicator.value || ""} (unverified)`
            : String(indicator);

        indicatorList.appendChild(item);
      });
    }

    if (safetyGuidance) {
      const guidanceByCategory = {
        digitalArrest: [
          "End the call or chat if you feel pressured; real law enforcement does not demand an urgent payment to avoid arrest.",
          "Do not transfer money or share OTPs, PINs, passwords, or identity documents.",
          "Verify the claim using an official contact you find independently; preserve the message and call details.",
          "If money was transferred, contact your bank and call India's 1930 helpline promptly.",
        ],
        creditCard: [
          "Do not open the link or share an OTP, PIN, CVV, password, or full card number.",
          "Contact your bank using its official app or the number printed on your card.",
          "If credentials or money may be at risk, ask the bank to secure the account and call 1930 promptly.",
          "Keep the message, sender details, and transaction reference as evidence.",
        ],
        sextortion: [
          "You are not to blame. Avoid paying or sending more material; payment may not stop the threats.",
          "Preserve messages, account names, URLs, and timestamps; avoid forwarding intimate material.",
          "Block and report the account on the platform, and seek support from someone you trust.",
          "For immediate danger or financial loss, contact local emergency support or India's cybercrime helpline 1930.",
        ],
        investment: [
          "Pause before investing; guaranteed high returns and pressure to act quickly are warning signs.",
          "Verify the firm and registration independently through official sources; do not rely on links the sender supplied.",
          "Do not share financial credentials or send more money to unlock a promised return.",
          "If you already paid, contact your bank and call 1930 promptly; preserve transaction records.",
        ],
        ecommerce: [
          "Do not pay outside the shopping platform or use an unfamiliar payment link.",
          "Check the seller and return policy independently; unusually low prices and urgency can be warning signs.",
          "Keep order, chat, and payment records; contact your bank if payment details may be exposed.",
        ],
        unclassified: [
          "Pause before replying, clicking, or transferring money.",
          "Never share OTPs, PINs, passwords, or full card details.",
          "Verify through an official contact you find independently and preserve relevant evidence.",
        ],
      };
      const guidance = guidanceByCategory[category] || guidanceByCategory.unclassified;
      safetyGuidance.replaceChildren();
      guidance.forEach((text) => {
        const item = document.createElement("li");
        item.textContent = text;
        safetyGuidance.appendChild(item);
      });
    }

    if (feedbackPanel) feedbackPanel.hidden = true;
    currentCaseId = null;

    detectionResults.hidden = false;

    detectionResults.scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  }

  // ==========================================
  // API ANALYSIS
  // ==========================================

  async function analyzeEvidence() {
    if (isAnalyzing) return;

    hideMessage();

    const value = getEvidenceValue();

    const validationError = validateEvidence(value);

    if (validationError) {
      showMessage(validationError, "error");
      return;
    }

    const token =
      localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY);

    if (!token) {
      showMessage("Please sign in before analyzing evidence.", "error");
      return;
    }

    setLoading(true);
    detectionResults.hidden = true;

    try {
      const response = await fetch(`${API_BASE_URL}/analysis/analyze`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },

        body: JSON.stringify({
          evidenceType: activeEvidence,
          evidence: value,
        }),
      });

      const data = await response.json();

      if (!response.ok || data.success === false) {
        throw new Error(data.message || "Analysis request failed.");
      }

      if (!data.result) {
        throw new Error("Invalid analysis response from server.");
      }

      renderResults(data.result);

      // Save a case linked to the analysis. Raw evidence is not copied into
      // the case description; only the structured assessment and clues persist.
      try {
        const caseResponse = await fetch(`${API_BASE_URL}/cases`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            title: `${String(data.result.fraudCategory || "Scam").replace(/([A-Z])/g, " $1")} review`,
            description: "User-submitted evidence reviewed by ScamShield's rule-based assessment. Original evidence is not stored in this case record.",
            analysisId: data.result.id,
            fraudCategory: data.result.fraudCategory,
            riskLevel: String(data.result.riskLevel || "medium").toLowerCase(),
            priority:
              Number(data.result.riskScore) >= 75
                ? "urgent"
                : Number(data.result.riskScore) >= 50
                  ? "high"
                  : "medium",
            indicators: Array.isArray(data.result.indicators)
              ? data.result.indicators
              : [],
          }),
        });

        const caseData = await caseResponse.json().catch(() => ({}));

        if (!caseResponse.ok || caseData.success === false) {
          throw new Error(caseData.message || "Case record could not be saved.");
        }

        currentCaseId = caseData.data?._id || caseData.data?.id || null;
        if (feedbackPanel && currentCaseId) feedbackPanel.hidden = false;

        showMessage("Analysis complete and case saved to your account.", "success");
      } catch (caseError) {
        console.error("ScamShield Case Save Error:", caseError);
        showMessage(
          `Analysis completed, but the case could not be saved: ${caseError.message}`,
          "error",
        );
      }
    } catch (error) {
      console.error("ScamShield Detection Error:", error);

      showMessage(
        error.message || "Unable to analyze evidence. Please try again.",
        "error",
      );
    } finally {
      setLoading(false);
    }
  }

  // ==========================================
  // CLEAR FORM
  // ==========================================

  function clearForm() {
    if (isAnalyzing) return;

    messageInput.value = "";
    urlInput.value = "";
    callInput.value = "";
    transactionInput.value = "";

    updateCounters();

    detectionResults.hidden = true;
    currentCaseId = null;
    if (feedbackPanel) feedbackPanel.hidden = true;

    hideMessage();

    activeEvidence = "message";

    evidenceButtons.forEach((button) => {
      const active = button.dataset.evidence === "message";

      button.classList.toggle("active", active);
      button.setAttribute("aria-pressed", String(active));
    });

    evidenceForms.forEach((form) => {
      const active = form.dataset.form === "message";

      form.classList.toggle("active", active);
      form.hidden = !active;
    });
  }

  function updateCounters() {
    const counters = [
      [messageInput, "messageCount", 10000],
      [callInput, "callCount", 15000],
      [transactionInput, "transactionCount", 10000],
    ];

    counters.forEach(([input, counterId, max]) => {
      const counter = document.getElementById(counterId);

      if (counter) {
        counter.textContent = `${input.value.length} / ${max}`;
      }
    });
  }

  // ==========================================
  // EVENT LISTENERS
  // ==========================================

  analyzeBtn.addEventListener("click", analyzeEvidence);

  clearBtn.addEventListener("click", clearForm);

  feedbackButton?.addEventListener("click", async () => {
    const token =
      localStorage.getItem(TOKEN_KEY) || sessionStorage.getItem(TOKEN_KEY);
    if (!currentCaseId || !token) return;

    feedbackButton.disabled = true;
    feedbackStatus.textContent = "Saving feedback…";
    try {
      const response = await fetch(`${API_BASE_URL}/cases/${encodeURIComponent(currentCaseId)}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          classificationFeedback: feedbackSelect.value,
        }),
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || result.success === false) {
        throw new Error(result.message || "Could not save feedback.");
      }
      feedbackStatus.textContent = "Feedback saved for case review.";
    } catch (error) {
      feedbackStatus.textContent = error.message;
    } finally {
      feedbackButton.disabled = false;
    }
  });

  // ==========================================
  // INITIALIZATION
  // ==========================================

  clearForm();

  console.log("ScamShield AI | Detection module initialized.");
});
