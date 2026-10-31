"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // ================================================
  // DOM ELEMENTS
  // ================================================

  const scenarioTitle = document.getElementById("scenarioTitle");
  const scenarioSender = document.getElementById("scenarioSender");
  const scenarioMessage = document.getElementById("scenarioMessage");

  const simulationOptions = document.getElementById("simulationOptions");
  const checkButton = document.getElementById("checkSimulation");
  const resetButton = document.getElementById("resetSimulation");

  const simulationResult = document.getElementById("simulationResult");
  const resultTitle = document.getElementById("simulationResultTitle");
  const resultMessage = document.getElementById("simulationResultMessage");
  const resultScore = document.getElementById("simulationScore");

  const scenarioButtons = document.querySelectorAll("[data-scenario]");

  // ================================================
  // VALIDATE REQUIRED ELEMENTS
  // ================================================

  const requiredElements = [
    scenarioTitle,
    scenarioSender,
    scenarioMessage,
    simulationOptions,
    checkButton,
    resetButton,
    simulationResult,
    resultTitle,
    resultMessage,
    resultScore,
  ];

  if (requiredElements.some((element) => !element)) {
    console.error("Decoy Lab: Required HTML elements are missing.");
    return;
  }

  if (!scenarioButtons.length) {
    console.error("Decoy Lab: No scenario buttons found.");
    return;
  }

  // ================================================
  // SCENARIO DATA
  // ================================================

  const scenarios = {
    investment: {
      title: "Fake Investment Opportunity",
      sender: "Unknown Investment Advisor",
      message:
        "Congratulations! You have been selected for an exclusive investment plan. Invest ₹5,000 today and receive guaranteed returns of ₹50,000 within 7 days. Limited seats available. Act immediately!",

      indicators: [
        "guaranteed-returns",
        "urgency",
        "payment-pressure",
      ],

      explanation:
        "Fraudsters often promise unrealistic returns, create urgency, and pressure people to transfer money.",
    },

    "digital-arrest": {
      title: "Digital Arrest Scam",
      sender: "Fake Police Officer",
      message:
        "Your Aadhaar has been linked to an illegal activity. A police case has been registered against you. Stay on video call and pay the verification fee immediately to avoid arrest.",

      indicators: [
        "urgency",
        "suspicious-contact",
        "payment-pressure",
      ],

      explanation:
        "Real law enforcement agencies do not conduct digital arrests or demand money to avoid arrest.",
    },

    "credit-card": {
      title: "Fake Credit Card Verification",
      sender: "Unknown Bank Representative",
      message:
        "Your credit card will be blocked today. Complete your KYC immediately using the verification link. Share your card details and OTP to reactivate your account.",

      indicators: [
        "urgency",
        "suspicious-contact",
        "payment-pressure",
      ],

      explanation:
        "Fraudsters impersonate banks and use account-blocking threats to steal confidential banking information.",
    },

    sextortion: {
      title: "Sextortion Threat",
      sender: "Unknown Online Contact",
      message:
        "We have recorded your private video. Pay the demanded amount immediately or we will share it with your friends and family. Do not report this to anyone.",

      indicators: [
        "urgency",
        "suspicious-contact",
        "payment-pressure",
      ],

      explanation:
        "Sextortion scammers use fear, threats, and financial pressure to force victims into paying money.",
    },

    ecommerce: {
      title: "Fake Shopping Offer",
      sender: "Unknown Shopping Website",
      message:
        "You have won an expensive smartphone in our lucky draw. Pay a small processing fee immediately to claim your prize. Offer expires in 10 minutes.",

      indicators: [
        "guaranteed-returns",
        "urgency",
        "payment-pressure",
      ],

      explanation:
        "Fake shopping offers use unrealistic rewards and advance-fee demands to trick people.",
    },
  };

  const indicatorLabels = {
    urgency: "Urgent action or deadline",
    "guaranteed-returns": "Guaranteed rewards or unrealistic returns",
    "suspicious-contact": "Suspicious or unknown contact",
    "payment-pressure": "Pressure to make a payment",
  };

  // ================================================
  // STATE
  // ================================================

  let currentScenario = "investment";

  const reducedMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)",
  ).matches;

  // ================================================
  // HELPERS
  // ================================================

  function scrollToElement(element) {
    if (!element) return;

    element.scrollIntoView({
      behavior: reducedMotion ? "auto" : "smooth",
      block: "start",
    });
  }

  function getSelectedIndicators() {
    return Array.from(
      simulationOptions.querySelectorAll(
        'input[name="simulationIndicator"]:checked',
      ),
    ).map((input) => input.value);
  }

  function getAllIndicators() {
    return Array.from(
      simulationOptions.querySelectorAll(
        'input[name="simulationIndicator"]',
      ),
    );
  }

  function updateStatus(message) {
    simulationResult.setAttribute("role", "status");
    simulationResult.setAttribute("aria-live", "polite");

    if (resultMessage) {
      resultMessage.textContent = message;
    }
  }

  // ================================================
  // RESET INDICATORS
  // ================================================

  function clearSelections() {
    getAllIndicators().forEach((input) => {
      input.checked = false;

      const option = input.closest(".simulation-option");

      if (option) {
        option.classList.remove(
          "selected",
          "correct",
          "incorrect",
          "missed",
        );
      }
    });
  }

  // ================================================
  // HIDE RESULTS
  // ================================================

  function hideResults() {
    simulationResult.hidden = true;

    resultTitle.textContent = "";
    resultMessage.textContent = "";
    resultScore.textContent = "--";

    simulationResult.removeAttribute("data-result");
  }

  // ================================================
  // UPDATE ACTIVE SCENARIO
  // ================================================

  function updateActiveScenarioButtons() {
    scenarioButtons.forEach((button) => {
      const isActive = button.dataset.scenario === currentScenario;

      if (button.classList.contains("workspace-scenario")) {
        button.classList.toggle("active", isActive);
        button.setAttribute("aria-pressed", String(isActive));
      }
    });
  }

  // ================================================
  // LOAD SCENARIO
  // ================================================

  function loadScenario(scenarioKey) {
    const scenario = scenarios[scenarioKey];

    if (!scenario) {
      console.warn("Unknown scenario:", scenarioKey);
      return;
    }

    currentScenario = scenarioKey;

    scenarioTitle.textContent = scenario.title;
    scenarioSender.textContent = scenario.sender;
    scenarioMessage.textContent = scenario.message;

    clearSelections();
    hideResults();

    updateActiveScenarioButtons();

    // Notify other Decoy Lab components.
    document.dispatchEvent(
      new CustomEvent("decoy:scenario-change", {
        detail: {
          scenario: scenarioKey,
        },
      }),
    );
  }

  // ================================================
  // SCENARIO BUTTON EVENTS
  // ================================================

  scenarioButtons.forEach((button) => {
    button.addEventListener("click", () => {
      const scenarioKey = button.dataset.scenario;

      loadScenario(scenarioKey);

      if (button.classList.contains("scenario-select-btn")) {
        scrollToElement(document.getElementById("simulation"));
      }
    });
  });

  // ================================================
  // INDICATOR SELECTION EVENTS
  // ================================================

  getAllIndicators().forEach((input) => {
    input.addEventListener("change", () => {
      const option = input.closest(".simulation-option");

      if (option) {
        option.classList.toggle("selected", input.checked);

        option.classList.remove(
          "correct",
          "incorrect",
          "missed",
        );
      }

      hideResults();
    });
  });

  // ================================================
  // ANALYZE SIMULATION
  // ================================================

  function analyzeSimulation() {
    const selectedIndicators = getSelectedIndicators();
    const scenario = scenarios[currentScenario];

    if (!scenario) return;

    if (selectedIndicators.length === 0) {
      simulationResult.hidden = false;
      simulationResult.dataset.result = "warning";

      resultTitle.textContent = "Select Warning Signs";
      resultScore.textContent = "--";

      updateStatus(
        "Please select at least one warning sign before checking the simulation.",
      );

      scrollToElement(simulationResult);
      return;
    }

    const expectedIndicators = scenario.indicators;

    let correctCount = 0;
    let missedCount = 0;
    let incorrectCount = 0;

    const allInputs = getAllIndicators();

    allInputs.forEach((input) => {
      const value = input.value;
      const isExpected = expectedIndicators.includes(value);
      const isSelected = input.checked;

      const option = input.closest(".simulation-option");

      if (option) {
        option.classList.remove(
          "correct",
          "incorrect",
          "missed",
        );
      }

      if (isExpected && isSelected) {
        correctCount++;

        if (option) option.classList.add("correct");
      } else if (isExpected && !isSelected) {
        missedCount++;

        if (option) option.classList.add("missed");
      } else if (!isExpected && isSelected) {
        incorrectCount++;

        if (option) option.classList.add("incorrect");
      }
    });

    // Exact classification accuracy:
    // True positives + True negatives / all available indicators.

    const totalIndicators = allInputs.length;

    const trueNegatives =
      totalIndicators -
      expectedIndicators.length -
      incorrectCount;

    const score =
      totalIndicators > 0
        ? Math.round(
            ((correctCount + trueNegatives) / totalIndicators) * 100,
          )
        : 0;

    // ==============================================
    // RESULT MESSAGE
    // ==============================================

    let title = "Keep Practicing";
    let resultType = "warning";

    if (score === 100) {
      title = "Excellent! All Signs Identified";
      resultType = "success";
    } else if (score >= 75) {
      title = "Good Work!";
      resultType = "success";
    } else if (score >= 50) {
      title = "Some Signs Were Missed";
      resultType = "warning";
    } else {
      title = "More Practice Needed";
      resultType = "danger";
    }

    const explanation = [
      `Correctly identified: ${correctCount}`,
      `Missed warning signs: ${missedCount}`,
      `Incorrect selections: ${incorrectCount}`,
      "",
      scenario.explanation,
    ].join("\n");

    simulationResult.hidden = false;
    simulationResult.dataset.result = resultType;

    resultTitle.textContent = title;
    resultScore.textContent = `${score}%`;

    updateStatus(explanation);

    scrollToElement(simulationResult);
  }

  // ================================================
  // RESET SIMULATION
  // ================================================

  function resetSimulation() {
    clearSelections();
    hideResults();
  }

  // ================================================
  // BUTTON EVENTS
  // ================================================

  checkButton.addEventListener("click", analyzeSimulation);

  resetButton.addEventListener("click", resetSimulation);

  // ================================================
  // INITIALIZE
  // ================================================

  loadScenario("investment");
});