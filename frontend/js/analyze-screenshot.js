/*
=========================================================
 SCAMSHIELD AI - SCREENSHOT ANALYSIS
 File: analyze-screenshot.js
 Version: 4.0.0

 Features:
 1. JPG, JPEG, PNG and WEBP screenshot upload.
 2. Drag and drop image support.
 3. Image preview and remove/replace.
 4. Browser-based OCR using Tesseract.js.
 5. English and Hindi + English OCR.
 6. OCR progress indicator.
 7. Editable extracted text.
 8. Node.js backend integration.
 9. Guardian Agent result.
 10. Intelligence Agent indicators.
 11. Victim Safety Agent guidance.
 12. Gemini advisory display.
 13. Decoy Agent status.
 14. Risk score visualization.
 15. User feedback.
 16. Safe DOM rendering.

 SECURITY:
 - Screenshot is processed locally in browser.
 - Image is NOT uploaded to backend.
 - Only extracted text is sent for analysis.
 - OCR output must be reviewed by the user.
=========================================================
*/

"use strict";

const ScreenshotAnalysis = (() => {
  /* =================================================
       CONFIGURATION
    ================================================= */

  const CONFIG = {
    version: "4.0.0",
    endpoint: "/analysis/analyze",
    evidenceType: "screenshot",
    maxLength: 20000,
    maxFileSize: 8 * 1024 * 1024,
    requestTimeout: 120000,

    allowedTypes: ["image/jpeg", "image/png", "image/webp"],

    tesseractCDN:
      "https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js",
  };

  /* =================================================
       STATE
    ================================================= */

  const state = {
    selectedFile: null,
    previewUrl: null,
    ocrCompleted: false,
    ocrRunning: false,
    analysisRunning: false,
    ocrWorker: null,
  };

  /* =================================================
       DOM HELPERS
    ================================================= */

  const $ = (id) => document.getElementById(id);

  const setText = (id, value) => {
    const element = $(id);

    if (element) {
      element.textContent = value ?? "";
    }
  };

  const show = (id) => {
    const element = $(id);

    if (element) {
      element.hidden = false;
    }
  };

  const hide = (id) => {
    const element = $(id);

    if (element) {
      element.hidden = true;
    }
  };

  const normalizeText = (value) => {
    if (value === null || value === undefined) {
      return "";
    }

    if (
      typeof value === "string" ||
      typeof value === "number" ||
      typeof value === "boolean"
    ) {
      return String(value).trim();
    }

    return "";
  };

  const isObject = (value) => {
    return value !== null && typeof value === "object" && !Array.isArray(value);
  };

  const getFirst = (...values) => {
    for (const value of values) {
      if (value !== undefined && value !== null && value !== "") {
        return value;
      }
    }

    return null;
  };

  /* =================================================
       RESPONSE NORMALIZATION
    ================================================= */

  function unwrapResponse(response) {
    let data = response;

    if (isObject(data?.data)) {
      data = data.data;
    }

    if (isObject(data?.result)) {
      return data.result;
    }

    return data;
  }

  function getAgent(rawAgents, name) {
    if (!isObject(rawAgents)) {
      return {};
    }

    const aliases = {
      guardian: ["guardian"],
      intelligence: ["intelligence"],
      victimSafety: ["victimSafety", "victim_safety", "victim-safety"],
      decoy: ["decoy"],
    };

    for (const key of aliases[name] || [name]) {
      if (isObject(rawAgents[key])) {
        return rawAgents[key];
      }
    }

    return {};
  }

  function unwrapAgent(agent) {
    if (!isObject(agent)) {
      return {};
    }

    const nested = getFirst(
      agent.pythonResult,
      agent.python_result,
      agent.result,
      agent.output,
    );

    return isObject(nested) ? nested : agent;
  }

  function normalizeAnalysis(raw) {
    const result = isObject(raw) ? raw : {};

    const rawAgents =
      getFirst(
        result.agents,
        result.agentResults,
        result.agent_results,
        result.orchestration?.results,
      ) || {};

    const guardianAgent = unwrapAgent(getAgent(rawAgents, "guardian"));

    const intelligenceAgent = unwrapAgent(getAgent(rawAgents, "intelligence"));

    const victimSafetyAgent = unwrapAgent(getAgent(rawAgents, "victimSafety"));

    const decoyAgent = unwrapAgent(getAgent(rawAgents, "decoy"));

    const guardianAnalysis =
      getFirst(
        guardianAgent.analysis,
        guardianAgent.guardian_analysis,
        guardianAgent,
      ) || {};

    const intelligenceData =
      getFirst(
        intelligenceAgent.intelligence,
        intelligenceAgent.indicators,
        {},
      ) || {};

    const safetyAssessment =
      getFirst(
        victimSafetyAgent.safety_assessment,
        victimSafetyAgent.safetyAssessment,
        victimSafetyAgent.safety,
        victimSafetyAgent.guidance,
        victimSafetyAgent,
      ) || {};

    const gemini =
      getFirst(
        result.geminiAdvisory,
        result.gemini_advisory,
        result.gemini,
        {},
      ) || {};

    return {
      raw: result,

      riskScore: getFirst(
        result.riskScore,
        result.risk_score,
        guardianAnalysis.risk_score,
        guardianAnalysis.riskScore,
        0,
      ),

      riskLevel: getFirst(
        result.riskLevel,
        result.risk_level,
        guardianAnalysis.risk_level,
        guardianAnalysis.riskLevel,
        "UNKNOWN",
      ),

      category: getFirst(
        result.detectionCategory,
        result.detection_category,
        guardianAnalysis.fraud_category,
        guardianAnalysis.fraudCategory,
        result.fraudCategory,
        "unclassified",
      ),

      description: getFirst(
        result.riskDescription,
        result.risk_description,
        result.summary,
        guardianAnalysis.summary,
        "Analysis completed.",
      ),

      explanation: getFirst(
        result.explanation,
        result.riskExplanation,
        guardianAnalysis.explanations,
        guardianAnalysis.explanation,
        guardianAnalysis.summary,
        "",
      ),

      indicators: intelligenceData,

      intelligenceSummary: getFirst(
        intelligenceAgent.summary,
        intelligenceAgent.indicator_summary,
        {},
      ),

      indicatorCounts: getFirst(
        intelligenceAgent.indicator_counts,
        intelligenceAgent.indicatorCounts,
        intelligenceData.indicator_counts,
        {},
      ),

      guardianAgent,
      guardianAnalysis,
      intelligenceAgent,
      victimSafetyAgent,
      safetyAssessment,
      gemini,
      decoyAgent,

      recommendations: getFirst(
        result.recommendations,
        victimSafetyAgent.recommended_actions,
        victimSafetyAgent.recommendedActions,
        guardianAnalysis.recommendations,
        [],
      ),
    };
  }

  /* =================================================
       STATUS MANAGEMENT
    ================================================= */

  function setStatus(title, message, visible = true) {
    if (!visible) {
      hide("screenshotAnalysisStatus");
      return;
    }

    setText("screenshotAnalysisStatusTitle", title);
    setText("screenshotAnalysisStatusMessage", message);

    show("screenshotAnalysisStatus");
  }

  function showInputError(message) {
    const error = $("screenshotInputError");

    if (!error) {
      alert(message);
      return;
    }

    error.textContent = message;
    error.hidden = false;
  }

  function clearInputError() {
    hide("screenshotInputError");
  }

  function setLoading(isLoading) {
    const button = $("analyzeScreenshotButton");

    if (!button) {
      return;
    }

    button.disabled = isLoading;

    if (isLoading) {
      button.dataset.originalText = button.textContent;

      button.textContent = "Analyzing...";

      button.setAttribute("aria-busy", "true");
    } else {
      button.textContent = button.dataset.originalText || "Analyze Screenshot";

      button.removeAttribute("aria-busy");
    }
  }

  /* =================================================
       CHARACTER COUNTER
    ================================================= */

  function updateCharacterCount() {
    const textarea = $("screenshotEvidence");
    const counter = $("screenshotCharacterCount");

    if (!textarea || !counter) {
      return;
    }

    const length = textarea.value.length;

    counter.textContent = `${length.toLocaleString()} / ${CONFIG.maxLength.toLocaleString()}`;

    counter.style.color = length > CONFIG.maxLength ? "var(--danger)" : "";
  }

  /* =================================================
       TESSERACT LOADER
    ================================================= */

  function loadTesseract() {
    return new Promise((resolve, reject) => {
      if (window.Tesseract) {
        resolve(window.Tesseract);
        return;
      }

      const existingScript = document.querySelector(
        'script[data-scamshield-tesseract="true"]',
      );

      if (existingScript) {
        existingScript.addEventListener(
          "load",
          () => {
            if (window.Tesseract) {
              resolve(window.Tesseract);
            } else {
              reject(new Error("OCR library could not initialize."));
            }
          },
          { once: true },
        );

        existingScript.addEventListener(
          "error",
          () => {
            reject(new Error("Unable to load the OCR library."));
          },
          { once: true },
        );

        return;
      }

      const script = document.createElement("script");

      script.src = CONFIG.tesseractCDN;

      script.async = true;

      script.dataset.scamshieldTesseract = "true";

      script.onload = () => {
        if (window.Tesseract) {
          resolve(window.Tesseract);
        } else {
          reject(new Error("OCR library initialization failed."));
        }
      };

      script.onerror = () => {
        reject(
          new Error(
            "Could not download OCR library. Check your internet connection.",
          ),
        );
      };

      document.head.appendChild(script);
    });
  }

  /* =================================================
       FILE VALIDATION
    ================================================= */

  function validateImage(file) {
    if (!file) {
      return {
        valid: false,
        message: "Please select a screenshot image.",
      };
    }

    if (!CONFIG.allowedTypes.includes(file.type)) {
      return {
        valid: false,
        message: "Unsupported image format. Please use JPG, PNG or WEBP.",
      };
    }

    if (file.size > CONFIG.maxFileSize) {
      return {
        valid: false,
        message: "Image size must not exceed 8 MB.",
      };
    }

    if (file.size === 0) {
      return {
        valid: false,
        message: "The selected image is empty.",
      };
    }

    return {
      valid: true,
    };
  }

  /* =================================================
       IMAGE PREVIEW
    ================================================= */

  function displayImagePreview(file) {
    const previewImage = $("screenshotPreviewImage");
    const fileName = $("screenshotFileName");

    if (!previewImage) {
      return;
    }

    if (state.previewUrl) {
      URL.revokeObjectURL(state.previewUrl);
    }

    state.previewUrl = URL.createObjectURL(file);

    previewImage.src = state.previewUrl;

    previewImage.alt = "Selected screenshot preview";

    if (fileName) {
      fileName.textContent = file.name;
    }

    show("screenshotImagePreview");

    show("screenshotRemoveImage");
  }

  function removeImage() {
    if (state.previewUrl) {
      URL.revokeObjectURL(state.previewUrl);

      state.previewUrl = null;
    }

    state.selectedFile = null;

    state.ocrCompleted = false;

    const input = $("screenshotImageInput");

    if (input) {
      input.value = "";
    }

    const previewImage = $("screenshotPreviewImage");

    if (previewImage) {
      previewImage.removeAttribute("src");
    }

    hide("screenshotImagePreview");

    hide("screenshotRemoveImage");

    hide("screenshotOcrProgress");

    setText("screenshotFileName", "");

    setText("screenshotOcrProgressText", "");

    const textarea = $("screenshotEvidence");

    if (textarea && textarea.dataset.ocrGenerated === "true") {
      textarea.value = "";

      delete textarea.dataset.ocrGenerated;

      updateCharacterCount();
    }

    setStatus(
      "Screenshot Removed",
      "The selected screenshot has been removed.",
      true,
    );
  }

  /* =================================================
       OCR LANGUAGE
    ================================================= */

  function getOCRLanguage() {
    const selector = $("screenshotOcrLanguage");

    const language = selector?.value || "eng";

    return language === "eng+hin" ? "eng+hin" : "eng";
  }

  /* =================================================
       OCR PROGRESS
    ================================================= */

  function updateOCRProgress(progress, status) {
    const percentage = Math.min(
      100,
      Math.max(0, Math.round((progress || 0) * 100)),
    );

    const progressBar = $("screenshotOcrProgressBar");

    if (progressBar) {
      progressBar.style.width = `${percentage}%`;

      progressBar.setAttribute("aria-valuenow", String(percentage));
    }

    let message = "Preparing OCR...";

    if (status === "loading tesseract core") {
      message = "Loading OCR engine...";
    } else if (status === "initializing tesseract") {
      message = "Initializing OCR...";
    } else if (status === "loading language traineddata") {
      message = "Downloading language data...";
    } else if (status === "recognizing text") {
      message = `Extracting text... ${percentage}%`;
    }

    setText("screenshotOcrProgressText", message);

    show("screenshotOcrProgress");
  }

  /* =================================================
       OCR PROCESSING
    ================================================= */

  async function extractTextFromImage(file) {
    if (state.ocrRunning) {
      return;
    }

    state.ocrRunning = true;

    const textarea = $("screenshotEvidence");

    const ocrButton = $("screenshotExtractTextButton");

    if (ocrButton) {
      ocrButton.disabled = true;
      ocrButton.textContent = "Extracting Text...";
    }

    setStatus(
      "Extracting Screenshot Text",
      "OCR is processing your image locally in the browser.",
    );

    try {
      const Tesseract = await loadTesseract();

      const language = getOCRLanguage();

      updateOCRProgress(0, "initializing tesseract");

      const result = await Tesseract.recognize(file, language, {
        logger: (info) => {
          updateOCRProgress(info.progress, info.status);
        },
      });

      const extractedText = normalizeText(result?.data?.text);

      if (!extractedText || extractedText.length < 2) {
        throw new Error(
          "No readable text was detected. Try a clearer screenshot or paste the text manually.",
        );
      }

      if (extractedText.length > CONFIG.maxLength) {
        throw new Error(
          "Extracted text exceeds the 20,000 character limit. Please use a smaller screenshot.",
        );
      }

      if (!textarea) {
        throw new Error("Screenshot text input was not found.");
      }

      textarea.value = extractedText;

      textarea.dataset.ocrGenerated = "true";

      state.ocrCompleted = true;

      updateCharacterCount();

      setText(
        "screenshotOcrProgressText",
        "Text extraction completed. Please review the extracted text.",
      );

      const progressBar = $("screenshotOcrProgressBar");

      if (progressBar) {
        progressBar.style.width = "100%";
        progressBar.setAttribute("aria-valuenow", "100");
      }

      setStatus(
        "Text Extraction Completed",
        "Review and correct the extracted text before starting fraud analysis.",
      );

      textarea.scrollIntoView({
        behavior: "smooth",
        block: "center",
      });
    } catch (error) {
      console.error("Screenshot OCR Error:", error);

      state.ocrCompleted = false;

      setStatus(
        "OCR Extraction Failed",
        normalizeText(error.message) ||
          "Unable to extract text from this image.",
      );
    } finally {
      state.ocrRunning = false;

      if (ocrButton) {
        ocrButton.disabled = false;
        ocrButton.textContent = "Extract Text";
      }
    }
  }

  /* =================================================
       IMAGE SELECTION
    ================================================= */

  function handleImageSelection(file) {
    clearInputError();

    const validation = validateImage(file);

    if (!validation.valid) {
      showInputError(validation.message);

      return;
    }

    state.selectedFile = file;

    state.ocrCompleted = false;

    displayImagePreview(file);

    const textarea = $("screenshotEvidence");

    if (textarea && textarea.dataset.ocrGenerated === "true") {
      textarea.value = "";

      delete textarea.dataset.ocrGenerated;

      updateCharacterCount();
    }

    setStatus(
      "Screenshot Selected",
      "Image preview is ready. Select Extract Text to run OCR.",
    );

    /*
     * OCR is intentionally not started automatically.
     * The user starts extraction explicitly.
     */
  }

  /* =================================================
       INPUT VALIDATION
    ================================================= */

  function validateInput() {
    const source = $("screenshotSource")?.value || "";

    const category = $("screenshotFraudCategory")?.value || "";

    const evidence = $("screenshotEvidence")?.value.trim() || "";

    const consent = $("screenshotAnalysisConsent");

    if (!source) {
      return {
        valid: false,
        message: "Please select the screenshot source.",
      };
    }

    if (!evidence) {
      return {
        valid: false,
        message: "Please upload a screenshot or paste its extracted text.",
      };
    }

    if (evidence.length < 10) {
      return {
        valid: false,
        message: "Please provide more screenshot text for meaningful analysis.",
      };
    }

    if (evidence.length > CONFIG.maxLength) {
      return {
        valid: false,
        message: `Maximum ${CONFIG.maxLength} characters are allowed.`,
      };
    }

    if (!consent || !consent.checked) {
      return {
        valid: false,
        message:
          "Please confirm the security and privacy notice before analysis.",
      };
    }

    const sensitivePatterns = [
      /\b\d{4,8}\b.*\b(?:otp|one time password)\b/i,
      /\b(?:password|passcode)\s*[:=]\s*\S+/i,
      /\b(?:cvv|cvc)\s*[:=]\s*\d{3,4}\b/i,
      /\b(?:pin|upi pin)\s*[:=]\s*\d{4,6}\b/i,
    ];

    if (sensitivePatterns.some((pattern) => pattern.test(evidence))) {
      return {
        valid: false,
        message:
          "Your text may contain an OTP, PIN, CVV or password. Remove sensitive information before submitting.",
      };
    }

    return {
      valid: true,
      source,
      category,
      evidence,
    };
  }

  /* =================================================
       CATEGORY FORMATTING
    ================================================= */

  function formatCategory(category) {
    if (!category) {
      return "Unclassified";
    }

    const labels = {
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
      unclassified: "Unclassified",
    };

    return (
      labels[category] ||
      String(category)
        .replace(/[_-]/g, " ")
        .replace(/\b\w/g, (char) => char.toUpperCase())
    );
  }

  function getRiskClass(level) {
    const normalized = String(level || "").toLowerCase();

    if (normalized.includes("critical")) return "critical";

    if (normalized.includes("high")) return "high";

    if (normalized.includes("medium") || normalized.includes("elevated")) {
      return "medium";
    }

    if (normalized.includes("low")) return "low";

    return "medium";
  }

  /* =================================================
       RISK OVERVIEW
    ================================================= */

  function renderRiskOverview(data) {
    const score = Math.min(100, Math.max(0, Number(data.riskScore) || 0));

    const riskClass = getRiskClass(data.riskLevel);

    const circle = $("screenshotRiskScoreCircle");

    if (circle) {
      circle.style.setProperty("--risk-progress", `${score * 3.6}deg`);

      circle.classList.remove("low", "medium", "high", "critical");

      circle.classList.add(riskClass);

      circle.setAttribute("aria-label", `Risk score ${score} out of 100`);
    }

    setText("screenshotRiskScore", score);

    const level = $("screenshotRiskLevel");

    if (level) {
      level.textContent = String(data.riskLevel || "UNKNOWN").toUpperCase();

      level.classList.remove("low", "medium", "high", "critical");

      level.classList.add(riskClass);
    }

    setText(
      "screenshotRiskDescription",
      normalizeText(data.description) || "No description available.",
    );

    setText("screenshotFraudCategoryResult", formatCategory(data.category));

    setText(
      "screenshotRiskExplanation",
      normalizeText(data.explanation) || "No additional explanation provided.",
    );
  }

  /* =================================================
       SAFE DOM HELPERS
    ================================================= */

  function clearElement(element) {
    if (element) {
      element.replaceChildren();
    }
  }

  function appendTextItem(container, text, icon = "fa-circle") {
    if (!container || !text) {
      return;
    }

    const item = document.createElement("li");

    const iconElement = document.createElement("i");

    iconElement.className = `fas ${icon}`;

    const textElement = document.createElement("span");

    textElement.textContent = String(text);

    item.append(iconElement, textElement);

    container.appendChild(item);
  }

  function renderList(container, values, emptyMessage) {
    clearElement(container);

    if (!container) {
      return;
    }

    const list = Array.isArray(values)
      ? values
      : typeof values === "string"
        ? [values]
        : [];

    if (!list.length) {
      const empty = document.createElement("p");

      empty.textContent = emptyMessage;

      container.appendChild(empty);

      return;
    }

    const ul = document.createElement("ul");

    list.forEach((item) => {
      let text = "";

      if (typeof item === "string") {
        text = item;
      } else if (isObject(item)) {
        text =
          getFirst(
            item.message,
            item.description,
            item.action,
            item.recommendation,
            item.value,
            item.name,
          ) || JSON.stringify(item);
      }

      if (text) {
        appendTextItem(ul, text);
      }
    });

    container.appendChild(ul);
  }

  /* =================================================
       AGENT STATUS
    ================================================= */

  function updateAgentStatus(id, status) {
    const element = $(id);

    if (!element) {
      return;
    }

    const normalized = String(status || "unknown").toLowerCase();

    const labels = {
      completed: "Completed",
      success: "Completed",
      successful: "Completed",
      failed: "Failed",
      error: "Error",
      unavailable: "Unavailable",
      not_started: "Not Started",
      skipped: "Skipped",
      pending: "Pending",
      running: "Running",
    };

    element.textContent = labels[normalized] || "Status Unknown";

    element.dataset.status = normalized;
  }

  function inferAgentStatus(agent, fallback = "unknown") {
    if (!isObject(agent)) {
      return fallback;
    }

    return getFirst(
      agent.status,
      agent.execution_status,
      agent.executionStatus,
      agent.success === true ? "completed" : null,
      agent.available === false ? "unavailable" : null,
      fallback,
    );
  }

  /* =================================================
       GUARDIAN AGENT
    ================================================= */

  function renderGuardian(data) {
    const agent = data.guardianAgent;

    const analysis = data.guardianAnalysis;

    updateAgentStatus(
      "screenshotGuardianStatus",
      inferAgentStatus(
        agent,
        Object.keys(analysis).length ? "completed" : "unknown",
      ),
    );

    const container = $("screenshotGuardianResult");

    if (!container) return;

    clearElement(container);

    const category = getFirst(
      analysis.fraud_category,
      analysis.fraudCategory,
      data.category,
    );

    const score = getFirst(
      analysis.risk_score,
      analysis.riskScore,
      data.riskScore,
    );

    const level = getFirst(
      analysis.risk_level,
      analysis.riskLevel,
      data.riskLevel,
    );

    const summary = getFirst(analysis.summary, analysis.explanation);

    [
      `Detection Category: ${formatCategory(category)}`,
      `Risk Score: ${score}/100`,
      `Risk Level: ${level}`,
    ].forEach((text) => {
      const p = document.createElement("p");

      p.textContent = text;

      container.appendChild(p);
    });

    if (summary) {
      const p = document.createElement("p");

      p.textContent = String(summary);

      container.appendChild(p);
    }

    const rules = getFirst(
      analysis.detected_rules,
      analysis.detectedRules,
      analysis.signals,
      [],
    );

    if (Array.isArray(rules) && rules.length) {
      const heading = document.createElement("p");

      heading.textContent = "Detected Signals:";

      container.appendChild(heading);

      const list = document.createElement("ul");

      rules.forEach((rule) => {
        const text =
          typeof rule === "string"
            ? rule
            : getFirst(rule.name, rule.description, rule.rule, rule.message);

        if (text) appendTextItem(list, text);
      });

      container.appendChild(list);
    }
  }

  /* =================================================
       INTELLIGENCE AGENT
    ================================================= */

  function collectIndicators(indicators) {
    const output = [];

    if (!isObject(indicators)) {
      return output;
    }

    const groups = [
      ["URLs", indicators.urls],
      ["Phone Numbers", indicators.phone_numbers || indicators.phoneNumbers],
      ["Emails", indicators.emails],
      ["UPI IDs", indicators.upi_ids || indicators.upiIds],
      [
        "Suspicious Keywords",
        indicators.suspicious_keywords || indicators.suspiciousKeywords,
      ],
    ];

    groups.forEach(([label, values]) => {
      if (!Array.isArray(values)) return;

      values.forEach((value) => {
        const text =
          typeof value === "string"
            ? value
            : getFirst(
                value.value,
                value.url,
                value.number,
                value.email,
                value.upi_id,
                value.keyword,
              );

        if (text) output.push({ label, value: text });
      });
    });

    return output;
  }

  function renderIntelligence(data) {
    const agent = data.intelligenceAgent;

    updateAgentStatus(
      "screenshotIntelligenceStatus",
      inferAgentStatus(
        agent,
        Object.keys(data.indicators).length ? "completed" : "unknown",
      ),
    );

    const container = $("screenshotIntelligenceResult");

    if (!container) return;

    clearElement(container);

    const summary = data.intelligenceSummary;

    const summaryMessage = getFirst(summary?.message, data.indicators.summary);

    if (summaryMessage) {
      const p = document.createElement("p");

      p.textContent = String(summaryMessage);

      container.appendChild(p);
    }

    const counts = data.indicatorCounts;

    if (isObject(counts) && Object.keys(counts).length) {
      const heading = document.createElement("p");

      heading.textContent = "Indicator Counts:";

      container.appendChild(heading);

      const list = document.createElement("ul");

      Object.entries(counts).forEach(([key, value]) => {
        appendTextItem(
          list,
          `${formatCategory(key)}: ${value}`,
          "fa-chart-bar",
        );
      });

      container.appendChild(list);
    }

    const indicatorContainer = $("screenshotIndicators");

    clearElement(indicatorContainer);

    const indicators = collectIndicators(data.indicators);

    if (indicatorContainer) {
      if (!indicators.length) {
        const empty = document.createElement("p");

        empty.textContent = "No additional indicators were extracted.";

        indicatorContainer.appendChild(empty);
      } else {
        indicators.forEach((indicator) => {
          const item = document.createElement("span");

          item.className = "indicator-item unverified";

          const icon = document.createElement("i");

          icon.className = "fas fa-exclamation-circle";

          const text = document.createElement("span");

          text.textContent = `${indicator.label}: ${indicator.value}`;

          item.append(icon, text);

          indicatorContainer.appendChild(item);
        });
      }
    }

    const verification = getFirst(
      agent.verification,
      data.indicators.verification,
      {},
    );

    if (isObject(verification) && verification.status) {
      const p = document.createElement("p");

      p.textContent = `Verification: ${verification.status}. Extracted indicators are not necessarily confirmed malicious.`;

      container.appendChild(p);
    }
  }

  /* =================================================
       VICTIM SAFETY AGENT
    ================================================= */

  function renderVictimSafety(data) {
    const agent = data.victimSafetyAgent;

    const safety = data.safetyAssessment;

    updateAgentStatus(
      "screenshotVictimSafetyStatus",
      inferAgentStatus(
        agent,
        Object.keys(safety).length ? "completed" : "unknown",
      ),
    );

    const container = $("screenshotVictimSafetyResult");

    if (!container) return;

    clearElement(container);

    const safetyLevel = getFirst(
      safety.safety_level,
      safety.safetyLevel,
      agent.safety_level,
      agent.safetyLevel,
    );

    const compromised = getFirst(
      safety.potentially_compromised,
      safety.potentiallyCompromised,
    );

    const sensitiveRequest = getFirst(
      safety.sensitive_request_detected,
      safety.sensitiveRequestDetected,
    );

    const facts = [];

    if (safetyLevel) {
      facts.push(`Safety Assessment: ${safetyLevel}`);
    }

    if (compromised !== null) {
      facts.push(`Potentially Compromised: ${compromised ? "Yes" : "No"}`);
    }

    if (sensitiveRequest !== null) {
      facts.push(
        `Sensitive Information Request: ${sensitiveRequest ? "Detected" : "Not Detected"}`,
      );
    }

    facts.forEach((text) => {
      const p = document.createElement("p");

      p.textContent = text;

      container.appendChild(p);
    });

    const actions = [
      agent.immediate_actions,
      agent.immediateActions,
      safety.immediate_actions,
      safety.immediateActions,
      agent.precautionary_actions,
      agent.precautionaryActions,
      safety.precautionary_actions,
      safety.precautionaryActions,
      agent.recommended_actions,
      agent.recommendedActions,
      safety.recommended_actions,
      safety.recommendedActions,
      data.recommendations,
    ];

    const allActions = [];

    actions.forEach((group) => {
      if (Array.isArray(group)) {
        allActions.push(...group);
      }
    });

    const uniqueActions = [
      ...new Set(
        allActions
          .map((action) => {
            if (typeof action === "string") {
              return action;
            }

            if (isObject(action)) {
              return getFirst(
                action.action,
                action.description,
                action.message,
                action.recommendation,
              );
            }

            return null;
          })
          .filter(Boolean),
      ),
    ];

    if (uniqueActions.length) {
      const heading = document.createElement("p");

      heading.textContent = "Recommended Safety Actions:";

      container.appendChild(heading);

      const list = document.createElement("ul");

      uniqueActions.forEach((action) => {
        appendTextItem(list, action, "fa-shield-alt");
      });

      container.appendChild(list);
    }

    const emergency = getFirst(
      agent.emergency_guidance,
      agent.emergencyGuidance,
      safety.emergency_guidance,
      safety.emergencyGuidance,
    );

    if (emergency) {
      const p = document.createElement("p");

      p.textContent =
        typeof emergency === "string" ? emergency : JSON.stringify(emergency);

      container.appendChild(p);
    }

    const notice = getFirst(
      agent.important_notice,
      agent.importantNotice,
      safety.important_notice,
      safety.importantNotice,
    );

    if (notice) {
      const p = document.createElement("p");

      p.textContent = String(notice);

      container.appendChild(p);
    }

    if (!container.children.length) {
      const empty = document.createElement("p");

      empty.textContent =
        "Victim Safety Agent did not return additional guidance.";

      container.appendChild(empty);
    }
  }

  /* =================================================
       GEMINI ADVISORY
    ================================================= */

  function renderGemini(data) {
    const gemini = data.gemini;

    const status = getFirst(
      gemini.status,
      gemini.availability,
      gemini.available === false ? "unavailable" : null,
      gemini.success === true ? "completed" : null,
      "unknown",
    );

    updateAgentStatus("screenshotGeminiStatus", status);

    const container = $("screenshotGeminiResult");

    if (!container) return;

    clearElement(container);

    const fields = [
      ["Explanation", gemini.explanation],
      ["Summary", gemini.summary],
      ["Scam Intent", gemini.scam_intent || gemini.scamIntent],
      ["Safety Notes", gemini.safety_notes || gemini.safetyNotes],
      [
        "Social Engineering Tactics",
        gemini.social_engineering_tactics || gemini.socialEngineeringTactics,
      ],
      [
        "Supporting Evidence",
        gemini.supporting_evidence || gemini.supportingEvidence,
      ],
      [
        "Alternative Interpretations",
        gemini.alternative_interpretations || gemini.alternativeInterpretations,
      ],
      [
        "Advisory Confidence",
        gemini.advisory_confidence || gemini.advisoryConfidence,
      ],
    ];

    fields.forEach(([label, value]) => {
      if (value === null || value === undefined || value === "") {
        return;
      }

      const section = document.createElement("div");

      section.className = "gemini-detail";

      const heading = document.createElement("strong");

      heading.textContent = `${label}:`;

      const content = document.createElement("p");

      content.textContent = Array.isArray(value)
        ? value.join(", ")
        : typeof value === "object"
          ? JSON.stringify(value)
          : String(value);

      section.append(heading, content);

      container.appendChild(section);
    });

    if (!container.children.length) {
      const message = document.createElement("p");

      message.textContent =
        status === "unavailable"
          ? "Gemini advisory is currently unavailable. Guardian's primary analysis remains unchanged."
          : "No additional Gemini advisory was returned.";

      container.appendChild(message);
    }

    const disclaimer = document.createElement("p");

    disclaimer.className = "advisory-disclaimer";

    disclaimer.textContent =
      "Gemini provides advisory information only. Guardian remains authoritative for the final fraud category and risk score.";

    container.appendChild(disclaimer);
  }

  /* =================================================
       DECOY AGENT
    ================================================= */

  function renderDecoy(data) {
    const agent = data.decoyAgent;

    const status = inferAgentStatus(agent, "not_started");

    updateAgentStatus("screenshotDecoyStatus", status);

    const container = $("screenshotDecoyResult");

    if (!container) return;

    clearElement(container);

    const message = document.createElement("p");

    if (
      status === "not_started" ||
      status === "skipped" ||
      status === "unknown"
    ) {
      message.textContent =
        "Decoy Agent was not started during this analysis. This is expected. Decoy simulations require a separate controlled action.";
    } else {
      message.textContent = getFirst(
        agent.message,
        agent.summary,
        agent.description,
        "Decoy Agent status received.",
      );
    }

    container.appendChild(message);
  }

  /* =================================================
       COMPLETE RESULT RENDERING
    ================================================= */

  function renderResults(rawResponse) {
    const data = normalizeAnalysis(rawResponse);

    renderRiskOverview(data);

    renderGuardian(data);

    renderIntelligence(data);

    renderVictimSafety(data);

    renderGemini(data);

    renderDecoy(data);

    setText("screenshotResultStatus", "Analysis Completed");

    show("screenshotResults");

    hide("screenshotAnalysisStatus");

    const results = $("screenshotResults");

    if (results) {
      results.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }

    return data;
  }

  /* =================================================
       BACKEND API REQUEST
    ================================================= */

  async function analyzeScreenshot() {
    if (state.analysisRunning || state.ocrRunning) {
      return;
    }

    clearInputError();

    const validation = validateInput();

    if (!validation.valid) {
      showInputError(validation.message);

      return;
    }

    if (
      !window.ScamShieldAPI ||
      typeof window.ScamShieldAPI.post !== "function"
    ) {
      setStatus(
        "API Service Unavailable",
        "ScamShield API service is not initialized. Please refresh the page and try again.",
      );

      return;
    }

    const evidence = [
      "Evidence Type: Screenshot",
      `Screenshot Source: ${validation.source}`,
      validation.category
        ? `User Suggested Category: ${formatCategory(validation.category)}`
        : "",
      state.selectedFile ? `Screenshot File: ${state.selectedFile.name}` : "",
      state.ocrCompleted
        ? "Text Extraction: Browser-based OCR"
        : "Text Extraction: User-provided text",
      "",
      "Extracted Screenshot Text:",
      validation.evidence,
    ]
      .filter(Boolean)
      .join("\n");

    const payload = {
      evidenceType: CONFIG.evidenceType,
      evidence,
    };

    state.analysisRunning = true;

    setLoading(true);

    hide("screenshotResults");

    setStatus(
      "Analyzing Screenshot",
      "Guardian, Intelligence and Victim Safety agents are processing the extracted text.",
    );

    try {
      const response = await window.ScamShieldAPI.post(
        CONFIG.endpoint,
        payload,
        {
          timeout: CONFIG.requestTimeout,
        },
      );

      if (!response) {
        throw new Error("The server returned an empty response.");
      }

      if (response.success === false) {
        throw new Error(
          response.message || response.error || "Screenshot analysis failed.",
        );
      }

      const result = unwrapResponse(response);

      if (!isObject(result)) {
        throw new Error("Invalid analysis response received from server.");
      }

      const hasAnalysis =
        result.riskScore !== undefined ||
        result.risk_score !== undefined ||
        result.agents !== undefined ||
        result.agent_results !== undefined ||
        result.detectionCategory !== undefined ||
        result.detection_category !== undefined;

      if (!hasAnalysis) {
        throw new Error(
          "The server response does not contain a valid analysis result.",
        );
      }

      renderResults(result);

      setStatus(
        "Analysis Completed",
        "Your screenshot text has been analyzed successfully.",
      );

      setTimeout(() => {
        hide("screenshotAnalysisStatus");
      }, 3500);

      console.info(
        `ScamShield Screenshot Analysis v${CONFIG.version}: Completed`,
      );
    } catch (error) {
      console.error("Screenshot Analysis Error:", error);

      setStatus(
        "Analysis Failed",
        normalizeText(error.message) ||
          "Unable to analyze screenshot text. Please try again.",
      );
    } finally {
      state.analysisRunning = false;

      setLoading(false);
    }
  }

  /* =================================================
       CLEAR FORM
    ================================================= */

  function clearForm() {
    const form = $("screenshotAnalysisForm");

    if (form) {
      form.reset();
    }

    removeImage();

    const textarea = $("screenshotEvidence");

    if (textarea) {
      textarea.value = "";
      delete textarea.dataset.ocrGenerated;
    }

    state.ocrCompleted = false;

    updateCharacterCount();

    clearInputError();

    hide("screenshotResults");

    hide("screenshotAnalysisStatus");

    hide("screenshotOcrProgress");

    setLoading(false);
  }

  /* =================================================
       FEEDBACK
    ================================================= */

  function handleFeedback(button, feedbackType) {
    if (!button) return;

    const buttons = [
      $("screenshotFeedbackHelpful"),
      $("screenshotFeedbackReview"),
    ].filter(Boolean);

    buttons.forEach((item) => {
      item.classList.remove("active");

      item.setAttribute("aria-pressed", "false");
    });

    button.classList.add("active");

    button.setAttribute("aria-pressed", "true");

    setText(
      "screenshotFeedbackStatus",
      feedbackType === "helpful"
        ? "Thank you! Your feedback has been recorded in this page session."
        : "Thank you! Your review feedback has been recorded in this page session.",
    );

    // UI-only feedback. No backend feedback API assumed.
  }

  /* =================================================
       MOBILE NAVIGATION
    ================================================= */

  function initializeNavigation() {
    const toggle = document.querySelector(".mobile-menu-toggle");

    const navigation = document.querySelector(".primary-navigation");

    if (!toggle || !navigation) return;

    toggle.addEventListener("click", () => {
      const isOpen = navigation.classList.toggle("open");

      toggle.setAttribute("aria-expanded", String(isOpen));
    });

    navigation.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        navigation.classList.remove("open");

        toggle.setAttribute("aria-expanded", "false");
      });
    });
  }

  /* =================================================
       UPLOAD EVENT LISTENERS
    ================================================= */

  function initializeUpload() {
    const input = $("screenshotImageInput");

    const zone = $("screenshotUploadZone");

    const removeButton = $("screenshotRemoveImage");

    const extractButton = $("screenshotExtractTextButton");

    if (input) {
      input.addEventListener("change", (event) => {
        const file = event.target.files?.[0];

        if (file) {
          handleImageSelection(file);
        }
      });
    }

    if (zone) {
      zone.addEventListener("click", (event) => {
        if (
          event.target.closest("#screenshotRemoveImage") ||
          event.target.closest("#screenshotExtractTextButton")
        ) {
          return;
        }

        input?.click();
      });

      zone.addEventListener("dragover", (event) => {
        event.preventDefault();

        zone.classList.add("drag-over");
      });

      zone.addEventListener("dragleave", (event) => {
        event.preventDefault();

        if (!zone.contains(event.relatedTarget)) {
          zone.classList.remove("drag-over");
        }
      });

      zone.addEventListener("drop", (event) => {
        event.preventDefault();

        zone.classList.remove("drag-over");

        const file = event.dataTransfer?.files?.[0];

        if (file) {
          handleImageSelection(file);
        }
      });

      zone.addEventListener("keydown", (event) => {
        if (
          event.target === zone &&
          (event.key === "Enter" || event.key === " ")
        ) {
          event.preventDefault();

          input?.click();
        }
      });
    }

    if (removeButton) {
      removeButton.addEventListener("click", (event) => {
        event.preventDefault();

        event.stopPropagation();

        removeImage();
      });
    }

    if (extractButton) {
      extractButton.addEventListener("click", (event) => {
        event.preventDefault();

        event.stopPropagation();

        if (!state.selectedFile) {
          showInputError("Please select a screenshot image first.");

          return;
        }

        extractTextFromImage(state.selectedFile);
      });
    }
  }

  /* =================================================
       EVENT LISTENERS
    ================================================= */

  function initializeEvents() {
    const form = $("screenshotAnalysisForm");

    const textarea = $("screenshotEvidence");

    const clearButton = $("clearScreenshotForm");

    const helpfulButton = $("screenshotFeedbackHelpful");

    const reviewButton = $("screenshotFeedbackReview");

    if (form) {
      form.addEventListener("submit", (event) => {
        event.preventDefault();

        analyzeScreenshot();
      });
    }

    if (textarea) {
      textarea.addEventListener("input", () => {
        updateCharacterCount();

        clearInputError();
      });
    }

    if (clearButton) {
      clearButton.addEventListener("click", clearForm);
    }

    if (helpfulButton) {
      helpfulButton.addEventListener("click", () => {
        handleFeedback(helpfulButton, "helpful");
      });
    }

    if (reviewButton) {
      reviewButton.addEventListener("click", () => {
        handleFeedback(reviewButton, "review");
      });
    }
  }

  /* =================================================
       INITIALIZATION
    ================================================= */

  function init() {
    initializeEvents();

    initializeUpload();

    initializeNavigation();

    updateCharacterCount();

    hide("screenshotResults");

    hide("screenshotAnalysisStatus");

    hide("screenshotImagePreview");

    hide("screenshotRemoveImage");

    hide("screenshotOcrProgress");

    clearInputError();

    console.info(
      `ScamShield Screenshot Analysis v${CONFIG.version} initialized successfully.`,
    );
  }

  return {
    init,
    analyzeScreenshot,
    clearForm,
    validateInput,
    renderResults,
    handleImageSelection,
    extractTextFromImage,
    removeImage,
  };
})();

/* =====================================================
   START APPLICATION
===================================================== */

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", ScreenshotAnalysis.init);
} else {
  ScreenshotAnalysis.init();
}
