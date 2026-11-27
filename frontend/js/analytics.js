"use strict";

/* =====================================================
   SCAMSHIELD AI - ANALYTICS
   File: frontend/js/analytics.js
   Version: 3.2.0

   Backend:
   GET /api/dashboard/overview

   Backend response:
   data.statistics
   data.riskDistribution
   data.fraudCategories       (12 categories)
   data.fraudModules          (5 modules)
   data.unclassifiedCategories
   data.recentActivity

   No fabricated statistics.
   No demo data.
   No fabricated historical trends.
   No fabricated agent/Gemini statistics.
===================================================== */

(() => {
  const API_BASE_URL = (
    window.SCAMSHIELD_API_URL || "http://localhost:5000/api"
  ).replace(/\/+$/, "");

  const API_ENDPOINT = `${API_BASE_URL}/dashboard/overview`;

  const elements = {
    totalAnalyses: document.getElementById("analyticsTotalAnalyses"),
    threats: document.getElementById("analyticsThreats"),
    lowRisk: document.getElementById("analyticsLowRisk"),
    critical: document.getElementById("analyticsCritical"),

    notice: document.getElementById("analyticsNotice"),
    statusMessage: document.getElementById("analyticsStatusMessage"),

    riskChart: document.getElementById("riskDistributionChart"),
    categoryChart: document.getElementById("fraudCategoryChart"),
    trendChart: document.getElementById("threatTrendChart"),

    activityBody: document.getElementById("analyticsActivityBody"),

    investment: document.getElementById("investmentAnalyticsCount"),
    arrest: document.getElementById("arrestAnalyticsCount"),
    card: document.getElementById("cardAnalyticsCount"),
    sextortion: document.getElementById("sextortionAnalyticsCount"),
    ecommerce: document.getElementById("ecommerceAnalyticsCount"),

    refreshButton: document.getElementById("refreshAnalytics"),
    currentYear: document.getElementById("currentYear"),
  };

  const CATEGORY_CONFIG = [
    {
      key: "fraud_message",
      id: "categoryFraudMessage",
      label: "Fraud Messages",
    },
    { key: "fraud_call", id: "categoryFraudCall", label: "Fraud Calls" },
    { key: "url_phishing", id: "categoryUrlPhishing", label: "URL Phishing" },
    { key: "email_scam", id: "categoryEmailScam", label: "Email Scams" },
    {
      key: "investment_scam",
      id: "categoryInvestmentScam",
      label: "Investment Scams",
    },
    {
      key: "digital_arrest",
      id: "categoryDigitalArrest",
      label: "Digital Arrest",
    },
    {
      key: "upi_banking_fraud",
      id: "categoryUpiBankingFraud",
      label: "UPI / Banking Fraud",
    },
    { key: "card_fraud", id: "categoryCardFraud", label: "Card Fraud" },
    {
      key: "ecommerce_scam",
      id: "categoryEcommerceScam",
      label: "E-commerce Scams",
    },
    {
      key: "job_loan_scam",
      id: "categoryJobLoanScam",
      label: "Job / Loan Scams",
    },
    {
      key: "sextortion_blackmail",
      id: "categorySextortionBlackmail",
      label: "Sextortion / Blackmail",
    },
    {
      key: "social_media_scam",
      id: "categorySocialMediaScam",
      label: "Social Media Scams",
    },
  ];

  const MODULE_CONFIG = [
    {
      key: "investment",
      element: elements.investment,
      label: "Investment Scams",
    },
    { key: "digitalArrest", element: elements.arrest, label: "Digital Arrest" },
    { key: "creditCard", element: elements.card, label: "Credit Card Fraud" },
    { key: "sextortion", element: elements.sextortion, label: "Sextortion" },
    {
      key: "ecommerce",
      element: elements.ecommerce,
      label: "E-commerce Fraud",
    },
  ];

  const UNSUPPORTED_METRICS = [
    "inputMessagesCount",
    "inputCallsCount",
    "inputEmailsCount",
    "inputUrlsCount",
    "inputScreenshotsCount",
    "inputTransactionsCount",

    "guardianAgentExecutions",
    "intelligenceAgentExecutions",
    "victimSafetyAgentExecutions",
    "decoyAgentExecutions",

    "geminiAdvisoryRequests",
    "geminiAdvisorySuccess",
    "geminiAdvisoryFailures",
  ];

  let activeController = null;
  let hasLoadedData = false;

  /* =====================================================
     INITIALIZATION
  ===================================================== */

  function initAnalytics() {
    setCurrentYear();
    setInitialState();
    setUnsupportedMetrics();

    if (elements.refreshButton) {
      elements.refreshButton.addEventListener("click", loadAnalytics);
    }

    loadAnalytics();
  }

  /* =====================================================
     HELPERS
  ===================================================== */

  function setCurrentYear() {
    if (elements.currentYear) {
      elements.currentYear.textContent = new Date().getFullYear();
    }
  }

  function getToken() {
    return (
      localStorage.getItem("scamshieldToken") ||
      sessionStorage.getItem("scamshieldToken") ||
      ""
    );
  }

  function formatNumber(value) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
      return "--";
    }

    return new Intl.NumberFormat("en-IN").format(number);
  }

  function getValidNumber(value) {
    if (value === null || value === undefined || value === "") {
      return 0;
    }

    const number = Number(value);

    return Number.isFinite(number) && number >= 0 ? number : 0;
  }

  function safeText(value, fallback = "Unknown") {
    if (value === null || value === undefined || value === "") {
      return fallback;
    }

    return String(value);
  }

  function createElement(tag, className = "", text) {
    const element = document.createElement(tag);

    if (className) {
      element.className = className;
    }

    if (text !== undefined && text !== null) {
      element.textContent = String(text);
    }

    return element;
  }

  function clearElement(element) {
    if (element) {
      element.replaceChildren();
    }
  }

  function updateText(element, value) {
    if (!element) return;

    element.textContent =
      value === null || value === undefined ? "--" : formatNumber(value);
  }

  function setUnavailable(id) {
    const element = document.getElementById(id);

    if (!element) return;

    element.textContent = "--";

    element.title = "This metric is not currently provided by the backend.";
  }

  /* =====================================================
     UNSUPPORTED METRICS
  ===================================================== */

  function setUnsupportedMetrics() {
    UNSUPPORTED_METRICS.forEach(setUnavailable);

    const geminiStatus = document.getElementById("geminiAdvisoryStatus");

    if (geminiStatus) {
      geminiStatus.textContent = "Statistics unavailable";
      geminiStatus.dataset.status = "unavailable";
    }
  }

  /* =====================================================
     NOTICE
  ===================================================== */

  function showNotice(message, type = "info") {
    if (!elements.notice) return;

    if (elements.statusMessage) {
      elements.statusMessage.textContent = message;
    }

    elements.notice.dataset.state = type;
  }

  /* =====================================================
     INITIAL STATE
  ===================================================== */

  function setInitialState() {
    const statistics = [
      elements.totalAnalyses,
      elements.threats,
      elements.lowRisk,
      elements.critical,
      elements.investment,
      elements.arrest,
      elements.card,
      elements.sextortion,
      elements.ecommerce,
    ];

    statistics.forEach((element) => {
      if (element) {
        element.textContent = "--";
      }
    });

    CATEGORY_CONFIG.forEach((category) => {
      setUnavailable(category.id);
    });

    if (elements.activityBody) {
      clearElement(elements.activityBody);
    }
  }

  /* =====================================================
     LOADING STATE
  ===================================================== */

  function setLoadingState(isLoading) {
    const button = elements.refreshButton;

    if (!button) return;

    button.disabled = isLoading;

    button.setAttribute("aria-busy", String(isLoading));

    const icon = button.querySelector("i");

    if (icon) {
      icon.classList.toggle("fa-spin", isLoading);
    }

    const textNode = Array.from(button.childNodes).find(
      (node) => node.nodeType === Node.TEXT_NODE,
    );

    if (textNode) {
      textNode.textContent = isLoading ? " Loading..." : " Refresh";
    }
  }

  /* =====================================================
     AUTHENTICATION
  ===================================================== */

  function handleUnauthorized() {
    localStorage.removeItem("scamshieldToken");
    localStorage.removeItem("scamshieldUser");

    sessionStorage.removeItem("scamshieldToken");
    sessionStorage.removeItem("scamshieldUser");

    showNotice("Your session has expired. Please log in again.", "error");

    window.setTimeout(() => {
      window.location.href = "login.html";
    }, 1200);
  }

  /* =====================================================
     API REQUEST
  ===================================================== */

  async function loadAnalytics() {
    if (activeController) {
      activeController.abort();
    }

    const controller = new AbortController();

    activeController = controller;

    setLoadingState(true);

    showNotice("Loading analytics from the server...", "loading");

    try {
      const token = getToken();

      if (!token) {
        showNotice("Please log in to access your security analytics.", "error");

        window.setTimeout(() => {
          if (activeController === controller) {
            window.location.href = "login.html";
          }
        }, 1200);

        return;
      }

      const response = await fetch(API_ENDPOINT, {
        method: "GET",
        cache: "no-store",

        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          "Cache-Control": "no-cache",
          Pragma: "no-cache",
        },

        signal: controller.signal,
      });

      if (response.status === 401) {
        handleUnauthorized();
        return;
      }

      if (response.status === 403) {
        throw new Error(
          "You do not have permission to access this analytics data.",
        );
      }

      let result;

      try {
        result = await response.json();
      } catch {
        throw new Error(
          `Server returned an invalid JSON response (HTTP ${response.status}).`,
        );
      }

      if (!response.ok) {
        throw new Error(
          result.message || `Analytics request failed (${response.status}).`,
        );
      }

      if (result.success !== true) {
        throw new Error(
          result.message || "Analytics data could not be retrieved.",
        );
      }

      const analyticsData = result.data;

      if (
        !analyticsData ||
        typeof analyticsData !== "object" ||
        Array.isArray(analyticsData)
      ) {
        throw new Error("The analytics response has an invalid structure.");
      }

      renderAnalytics(analyticsData);

      hasLoadedData = true;

      showNotice("Analytics successfully updated from the backend.", "success");
    } catch (error) {
      if (error.name === "AbortError") {
        return;
      }

      console.error("[ScamShield Analytics]", error);

      if (!hasLoadedData) {
        renderEmptyStates();
      }

      showNotice(
        error.message || "Analytics service is unavailable. Please try again.",
        "error",
      );
    } finally {
      if (activeController === controller) {
        activeController = null;
        setLoadingState(false);
      }
    }
  }

  /* =====================================================
     MAIN RENDERER
  ===================================================== */

  function renderAnalytics(data) {
    const statistics = data.statistics || {};

    const riskDistribution = data.riskDistribution || {};

    const fraudCategories = data.fraudCategories || {};

    const fraudModules = data.fraudModules || {};

    const threatTrends = Array.isArray(data.threatTrends)
      ? data.threatTrends
      : [];

    const recentActivity = Array.isArray(data.recentActivity)
      ? data.recentActivity
      : [];

    renderStatistics(statistics, riskDistribution);

    renderRiskDistribution(riskDistribution);

    renderFraudCategories(fraudCategories);

    renderFraudModules(fraudModules);

    renderThreatTrends(threatTrends);

    renderRecentActivity(recentActivity);

    setUnsupportedMetrics();
  }

  /* =====================================================
     STATISTICS
  ===================================================== */

  function renderStatistics(statistics, riskDistribution) {
    updateText(elements.totalAnalyses, statistics.totalAnalyses);

    updateText(elements.threats, statistics.threatsDetected);

    updateText(elements.lowRisk, statistics.lowRiskResults);

    updateText(elements.critical, riskDistribution.critical);
  }

  /* =====================================================
     RISK DISTRIBUTION
  ===================================================== */

  function renderRiskDistribution(distribution) {
    const container = elements.riskChart;

    if (!container) return;

    clearElement(container);

    const riskLevels = [
      { key: "low", label: "Low Risk", color: "#60a5fa" },
      { key: "medium", label: "Medium Risk", color: "#93c5fd" },
      { key: "high", label: "High Risk", color: "#fbbf24" },
      { key: "critical", label: "Critical Risk", color: "#f87171" },
    ];

    const values = riskLevels.map((level) => ({
      ...level,
      value: getValidNumber(distribution[level.key]),
    }));

    const total = values.reduce((sum, item) => sum + item.value, 0);

    if (!total) {
      renderChartEmptyState(
        container,
        "No risk data available",
        "Risk distribution will appear when completed analysis records are available.",
        "fa-chart-pie",
      );

      return;
    }

    const chart = createElement("div", "analytics-horizontal-chart");

    values.forEach((item) => {
      const percentage = (item.value / total) * 100;

      const row = createElement("div", "analytics-bar-row");

      const header = createElement("div", "analytics-bar-header");

      header.append(
        createElement("span", "", item.label),

        createElement(
          "strong",
          "",
          `${formatNumber(item.value)} (${percentage.toFixed(1)}%)`,
        ),
      );

      const track = createElement("div", "analytics-bar-track");

      const bar = createElement("div", "analytics-bar-fill");

      bar.style.width = `${percentage}%`;
      bar.style.backgroundColor = item.color;

      track.appendChild(bar);
      row.append(header, track);
      chart.appendChild(row);
    });

    container.appendChild(chart);
  }

  /* =====================================================
     12 INDIVIDUAL DETECTION CATEGORIES
  ===================================================== */

  function renderFraudCategories(categories) {
    CATEGORY_CONFIG.forEach((category) => {
      const value = categories[category.key];

      const element = document.getElementById(category.id);

      if (element) {
        updateText(element, value);
      }
    });

    const container = elements.categoryChart;

    if (!container) return;

    clearElement(container);

    const values = CATEGORY_CONFIG.map((category) => ({
      ...category,
      value: getValidNumber(categories[category.key]),
    }));

    const total = values.reduce((sum, item) => sum + item.value, 0);

    if (!total) {
      renderChartEmptyState(
        container,
        "No category data available",
        "Fraud category statistics will appear when completed analysis records are available.",
        "fa-chart-column",
      );

      return;
    }

    const chart = createElement("div", "analytics-horizontal-chart");

    values.forEach((item) => {
      const percentage = (item.value / total) * 100;

      const row = createElement("div", "analytics-bar-row");

      const header = createElement("div", "analytics-bar-header");

      header.append(
        createElement("span", "", item.label),

        createElement(
          "strong",
          "",
          `${formatNumber(item.value)} (${percentage.toFixed(1)}%)`,
        ),
      );

      const track = createElement("div", "analytics-bar-track");

      const bar = createElement("div", "analytics-bar-fill category-fill");

      bar.style.width = `${percentage}%`;

      track.appendChild(bar);
      row.append(header, track);
      chart.appendChild(row);
    });

    container.appendChild(chart);
  }

  /* =====================================================
     FIVE MAJOR FRAUD MODULES

     IMPORTANT:
     These values come from data.fraudModules,
     NOT data.fraudCategories.
  ===================================================== */

  function renderFraudModules(modules) {
    MODULE_CONFIG.forEach((module) => {
      updateText(module.element, modules[module.key]);
    });
  }

  /* =====================================================
     HISTORICAL TRENDS
  ===================================================== */

  function renderThreatTrends(trends) {
    const container = elements.trendChart;

    if (!container) return;

    clearElement(container);

    if (!trends.length) {
      renderChartEmptyState(
        container,
        "Historical trends not available",
        "The current dashboard API does not provide historical trend aggregation yet.",
        "fa-chart-line",
      );

      return;
    }

    const validTrends = trends.filter(
      (item) =>
        item &&
        Number.isFinite(Number(item.analyses)) &&
        Number.isFinite(Number(item.threats)) &&
        Number(item.analyses) >= 0 &&
        Number(item.threats) >= 0,
    );

    if (!validTrends.length) {
      renderChartEmptyState(
        container,
        "Trend data unavailable",
        "The server did not return valid trend values.",
        "fa-chart-line",
      );

      return;
    }

    const chart = createElement("div", "analytics-trend-chart");

    const maximum = Math.max(
      1,
      ...validTrends.map((item) =>
        Math.max(getValidNumber(item.analyses), getValidNumber(item.threats)),
      ),
    );

    validTrends.forEach((item) => {
      const analyses = getValidNumber(item.analyses);

      const threats = getValidNumber(item.threats);

      const column = createElement("div", "trend-column");

      const bars = createElement("div", "trend-bars");

      const analysisBar = createElement("div", "trend-bar analysis-bar");

      const threatBar = createElement("div", "trend-bar threat-bar");

      analysisBar.style.height = `${(analyses / maximum) * 100}%`;

      threatBar.style.height = `${(threats / maximum) * 100}%`;

      analysisBar.title = `Analyses: ${analyses}`;
      threatBar.title = `Threats: ${threats}`;

      bars.append(analysisBar, threatBar);

      const label = createElement(
        "span",
        "trend-label",
        safeText(item.label, "Unknown"),
      );

      column.append(bars, label);
      chart.appendChild(column);
    });

    const legend = createElement("div", "trend-legend");

    legend.append(
      createLegendItem("analysis-bar", "Analyses"),
      createLegendItem("threat-bar", "Threats"),
    );

    container.append(chart, legend);
  }

  function createLegendItem(className, label) {
    const item = createElement("span", "trend-legend-item");

    const dot = createElement("i", `trend-legend-dot ${className}`);

    dot.setAttribute("aria-hidden", "true");

    item.append(dot, document.createTextNode(label));

    return item;
  }

  /* =====================================================
     RECENT ACTIVITY
  ===================================================== */

  function renderRecentActivity(records) {
    const container = elements.activityBody;

    if (!container) return;

    clearElement(container);

    if (!records.length) {
      renderTableEmptyState();
      return;
    }

    records.forEach((record) => {
      if (!record || typeof record !== "object") {
        return;
      }

      const row = document.createElement("tr");

      const analysisId = record._id || record.evidenceId || record.analysisId;

      const riskScore = Number(record.riskScore);

      const category = record.detectionCategory || record.fraudCategory;

      const cells = [
        safeText(analysisId),
        safeText(record.evidenceType),
        safeText(category),
        Number.isFinite(riskScore) ? `${riskScore}/100` : "--",
      ];

      cells.forEach((value) => {
        row.appendChild(createElement("td", "", value));
      });

      const riskCell = document.createElement("td");

      riskCell.appendChild(createRiskBadge(record.riskLevel));

      row.appendChild(riskCell);

      row.appendChild(createElement("td", "", formatDate(record.createdAt)));

      container.appendChild(row);
    });

    if (!container.children.length) {
      renderTableEmptyState();
    }
  }

  /* =====================================================
     RISK BADGE
  ===================================================== */

  function createRiskBadge(level) {
    const normalized = String(level || "")
      .trim()
      .toLowerCase();

    const allowedLevels = ["low", "medium", "high", "critical"];

    const safeLevel = allowedLevels.includes(normalized)
      ? normalized
      : "unknown";

    const label =
      safeLevel === "unknown"
        ? "Unknown"
        : safeLevel.charAt(0).toUpperCase() + safeLevel.slice(1);

    return createElement("span", `analytics-risk-badge ${safeLevel}`, label);
  }

  /* =====================================================
     DATE FORMATTER
  ===================================================== */

  function formatDate(value) {
    if (!value) return "--";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "--";
    }

    return date.toLocaleDateString("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    });
  }

  /* =====================================================
     EMPTY CHART STATE
  ===================================================== */

  function renderChartEmptyState(container, title, description, icon) {
    if (!container) return;

    clearElement(container);

    const state = createElement("div", "chart-empty-state");

    const iconElement = createElement("i", `fa-solid ${icon}`);

    iconElement.setAttribute("aria-hidden", "true");

    state.append(
      iconElement,
      createElement("h4", "", title),
      createElement("p", "", description),
    );

    container.appendChild(state);
  }

  /* =====================================================
     EMPTY TABLE STATE
  ===================================================== */

  function renderTableEmptyState() {
    const container = elements.activityBody;

    if (!container) return;

    clearElement(container);

    const row = document.createElement("tr");

    const cell = document.createElement("td");

    cell.colSpan = 6;

    const state = createElement("div", "table-empty-state");

    const icon = createElement("i", "fa-solid fa-folder-open");

    icon.setAttribute("aria-hidden", "true");

    state.append(
      icon,

      createElement("strong", "", "No analysis records found"),

      createElement(
        "span",
        "",
        "Recent activity will appear here when analysis records are available.",
      ),
    );

    cell.appendChild(state);
    row.appendChild(cell);
    container.appendChild(row);
  }

  /* =====================================================
     ALL EMPTY STATES
  ===================================================== */

  function renderEmptyStates() {
    renderChartEmptyState(
      elements.riskChart,
      "No risk data available",
      "Risk distribution will appear when analysis records are available.",
      "fa-chart-pie",
    );

    renderChartEmptyState(
      elements.categoryChart,
      "No category data available",
      "Fraud category statistics will appear when records are available.",
      "fa-chart-column",
    );

    renderChartEmptyState(
      elements.trendChart,
      "Historical trends not available",
      "Historical trend aggregation is not currently provided by the backend.",
      "fa-chart-line",
    );

    renderTableEmptyState();
  }

  /* =====================================================
     START APPLICATION
  ===================================================== */

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initAnalytics);
  } else {
    initAnalytics();
  }
})();
