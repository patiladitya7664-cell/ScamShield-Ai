"use strict";

/* =====================================================
   SCAMSHIELD AI - ANALYTICS
   File: frontend/js/analytics.js

   Backend:
   GET /api/dashboard/overview

   Features:
   - Backend-connected analytics
   - Risk distribution
   - Fraud category breakdown
   - Threat activity trends (only real API data)
   - Recent activity
   - Authentication handling
   - Accessible loading and error states
   - Safe DOM rendering
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

  let activeController = null;
  let hasLoadedData = false;

  /* =====================================================
     INITIALIZATION
  ===================================================== */

  function initAnalytics() {
    setCurrentYear();
    setInitialState();

    if (elements.refreshButton) {
      elements.refreshButton.addEventListener("click", loadAnalytics);
    }

    loadAnalytics();
  }

  /* =====================================================
     BASIC HELPERS
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

  function safeText(value, fallback = "Unknown") {
    if (value === null || value === undefined || value === "") {
      return fallback;
    }

    return String(value);
  }

  function getValidNumber(value) {
    const number = Number(value);

    if (!Number.isFinite(number) || number < 0) {
      return 0;
    }

    return number;
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
      value === undefined || value === null
        ? "--"
        : formatNumber(value);
  }

  /* =====================================================
     STATUS NOTIFICATIONS
  ===================================================== */

  function showNotice(message, type = "info") {
    if (!elements.notice || !elements.statusMessage) {
      return;
    }

    elements.statusMessage.textContent = message;

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
      (node) => node.nodeType === Node.TEXT_NODE
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

    showNotice(
      "Your session has expired. Please log in again.",
      "error"
    );

    window.setTimeout(() => {
      window.location.href = "login.html";
    }, 1200);
  }

  /* =====================================================
     API REQUEST
  ===================================================== */

  async function loadAnalytics() {
    // Cancel the previous request.
    if (activeController) {
      activeController.abort();
    }

    const controller = new AbortController();

    activeController = controller;

    setLoadingState(true);

    showNotice(
      "Loading analytics from the server...",
      "loading"
    );

    try {
      const token = getToken();

      if (!token) {
        showNotice(
          "Please log in to access your security analytics.",
          "error"
        );

        window.setTimeout(() => {
          if (activeController === controller) {
            window.location.href = "login.html";
          }
        }, 1200);

        return;
      }

      const response = await fetch(API_ENDPOINT, {
        method: "GET",

        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
        },

        signal: controller.signal,
      });

      let result;

      try {
        result = await response.json();
      } catch {
        throw new Error(
          "The server returned an invalid response."
        );
      }

      if (response.status === 401) {
        handleUnauthorized();
        return;
      }

      if (response.status === 403) {
        throw new Error(
          "You do not have permission to access this analytics data."
        );
      }

      if (!response.ok) {
        throw new Error(
          result.message ||
            `Analytics request failed (${response.status}).`
        );
      }

      if (result.success !== true) {
        throw new Error(
          result.message ||
            "Analytics data could not be retrieved."
        );
      }

      const analyticsData = result.data || result.analytics;

      if (
        !analyticsData ||
        typeof analyticsData !== "object" ||
        Array.isArray(analyticsData)
      ) {
        throw new Error(
          "The analytics response has an invalid structure."
        );
      }

      // Render actual backend data.
      renderAnalytics(analyticsData);

      hasLoadedData = true;

      showNotice(
        "Analytics successfully updated from the backend.",
        "success"
      );

    } catch (error) {
      if (error.name === "AbortError") {
        return;
      }

      console.error(
        "[ScamShield Analytics]",
        error.message
      );

      // Preserve previously loaded data if refresh fails.
      if (!hasLoadedData) {
        renderEmptyStates();
      }

      showNotice(
        error.message ||
          "Analytics service is unavailable. Please try again.",
        "error"
      );

    } finally {
      // Only the latest request can update the loading state.
      if (activeController === controller) {
        activeController = null;
        setLoadingState(false);
      }
    }
  }

  /* =====================================================
     MAIN ANALYTICS RENDERER
  ===================================================== */

  function renderAnalytics(data) {
    const statistics = data.statistics || {};

    const riskDistribution = data.riskDistribution || {};

    const fraudCategories = data.fraudCategories || {};

    const threatTrends = Array.isArray(data.threatTrends)
      ? data.threatTrends
      : [];

    const recentActivity = Array.isArray(data.recentActivity)
      ? data.recentActivity
      : [];

    renderStatistics(statistics, riskDistribution);

    renderRiskDistribution(riskDistribution);

    renderFraudCategories(fraudCategories);

    renderThreatTrends(threatTrends);

    renderRecentActivity(recentActivity);
  }

  /* =====================================================
     STATISTICS
  ===================================================== */

  function renderStatistics(statistics, riskDistribution) {
    const totalAnalyses = statistics.totalAnalyses;

    const threatsDetected = statistics.threatsDetected;

    const lowRisk =
      statistics.lowRiskResults ??
      statistics.lowRiskCases;

    const criticalRisk =
      statistics.criticalCases ??
      riskDistribution.critical;

    updateText(elements.totalAnalyses, totalAnalyses);

    updateText(elements.threats, threatsDetected);

    updateText(elements.lowRisk, lowRisk);

    updateText(elements.critical, criticalRisk);
  }

  /* =====================================================
     RISK DISTRIBUTION
  ===================================================== */

  function renderRiskDistribution(distribution) {
    const container = elements.riskChart;

    if (!container) return;

    clearElement(container);

    const riskLevels = [
      {
        key: "low",
        label: "Low Risk",
        color: "#34d399",
      },
      {
        key: "medium",
        label: "Medium Risk",
        color: "#60a5fa",
      },
      {
        key: "high",
        label: "High Risk",
        color: "#fbbf24",
      },
      {
        key: "critical",
        label: "Critical Risk",
        color: "#f87171",
      },
    ];

    const values = riskLevels.map((level) => ({
      ...level,
      value: getValidNumber(distribution[level.key]),
    }));

    const total = values.reduce(
      (sum, item) => sum + item.value,
      0
    );

    if (!total) {
      renderChartEmptyState(
        container,
        "No risk data available",
        "Risk distribution will appear when analysis records are available.",
        "fa-chart-pie"
      );

      return;
    }

    const chart = createElement(
      "div",
      "analytics-horizontal-chart"
    );

    values.forEach((item) => {
      const percentage = (item.value / total) * 100;

      const row = createElement(
        "div",
        "analytics-bar-row"
      );

      const header = createElement(
        "div",
        "analytics-bar-header"
      );

      header.append(
        createElement("span", "", item.label),

        createElement(
          "strong",
          "",
          `${formatNumber(item.value)} (${percentage.toFixed(1)}%)`
        )
      );

      const track = createElement(
        "div",
        "analytics-bar-track"
      );

      track.setAttribute("role", "progressbar");
      track.setAttribute("aria-label", item.label);
      track.setAttribute("aria-valuemin", "0");
      track.setAttribute("aria-valuemax", "100");
      track.setAttribute(
        "aria-valuenow",
        percentage.toFixed(1)
      );

      const bar = createElement(
        "div",
        "analytics-bar-fill"
      );

      bar.style.width = `${percentage}%`;
      bar.style.backgroundColor = item.color;

      track.appendChild(bar);

      row.append(header, track);

      chart.appendChild(row);
    });

    container.appendChild(chart);
  }

  /* =====================================================
     FRAUD CATEGORY BREAKDOWN
  ===================================================== */

  function renderFraudCategories(categories) {
    const categoryConfig = [
      {
        key: "investment",
        element: elements.investment,
        label: "Investment Scams",
      },
      {
        key: "digitalArrest",
        element: elements.arrest,
        label: "Digital Arrest",
      },
      {
        key: "creditCard",
        element: elements.card,
        label: "Credit Card Fraud",
      },
      {
        key: "sextortion",
        element: elements.sextortion,
        label: "Sextortion",
      },
      {
        key: "ecommerce",
        element: elements.ecommerce,
        label: "E-commerce Fraud",
      },
    ];

    let total = 0;

    categoryConfig.forEach((category) => {
      const value = getValidNumber(
        categories[category.key]
      );

      total += value;

      updateText(category.element, value);
    });

    const container = elements.categoryChart;

    if (!container) return;

    clearElement(container);

    if (!total) {
      renderChartEmptyState(
        container,
        "No category data available",
        "Fraud category statistics will appear when records are available.",
        "fa-chart-column"
      );

      return;
    }

    const chart = createElement(
      "div",
      "analytics-horizontal-chart"
    );

    categoryConfig.forEach((category) => {
      const value = getValidNumber(
        categories[category.key]
      );

      const percentage = (value / total) * 100;

      const row = createElement(
        "div",
        "analytics-bar-row"
      );

      const header = createElement(
        "div",
        "analytics-bar-header"
      );

      header.append(
        createElement("span", "", category.label),

        createElement(
          "strong",
          "",
          `${formatNumber(value)} (${percentage.toFixed(1)}%)`
        )
      );

      const track = createElement(
        "div",
        "analytics-bar-track"
      );

      const bar = createElement(
        "div",
        "analytics-bar-fill category-fill"
      );

      bar.style.width = `${percentage}%`;

      track.appendChild(bar);

      row.append(header, track);

      chart.appendChild(row);
    });

    container.appendChild(chart);
  }

  /* =====================================================
     THREAT ACTIVITY TRENDS

     Only displays real API data.

     Expected structure:
     [
       {
         label: "Monday",
         analyses: 10,
         threats: 4
       }
     ]

     Current dashboard backend does not yet provide
     threatTrends. Therefore, the chart will show an
     honest empty state until backend aggregation exists.
  ===================================================== */

  function renderThreatTrends(trends) {
    const container = elements.trendChart;

    if (!container) return;

    clearElement(container);

    if (!Array.isArray(trends) || trends.length === 0) {
      renderChartEmptyState(
        container,
        "Historical trends not available",
        "Trend information will appear after historical analytics are added to the backend.",
        "fa-chart-line"
      );

      return;
    }

    const validTrends = trends.filter((item) => {
      return (
        item &&
        Number.isFinite(Number(item.analyses)) &&
        Number.isFinite(Number(item.threats))
      );
    });

    if (!validTrends.length) {
      renderChartEmptyState(
        container,
        "Trend data unavailable",
        "The server did not return valid trend values.",
        "fa-chart-line"
      );

      return;
    }

    const chart = createElement(
      "div",
      "analytics-trend-chart"
    );

    const maximum = Math.max(
      1,
      ...validTrends.map((item) =>
        Math.max(
          getValidNumber(item.analyses),
          getValidNumber(item.threats)
        )
      )
    );

    validTrends.forEach((item) => {
      const analyses = getValidNumber(item.analyses);

      const threats = getValidNumber(item.threats);

      const column = createElement(
        "div",
        "trend-column"
      );

      const bars = createElement(
        "div",
        "trend-bars"
      );

      const analysisBar = createElement(
        "div",
        "trend-bar analysis-bar"
      );

      const threatBar = createElement(
        "div",
        "trend-bar threat-bar"
      );

      const analysisHeight =
        (analyses / maximum) * 100;

      const threatHeight =
        (threats / maximum) * 100;

      analysisBar.style.height = `${analysisHeight}%`;

      threatBar.style.height = `${threatHeight}%`;

      analysisBar.title = `Analyses: ${analyses}`;

      threatBar.title = `Threats: ${threats}`;

      analysisBar.setAttribute(
        "aria-label",
        `${analyses} analyses`
      );

      threatBar.setAttribute(
        "aria-label",
        `${threats} threats`
      );

      bars.append(analysisBar, threatBar);

      const label = createElement(
        "span",
        "trend-label",
        safeText(item.label, "Unknown")
      );

      column.append(bars, label);

      chart.appendChild(column);
    });

    const legend = createElement(
      "div",
      "trend-legend"
    );

    legend.append(
      createLegendItem(
        "analysis-bar",
        "Analyses"
      ),

      createLegendItem(
        "threat-bar",
        "Threats"
      )
    );

    container.append(chart, legend);
  }

  function createLegendItem(className, label) {
    const item = createElement(
      "span",
      "trend-legend-item"
    );

    const dot = createElement(
      "i",
      `trend-legend-dot ${className}`
    );

    dot.setAttribute("aria-hidden", "true");

    item.append(
      dot,
      document.createTextNode(label)
    );

    return item;
  }

  /* =====================================================
     RECENT ACTIVITY TABLE

     Backend fields:
     - _id
     - evidenceId
     - evidenceType
     - fraudCategory
     - riskScore
     - riskLevel
     - createdAt
  ===================================================== */

  function renderRecentActivity(records) {
    const container = elements.activityBody;

    if (!container) return;

    clearElement(container);

    if (!Array.isArray(records) || records.length === 0) {
      renderTableEmptyState();

      return;
    }

    records.forEach((record) => {
      if (!record || typeof record !== "object") {
        return;
      }

      const row = document.createElement("tr");

      // Match the actual backend response.
      const analysisId =
        record.evidenceId ||
        record.analysisId ||
        record._id;

      const riskScore = Number(record.riskScore);

      const cells = [
        safeText(analysisId),
        safeText(record.evidenceType),
        safeText(record.fraudCategory),
        Number.isFinite(riskScore)
          ? `${riskScore}/100`
          : "--",
      ];

      cells.forEach((value) => {
        row.appendChild(
          createElement("td", "", value)
        );
      });

      const riskCell = document.createElement("td");

      riskCell.appendChild(
        createRiskBadge(record.riskLevel)
      );

      row.appendChild(riskCell);

      const dateCell = createElement(
        "td",
        "",
        formatDate(record.createdAt || record.analyzedAt)
      );

      row.appendChild(dateCell);

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

    const allowedLevels = [
      "low",
      "medium",
      "high",
      "critical",
    ];

    const safeLevel = allowedLevels.includes(normalized)
      ? normalized
      : "unknown";

    const label =
      safeLevel === "unknown"
        ? "Unknown"
        : safeLevel.charAt(0).toUpperCase() +
          safeLevel.slice(1);

    return createElement(
      "span",
      `analytics-risk-badge ${safeLevel}`,
      label
    );
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

  function renderChartEmptyState(
    container,
    title,
    description,
    icon
  ) {
    if (!container) return;

    clearElement(container);

    const state = createElement(
      "div",
      "chart-empty-state"
    );

    const iconElement = createElement(
      "i",
      `fa-solid ${icon}`
    );

    iconElement.setAttribute(
      "aria-hidden",
      "true"
    );

    state.append(
      iconElement,

      createElement("h4", "", title),

      createElement("p", "", description)
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

    const state = createElement(
      "div",
      "table-empty-state"
    );

    const icon = createElement(
      "i",
      "fa-solid fa-folder-open"
    );

    icon.setAttribute(
      "aria-hidden",
      "true"
    );

    state.append(
      icon,

      createElement(
        "strong",
        "",
        "No analysis records found"
      ),

      createElement(
        "span",
        "",
        "Recent activity will appear here when analysis records are available."
      )
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
      "fa-chart-pie"
    );

    renderChartEmptyState(
      elements.categoryChart,
      "No category data available",
      "Fraud category statistics will appear when records are available.",
      "fa-chart-column"
    );

    renderChartEmptyState(
      elements.trendChart,
      "Historical trends not available",
      "Trend information will appear after historical analytics are added to the backend.",
      "fa-chart-line"
    );

    renderTableEmptyState();
  }

  /* =====================================================
     START APPLICATION
  ===================================================== */

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      initAnalytics
    );
  } else {
    initAnalytics();
  }

})();