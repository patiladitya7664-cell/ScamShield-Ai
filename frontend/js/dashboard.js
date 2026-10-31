/* =====================================================
   SCAMSHIELD AI - SECURITY DASHBOARD
   Statistics + Risk Distribution + Activity
===================================================== */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // ================================================
  // CONFIGURATION
  // ================================================

  const API_BASE_URL = window.SCAMSHIELD_API_URL || "http://localhost:5000/api";

  const DASHBOARD_ENDPOINT = `${API_BASE_URL}/dashboard/overview`;

  // ================================================
  // DOM ELEMENTS
  // ================================================

  const elements = {
    dashboardDate: document.getElementById("dashboardDate"),

    refreshButton: document.getElementById("refreshDashboard"),

    platformStatus: document.getElementById("platformStatus"),

    statisticsStatus: document.getElementById("statisticsStatus"),

    totalAnalyses: document.getElementById("totalAnalyses"),

    threatsDetected: document.getElementById("threatsDetected"),

    lowRiskResults: document.getElementById("lowRiskResults"),

    highRiskResults: document.getElementById("highRiskResults"),

    totalRiskCases: document.getElementById("totalRiskCases"),

    riskChart: document.getElementById("riskChart"),

    lowRiskCount: document.getElementById("lowRiskCount"),

    mediumRiskCount: document.getElementById("mediumRiskCount"),

    highRiskCount: document.getElementById("highRiskCount"),

    criticalRiskCount: document.getElementById("criticalRiskCount"),

    investmentCount: document.getElementById("investmentCount"),

    digitalArrestCount: document.getElementById("digitalArrestCount"),

    creditCardCount: document.getElementById("creditCardCount"),

    sextortionCount: document.getElementById("sextortionCount"),

    ecommerceCount: document.getElementById("ecommerceCount"),

    activityTableBody: document.getElementById("activityTableBody"),
  };

  // ================================================
  // DATE
  // ================================================

  function updateDashboardDate() {
    if (!elements.dashboardDate) return;

    const formattedDate = new Intl.DateTimeFormat("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    }).format(new Date());

    elements.dashboardDate.innerHTML = `
            <i class="fa-regular fa-calendar"></i>
            ${formattedDate}
        `;
  }

  // ================================================
  // NUMBER FORMAT
  // ================================================

  function formatNumber(value) {
    const number = Number(value);

    if (!Number.isFinite(number) || number < 0) {
      return "0";
    }

    return number.toLocaleString("en-IN");
  }

  // ================================================
  // PLATFORM STATUS
  // ================================================

  function updatePlatformStatus(status, connected = false) {
    if (!elements.platformStatus) return;

    elements.platformStatus.textContent = status;

    const indicator = document.querySelector(".system-status-indicator");

    if (indicator) {
      indicator.style.background = connected ? "#34d399" : "#fbbf24";

      indicator.style.boxShadow = connected
        ? "0 0 12px rgba(52, 211, 153, 0.4)"
        : "0 0 12px rgba(251, 191, 36, 0.4)";
    }
  }

  // ================================================
  // STATISTICS STATUS
  // ================================================

  function updateStatisticsStatus(message) {
    if (elements.statisticsStatus) {
      elements.statisticsStatus.textContent = message;
    }
  }

  // ================================================
  // SAFE VALUE
  // ================================================

  function safeCount(value) {
    const number = Number(value);

    if (!Number.isFinite(number) || number < 0) {
      return 0;
    }

    return Math.floor(number);
  }

  // ================================================
  // UPDATE OVERVIEW CARDS
  // ================================================

  function updateOverview(statistics = {}) {
    const total = safeCount(statistics.totalAnalyses);

    const threats = safeCount(statistics.threatsDetected);

    const lowRisk = safeCount(statistics.lowRiskResults);

    const highRisk = safeCount(statistics.highRiskResults);

    if (elements.totalAnalyses) {
      elements.totalAnalyses.textContent = formatNumber(total);
    }

    if (elements.threatsDetected) {
      elements.threatsDetected.textContent = formatNumber(threats);
    }

    if (elements.lowRiskResults) {
      elements.lowRiskResults.textContent = formatNumber(lowRisk);
    }

    if (elements.highRiskResults) {
      elements.highRiskResults.textContent = formatNumber(highRisk);
    }
  }

  // ================================================
  // RISK DISTRIBUTION
  // ================================================

  function updateRiskDistribution(risk = {}) {
    const low = safeCount(risk.low);

    const medium = safeCount(risk.medium);

    const high = safeCount(risk.high);

    const critical = safeCount(risk.critical);

    const total = low + medium + high + critical;

    if (elements.totalRiskCases) {
      elements.totalRiskCases.textContent = formatNumber(total);
    }

    if (elements.lowRiskCount) {
      elements.lowRiskCount.textContent = formatNumber(low);
    }

    if (elements.mediumRiskCount) {
      elements.mediumRiskCount.textContent = formatNumber(medium);
    }

    if (elements.highRiskCount) {
      elements.highRiskCount.textContent = formatNumber(high);
    }

    if (elements.criticalRiskCount) {
      elements.criticalRiskCount.textContent = formatNumber(critical);
    }

    if (!elements.riskChart) return;

    if (total === 0) {
      elements.riskChart.style.background =
        "conic-gradient(rgba(255,255,255,0.07) 0% 100%)";

      return;
    }

    const lowEnd = (low / total) * 100;

    const mediumEnd = lowEnd + (medium / total) * 100;

    const highEnd = mediumEnd + (high / total) * 100;

    const criticalEnd = 100;

    elements.riskChart.style.background = `
            conic-gradient(
                #34d399 0% ${lowEnd}%,
                #fbbf24 ${lowEnd}% ${mediumEnd}%,
                #fb923c ${mediumEnd}% ${highEnd}%,
                #f87171 ${highEnd}% ${criticalEnd}%
            )
        `;
  }

  // ================================================
  // FRAUD CATEGORIES
  // ================================================

  function updateFraudCategories(categories = {}) {
    const categoryElements = {
      investment: elements.investmentCount,

      digitalArrest: elements.digitalArrestCount,

      creditCard: elements.creditCardCount,

      sextortion: elements.sextortionCount,

      ecommerce: elements.ecommerceCount,
    };

    Object.entries(categoryElements).forEach(([key, element]) => {
      if (!element) return;

      element.textContent = formatNumber(safeCount(categories[key]));
    });
  }

  // ================================================
  // DATE FORMAT FOR ACTIVITY
  // ================================================

  function formatActivityDate(value) {
    if (!value) return "N/A";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
      return "N/A";
    }

    return new Intl.DateTimeFormat("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
    }).format(date);
  }

  // ================================================
  // RISK LEVEL CLASS
  // ================================================

  function getRiskClass(level) {
    const normalized = String(level || "").toLowerCase();

    const allowed = ["low", "medium", "high", "critical"];

    return allowed.includes(normalized) ? normalized : "unknown";
  }

  // ================================================
  // CREATE TABLE CELL
  // ================================================

  function createCell(value) {
    const cell = document.createElement("td");

    cell.textContent = value ?? "N/A";

    return cell;
  }

  // ================================================
  // EMPTY ACTIVITY
  // ================================================

  function showEmptyActivity(message = "No analysis records yet") {
    if (!elements.activityTableBody) return;

    elements.activityTableBody.replaceChildren();

    const row = document.createElement("tr");

    const cell = document.createElement("td");

    cell.colSpan = 6;

    cell.className = "empty-activity";

    const icon = document.createElement("i");

    icon.className = "fa-solid fa-folder-open";

    const title = document.createElement("strong");

    title.textContent = message;

    const description = document.createElement("span");

    description.textContent =
      "Analysis records will appear here when available.";

    cell.append(icon, title, description);

    row.appendChild(cell);

    elements.activityTableBody.appendChild(row);
  }

  // ================================================
  // RECENT ACTIVITY
  // ================================================

  function renderRecentActivity(activities = []) {
    if (!elements.activityTableBody) return;

    elements.activityTableBody.replaceChildren();

    if (!Array.isArray(activities) || activities.length === 0) {
      showEmptyActivity();

      return;
    }

    activities.slice(0, 10).forEach((activity) => {
      const row = document.createElement("tr");

      const evidenceId = createCell(
        activity.evidenceId || activity._id || "N/A",
      );

      const evidenceType = createCell(activity.evidenceType || "N/A");

      const fraudCategory = createCell(
        activity.fraudCategory || "Unclassified",
      );

      const riskScore = createCell(
        Number.isFinite(Number(activity.riskScore))
          ? `${Number(activity.riskScore)}/100`
          : "N/A",
      );

      const riskLevel = createCell(activity.riskLevel || "Unknown");

      const date = createCell(formatActivityDate(activity.createdAt));

      const riskClass = getRiskClass(activity.riskLevel);

      riskLevel.className = `risk-level-cell ${riskClass}`;

      row.append(
        evidenceId,
        evidenceType,
        fraudCategory,
        riskScore,
        riskLevel,
        date,
      );

      elements.activityTableBody.appendChild(row);
    });
  }

  // ================================================
  // VALIDATE DASHBOARD RESPONSE
  // ================================================

  function validateDashboardData(data) {
    if (!data || typeof data !== "object") {
      throw new Error("Invalid dashboard response.");
    }

    if (data.success === false) {
      throw new Error(data.message || "Unable to load dashboard data.");
    }

    const dashboard = data.data || data.dashboard;

    if (!dashboard || typeof dashboard !== "object") {
      throw new Error("Dashboard data is missing.");
    }

    return dashboard;
  }

  // ================================================
  // LOAD DASHBOARD DATA
  // ================================================

  async function loadDashboard() {
    if (elements.refreshButton) {
      elements.refreshButton.disabled = true;

      elements.refreshButton.innerHTML = `
                <i class="fa-solid fa-spinner fa-spin"></i>
                Loading...
            `;
    }

    updatePlatformStatus("Connecting to backend...");

    updateStatisticsStatus("Loading statistics...");

    try {
      const response = await fetch(DASHBOARD_ENDPOINT, {
        method: "GET",

        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${localStorage.getItem("scamshieldToken") || sessionStorage.getItem("scamshieldToken") || ""}`,
        },

        cache: "no-store",
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        throw new Error(
          data.message || `Dashboard API error: ${response.status}`,
        );
      }

      const dashboard = validateDashboardData(data);

      updateOverview(dashboard.statistics || {});

      updateRiskDistribution(dashboard.riskDistribution || {});

      updateFraudCategories(dashboard.fraudCategories || {});

      renderRecentActivity(dashboard.recentActivity || []);

      updatePlatformStatus("Backend connected", true);

      updateStatisticsStatus("Data loaded successfully");
    } catch (error) {
      console.error("ScamShield Dashboard Error:", error);

      updatePlatformStatus("Backend unavailable");

      updateStatisticsStatus("Data unavailable");

      showEmptyActivity("Dashboard data unavailable");
    } finally {
      if (elements.refreshButton) {
        elements.refreshButton.disabled = false;

        elements.refreshButton.innerHTML = `
                    <i class="fa-solid fa-rotate"></i>
                    Refresh
                `;
      }
    }
  }

  // ================================================
  // REFRESH BUTTON
  // ================================================

  if (elements.refreshButton) {
    elements.refreshButton.addEventListener("click", loadDashboard);
  }

  // ================================================
  // INITIALIZATION
  // ================================================

  updateDashboardDate();

  updateOverview();

  updateRiskDistribution();

  updateFraudCategories();

  showEmptyActivity();

  loadDashboard();

  console.log("ScamShield Dashboard Initialized.");
});
