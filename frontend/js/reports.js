
/* =====================================================
   SCAMSHIELD AI - REPORTS MODULE
   Case + Analysis Integration
   Search | Filters | Pagination | CSV | PDF
===================================================== */

"use strict";

document.addEventListener("DOMContentLoaded", () => {

  // ================================================
  // CONFIGURATION
  // ================================================

  const API = window.ScamShieldAPI;
  const REPORTS_PER_PAGE = 8;
  const API_ENDPOINT = "/cases?limit=100";

  // ================================================
  // DOM ELEMENTS
  // ================================================

  const el = {
    total: document.getElementById("totalReports"),
    highRisk: document.getElementById("highRiskReports"),
    review: document.getElementById("reviewReports"),
    completed: document.getElementById("completedReports"),

    notice: document.getElementById("reportsNotice"),
    noticeMessage: document.getElementById("reportsStatusMessage"),

    search: document.getElementById("reportSearch"),
    risk: document.getElementById("riskFilter"),
    category: document.getElementById("categoryFilter"),
    date: document.getElementById("dateFilter"),

    clear: document.getElementById("clearReportFilters"),
    refresh: document.getElementById("refreshReports"),
    export: document.getElementById("exportReports"),

    resultCount: document.getElementById("reportResultCount"),
    table: document.getElementById("reportsTableBody"),

    pagination: document.getElementById("reportsPagination"),
    paginationInfo: document.getElementById("paginationInfo"),
    previous: document.getElementById("previousPage"),
    currentPage: document.getElementById("currentPage"),
    next: document.getElementById("nextPage"),

    modal: document.getElementById("reportDetailsModal"),
    modalTitle: document.getElementById("reportModalTitle"),
    modalContent: document.getElementById("reportDetailsContent"),

    overlay: document.getElementById("closeModalOverlay"),
    close: document.getElementById("closeReportModal"),
    closeDetails: document.getElementById("closeReportDetails"),

    downloadSingle: document.getElementById("downloadSingleReport"),

    currentYear: document.getElementById("currentYear"),
  };

  // ================================================
  // API AVAILABILITY
  // ================================================

  if (!API || typeof API.get !== "function") {
    console.error("ScamShield Reports: API service unavailable.");

    showNotice(
      "API service unavailable. Check frontend/js/services/api.js.",
      "error"
    );

    renderEmpty("API service unavailable.");

    return;
  }

  // ================================================
  // STATE
  // ================================================

  let allReports = [];
  let filteredReports = [];

  let currentPage = 1;
  let selectedReport = null;
  let isLoading = false;

  // ================================================
  // HELPERS
  // ================================================

  function normalize(value) {
    return String(value ?? "").trim().toLowerCase();
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString("en-IN");
  }

  function formatDate(value) {
    if (!value) return "N/A";

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) return "N/A";

    return date.toLocaleString("en-IN", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function getAnalysis(report) {
    return report.analysis && typeof report.analysis === "object"
      ? report.analysis
      : {};
  }

  function getId(report) {
    return String(report._id || report.id || report.reportId || "N/A");
  }

  function getScore(report) {
    const analysis = getAnalysis(report);

    const raw = report.riskScore ?? analysis.riskScore;

    if (raw === null || raw === undefined || raw === "") {
      return null;
    }

    const score = Number(raw);

    if (!Number.isFinite(score) || score < 0 || score > 100) {
      return null;
    }

    return score;
  }

  function getRisk(report) {
    const analysis = getAnalysis(report);

    const value = normalize(
      report.riskLevel || analysis.riskLevel
    );

    if (["low", "medium", "high", "critical"].includes(value)) {
      return value;
    }

    const score = getScore(report);

    if (score === null) return "unknown";

    if (score < 25) return "low";
    if (score < 50) return "medium";
    if (score < 75) return "high";

    return "critical";
  }

  function getCategory(report) {
    const analysis = getAnalysis(report);

    return (
      report.fraudCategory ||
      analysis.fraudCategory ||
      "unclassified"
    );
  }

  function getEvidenceType(report) {
    const analysis = getAnalysis(report);

    return (
      report.evidenceType ||
      analysis.evidenceType ||
      "N/A"
    );
  }

  function getStatus(report) {
    const value = normalize(report.status);

    const allowed = [
      "pending",
      "review",
      "completed",
      "resolved",
      "open",
      "investigating",
      "closed",
      "failed",
    ];

    return allowed.includes(value) ? value : "pending";
  }

  function getDate(report) {
    const analysis = getAnalysis(report);

    return (
      report.createdAt ||
      analysis.analyzedAt ||
      analysis.createdAt ||
      null
    );
  }

  function getExplanation(report) {
    const analysis = getAnalysis(report);

    const explanation =
      report.description ||
      analysis.explanation ||
      analysis.summary ||
      analysis.riskDescription ||
      "No explanation available.";

    return Array.isArray(explanation)
      ? explanation.join("\n")
      : String(explanation);
  }

  function formatCategory(value) {
    const categories = {
      investment: "Investment Scam",
      digitalarrest: "Digital Arrest",
      "digital-arrest": "Digital Arrest",
      digital_arrest: "Digital Arrest",
      creditcard: "Credit Card Fraud",
      "credit-card": "Credit Card Fraud",
      credit_card: "Credit Card Fraud",
      sextortion: "Sextortion",
      ecommerce: "E-commerce Fraud",
      "e-commerce": "E-commerce Fraud",
      other: "Other",
      unclassified: "Unclassified",
    };

    const key = normalize(value).replace(/\s+/g, "");

    return categories[key] || categories[normalize(value)] || value;
  }

  function normalizeCategoryFilter(value) {
    const aliases = {
      investment: "investment",
      "investment scam": "investment",

      "digital arrest": "digital-arrest",
      digital_arrest: "digital-arrest",
      "digital-arrest": "digital-arrest",

      "credit card": "credit-card",
      "credit card fraud": "credit-card",
      credit_card: "credit-card",
      "credit-card": "credit-card",

      ecommerce: "ecommerce",
      "e-commerce": "ecommerce",
      "e-commerce fraud": "ecommerce",

      sextortion: "sextortion",
    };

    return aliases[normalize(value)] || normalize(value);
  }

  // ================================================
  // NOTICE
  // ================================================

  function showNotice(message, state = "info") {
    if (!el.notice) return;

    el.notice.classList.add("show");
    el.notice.dataset.state = state;

    if (el.noticeMessage) {
      el.noticeMessage.textContent = message;
    }
  }

  function hideNotice() {
    el.notice?.classList.remove("show");
  }

  // ================================================
  // EMPTY STATE
  // ================================================

  function renderEmpty(
    heading = "No reports available",
    description = "Investigation records will appear here when available."
  ) {
    if (!el.table) return;

    el.table.replaceChildren();

    const row = document.createElement("tr");
    const cell = document.createElement("td");

    cell.colSpan = 8;

    const wrapper = document.createElement("div");
    wrapper.className = "reports-empty-state";

    const icon = document.createElement("i");
    icon.className = "fa-solid fa-folder-open";

    const title = document.createElement("h4");
    title.textContent = heading;

    const text = document.createElement("p");
    text.textContent = description;

    wrapper.append(icon, title, text);
    cell.appendChild(wrapper);
    row.appendChild(cell);

    el.table.appendChild(row);
  }

  // ================================================
  // LOADING
  // ================================================

  function setLoading(value) {
    isLoading = value;

    if (el.refresh) {
      el.refresh.disabled = value;

      el.refresh.innerHTML = value
        ? '<i class="fa-solid fa-spinner fa-spin"></i> Loading...'
        : '<i class="fa-solid fa-rotate"></i> Refresh';
    }
  }

  // ================================================
  // RESPONSE NORMALIZATION
  // ================================================

  function extractRecords(response) {
    if (Array.isArray(response?.cases)) {
      return response.cases;
    }

    if (Array.isArray(response?.data?.cases)) {
      return response.data.cases;
    }

    if (Array.isArray(response?.data?.data)) {
      return response.data.data;
    }

    if (Array.isArray(response?.data)) {
      return response.data;
    }

    if (Array.isArray(response?.results)) {
      return response.results;
    }

    return [];
  }

  // ================================================
  // FETCH REPORTS
  // ================================================

  async function fetchReports() {
    if (isLoading) return;

    setLoading(true);
    hideNotice();

    try {
      const response = await API.get(API_ENDPOINT);

      if (!response || response.success === false) {
        throw new Error(
          response?.message || "Unable to retrieve reports."
        );
      }

      const records = extractRecords(response);

      allReports = records.map((record) => ({
        ...record,
        analysis:
          record.analysis && typeof record.analysis === "object"
            ? record.analysis
            : null,
      }));

      currentPage = 1;

      updateStatistics();
      applyFilters();

      if (allReports.length === 0) {
        showNotice(
          "No investigation records found. Analyze evidence to create your first report.",
          "info"
        );
      } else {
        showNotice(
          `${allReports.length} investigation record(s) loaded successfully.`,
          "success"
        );
      }

      console.log(
        "ScamShield Reports loaded:",
        allReports.length
      );

    } catch (error) {
      console.error("Reports API Error:", error);

      allReports = [];
      filteredReports = [];

      updateStatistics();

      renderEmpty(
        "Unable to load reports",
        error.message || "Please check your backend connection."
      );

      updatePagination();
      updateExportButton();

      showNotice(
        error.message || "Unable to connect to the reports API.",
        "error"
      );

    } finally {
      setLoading(false);
    }
  }

  // ================================================
  // STATISTICS
  // ================================================

  function updateStatistics() {
    const total = allReports.length;

    const high = allReports.filter((report) => {
      const risk = getRisk(report);

      return risk === "high" || risk === "critical";
    }).length;

    const review = allReports.filter((report) => {
      return ["pending", "review", "open", "investigating"]
        .includes(getStatus(report));
    }).length;

    const completed = allReports.filter((report) => {
      return ["completed", "resolved", "closed"]
        .includes(getStatus(report));
    }).length;

    if (el.total) el.total.textContent = formatNumber(total);
    if (el.highRisk) el.highRisk.textContent = formatNumber(high);
    if (el.review) el.review.textContent = formatNumber(review);

    if (el.completed) {
      el.completed.textContent = formatNumber(completed);
    }
  }

  // ================================================
  // FILTERS
  // ================================================

  function applyFilters() {
    const search = normalize(el.search?.value);
    const selectedRisk = el.risk?.value || "all";
    const selectedCategory = el.category?.value || "all";
    const selectedDate = el.date?.value || "all";

    const now = new Date();
    const oneDay = 86400000;

    filteredReports = allReports.filter((report) => {
      const id = normalize(getId(report));
      const type = normalize(getEvidenceType(report));
      const category = normalize(getCategory(report));
      const risk = getRisk(report);
      const status = getStatus(report);

      const searchable = [
        id,
        type,
        category,
        formatCategory(category),
        risk,
        status,
      ].join(" ");

      if (search && !searchable.includes(search)) {
        return false;
      }

      if (selectedRisk !== "all" && risk !== selectedRisk) {
        return false;
      }

      if (
        selectedCategory !== "all" &&
        normalizeCategoryFilter(category) !== selectedCategory
      ) {
        return false;
      }

      if (selectedDate !== "all") {
        const date = new Date(getDate(report));

        if (Number.isNaN(date.getTime())) return false;

        const difference = now.getTime() - date.getTime();

        if (selectedDate === "today") {
          if (date.toDateString() !== now.toDateString()) {
            return false;
          }
        }

        if (selectedDate === "7days") {
          if (difference < 0 || difference > 7 * oneDay) {
            return false;
          }
        }

        if (selectedDate === "30days") {
          if (difference < 0 || difference > 30 * oneDay) {
            return false;
          }
        }
      }

      return true;
    });

    currentPage = 1;

    renderTable();
  }

  // ================================================
  // TABLE
  // ================================================

  function renderTable() {
    if (!el.table) return;

    el.table.replaceChildren();

    if (filteredReports.length === 0) {
      renderEmpty(
        "No matching reports",
        "Try changing your search term or filters."
      );

      updatePagination();
      updateExportButton();

      return;
    }

    const start = (currentPage - 1) * REPORTS_PER_PAGE;

    const records = filteredReports.slice(
      start,
      start + REPORTS_PER_PAGE
    );

    records.forEach((report) => {
      el.table.appendChild(createRow(report));
    });

    updatePagination();
    updateExportButton();
  }

  // ================================================
  // TABLE ROW
  // ================================================

  function createRow(report) {
    const row = document.createElement("tr");

    const score = getScore(report);
    const risk = getRisk(report);
    const status = getStatus(report);

    const values = [
      getId(report),
      getEvidenceType(report),
      formatCategory(getCategory(report)),
      score === null ? "N/A" : `${score}/100`,
      risk,
      status,
      formatDate(getDate(report)),
    ];

    values.forEach((value, index) => {
      const cell = document.createElement("td");

      if (index === 0) cell.className = "report-id";
      if (index === 2) cell.className = "report-category";
      if (index === 3) cell.className = "report-score";
      if (index === 6) cell.className = "report-date";

      if (index === 4 || index === 5) {
        const badge = document.createElement("span");

        badge.className = index === 4
          ? `report-risk-badge ${risk}`
          : `report-status-badge ${status}`;

        badge.textContent = value;

        cell.appendChild(badge);
      } else {
        cell.textContent = String(value);
      }

      row.appendChild(cell);
    });

    const action = document.createElement("td");

    const button = document.createElement("button");

    button.type = "button";
    button.className = "report-view-btn";

    button.innerHTML = '<i class="fa-solid fa-eye"></i> View';

    button.addEventListener("click", () => {
      openDetails(report);
    });

    action.appendChild(button);
    row.appendChild(action);

    return row;
  }

  // ================================================
  // PAGINATION
  // ================================================

  function updatePagination() {
    const total = filteredReports.length;

    const pages = Math.max(
      1,
      Math.ceil(total / REPORTS_PER_PAGE)
    );

    currentPage = Math.min(currentPage, pages);

    const start = total === 0
      ? 0
      : (currentPage - 1) * REPORTS_PER_PAGE + 1;

    const end = Math.min(
      currentPage * REPORTS_PER_PAGE,
      total
    );

    if (el.resultCount) {
      el.resultCount.textContent = `${total} report(s)`;
    }

    if (el.paginationInfo) {
      el.paginationInfo.textContent =
        `Showing ${start}-${end} of ${total} reports`;
    }

    if (el.currentPage) {
      el.currentPage.textContent = `${currentPage} / ${pages}`;
    }

    if (el.previous) {
      el.previous.disabled = currentPage <= 1;
    }

    if (el.next) {
      el.next.disabled = currentPage >= pages;
    }

    if (el.pagination) {
      el.pagination.style.display =
        total > REPORTS_PER_PAGE ? "flex" : "none";
    }
  }

  function previousPage() {
    if (currentPage <= 1) return;

    currentPage--;
    renderTable();
  }

  function nextPage() {
    const pages = Math.ceil(
      filteredReports.length / REPORTS_PER_PAGE
    );

    if (currentPage >= pages) return;

    currentPage++;
    renderTable();
  }

  // ================================================
  // DETAILS MODAL
  // ================================================

  function createDetail(label, value) {
    const wrapper = document.createElement("div");

    wrapper.className = "report-detail-item";

    const title = document.createElement("span");
    title.className = "report-detail-label";
    title.textContent = label;

    const content = document.createElement("div");
    content.className = "report-detail-value";
    content.textContent = String(value ?? "N/A");

    wrapper.append(title, content);

    return wrapper;
  }

  function openDetails(report) {
    if (!el.modal || !el.modalContent) return;

    selectedReport = report;

    const score = getScore(report);

    if (el.modalTitle) {
      el.modalTitle.textContent =
        `Report Details - ${getId(report)}`;
    }

    const grid = document.createElement("div");
    grid.className = "report-detail-grid";

    grid.append(
      createDetail("Report ID", getId(report)),
      createDetail("Evidence Type", getEvidenceType(report)),
      createDetail("Fraud Category", formatCategory(getCategory(report))),
      createDetail("Risk Score", score === null ? "N/A" : `${score}/100`),
      createDetail("Risk Level", getRisk(report)),
      createDetail("Report Status", getStatus(report)),
      createDetail("Created At", formatDate(getDate(report))),
      createDetail("Analysis Explanation", getExplanation(report))
    );

    el.modalContent.replaceChildren(grid);

    el.modal.classList.add("show");
    el.modal.setAttribute("aria-hidden", "false");

    document.body.style.overflow = "hidden";

    if (el.downloadSingle) {
      el.downloadSingle.disabled = false;
    }
  }

  function closeModal() {
    if (!el.modal) return;

    el.modal.classList.remove("show");
    el.modal.setAttribute("aria-hidden", "true");

    document.body.style.overflow = "";

    selectedReport = null;

    if (el.downloadSingle) {
      el.downloadSingle.disabled = true;
    }
  }

  // ================================================
  // CSV EXPORT
  // ================================================

  function csvEscape(value) {
    let text = String(value ?? "");

    // Prevent spreadsheet formula injection.
    if (/^[\s]*[=+\-@\t\r]/.test(text)) {
      text = "'" + text;
    }

    return `"${text.replace(/"/g, '""')}"`;
  }

  function exportCSV(records) {
    if (!records.length) {
      showNotice("No reports available to export.", "warning");
      return;
    }

    const headers = [
      "Report ID",
      "Evidence Type",
      "Fraud Category",
      "Risk Score",
      "Risk Level",
      "Status",
      "Created At",
    ];

    const rows = records.map((report) => [
      getId(report),
      getEvidenceType(report),
      formatCategory(getCategory(report)),
      getScore(report) ?? "N/A",
      getRisk(report),
      getStatus(report),
      formatDate(getDate(report)),
    ]);

    const csv = [headers, ...rows]
      .map((row) => row.map(csvEscape).join(","))
      .join("\r\n");

    const blob = new Blob(["\uFEFF" + csv], {
      type: "text/csv;charset=utf-8;",
    });

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;
    link.download =
      `scamshield-reports-${new Date().toISOString().slice(0, 10)}.csv`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(url), 1000);

    showNotice(
      `${records.length} report(s) exported successfully.`,
      "success"
    );
  }

  function updateExportButton() {
    if (el.export) {
      el.export.disabled = filteredReports.length === 0;
    }
  }

  // ================================================
  // PRINT / SAVE PDF
  // ================================================

  function printReport() {
    if (!selectedReport) return;

    const report = selectedReport;

    const printWindow = window.open(
      "",
      "_blank",
      "width=900,height=720"
    );

    if (!printWindow) {
      showNotice(
        "Please allow pop-ups to print or save the report.",
        "error"
      );

      return;
    }

    const escapeHTML = (value) =>
      String(value ?? "").replace(/[&<>"']/g, (character) => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character]);

    const score = getScore(report);

    const html = `
      <!doctype html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>ScamShield Report</title>

        <style>
          body {
            font-family: Arial, sans-serif;
            color: #172033;
            max-width: 780px;
            margin: 40px auto;
            padding: 20px;
          }

          h1 { color: #14532d; }

          .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
          }

          .item {
            background: #f3f6fa;
            padding: 14px;
            border-radius: 6px;
          }

          .label {
            display: block;
            color: #64748b;
            font-size: 11px;
            margin-bottom: 5px;
          }

          .notice {
            margin-top: 25px;
            padding: 14px;
            background: #fff9ea;
            border: 1px solid #e5c477;
          }

          @media print {
            body { margin: 0; }
          }
        </style>
      </head>

      <body>
        <h1>ScamShield AI</h1>
        <p>Security Investigation Report</p>

        <div class="grid">
          <div class="item">
            <span class="label">Report ID</span>
            ${escapeHTML(getId(report))}
          </div>

          <div class="item">
            <span class="label">Evidence Type</span>
            ${escapeHTML(getEvidenceType(report))}
          </div>

          <div class="item">
            <span class="label">Fraud Category</span>
            ${escapeHTML(formatCategory(getCategory(report)))}
          </div>

          <div class="item">
            <span class="label">Risk Score</span>
            ${score === null ? "N/A" : `${score}/100`}
          </div>

          <div class="item">
            <span class="label">Risk Level</span>
            ${escapeHTML(getRisk(report))}
          </div>

          <div class="item">
            <span class="label">Status</span>
            ${escapeHTML(getStatus(report))}
          </div>

          <div class="item">
            <span class="label">Created At</span>
            ${escapeHTML(formatDate(getDate(report)))}
          </div>
        </div>

        <h3>Assessment Explanation</h3>

        <p>${escapeHTML(getExplanation(report))}</p>

        <div class="notice">
          <strong>Important Disclaimer</strong>
          <p>
            This report contains a risk assessment, not definitive proof
            of fraud. Extracted indicators are unverified and require
            independent verification.
          </p>
        </div>

        <p>
          Generated by ScamShield AI.
        </p>

        <script>
          window.addEventListener("load", () => window.print());
        <\/script>
      </body>
      </html>
    `;

    printWindow.document.open();
    printWindow.document.write(html);
    printWindow.document.close();
  }

  // ================================================
  // CLEAR FILTERS
  // ================================================

  function clearFilters() {
    if (el.search) el.search.value = "";
    if (el.risk) el.risk.value = "all";
    if (el.category) el.category.value = "all";
    if (el.date) el.date.value = "all";

    applyFilters();
  }

  // ================================================
  // EVENTS
  // ================================================

  function initializeEvents() {
    el.search?.addEventListener("input", applyFilters);
    el.risk?.addEventListener("change", applyFilters);
    el.category?.addEventListener("change", applyFilters);
    el.date?.addEventListener("change", applyFilters);

    el.clear?.addEventListener("click", clearFilters);
    el.refresh?.addEventListener("click", fetchReports);

    el.export?.addEventListener("click", () => {
      exportCSV(filteredReports);
    });

    el.previous?.addEventListener("click", previousPage);
    el.next?.addEventListener("click", nextPage);

    el.close?.addEventListener("click", closeModal);
    el.closeDetails?.addEventListener("click", closeModal);
    el.overlay?.addEventListener("click", closeModal);

    el.downloadSingle?.addEventListener("click", printReport);

    document.addEventListener("keydown", (event) => {
      if (
        event.key === "Escape" &&
        el.modal?.classList.contains("show")
      ) {
        closeModal();
      }
    });
  }

  // ================================================
  // INITIALIZATION
  // ================================================

  function initialize() {
    if (el.currentYear) {
      el.currentYear.textContent = new Date().getFullYear();
    }

    initializeEvents();

    fetchReports();

    console.log(
      "ScamShield AI Reports Module Initialized Successfully."
    );
  }

  initialize();

});
