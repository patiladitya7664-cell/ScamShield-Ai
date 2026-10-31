/* =====================================================
   SCAMSHIELD AI - REPORTS
   Reports Management & Filtering
===================================================== */

"use strict";

/* =====================================================
   CONFIGURATION
===================================================== */

const REPORTS_API_BASE =
  window.SCAMSHIELD_API_URL || "http://localhost:5000/api";

const REPORTS_API_URL = `${REPORTS_API_BASE}/cases?limit=50`;

const REPORTS_PER_PAGE = 8;

/* =====================================================
   DOM ELEMENTS
===================================================== */

const reportsElements = {
  totalReports: document.getElementById("totalReports"),
  highRiskReports: document.getElementById("highRiskReports"),
  reviewReports: document.getElementById("reviewReports"),
  completedReports: document.getElementById("completedReports"),

  notice: document.getElementById("reportsNotice"),
  noticeMessage: document.getElementById("reportsStatusMessage"),

  search: document.getElementById("reportSearch"),
  riskFilter: document.getElementById("riskFilter"),
  categoryFilter: document.getElementById("categoryFilter"),
  dateFilter: document.getElementById("dateFilter"),

  clearFilters: document.getElementById("clearReportFilters"),
  refresh: document.getElementById("refreshReports"),
  export: document.getElementById("exportReports"),

  resultCount: document.getElementById("reportResultCount"),
  tableBody: document.getElementById("reportsTableBody"),

  pagination: document.getElementById("reportsPagination"),
  paginationInfo: document.getElementById("paginationInfo"),
  previousPage: document.getElementById("previousPage"),
  currentPage: document.getElementById("currentPage"),
  nextPage: document.getElementById("nextPage"),

  modal: document.getElementById("reportDetailsModal"),
  modalTitle: document.getElementById("reportModalTitle"),
  modalContent: document.getElementById("reportDetailsContent"),

  closeModalOverlay: document.getElementById("closeModalOverlay"),
  closeModal: document.getElementById("closeReportModal"),
  closeDetails: document.getElementById("closeReportDetails"),

  downloadSingle: document.getElementById("downloadSingleReport"),

  currentYear: document.getElementById("currentYear"),
};

/* =====================================================
   STATE
===================================================== */

let allReports = [];
let filteredReports = [];

let currentPage = 1;
let selectedReport = null;

let isLoadingReports = false;

/* =====================================================
   HELPERS
===================================================== */

function reportElementExists(element) {
  return Boolean(element);
}

function formatReportNumber(value) {
  const number = Number(value);

  return Number.isFinite(number) ? number.toLocaleString("en-IN") : "0";
}

function normalizeReportValue(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function formatReportDate(value) {
  if (!value) return "N/A";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "N/A";
  }

  return date.toLocaleString("en-IN", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatCategory(value) {
  const categories = {
    investment: "Investment Scam",
    "digital-arrest": "Digital Arrest",
    digital_arrest: "Digital Arrest",
    "credit-card": "Credit Card Fraud",
    credit_card: "Credit Card Fraud",
    sextortion: "Sextortion",
    ecommerce: "E-commerce Fraud",
    "e-commerce": "E-commerce Fraud",
  };

  const normalized = normalizeReportValue(value);

  return categories[normalized] || value || "Unclassified";
}

function normalizeRisk(value, score) {
  const normalized = normalizeReportValue(value);

  if (["low", "medium", "high", "critical"].includes(normalized)) {
    return normalized;
  }

  const numericScore = Number(score);

  if (!Number.isFinite(numericScore)) {
    return "unknown";
  }

  if (numericScore <= 24) return "low";
  if (numericScore <= 49) return "medium";
  if (numericScore <= 74) return "high";

  return "critical";
}

function normalizeStatus(value) {
  const normalized = normalizeReportValue(value);

  if (
    ["pending", "review", "completed", "resolved", "failed"].includes(
      normalized,
    )
  ) {
    return normalized;
  }

  return "pending";
}

function getReportId(report) {
  return report.reportId || report._id || report.id || "N/A";
}

function getReportScore(report) {
  const score = Number(report.riskScore ?? report.score);

  return Number.isFinite(score) ? Math.min(100, Math.max(0, score)) : 0;
}

function getReportCategory(report) {
  return report.fraudCategory || report.category || "Unclassified";
}

function getReportEvidenceType(report) {
  return report.evidenceType || report.type || "N/A";
}

function getReportDate(report) {
  return report.createdAt || report.date || report.timestamp || null;
}

/* =====================================================
   NOTICE SYSTEM
===================================================== */

function showReportsNotice(message, state = "info") {
  if (!reportsElements.notice) return;

  reportsElements.notice.classList.add("show");

  reportsElements.notice.dataset.state = state;

  if (reportsElements.noticeMessage) {
    reportsElements.noticeMessage.textContent = message;
  }
}

function hideReportsNotice() {
  if (!reportsElements.notice) return;

  reportsElements.notice.classList.remove("show");
}

/* =====================================================
   EMPTY STATE
===================================================== */

function renderEmptyState(
  message = "No reports found.",
  description = "Reports will appear here when analysis records are available.",
) {
  if (!reportsElements.tableBody) return;

  reportsElements.tableBody.replaceChildren();

  const row = document.createElement("tr");
  const cell = document.createElement("td");

  cell.colSpan = 8;

  const wrapper = document.createElement("div");
  wrapper.className = "reports-empty-state";

  const icon = document.createElement("i");
  icon.className = "fa-solid fa-folder-open";

  const heading = document.createElement("h3");
  heading.textContent = message;

  const paragraph = document.createElement("p");
  paragraph.textContent = description;

  wrapper.append(icon, heading, paragraph);
  cell.appendChild(wrapper);
  row.appendChild(cell);

  reportsElements.tableBody.appendChild(row);
}

/* =====================================================
   LOADING STATE
===================================================== */

function setReportsLoading(loading) {
  isLoadingReports = loading;

  if (reportsElements.refresh) {
    reportsElements.refresh.disabled = loading;

    reportsElements.refresh.innerHTML = loading
      ? '<i class="fa-solid fa-spinner fa-spin"></i> Loading...'
      : '<i class="fa-solid fa-rotate"></i> Refresh';
  }

  if (loading) {
    renderEmptyState(
      "Loading reports...",
      "Please wait while report records are being retrieved.",
    );
  }
}

/* =====================================================
   API REQUEST
===================================================== */

async function fetchReports() {
  if (isLoadingReports) return;

  setReportsLoading(true);
  hideReportsNotice();

  try {
    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, 20000);

    let response;

    try {
      response = await fetch(REPORTS_API_URL, {
        method: "GET",
        headers: {
          Accept: "application/json",
          Authorization: `Bearer ${localStorage.getItem("scamshieldToken") || sessionStorage.getItem("scamshieldToken") || ""}`,
        },
        credentials: "include",
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    let data;

    try {
      data = await response.json();
    } catch {
      throw new Error("The server returned an invalid response.");
    }

    if (!response.ok || data.success === false) {
      throw new Error(
        data.message || `Unable to load reports (${response.status}).`,
      );
    }

    const records = Array.isArray(data.reports)
      ? data.reports
      : Array.isArray(data.data?.reports)
        ? data.data.reports
        : Array.isArray(data.data)
          ? data.data
          : [];

    allReports = records.map((record) => ({
      ...record,
      reportId: record.reportId || record._id || record.id,
      evidenceType: record.evidenceType || record.analysis?.evidenceType || "message",
      fraudCategory: record.fraudCategory || record.analysis?.fraudCategory,
      riskScore: record.riskScore ?? record.analysis?.riskScore,
      riskLevel: record.riskLevel || record.analysis?.riskLevel,
      explanation: record.explanation || record.analysis?.summary,
      createdAt: record.createdAt || record.analysis?.analyzedAt,
      indicators: record.indicators || record.analysis?.indicators || [],
    }));

    currentPage = 1;

    updateReportStatistics();
    applyReportFilters();

    if (allReports.length === 0) {
      showReportsNotice("No report records are currently available.", "info");
    } else {
      showReportsNotice(
        `${allReports.length} report record(s) loaded successfully.`,
        "success",
      );
    }
  } catch (error) {
    console.error("Reports API Error:", error);

    allReports = [];
    filteredReports = [];

    updateReportStatistics();
    renderEmptyState(
      "Unable to load reports",
      error.name === "AbortError"
        ? "The request timed out. Please try again."
        : error.message,
    );

    updateReportPagination();

    showReportsNotice(
      error.message || "Could not connect to the reports server.",
      "error",
    );
  } finally {
    setReportsLoading(false);
  }
}

/* =====================================================
   STATISTICS
===================================================== */

function updateReportStatistics() {
  const total = allReports.length;

  const highRisk = allReports.filter((report) => {
    const risk = normalizeRisk(report.riskLevel, getReportScore(report));

    return risk === "high" || risk === "critical";
  }).length;

  const review = allReports.filter((report) => {
    const status = normalizeStatus(report.status);

    return status === "pending" || status === "review";
  }).length;

  const completed = allReports.filter((report) => {
    const status = normalizeStatus(report.status);

    return status === "completed" || status === "resolved";
  }).length;

  if (reportsElements.totalReports) {
    reportsElements.totalReports.textContent = formatReportNumber(total);
  }

  if (reportsElements.highRiskReports) {
    reportsElements.highRiskReports.textContent = formatReportNumber(highRisk);
  }

  if (reportsElements.reviewReports) {
    reportsElements.reviewReports.textContent = formatReportNumber(review);
  }

  if (reportsElements.completedReports) {
    reportsElements.completedReports.textContent =
      formatReportNumber(completed);
  }
}

/* =====================================================
   FILTERING
===================================================== */

function applyReportFilters() {
  const searchTerm = normalizeReportValue(reportsElements.search?.value);

  const selectedRisk = reportsElements.riskFilter?.value || "all";

  const selectedCategory = reportsElements.categoryFilter?.value || "all";

  const selectedDate = reportsElements.dateFilter?.value || "all";

  const now = new Date();

  filteredReports = allReports.filter((report) => {
    const reportId = normalizeReportValue(getReportId(report));

    const evidenceType = normalizeReportValue(getReportEvidenceType(report));

    const category = normalizeReportValue(getReportCategory(report));

    const risk = normalizeRisk(report.riskLevel, getReportScore(report));

    const status = normalizeStatus(report.status);

    const searchableText = [
      reportId,
      evidenceType,
      category,
      risk,
      status,
    ].join(" ");

    if (searchTerm && !searchableText.includes(searchTerm)) {
      return false;
    }

    if (selectedRisk !== "all" && risk !== selectedRisk) {
      return false;
    }

    if (
      selectedCategory !== "all" &&
      normalizeCategoryForFilter(category) !== selectedCategory
    ) {
      return false;
    }

    if (selectedDate !== "all") {
      const reportDate = new Date(getReportDate(report));

      if (Number.isNaN(reportDate.getTime())) {
        return false;
      }

      const difference = now.getTime() - reportDate.getTime();

      const oneDay = 24 * 60 * 60 * 1000;

      if (selectedDate === "today") {
        if (reportDate.toDateString() !== now.toDateString()) {
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

  renderReportsTable();
}

/* =====================================================
   CATEGORY FILTER NORMALIZATION
===================================================== */

function normalizeCategoryForFilter(category) {
  const value = normalizeReportValue(category);

  const aliases = {
    "investment scam": "investment",
    investment: "investment",

    "digital arrest": "digital-arrest",
    "digital arrest scam": "digital-arrest",
    "digital-arrest": "digital-arrest",
    digital_arrest: "digital-arrest",

    "credit card fraud": "credit-card",
    "credit card": "credit-card",
    "credit-card": "credit-card",
    credit_card: "credit-card",

    sextortion: "sextortion",

    "e-commerce fraud": "ecommerce",
    "e-commerce": "ecommerce",
    ecommerce: "ecommerce",
  };

  return aliases[value] || value;
}

/* =====================================================
   TABLE RENDERING
===================================================== */

function renderReportsTable() {
  if (!reportsElements.tableBody) return;

  reportsElements.tableBody.replaceChildren();

  if (filteredReports.length === 0) {
    renderEmptyState(
      "No matching reports",
      "Try changing your search term or filters.",
    );

    updateReportPagination();
    updateReportExportButton();

    return;
  }

  const startIndex = (currentPage - 1) * REPORTS_PER_PAGE;

  const currentReports = filteredReports.slice(
    startIndex,
    startIndex + REPORTS_PER_PAGE,
  );

  currentReports.forEach((report) => {
    const row = createReportRow(report);

    reportsElements.tableBody.appendChild(row);
  });

  updateReportPagination();
  updateReportExportButton();
}

/* =====================================================
   CREATE REPORT ROW
===================================================== */

function createReportRow(report) {
  const row = document.createElement("tr");

  const reportId = getReportId(report);
  const evidenceType = getReportEvidenceType(report);
  const category = getReportCategory(report);
  const score = getReportScore(report);

  const risk = normalizeRisk(report.riskLevel, score);

  const status = normalizeStatus(report.status);

  const date = formatReportDate(getReportDate(report));

  const values = [
    reportId,
    evidenceType,
    formatCategory(category),
    `${score}/100`,
    risk,
    status,
    date,
  ];

  values.forEach((value, index) => {
    const cell = document.createElement("td");

    if (index === 0) {
      cell.className = "report-id";
    }

    if (index === 2) {
      cell.className = "report-category";
    }

    if (index === 3) {
      cell.className = "report-score";
    }

    if (index === 6) {
      cell.className = "report-date";
    }

    if (index === 4) {
      const badge = document.createElement("span");

      badge.className = `report-risk-badge ${risk}`;
      badge.textContent = risk;

      cell.appendChild(badge);
    } else if (index === 5) {
      const badge = document.createElement("span");

      badge.className = `report-status-badge ${status}`;
      badge.textContent = status;

      cell.appendChild(badge);
    } else {
      cell.textContent = String(value);
    }

    row.appendChild(cell);
  });

  const actionCell = document.createElement("td");

  const viewButton = document.createElement("button");

  viewButton.type = "button";
  viewButton.className = "report-view-btn";

  viewButton.innerHTML = '<i class="fa-solid fa-eye"></i> View';

  viewButton.addEventListener("click", () => {
    openReportDetails(report);
  });

  actionCell.appendChild(viewButton);
  row.appendChild(actionCell);

  return row;
}

/* =====================================================
   PAGINATION
===================================================== */

function updateReportPagination() {
  const total = filteredReports.length;

  const totalPages = Math.max(1, Math.ceil(total / REPORTS_PER_PAGE));

  currentPage = Math.min(currentPage, totalPages);

  const start = total === 0 ? 0 : (currentPage - 1) * REPORTS_PER_PAGE + 1;

  const end = Math.min(currentPage * REPORTS_PER_PAGE, total);

  if (reportsElements.resultCount) {
    reportsElements.resultCount.textContent = `${total} report(s)`;
  }

  if (reportsElements.paginationInfo) {
    reportsElements.paginationInfo.textContent = `Showing ${start}-${end} of ${total} reports`;
  }

  if (reportsElements.currentPage) {
    reportsElements.currentPage.textContent = `${currentPage} / ${totalPages}`;
  }

  if (reportsElements.previousPage) {
    reportsElements.previousPage.disabled = currentPage <= 1;
  }

  if (reportsElements.nextPage) {
    reportsElements.nextPage.disabled = currentPage >= totalPages;
  }

  if (reportsElements.pagination) {
    reportsElements.pagination.style.display =
      total > REPORTS_PER_PAGE ? "flex" : "none";
  }
}

function goToPreviousReportPage() {
  if (currentPage <= 1) return;

  currentPage--;

  renderReportsTable();
}

function goToNextReportPage() {
  const totalPages = Math.ceil(filteredReports.length / REPORTS_PER_PAGE);

  if (currentPage >= totalPages) return;

  currentPage++;

  renderReportsTable();
}

/* =====================================================
   REPORT DETAILS MODAL
===================================================== */

function createDetailItem(label, value, fullWidth = false) {
  const wrapper = document.createElement("div");

  wrapper.className = fullWidth
    ? "report-detail-item full-width"
    : "report-detail-item";

  const title = document.createElement("span");

  title.className = "report-detail-label";
  title.textContent = label;

  const content = document.createElement("div");

  content.className = "report-detail-value";
  content.textContent = String(value ?? "N/A");

  wrapper.append(title, content);

  return wrapper;
}

function openReportDetails(report) {
  if (!reportsElements.modal || !reportsElements.modalContent) {
    return;
  }

  selectedReport = report;

  const reportId = getReportId(report);
  const score = getReportScore(report);

  const risk = normalizeRisk(report.riskLevel, score);

  const status = normalizeStatus(report.status);

  if (reportsElements.modalTitle) {
    reportsElements.modalTitle.textContent = `Report Details - ${reportId}`;
  }

  const details = document.createElement("div");

  details.className = "report-detail-grid";

  details.append(
    createDetailItem("Report ID", reportId),
    createDetailItem("Evidence Type", getReportEvidenceType(report)),
    createDetailItem(
      "Fraud Category",
      formatCategory(getReportCategory(report)),
    ),
    createDetailItem("Risk Score", `${score}/100`),
    createDetailItem("Risk Level", risk),
    createDetailItem("Report Status", status),
    createDetailItem("Created At", formatReportDate(getReportDate(report))),
    createDetailItem(
      "Analysis Explanation",
      report.explanation ||
        report.riskExplanation ||
        "No explanation is available for this report.",
      true,
    ),
  );

  reportsElements.modalContent.replaceChildren(details);

  reportsElements.modal.classList.add("show");
  reportsElements.modal.setAttribute("aria-hidden", "false");

  document.body.style.overflow = "hidden";

  if (reportsElements.downloadSingle) {
    reportsElements.downloadSingle.disabled = false;
  }
}

function closeReportDetailsModal() {
  if (!reportsElements.modal) return;

  reportsElements.modal.classList.remove("show");
  reportsElements.modal.setAttribute("aria-hidden", "true");

  document.body.style.overflow = "";

  selectedReport = null;

  if (reportsElements.downloadSingle) {
    reportsElements.downloadSingle.disabled = true;
  }
}

/* =====================================================
   CSV EXPORT
===================================================== */

function escapeCSVValue(value) {
  const text = String(value ?? "");

  return `"${text.replace(/"/g, '""')}"`;
}

function exportReportsCSV(reports) {
  if (!reports.length) {
    showReportsNotice("There are no report records to export.", "warning");

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

  const rows = reports.map((report) => [
    getReportId(report),
    getReportEvidenceType(report),
    formatCategory(getReportCategory(report)),
    getReportScore(report),
    normalizeRisk(report.riskLevel, getReportScore(report)),
    normalizeStatus(report.status),
    formatReportDate(getReportDate(report)),
  ]);

  const csvContent = [headers, ...rows]
    .map((row) => row.map(escapeCSVValue).join(","))
    .join("\r\n");

  const blob = new Blob(["\uFEFF" + csvContent], {
    type: "text/csv;charset=utf-8;",
  });

  const url = URL.createObjectURL(blob);

  const link = document.createElement("a");

  link.href = url;
  link.download = `scamshield-reports-${new Date()
    .toISOString()
    .slice(0, 10)}.csv`;

  document.body.appendChild(link);

  link.click();
  link.remove();

  URL.revokeObjectURL(url);

  showReportsNotice(
    `${reports.length} report(s) exported successfully.`,
    "success",
  );
}

function updateReportExportButton() {
  if (!reportsElements.export) return;

  reportsElements.export.disabled = filteredReports.length === 0;
}

/* =====================================================
   SINGLE REPORT PRINT / SAVE AS PDF
===================================================== */

function downloadSingleReport() {
  if (!selectedReport) return;

  const safeReport = {
    reportId: getReportId(selectedReport),
    evidenceType: getReportEvidenceType(selectedReport),
    fraudCategory: formatCategory(getReportCategory(selectedReport)),
    riskScore: getReportScore(selectedReport),
    riskLevel: normalizeRisk(
      selectedReport.riskLevel,
      getReportScore(selectedReport),
    ),
    status: normalizeStatus(selectedReport.status),
    createdAt: formatReportDate(getReportDate(selectedReport)),
    explanation:
      selectedReport.explanation ||
      selectedReport.riskExplanation ||
      "Not available",
    indicators: Array.isArray(selectedReport.indicators)
      ? selectedReport.indicators
      : [],
  };

  const printWindow = window.open("", "_blank", "width=900,height=720");

  if (!printWindow) {
    showReportsNotice("Allow pop-ups to print or save the report as PDF.", "error");
    return;
  }

  const escapeHtml = (value) =>
    String(value ?? "").replace(/[&<>"']/g, (character) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    })[character]);

  const indicatorRows = safeReport.indicators.length
    ? safeReport.indicators
        .map((item) => {
          const type = typeof item === "object" ? item.type : "clue";
          const value = typeof item === "object" ? item.value : item;
          return `<li><b>${escapeHtml(type || "clue")}:</b> ${escapeHtml(value)} <small>Unverified</small></li>`;
        })
        .join("")
    : "<li>No indicators recorded.</li>";

  printWindow.document.write(`<!doctype html><html><head><meta charset="utf-8"><title>ScamShield case ${escapeHtml(safeReport.reportId)}</title><style>
    body{font:15px/1.55 Arial,sans-serif;color:#172033;max-width:780px;margin:40px auto;padding:0 24px}h1{margin-bottom:4px;color:#0b2340}h2{font-size:17px;margin:26px 0 8px;border-bottom:1px solid #ccd5df;padding-bottom:5px}.sub{color:#52657b;font-size:12px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.item{padding:12px;background:#f3f6fa;border-radius:6px}.label{display:block;color:#607187;font-size:10px;text-transform:uppercase;letter-spacing:.08em}.value{font-weight:700}.notice{margin-top:22px;padding:12px;border:1px solid #d8a951;background:#fff9ea;border-radius:6px;font-size:12px}li{margin:8px 0}small{color:#9a6900;margin-left:8px}.footer{margin-top:32px;border-top:1px solid #ccd5df;padding-top:10px;font-size:11px;color:#52657b}@media print{body{margin:0 auto}.notice{break-inside:avoid}}
  </style></head><body><h1>ScamShield AI</h1><div class="sub">Cyber fraud case report draft · Prepared ${escapeHtml(safeReport.createdAt)}</div><h2>Case summary</h2><div class="grid"><div class="item"><span class="label">Case ID</span><span class="value">${escapeHtml(safeReport.reportId)}</span></div><div class="item"><span class="label">Fraud category</span><span class="value">${escapeHtml(safeReport.fraudCategory)}</span></div><div class="item"><span class="label">Risk assessment</span><span class="value">${escapeHtml(safeReport.riskLevel)} · ${escapeHtml(safeReport.riskScore)}/100</span></div><div class="item"><span class="label">Review status</span><span class="value">${escapeHtml(safeReport.status)}</span></div></div><h2>Assessment</h2><p>${escapeHtml(safeReport.explanation)}</p><h2>Extracted clues</h2><ul>${indicatorRows}</ul><div class="notice"><b>Human review required.</b> This is a rule-based risk assessment, not proof of fraud. Extracted identifiers are unverified clues. Verify details and review evidence before making a report. This draft is not submitted to any government system.</div><div class="footer">For suspected financial cyber fraud in India, contact 1930 promptly and use the official portal at cybercrime.gov.in. Preserve original evidence securely.</div><script>window.addEventListener('load',()=>window.print());</script></body></html>`);
  printWindow.document.close();
}

/* =====================================================
   CLEAR FILTERS
===================================================== */

function clearReportFilters() {
  if (reportsElements.search) {
    reportsElements.search.value = "";
  }

  if (reportsElements.riskFilter) {
    reportsElements.riskFilter.value = "all";
  }

  if (reportsElements.categoryFilter) {
    reportsElements.categoryFilter.value = "all";
  }

  if (reportsElements.dateFilter) {
    reportsElements.dateFilter.value = "all";
  }

  applyReportFilters();
}

/* =====================================================
   EVENT LISTENERS
===================================================== */

function initializeReportsEvents() {
  reportsElements.search?.addEventListener("input", applyReportFilters);

  reportsElements.riskFilter?.addEventListener("change", applyReportFilters);

  reportsElements.categoryFilter?.addEventListener(
    "change",
    applyReportFilters,
  );

  reportsElements.dateFilter?.addEventListener("change", applyReportFilters);

  reportsElements.clearFilters?.addEventListener("click", clearReportFilters);

  reportsElements.refresh?.addEventListener("click", fetchReports);

  reportsElements.export?.addEventListener("click", () =>
    exportReportsCSV(filteredReports),
  );

  reportsElements.previousPage?.addEventListener(
    "click",
    goToPreviousReportPage,
  );

  reportsElements.nextPage?.addEventListener("click", goToNextReportPage);

  reportsElements.closeModal?.addEventListener(
    "click",
    closeReportDetailsModal,
  );

  reportsElements.closeDetails?.addEventListener(
    "click",
    closeReportDetailsModal,
  );

  reportsElements.closeModalOverlay?.addEventListener(
    "click",
    closeReportDetailsModal,
  );

  reportsElements.downloadSingle?.addEventListener(
    "click",
    downloadSingleReport,
  );

  document.addEventListener("keydown", (event) => {
    if (
      event.key === "Escape" &&
      reportsElements.modal?.classList.contains("show")
    ) {
      closeReportDetailsModal();
    }
  });
}

/* =====================================================
   INITIALIZATION
===================================================== */

function initializeReportsPage() {
  if (reportsElements.currentYear) {
    reportsElements.currentYear.textContent = new Date().getFullYear();
  }

  initializeReportsEvents();

  fetchReports();
}

document.addEventListener("DOMContentLoaded", initializeReportsPage);
