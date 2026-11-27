/* =====================================================
   SCAMSHIELD AI - REPORTS MODULE
   Version: 2.1.0
   Case + Analysis Integration

   Features:
   Search | Filters | Pagination | CSV | PDF
   Category Normalization | Accessible Modal
===================================================== */

"use strict";

document.addEventListener("DOMContentLoaded", () => {

  // ================================================
  // CONFIGURATION
  // ================================================

  const API = window.ScamShieldAPI;

  const REPORTS_PER_PAGE = 8;
  const API_ENDPOINT = "/cases?limit=100";

  const ALLOWED_RISKS = [
    "low",
    "medium",
    "high",
    "critical",
  ];

  const ALLOWED_STATUSES = [
    "open",
    "pending",
    "review",
    "under_review",
    "investigating",
    "in_progress",
    "completed",
    "resolved",
    "closed",
    "failed",
    "rejected",
    "cancelled",
    "canceled",
  ];

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

    console.error(
      "ScamShield Reports: API service unavailable."
    );

    showNotice(
      "API service unavailable. Check frontend/js/services/api.js.",
      "error"
    );

    renderEmpty(
      "API service unavailable.",
      "Please verify that the ScamShield API service is initialized."
    );

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

  let previousFocusElement = null;
  let previousBodyOverflow = "";

  // ================================================
  // GENERAL HELPERS
  // ================================================

  function normalize(value) {
    return String(value ?? "")
      .trim()
      .toLowerCase();
  }

  function formatNumber(value) {
    return Number(value || 0).toLocaleString("en-IN");
  }

  function firstValue(...values) {
    return values.find(
      value =>
        value !== undefined &&
        value !== null &&
        value !== ""
    );
  }

  function isObject(value) {
    return (
      value !== null &&
      typeof value === "object" &&
      !Array.isArray(value)
    );
  }

  function formatDate(value) {

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

  // ================================================
  // ANALYSIS OBJECT RESOLUTION
  // ================================================

  function getAnalysis(report) {

    const candidates = [
      report?.analysis,
      report?.analysisResult,
      report?.detection,
      report?.result,
      report?.aiResult,
      report?.aiAnalysis,
    ];

    for (const candidate of candidates) {

      if (isObject(candidate)) {

        if (isObject(candidate.result)) {
          return {
            ...candidate,
            ...candidate.result,
          };
        }

        return candidate;
      }
    }

    return {};
  }

  function getIntelligence(report) {

    const analysis = getAnalysis(report);

    return (
      report?.intelligence ||
      analysis?.intelligence ||
      {}
    );
  }

  // ================================================
  // REPORT ID
  // ================================================

  function getId(report) {

    return String(
      firstValue(
        report?._id,
        report?.id,
        report?.reportId,
        report?.caseId,
        "N/A"
      )
    );
  }

  // ================================================
  // RISK SCORE
  // ================================================

  function getScore(report) {

    const analysis = getAnalysis(report);

    const raw = firstValue(
      report?.riskScore,
      report?.score,
      analysis?.riskScore,
      analysis?.score,
      analysis?.result?.riskScore
    );

    if (
      raw === null ||
      raw === undefined ||
      raw === ""
    ) {
      return null;
    }

    const score = Number(raw);

    if (
      !Number.isFinite(score) ||
      score < 0 ||
      score > 100
    ) {
      return null;
    }

    return score;
  }

  // ================================================
  // RISK LEVEL
  // ================================================

  function getRisk(report) {

    const analysis = getAnalysis(report);

    const raw = normalize(
      firstValue(
        report?.riskLevel,
        report?.severity,
        analysis?.riskLevel,
        analysis?.severity,
        analysis?.result?.riskLevel
      )
    );

    if (ALLOWED_RISKS.includes(raw)) {
      return raw;
    }

    const score = getScore(report);

    if (score === null) {
      return "unknown";
    }

    if (score < 25) return "low";
    if (score < 50) return "medium";
    if (score < 75) return "high";

    return "critical";
  }

  // ================================================
  // CATEGORY NORMALIZATION
  // ================================================

  const CATEGORY_MAP = {

    fraud_message: "fraud_message",
    message_fraud: "fraud_message",

    fraud_call: "fraud_call",
    call_fraud: "fraud_call",

    url_phishing: "url_phishing",
    phishing: "url_phishing",
    url_fraud: "url_phishing",

    email_scam: "email_scam",
    email_fraud: "email_scam",

    investment_scam: "investment_scam",
    investment: "investment_scam",
    investment_fraud: "investment_scam",

    digital_arrest: "digital_arrest",
    digitalarrest: "digital_arrest",
    "digital-arrest": "digital_arrest",

    upi_banking_fraud: "upi_banking_fraud",
    upi_fraud: "upi_banking_fraud",
    banking_fraud: "upi_banking_fraud",
    upi: "upi_banking_fraud",

    card_fraud: "card_fraud",
    credit_card_fraud: "card_fraud",
    creditcard_fraud: "card_fraud",
    credit_card: "card_fraud",

    ecommerce_scam: "ecommerce_scam",
    ecommerce_fraud: "ecommerce_scam",
    "e-commerce": "ecommerce_scam",
    "e-commerce fraud": "ecommerce_scam",

    job_loan_scam: "job_loan_scam",
    job_scam: "job_loan_scam",
    loan_scam: "job_loan_scam",

    sextortion_blackmail: "sextortion_blackmail",
    sextortion: "sextortion_blackmail",
    blackmail: "sextortion_blackmail",

    social_media_scam: "social_media_scam",
    social_media_fraud: "social_media_scam",

    other: "other",
    unclassified: "unclassified",
  };

  const CATEGORY_LABELS = {

    fraud_message: "Fraud Message",
    fraud_call: "Fraud Call",
    url_phishing: "URL Phishing",
    email_scam: "Email Scam",

    investment_scam: "Investment Scam",
    digital_arrest: "Digital Arrest",

    upi_banking_fraud: "UPI & Banking Fraud",
    card_fraud: "Credit Card Fraud",

    ecommerce_scam: "E-commerce Fraud",
    job_loan_scam: "Job & Loan Scam",

    sextortion_blackmail: "Sextortion / Blackmail",
    social_media_scam: "Social Media Scam",

    other: "Other",
    unclassified: "Unclassified",
  };

  function normalizeCategory(value) {

    const raw = normalize(value);

    if (!raw) {
      return "unclassified";
    }

    const key = raw
      .replace(/[\s-]+/g, "_")
      .replace(/[^a-z0-9_]/g, "");

    return CATEGORY_MAP[key] || CATEGORY_MAP[raw] || key;
  }

  function getCategory(report) {

    const analysis = getAnalysis(report);
    const result = analysis?.result || {};
    const intelligence = getIntelligence(report);

    const raw = firstValue(

      report?.fraudCategory,
      report?.detectionCategory,
      report?.category,

      analysis?.fraudCategory,
      analysis?.detectionCategory,
      analysis?.category,

      result?.fraudCategory,
      result?.detectionCategory,
      result?.category,

      intelligence?.category,

      "unclassified"
    );

    return normalizeCategory(raw);
  }

  function formatCategory(value) {

    const category = normalizeCategory(value);

    return (
      CATEGORY_LABELS[category] ||
      category
        .replace(/_/g, " ")
        .replace(/\b\w/g, character => character.toUpperCase())
    );
  }

  // ================================================
  // CATEGORY FILTER COMPATIBILITY
  // ================================================

  const CATEGORY_FILTER_ALIASES = {

    investment: "investment_scam",
    investment_scam: "investment_scam",
    "investment scam": "investment_scam",

    "digital-arrest": "digital_arrest",
    digital_arrest: "digital_arrest",
    digitalarrest: "digital_arrest",

    "credit-card": "card_fraud",
    credit_card: "card_fraud",
    creditcard: "card_fraud",
    card_fraud: "card_fraud",

    ecommerce: "ecommerce_scam",
    "e-commerce": "ecommerce_scam",
    ecommerce_scam: "ecommerce_scam",

    sextortion: "sextortion_blackmail",
    sextortion_blackmail: "sextortion_blackmail",

    upi: "upi_banking_fraud",
    upi_banking: "upi_banking_fraud",
    upi_banking_fraud: "upi_banking_fraud",

    email: "email_scam",
    email_scam: "email_scam",

    phishing: "url_phishing",
    url_phishing: "url_phishing",

    fraud_message: "fraud_message",
    fraud_call: "fraud_call",

    job_loan: "job_loan_scam",
    job_loan_scam: "job_loan_scam",

    social_media: "social_media_scam",
    social_media_scam: "social_media_scam",
  };

  function normalizeCategoryFilter(value) {

    const raw = normalize(value);

    return (
      CATEGORY_FILTER_ALIASES[raw] ||
      normalizeCategory(raw)
    );
  }

  // ================================================
  // EVIDENCE TYPE
  // ================================================

  function getEvidenceType(report) {

    const analysis = getAnalysis(report);

    const value = firstValue(
      report?.evidenceType,
      report?.inputType,
      report?.sourceType,

      analysis?.evidenceType,
      analysis?.inputType,
      analysis?.sourceType,

      "N/A"
    );

    return String(value);
  }

  // ================================================
  // REPORT STATUS
  // ================================================

  function getStatus(report) {

    const raw = normalize(
      firstValue(
        report?.status,
        report?.caseStatus,
        "open"
      )
    );

    const aliases = {

      "under-review": "under_review",
      under_review: "under_review",

      "in-progress": "in_progress",
      in_progress: "in_progress",

      complete: "completed",

      cancel: "cancelled",
    };

    const status = aliases[raw] || raw;

    return ALLOWED_STATUSES.includes(status)
      ? status
      : "unknown";
  }

  // ================================================
  // REPORT DATE
  // ================================================

  function getDate(report) {

    const analysis = getAnalysis(report);

    return firstValue(
      report?.createdAt,
      report?.updatedAt,
      analysis?.analyzedAt,
      analysis?.createdAt,
      null
    );
  }

  // ================================================
  // EXPLANATION
  // ================================================

  function getExplanation(report) {

    const analysis = getAnalysis(report);

    const result = analysis?.result || {};

    const explanation = firstValue(

      report?.description,
      report?.explanation,
      report?.summary,

      analysis?.explanation,
      analysis?.summary,
      analysis?.riskDescription,

      result?.explanation,
      result?.summary,

      "No explanation available."
    );

    if (Array.isArray(explanation)) {
      return explanation.join("\n");
    }

    if (typeof explanation === "object") {
      return JSON.stringify(explanation, null, 2);
    }

    return String(explanation);
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

    if (!el.notice) return;

    el.notice.classList.remove("show");
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
    icon.setAttribute("aria-hidden", "true");

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

    if (!el.refresh) return;

    el.refresh.disabled = value;

    el.refresh.innerHTML = value
      ? '<i class="fa-solid fa-spinner fa-spin" aria-hidden="true"></i> Loading...'
      : '<i class="fa-solid fa-rotate" aria-hidden="true"></i> Refresh';
  }

  // ================================================
  // RESPONSE NORMALIZATION
  // ================================================

  function extractRecords(response) {

    const candidates = [

      response?.cases,
      response?.data?.cases,

      response?.data?.items,
      response?.items,

      response?.data?.results,
      response?.results,

      response?.data?.data,

      response?.data,
    ];

    for (const candidate of candidates) {

      if (Array.isArray(candidate)) {
        return candidate.filter(isObject);
      }
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

      if (
        !response ||
        response.success === false ||
        response.error
      ) {
        throw new Error(
          response?.message ||
          response?.error?.message ||
          "Unable to retrieve reports."
        );
      }

      const records = extractRecords(response);

      allReports = records.map(record => ({
        ...record,
        analysis: isObject(record.analysis)
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

    const high = allReports.filter(report => {

      const risk = getRisk(report);

      return (
        risk === "high" ||
        risk === "critical"
      );

    }).length;

    const reviewStatuses = [
      "pending",
      "review",
      "under_review",
      "open",
      "investigating",
      "in_progress",
    ];

    const completedStatuses = [
      "completed",
      "resolved",
      "closed",
    ];

    const review = allReports.filter(report => {

      return reviewStatuses.includes(
        getStatus(report)
      );

    }).length;

    const completed = allReports.filter(report => {

      return completedStatuses.includes(
        getStatus(report)
      );

    }).length;

    if (el.total) {
      el.total.textContent = formatNumber(total);
    }

    if (el.highRisk) {
      el.highRisk.textContent = formatNumber(high);
    }

    if (el.review) {
      el.review.textContent = formatNumber(review);
    }

    if (el.completed) {
      el.completed.textContent = formatNumber(completed);
    }
  }

  // ================================================
  // SEARCH
  // ================================================

  function getSearchableText(report) {

    return [

      getId(report),
      getEvidenceType(report),

      getCategory(report),
      formatCategory(getCategory(report)),

      getRisk(report),
      getStatus(report),

      getExplanation(report),

      report?.title,
      report?.description,
      report?.caseNumber,

    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();
  }

  // ================================================
  // FILTERS
  // ================================================

  function applyFilters() {

    const search = normalize(el.search?.value);

    const selectedRisk =
      el.risk?.value || "all";

    const selectedCategory =
      el.category?.value || "all";

    const selectedDate =
      el.date?.value || "all";

    const now = new Date();

    const oneDay = 86400000;

    filteredReports = allReports.filter(report => {

      const risk = getRisk(report);
      const category = getCategory(report);

      if (
        search &&
        !getSearchableText(report).includes(search)
      ) {
        return false;
      }

      if (
        selectedRisk !== "all" &&
        risk !== selectedRisk
      ) {
        return false;
      }

      if (
        selectedCategory !== "all" &&
        normalizeCategoryFilter(category) !==
          normalizeCategoryFilter(selectedCategory)
      ) {
        return false;
      }

      if (selectedDate !== "all") {

        const date = new Date(getDate(report));

        if (Number.isNaN(date.getTime())) {
          return false;
        }

        const difference =
          now.getTime() - date.getTime();

        if (selectedDate === "today") {

          if (
            date.toDateString() !== now.toDateString()
          ) {
            return false;
          }
        }

        if (selectedDate === "7days") {

          if (
            difference < 0 ||
            difference > 7 * oneDay
          ) {
            return false;
          }
        }

        if (selectedDate === "30days") {

          if (
            difference < 0 ||
            difference > 30 * oneDay
          ) {
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

    const start =
      (currentPage - 1) * REPORTS_PER_PAGE;

    const records = filteredReports.slice(
      start,
      start + REPORTS_PER_PAGE
    );

    records.forEach(report => {

      el.table.appendChild(
        createRow(report)
      );

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

      score === null
        ? "N/A"
        : `${score}/100`,

      risk,
      status,

      formatDate(getDate(report)),

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

      if (index === 4 || index === 5) {

        const badge = document.createElement("span");

        badge.className =
          index === 4
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

    button.setAttribute(
      "aria-label",
      `View report ${getId(report)}`
    );

    const icon = document.createElement("i");

    icon.className = "fa-solid fa-eye";
    icon.setAttribute("aria-hidden", "true");

    button.append(icon, document.createTextNode(" View"));

    button.addEventListener("click", () => {
      openDetails(report, button);
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

    currentPage = Math.min(
      currentPage,
      pages
    );

    const start = total === 0
      ? 0
      : (currentPage - 1) * REPORTS_PER_PAGE + 1;

    const end = Math.min(
      currentPage * REPORTS_PER_PAGE,
      total
    );

    if (el.resultCount) {

      el.resultCount.textContent =
        `${total} report(s)`;
    }

    if (el.paginationInfo) {

      el.paginationInfo.textContent =
        `Showing ${start}-${end} of ${total} reports`;
    }

    if (el.currentPage) {

      el.currentPage.textContent =
        `${currentPage} / ${pages}`;
    }

    if (el.previous) {
      el.previous.disabled = currentPage <= 1;
    }

    if (el.next) {
      el.next.disabled = currentPage >= pages;
    }

    if (el.pagination) {

      el.pagination.style.display =
        total > REPORTS_PER_PAGE
          ? "flex"
          : "none";
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
  // MODAL DETAILS
  // ================================================

  function createDetail(label, value, fullWidth = false) {

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

  function getModalFocusableElements() {

    if (!el.modal) return [];

    return Array.from(
      el.modal.querySelectorAll(
        'button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])'
      )
    ).filter(element => {

      return (
        element.offsetWidth > 0 ||
        element.offsetHeight > 0 ||
        element === document.activeElement
      );
    });
  }

  function openDetails(report, triggerElement = null) {

    if (!el.modal || !el.modalContent) {
      return;
    }

    selectedReport = report;

    previousFocusElement =
      triggerElement || document.activeElement;

    const score = getScore(report);

    if (el.modalTitle) {

      el.modalTitle.textContent =
        `Report Details - ${getId(report)}`;
    }

    const grid = document.createElement("div");

    grid.className = "report-detail-grid";

    grid.append(

      createDetail(
        "Report ID",
        getId(report)
      ),

      createDetail(
        "Evidence Type",
        getEvidenceType(report)
      ),

      createDetail(
        "Fraud Category",
        formatCategory(getCategory(report))
      ),

      createDetail(
        "Risk Score",
        score === null
          ? "N/A"
          : `${score}/100`
      ),

      createDetail(
        "Risk Level",
        getRisk(report)
      ),

      createDetail(
        "Report Status",
        getStatus(report)
      ),

      createDetail(
        "Created At",
        formatDate(getDate(report))
      ),

      createDetail(
        "Analysis Explanation",
        getExplanation(report),
        true
      )
    );

    el.modalContent.replaceChildren(grid);

    previousBodyOverflow =
      document.body.style.overflow;

    el.modal.classList.add("show");

    el.modal.setAttribute(
      "aria-hidden",
      "false"
    );

    document.body.style.overflow = "hidden";

    if (el.downloadSingle) {
      el.downloadSingle.disabled = false;
    }

    requestAnimationFrame(() => {

      if (el.close) {
        el.close.focus();
      } else {
        const focusable = getModalFocusableElements();

        focusable[0]?.focus();
      }

    });
  }

  function closeModal() {

    if (
      !el.modal ||
      !el.modal.classList.contains("show")
    ) {
      return;
    }

    el.modal.classList.remove("show");

    el.modal.setAttribute(
      "aria-hidden",
      "true"
    );

    document.body.style.overflow =
      previousBodyOverflow;

    selectedReport = null;

    if (el.downloadSingle) {
      el.downloadSingle.disabled = true;
    }

    if (
      previousFocusElement &&
      document.contains(previousFocusElement)
    ) {
      previousFocusElement.focus();
    }

    previousFocusElement = null;
  }

  // ================================================
  // MODAL KEYBOARD ACCESSIBILITY
  // ================================================

  function handleModalKeyboard(event) {

    if (
      !el.modal ||
      !el.modal.classList.contains("show")
    ) {
      return;
    }

    if (event.key === "Escape") {

      event.preventDefault();

      closeModal();

      return;
    }

    if (event.key !== "Tab") {
      return;
    }

    const focusable = getModalFocusableElements();

    if (focusable.length === 0) {

      event.preventDefault();

      el.modal.focus();

      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (event.shiftKey) {

      if (
        document.activeElement === first ||
        !el.modal.contains(document.activeElement)
      ) {

        event.preventDefault();

        last.focus();
      }

    } else {

      if (
        document.activeElement === last ||
        !el.modal.contains(document.activeElement)
      ) {

        event.preventDefault();

        first.focus();
      }
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

      showNotice(
        "No reports available to export.",
        "warning"
      );

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

    const rows = records.map(report => [

      getId(report),
      getEvidenceType(report),

      formatCategory(getCategory(report)),

      getScore(report) ?? "N/A",

      getRisk(report),
      getStatus(report),

      formatDate(getDate(report)),

    ]);

    const csv = [
      headers,
      ...rows,
    ]
      .map(row =>
        row.map(csvEscape).join(",")
      )
      .join("\r\n");

    const blob = new Blob(
      ["\uFEFF" + csv],
      {
        type: "text/csv;charset=utf-8;",
      }
    );

    const url = URL.createObjectURL(blob);

    const link = document.createElement("a");

    link.href = url;

    link.download =
      `scamshield-reports-${new Date()
        .toISOString()
        .slice(0, 10)}.csv`;

    document.body.appendChild(link);

    link.click();
    link.remove();

    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 1000);

    showNotice(
      `${records.length} report(s) exported successfully.`,
      "success"
    );
  }

  function updateExportButton() {

    if (el.export) {

      el.export.disabled =
        filteredReports.length === 0;
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

    const escapeHTML = value => {

      return String(value ?? "").replace(
        /[&<>"']/g,
        character => ({

          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",

        })[character]
      );
    };

    const score = getScore(report);

    const html = `
      <!doctype html>

      <html lang="en">

      <head>

        <meta charset="utf-8">

        <meta
          name="viewport"
          content="width=device-width, initial-scale=1"
        >

        <title>ScamShield Security Report</title>

        <style>

          * {
            box-sizing: border-box;
          }

          body {
            font-family: Arial, sans-serif;
            color: #172033;
            max-width: 780px;
            margin: 40px auto;
            padding: 20px;
            line-height: 1.6;
          }

          h1 {
            color: #14532d;
          }

          .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
          }

          .item {
            background: #f3f6fa;
            padding: 14px;
            border-radius: 6px;
            overflow-wrap: anywhere;
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

          .explanation {
            white-space: pre-wrap;
            overflow-wrap: anywhere;
          }

          @media print {

            body {
              margin: 0;
            }

            .item,
            .notice {
              break-inside: avoid;
            }
          }

          @media (max-width: 600px) {

            .grid {
              grid-template-columns: 1fr;
            }
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

        <p class="explanation">
          ${escapeHTML(getExplanation(report))}
        </p>

        <div class="notice">

          <strong>Important Disclaimer</strong>

          <p>
            This report contains a risk assessment, not definitive
            proof of fraud. Extracted indicators are unverified
            unless independently verified.
          </p>

        </div>

        <p>Generated by ScamShield AI.</p>

        <script>

          window.addEventListener("load", () => {
            window.print();
          });

        <\/script>

      </body>

      </html>
    `;

    try {

      printWindow.document.open();

      printWindow.document.write(html);

      printWindow.document.close();

    } catch (error) {

      console.error(
        "Report print error:",
        error
      );

      printWindow.close();

      showNotice(
        "Unable to prepare the report for printing.",
        "error"
      );
    }
  }

  // ================================================
  // CLEAR FILTERS
  // ================================================

  function clearFilters() {

    if (el.search) {
      el.search.value = "";
    }

    if (el.risk) {
      el.risk.value = "all";
    }

    if (el.category) {
      el.category.value = "all";
    }

    if (el.date) {
      el.date.value = "all";
    }

    applyFilters();
  }

  // ================================================
  // EVENTS
  // ================================================

  function initializeEvents() {

    el.search?.addEventListener(
      "input",
      applyFilters
    );

    el.risk?.addEventListener(
      "change",
      applyFilters
    );

    el.category?.addEventListener(
      "change",
      applyFilters
    );

    el.date?.addEventListener(
      "change",
      applyFilters
    );

    el.clear?.addEventListener(
      "click",
      clearFilters
    );

    el.refresh?.addEventListener(
      "click",
      fetchReports
    );

    el.export?.addEventListener(
      "click",
      () => exportCSV(filteredReports)
    );

    el.previous?.addEventListener(
      "click",
      previousPage
    );

    el.next?.addEventListener(
      "click",
      nextPage
    );

    el.close?.addEventListener(
      "click",
      closeModal
    );

    el.closeDetails?.addEventListener(
      "click",
      closeModal
    );

    el.overlay?.addEventListener(
      "click",
      closeModal
    );

    el.downloadSingle?.addEventListener(
      "click",
      printReport
    );

    document.addEventListener(
      "keydown",
      handleModalKeyboard
    );
  }

  // ================================================
  // INITIALIZATION
  // ================================================

  function initialize() {

    if (el.currentYear) {

      el.currentYear.textContent =
        new Date().getFullYear();
    }

    if (el.downloadSingle) {
      el.downloadSingle.disabled = true;
    }

    initializeEvents();

    fetchReports();

    console.log(
      "ScamShield AI Reports Module v2.1.0 initialized successfully."
    );
  }

  initialize();

});