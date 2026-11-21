"use strict";

/* =========================================================
   SCAMSHIELD AI - SECURITY DASHBOARD
   Version: 4.0.0

   Features:
   1. Authenticated dashboard access
   2. Backend dashboard statistics
   3. Risk distribution visualization
   4. Five major detection modules
   5. Twelve fraud category statistics
   6. Recent analysis activity
   7. Backend connectivity status
   8. Shared API service integration
   9. Logout and session expiration handling
   10. Loading, error and empty states
   11. Safe DOM rendering
   12. Refresh functionality

   API:
   GET /api/auth/me
   GET /api/dashboard/overview
========================================================= */

(function (window, document) {

    if (window.ScamShieldDashboardInitialized) {
        return;
    }

    window.ScamShieldDashboardInitialized = true;

    /* =====================================================
       CONFIGURATION
    ===================================================== */

    const DASHBOARD_ENDPOINT = "/dashboard/overview";

    const LOGIN_PAGE = "login.html";

    const MAX_ACTIVITY_RECORDS = 10;

    const REQUEST_TIMEOUT = 30000;

    const RISK_LEVELS = [
        "low",
        "medium",
        "high",
        "critical"
    ];

    const RISK_COLORS = {
        low: "#34d399",
        medium: "#fbbf24",
        high: "#fb923c",
        critical: "#f87171"
    };

    const CATEGORY_ALIASES = {

        investment: [
            "investment",
            "investment_scam"
        ],

        digitalArrest: [
            "digitalArrest",
            "digital_arrest"
        ],

        creditCard: [
            "creditCard",
            "card_fraud",
            "credit_card_fraud"
        ],

        sextortion: [
            "sextortion",
            "sextortion_blackmail"
        ],

        ecommerce: [
            "ecommerce",
            "ecommerce_scam"
        ],

        fraud_message: [
            "fraud_message"
        ],

        fraud_call: [
            "fraud_call"
        ],

        url_phishing: [
            "url_phishing"
        ],

        email_scam: [
            "email_scam"
        ],

        upi_banking_fraud: [
            "upi_banking_fraud"
        ],

        job_loan_scam: [
            "job_loan_scam"
        ],

        social_media_scam: [
            "social_media_scam"
        ]

    };

    const MAJOR_MODULES = [
        "investment",
        "digitalArrest",
        "creditCard",
        "sextortion",
        "ecommerce"
    ];

    /* =====================================================
       DOM ELEMENTS
    ===================================================== */

    const elements = {

        dashboardDate:
            document.getElementById("dashboardDate"),

        refreshButton:
            document.getElementById("refreshDashboard"),

        platformStatus:
            document.querySelector(".platform-status"),

        statisticsStatus:
            document.getElementById("statisticsStatus"),

        totalAnalyses:
            document.getElementById("totalAnalyses"),

        threatsDetected:
            document.getElementById("threatsDetected"),

        lowRiskResults:
            document.getElementById("lowRiskResults"),

        highRiskResults:
            document.getElementById("highRiskResults"),

        riskChart:
            document.getElementById("riskChart"),

        riskLegend:
            document.getElementById("riskLegend"),

        activityTableBody:
            document.getElementById("activityTableBody"),

        logoutButtons:
            document.querySelectorAll("[data-logout]")

    };

    /* =====================================================
       STATE
    ===================================================== */

    const state = {

        loading: false,

        authenticated: false,

        lastUpdated: null,

        lastDashboardData: null,

        requestController: null,

        requestId: 0,

        initialized: false

    };

    /* =====================================================
       API SERVICE
    ===================================================== */

    function getAPI() {

        const api = window.ScamShieldAPI;

        if (!api) {

            throw new Error(
                "ScamShield API service is not loaded."
            );

        }

        return api;

    }

    /* =====================================================
       GENERAL HELPERS
    ===================================================== */

    function safeCount(value) {

        const number = Number(value);

        if (
            value === null ||
            value === undefined ||
            value === "" ||
            !Number.isFinite(number) ||
            number < 0
        ) {

            return null;

        }

        return Math.floor(number);

    }

    function formatNumber(value) {

        const number = safeCount(value);

        return number === null
            ? "—"
            : number.toLocaleString("en-IN");

    }

    function getNestedValue(object, path) {

        return path.split(".").reduce(
            (current, key) => {

                if (
                    current === null ||
                    current === undefined ||
                    typeof current !== "object"
                ) {
                    return undefined;
                }

                return current[key];

            },
            object
        );

    }

    function getFirstAvailableValue(
        object,
        paths,
        fallback = undefined
    ) {

        for (const path of paths) {

            const value = getNestedValue(
                object,
                path
            );

            if (
                value !== undefined &&
                value !== null
            ) {

                return value;

            }

        }

        return fallback;

    }

    function normalizeRiskLevel(value) {

        const level = String(value || "")
            .trim()
            .toLowerCase();

        return RISK_LEVELS.includes(level)
            ? level
            : "unknown";

    }

    function getRiskLevelFromScore(score) {

        const value = Number(score);

        if (
            !Number.isFinite(value) ||
            value < 0 ||
            value > 100
        ) {

            return "unknown";

        }

        if (value >= 75) return "critical";

        if (value >= 50) return "high";

        if (value >= 25) return "medium";

        return "low";

    }

    function isPlainObject(value) {

        return (
            value !== null &&
            typeof value === "object" &&
            !Array.isArray(value)
        );

    }

    /* =====================================================
       REDIRECT TO LOGIN
    ===================================================== */

    function redirectToLogin() {

        if (state.loading && state.requestController) {

            state.requestController.abort();

        }

        state.authenticated = false;

        state.loading = false;

        const currentPage = window.location.pathname;

        const loginPath = new URL(
            LOGIN_PAGE,
            currentPage
        );

        if (
            window.location.pathname !== loginPath.pathname
        ) {

            window.location.replace(
                loginPath.href
            );

        }

    }

    /* =====================================================
       LOGOUT
    ===================================================== */

    async function logout() {

        const api = window.ScamShieldAPI;

        try {

            if (
                api &&
                typeof api.logout === "function"
            ) {

                await api.logout();

            }

        } catch (error) {

            console.error(
                "ScamShield logout error:",
                error
            );

        } finally {

            redirectToLogin();

        }

    }

    function initializeLogout() {

        elements.logoutButtons.forEach(button => {

            button.addEventListener(
                "click",
                event => {

                    event.preventDefault();

                    logout();

                }
            );

        });

    }

    /* =====================================================
       AUTHENTICATION VERIFICATION
    ===================================================== */

    async function verifyAuthentication() {

        const api = getAPI();

        if (
            typeof api.getToken !== "function" ||
            typeof api.getCurrentUser !== "function"
        ) {

            throw new Error(
                "Authentication methods are missing from the API service."
            );

        }

        const token = api.getToken();

        if (!token) {

            const error = new Error(
                "Authentication required."
            );

            error.status = 401;

            throw error;

        }

        const user = await api.getCurrentUser();

        if (
            !user ||
            typeof user !== "object" ||
            !user.id
        ) {

            const error = new Error(
                "Unable to verify your account session."
            );

            error.status = 401;

            throw error;

        }

        state.authenticated = true;

        return user;

    }

    /* =====================================================
       DASHBOARD DATE
    ===================================================== */

    function updateDashboardDate() {

        const element = elements.dashboardDate;

        if (!element) return;

        const formattedDate = new Intl.DateTimeFormat(
            "en-IN",
            {
                weekday: "long",
                day: "2-digit",
                month: "long",
                year: "numeric"
            }
        ).format(new Date());

        element.replaceChildren();

        const icon = document.createElement("i");

        icon.className = "fa-regular fa-calendar";

        const text = document.createElement("span");

        text.textContent = formattedDate;

        element.append(icon, text);

    }

    /* =====================================================
       PLATFORM STATUS
    ===================================================== */

    function updatePlatformStatus(
        status,
        connected = false
    ) {

        const container = elements.platformStatus;

        if (!container) return;

        const indicator = document.createElement("span");

        indicator.className = "status-indicator";

        const label = document.createElement("span");

        label.className = "platform-status-text";

        label.textContent = status;

        indicator.style.backgroundColor = connected
            ? RISK_COLORS.low
            : RISK_COLORS.medium;

        indicator.style.boxShadow = connected
            ? "0 0 12px rgba(52, 211, 153, 0.4)"
            : "0 0 12px rgba(251, 191, 36, 0.4)";

        container.replaceChildren(
            indicator,
            label
        );

        container.setAttribute(
            "role",
            "status"
        );

        container.setAttribute(
            "aria-label",
            `Backend status: ${status}`
        );

        container.dataset.connected = String(connected);

    }

    /* =====================================================
       STATISTICS STATUS
    ===================================================== */

    function updateStatisticsStatus(message) {

        if (elements.statisticsStatus) {

            elements.statisticsStatus.textContent = message;

        }

    }

    /* =====================================================
       REFRESH BUTTON
    ===================================================== */

    function setRefreshButtonLoading(loading) {

        const button = elements.refreshButton;

        if (!button) return;

        button.disabled = loading;

        button.setAttribute(
            "aria-busy",
            String(loading)
        );

        button.replaceChildren();

        const icon = document.createElement("i");

        icon.className = loading
            ? "fa-solid fa-spinner fa-spin"
            : "fa-solid fa-rotate";

        const text = document.createTextNode(
            loading ? " Loading..." : " Refresh"
        );

        button.append(icon, text);

    }

    /* =====================================================
       OVERVIEW STATISTICS
    ===================================================== */

    function updateOverview(statistics = {}) {

        const total = getFirstAvailableValue(
            statistics,
            [
                "totalAnalyses",
                "total_analyses",
                "total"
            ]
        );

        const threats = getFirstAvailableValue(
            statistics,
            [
                "threatsDetected",
                "threats_detected",
                "totalThreats"
            ]
        );

        const lowRisk = getFirstAvailableValue(
            statistics,
            [
                "lowRiskResults",
                "low_risk_results",
                "lowRisk"
            ]
        );

        const highRisk = getFirstAvailableValue(
            statistics,
            [
                "highRiskResults",
                "high_risk_results",
                "highRisk"
            ]
        );

        if (elements.totalAnalyses) {

            elements.totalAnalyses.textContent =
                formatNumber(total);

        }

        if (elements.threatsDetected) {

            elements.threatsDetected.textContent =
                formatNumber(threats);

        }

        if (elements.lowRiskResults) {

            elements.lowRiskResults.textContent =
                formatNumber(lowRisk);

        }

        if (elements.highRiskResults) {

            elements.highRiskResults.textContent =
                formatNumber(highRisk);

        }

    }

    /* =====================================================
       RISK DISTRIBUTION
    ===================================================== */

    function updateRiskDistribution(risk = {}) {

        const counts = {};

        RISK_LEVELS.forEach(level => {

            counts[level] = safeCount(
                getFirstAvailableValue(
                    risk,
                    [
                        level,
                        level.toUpperCase()
                    ]
                )
            ) ?? 0;

        });

        const total = Object.values(counts).reduce(
            (sum, count) => sum + count,
            0
        );

        if (!elements.riskChart) return;

        elements.riskChart.replaceChildren();

        if (total === 0) {

            elements.riskChart.style.background =
                "conic-gradient(rgba(255,255,255,0.07) 0% 100%)";

            const placeholder = document.createElement("span");

            placeholder.className = "chart-placeholder";

            placeholder.textContent =
                "No risk distribution data available.";

            elements.riskChart.appendChild(
                placeholder
            );

            elements.riskChart.setAttribute(
                "aria-label",
                "No risk distribution data available."
            );

        } else {

            let currentPosition = 0;

            const gradientParts = [];

            RISK_LEVELS.forEach(level => {

                const percentage =
                    (counts[level] / total) * 100;

                const nextPosition =
                    currentPosition + percentage;

                gradientParts.push(
                    `${RISK_COLORS[level]} ${currentPosition}% ${nextPosition}%`
                );

                currentPosition = nextPosition;

            });

            elements.riskChart.style.background =
                `conic-gradient(${gradientParts.join(", ")})`;

            const center = document.createElement("div");

            center.className = "risk-chart-center";

            const totalElement = document.createElement("strong");

            totalElement.textContent = formatNumber(total);

            const label = document.createElement("span");

            label.textContent = "Total Results";

            center.append(
                totalElement,
                label
            );

            elements.riskChart.appendChild(center);

            elements.riskChart.setAttribute(
                "aria-label",
                `Risk distribution: ${counts.low} low, ${counts.medium} medium, ${counts.high} high and ${counts.critical} critical cases.`
            );

        }

        RISK_LEVELS.forEach(level => {

            const countElement = document.getElementById(
                `${level}RiskCount`
            );

            if (countElement) {

                countElement.textContent =
                    formatNumber(counts[level]);

            }

        });

    }

    /* =====================================================
       CATEGORY COUNT
    ===================================================== */

    function getCategoryCount(
        categories,
        aliases
    ) {

        for (const alias of aliases) {

            const value = categories[alias];

            if (
                value === undefined ||
                value === null
            ) {
                continue;
            }

            if (isPlainObject(value)) {

                return safeCount(
                    value.count ??
                    value.total ??
                    value.totalCases
                );

            }

            return safeCount(value);

        }

        return null;

    }

    /* =====================================================
       FRAUD CATEGORY STATISTICS
    ===================================================== */

    function updateFraudCategories(categories = {}) {

        if (!isPlainObject(categories)) {

            categories = {};

        }

        document.querySelectorAll(
            "[data-category-count]"
        ).forEach(element => {

            const category =
                element.dataset.categoryCount;

            const aliases =
                CATEGORY_ALIASES[category] || [category];

            const count = getCategoryCount(
                categories,
                aliases
            );

            element.textContent =
                formatNumber(count);

        });

    }

    /* =====================================================
       FIVE MAJOR DETECTION MODULES
    ===================================================== */

    function updateMajorModuleStatistics(
        categories = {}
    ) {

        MAJOR_MODULES.forEach(module => {

            const aliases =
                CATEGORY_ALIASES[module] || [module];

            const count = getCategoryCount(
                categories,
                aliases
            );

            const element = document.querySelector(
                `[data-module-count="${module}"]`
            );

            if (element) {

                element.textContent =
                    formatNumber(count);

            }

        });

    }

    /* =====================================================
       ACTIVITY DATE FORMAT
    ===================================================== */

    function formatActivityDate(value) {

        if (!value) return "N/A";

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {

            return "N/A";

        }

        return new Intl.DateTimeFormat(
            "en-IN",
            {
                day: "2-digit",
                month: "short",
                year: "numeric"
            }
        ).format(date);

    }

    /* =====================================================
       SAFE TABLE CELL
    ===================================================== */

    function createCell(
        value,
        className = ""
    ) {

        const cell = document.createElement("td");

        cell.textContent =
            value === null ||
            value === undefined ||
            value === ""
                ? "N/A"
                : String(value);

        if (className) {

            cell.className = className;

        }

        return cell;

    }

    /* =====================================================
       EMPTY ACTIVITY
    ===================================================== */

    function showEmptyActivity(
        message = "No Recent Activity",
        description = "Your analysis history will appear here when available."
    ) {

        const tbody = elements.activityTableBody;

        if (!tbody) return;

        tbody.replaceChildren();

        const row = document.createElement("tr");

        const cell = document.createElement("td");

        cell.colSpan = 6;

        cell.className = "empty-activity";

        const wrapper = document.createElement("div");

        wrapper.className = "empty-state";

        const icon = document.createElement("i");

        icon.className = "fa-solid fa-folder-open";

        const title = document.createElement("h3");

        title.textContent = message;

        const text = document.createElement("p");

        text.textContent = description;

        wrapper.append(
            icon,
            title,
            text
        );

        cell.appendChild(wrapper);

        row.appendChild(cell);

        tbody.appendChild(row);

    }

    /* =====================================================
       ACTIVITY STATUS
    ===================================================== */

    function normalizeActivityStatus(value) {

        const status = String(value || "")
            .trim()
            .toLowerCase();

        const allowedStatuses = [
            "completed",
            "resolved",
            "open",
            "investigating",
            "pending",
            "failed",
            "closed"
        ];

        return allowedStatuses.includes(status)
            ? status
            : "unknown";

    }

    /* =====================================================
       RECENT ACTIVITY
    ===================================================== */

    function renderRecentActivity(
        activities = []
    ) {

        const tbody = elements.activityTableBody;

        if (!tbody) return;

        if (
            !Array.isArray(activities) ||
            activities.length === 0
        ) {

            showEmptyActivity();

            return;

        }

        tbody.replaceChildren();

        activities
            .slice(0, MAX_ACTIVITY_RECORDS)
            .forEach(activity => {

                if (!isPlainObject(activity)) return;

                const row = document.createElement("tr");

                const evidenceType = String(
                    activity.evidenceType ||
                    activity.evidence_type ||
                    activity.type ||
                    "Unknown"
                );

                const evidenceId = String(
                    activity.evidenceId ||
                    activity.evidence_id ||
                    activity._id ||
                    ""
                );

                const category = String(
                    activity.fraudCategory ||
                    activity.fraud_category ||
                    activity.category ||
                    "Unclassified"
                );

                const riskScoreValue = Number(
                    activity.riskScore ??
                    activity.risk_score ??
                    activity.score
                );

                const validRiskScore = (
                    Number.isFinite(riskScoreValue) &&
                    riskScoreValue >= 0 &&
                    riskScoreValue <= 100
                );

                const riskScore = validRiskScore
                    ? `${riskScoreValue}/100`
                    : "N/A";

                let riskLevel = normalizeRiskLevel(
                    activity.riskLevel ||
                    activity.risk_level ||
                    activity.severity
                );

                if (
                    riskLevel === "unknown" &&
                    validRiskScore
                ) {

                    riskLevel =
                        getRiskLevelFromScore(
                            riskScoreValue
                        );

                }

                const createdAt =
                    activity.createdAt ||
                    activity.created_at ||
                    activity.date;

                const status = normalizeActivityStatus(
                    activity.status
                );

                const evidenceCell = createCell(
                    evidenceId
                        ? `${evidenceType} · ${evidenceId}`
                        : evidenceType
                );

                const categoryCell = createCell(
                    category
                );

                const scoreCell = createCell(
                    riskScore
                );

                const riskCell = createCell(
                    riskLevel === "unknown"
                        ? "N/A"
                        : riskLevel.charAt(0).toUpperCase() +
                          riskLevel.slice(1)
                );

                riskCell.className =
                    `risk-level-cell ${riskLevel}`;

                const dateCell = createCell(
                    formatActivityDate(createdAt)
                );

                const statusCell = createCell(
                    status === "unknown"
                        ? "N/A"
                        : status.charAt(0).toUpperCase() +
                          status.slice(1)
                );

                statusCell.className =
                    `activity-status ${status}`;

                row.append(
                    evidenceCell,
                    categoryCell,
                    scoreCell,
                    riskCell,
                    dateCell,
                    statusCell
                );

                tbody.appendChild(row);

            });

        if (!tbody.children.length) {

            showEmptyActivity();

        }

    }

    /* =====================================================
       RESPONSE VALIDATION
    ===================================================== */

    function validateDashboardData(data) {

        if (!isPlainObject(data)) {

            throw new Error(
                "Invalid dashboard response."
            );

        }

        if (data.success === false) {

            throw new Error(
                data.message ||
                "Unable to load dashboard data."
            );

        }

        const dashboard =
            data.data ||
            data.dashboard ||
            data.result ||
            data;

        if (!isPlainObject(dashboard)) {

            throw new Error(
                "Dashboard data is missing or invalid."
            );

        }

        return dashboard;

    }

    /* =====================================================
       APPLY DASHBOARD DATA
    ===================================================== */

    function applyDashboardData(dashboard) {

        const statistics =
            dashboard.statistics ||
            dashboard.overview ||
            {};

        const riskDistribution =
            dashboard.riskDistribution ||
            dashboard.risk_distribution ||
            dashboard.riskBreakdown ||
            dashboard.risk_breakdown ||
            dashboard.risk ||
            {};

        const fraudCategories =
            dashboard.fraudCategories ||
            dashboard.fraud_categories ||
            dashboard.categoryStatistics ||
            dashboard.category_statistics ||
            dashboard.categories ||
            {};

        const recentActivity =
            dashboard.recentActivity ||
            dashboard.recent_activity ||
            dashboard.activities ||
            dashboard.recentCases ||
            [];

        updateOverview(statistics);

        updateRiskDistribution(
            riskDistribution
        );

        updateFraudCategories(
            fraudCategories
        );

        updateMajorModuleStatistics(
            fraudCategories
        );

        renderRecentActivity(
            recentActivity
        );

        state.lastDashboardData = dashboard;

        state.lastUpdated = new Date();

        updateStatisticsStatus(
            `Last updated: ${state.lastUpdated.toLocaleTimeString("en-IN")}`
        );

    }

    /* =====================================================
       FETCH DASHBOARD DATA
    ===================================================== */

    async function fetchDashboardData(signal) {

        const api = getAPI();

        if (typeof api.get !== "function") {

            throw new Error(
                "GET method is missing from ScamShield API service."
            );

        }

        return api.get(
            DASHBOARD_ENDPOINT,
            {
                signal,
                timeout: REQUEST_TIMEOUT
            }
        );

    }

    /* =====================================================
       ERROR HANDLING
    ===================================================== */

    function showDashboardError(error) {

        console.error(
            "ScamShield Dashboard Error:",
            error
        );

        if (
            error.status === 401 ||
            error.status === 403
        ) {

            if (error.status === 401) {

                updatePlatformStatus(
                    "Session expired",
                    false
                );

                updateStatisticsStatus(
                    "Please log in again to access your dashboard."
                );

                showEmptyActivity(
                    "Session Expired",
                    "Please log in again to continue."
                );

                redirectToLogin();

                return;

            }

            updatePlatformStatus(
                "Access denied",
                false
            );

            updateStatisticsStatus(
                "Your account does not have permission to access this dashboard."
            );

            showEmptyActivity(
                "Access Denied",
                "Your account does not have permission to view this dashboard."
            );

            return;

        }

        updatePlatformStatus(
            "Backend unavailable",
            false
        );

        updateStatisticsStatus(
            state.lastUpdated
                ? `Unable to refresh. Showing previously loaded data. Last updated: ${state.lastUpdated.toLocaleTimeString("en-IN")}`
                : "Unable to load dashboard data. Check your backend connection."
        );

        if (!state.lastDashboardData) {

            showEmptyActivity(
                "Dashboard Data Unavailable",
                "Please check your backend connection and try refreshing."
            );

        }

    }

    /* =====================================================
       LOAD DASHBOARD
    ===================================================== */

    async function loadDashboard() {

        if (state.loading) return;

        state.loading = true;

        const currentRequestId =
            ++state.requestId;

        const controller = new AbortController();

        state.requestController = controller;

        const timeoutId = setTimeout(
            () => controller.abort(),
            REQUEST_TIMEOUT
        );

        setRefreshButtonLoading(true);

        updateStatisticsStatus(
            "Verifying account and loading dashboard..."
        );

        updatePlatformStatus(
            "Connecting to backend...",
            false
        );

        try {

            /*
             * STEP 1:
             * Verify the authenticated account.
             */

            if (!state.authenticated) {

                await verifyAuthentication();

            }

            if (currentRequestId !== state.requestId) {
                return;
            }

            /*
             * STEP 2:
             * Fetch dashboard statistics.
             */

            const response = await fetchDashboardData(
                controller.signal
            );

            if (currentRequestId !== state.requestId) {
                return;
            }

            /*
             * STEP 3:
             * Validate response.
             */

            const dashboard =
                validateDashboardData(response);

            /*
             * STEP 4:
             * Update dashboard UI.
             */

            applyDashboardData(dashboard);

            updatePlatformStatus(
                "Backend Connected",
                true
            );

        } catch (error) {

            if (currentRequestId !== state.requestId) {
                return;
            }

            if (
                error.name === "AbortError"
            ) {

                updateStatisticsStatus(
                    "Dashboard request timed out."
                );

                updatePlatformStatus(
                    "Connection interrupted",
                    false
                );

                return;

            }

            if (
                error.status === 401
            ) {

                state.authenticated = false;

            }

            showDashboardError(error);

        } finally {

            clearTimeout(timeoutId);

            if (currentRequestId === state.requestId) {

                state.loading = false;

                state.requestController = null;

                setRefreshButtonLoading(false);

            }

        }

    }

    /* =====================================================
       REFRESH BUTTON
    ===================================================== */

    function initializeRefreshButton() {

        if (!elements.refreshButton) return;

        elements.refreshButton.addEventListener(
            "click",
            loadDashboard
        );

    }

    /* =====================================================
       AUTHENTICATION EVENTS
    ===================================================== */

    function initializeAuthenticationEvents() {

        window.addEventListener(
            "scamshield:session-expired",
            () => {

                state.authenticated = false;

                redirectToLogin();

            }
        );

        window.addEventListener(
            "scamshield:logout",
            () => {

                state.authenticated = false;

                redirectToLogin();

            }
        );

        window.addEventListener(
            "storage",
            event => {

                if (
                    event.key === "scamshield_token" &&
                    !event.newValue
                ) {

                    state.authenticated = false;

                    redirectToLogin();

                }

            }
        );

    }

    /* =====================================================
       INITIAL DASHBOARD STATE
    ===================================================== */

    function initializeDashboardState() {

        updateDashboardDate();

        updateOverview();

        updateRiskDistribution();

        updateFraudCategories();

        updateMajorModuleStatistics();

        showEmptyActivity(
            "Loading Activity",
            "Your recent analysis activity will appear here."
        );

        updatePlatformStatus(
            "Connecting to backend...",
            false
        );

        updateStatisticsStatus(
            "Waiting for dashboard data..."
        );

    }

    /* =====================================================
       INITIALIZATION
    ===================================================== */

    function initialize() {

        if (state.initialized) return;

        state.initialized = true;

        initializeDashboardState();

        initializeRefreshButton();

        initializeLogout();

        initializeAuthenticationEvents();

        loadDashboard();

        console.log(
            "ScamShield AI Dashboard v4.0.0 initialized."
        );

    }

    /* =====================================================
       PUBLIC API
    ===================================================== */

    window.ScamShieldDashboard = Object.freeze({

        loadDashboard,

        logout,

        updateOverview,

        updateRiskDistribution,

        updateFraudCategories,

        updateMajorModuleStatistics,

        renderRecentActivity,

        getLastDashboardData() {

            return state.lastDashboardData;

        },

        getLastUpdated() {

            return state.lastUpdated;

        },

        isLoading() {

            return state.loading;

        },

        isAuthenticated() {

            return state.authenticated;

        }

    });

    /* =====================================================
       START APPLICATION
    ===================================================== */

    if (document.readyState === "loading") {

        document.addEventListener(
            "DOMContentLoaded",
            initialize,
            { once: true }
        );

    } else {

        initialize();

    }

})(window, document);