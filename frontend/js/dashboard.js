/*
=========================================================
 SCAMSHIELD AI - SECURITY DASHBOARD
 File: dashboard.js
 Version: 3.1.0

 Compatible with:
 frontend/pages/dashboard.html

 Architecture:
 1. Universal Input Layer
 2. Fraud Detection Engine
 3. Five Major Detection Modules
 4. Twelve Fraud Categories
 5. Four AI Agents
 6. Risk Distribution
 7. Recent Analysis Activity

 Responsibilities:
 - Verify authentication.
 - Load dashboard overview from Node.js backend.
 - Normalize API responses.
 - Display dashboard statistics.
 - Display risk distribution chart.
 - Display all 12 fraud categories.
 - Display 5 major detection module counts.
 - Display recent analysis activity.
 - Handle loading, errors and logout.
 - Support manual and automatic refresh.

 API:
 GET /api/dashboard/overview

=========================================================
*/

(() => {
    "use strict";

    /* =====================================================
       CONFIGURATION
    ===================================================== */

    const CONFIG = Object.freeze({
        VERSION: "3.1.0",
        ENDPOINT: "/dashboard/overview",
        LOGIN_PAGE: "login.html",
        MAX_ACTIVITY: 10,
        REQUEST_TIMEOUT: 30000,
        REFRESH_INTERVAL: 60000
    });

    const RISK_LEVELS = Object.freeze([
        "low",
        "medium",
        "high",
        "critical"
    ]);

    /* =====================================================
       12 FRAUD CATEGORIES
    ===================================================== */

    const CATEGORY_ALIASES = Object.freeze({

        fraud_message: [
            "fraud_message",
            "message_fraud",
            "sms_fraud"
        ],

        fraud_call: [
            "fraud_call",
            "call_fraud"
        ],

        url_phishing: [
            "url_phishing",
            "phishing_url",
            "phishing"
        ],

        email_scam: [
            "email_scam",
            "email_fraud"
        ],

        investment_scam: [
            "investment_scam",
            "investment_fraud"
        ],

        digital_arrest: [
            "digital_arrest",
            "digital_arrest_scam"
        ],

        upi_banking_fraud: [
            "upi_banking_fraud",
            "upi_fraud",
            "banking_fraud"
        ],

        card_fraud: [
            "card_fraud",
            "credit_card_fraud"
        ],

        ecommerce_scam: [
            "ecommerce_scam",
            "e_commerce_scam",
            "online_shopping_fraud"
        ],

        job_loan_scam: [
            "job_loan_scam",
            "job_scam",
            "loan_scam"
        ],

        sextortion_blackmail: [
            "sextortion_blackmail",
            "sextortion",
            "blackmail"
        ],

        social_media_scam: [
            "social_media_scam",
            "social_media_fraud"
        ]

    });

    /* =====================================================
       FIVE MAJOR DETECTION MODULES

       These modules represent the main detection groups
       in the ScamShield AI architecture.
    ===================================================== */

    const MAJOR_MODULES = Object.freeze({

        investment: [
            "investment_scam",
            "investment_fraud"
        ],

        digitalArrest: [
            "digital_arrest",
            "digital_arrest_scam"
        ],

        creditCard: [
            "card_fraud",
            "credit_card_fraud"
        ],

        sextortion: [
            "sextortion_blackmail",
            "sextortion",
            "blackmail"
        ],

        ecommerce: [
            "ecommerce_scam",
            "e_commerce_scam",
            "online_shopping_fraud"
        ]

    });

    /* =====================================================
       APPLICATION STATE
    ===================================================== */

    const state = {
        loading: false,
        requestId: 0,
        controller: null,
        refreshTimer: null,
        lastData: null,
        initialized: false
    };

    const elements = {};

    /* =====================================================
       DOM HELPERS
    ===================================================== */

    function getElement(id) {
        return document.getElementById(id);
    }

    function cacheElements() {

        const ids = [
            "dashboardDate",
            "refreshDashboard",
            "statisticsStatus",

            "totalAnalyses",
            "threatsDetected",
            "lowRiskResults",
            "highRiskResults",

            "riskChart",
            "riskLegend",

            "activityTableBody",

            "lowRiskCount",
            "mediumRiskCount",
            "highRiskCount",
            "criticalRiskCount"
        ];

        ids.forEach(id => {
            elements[id] = getElement(id);
        });

        elements.logoutButtons =
            document.querySelectorAll("[data-logout]");

        elements.platformStatuses =
            document.querySelectorAll(".platform-status");
    }

    function setText(element, value) {

        if (!element) return;

        element.textContent =
            value === null || value === undefined
                ? "—"
                : String(value);
    }

    function safeCount(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {
            return 0;
        }

        if (typeof value === "boolean") {
            return 0;
        }

        const number = Number(value);

        if (
            !Number.isFinite(number) ||
            number < 0
        ) {
            return 0;
        }

        return Math.floor(number);
    }

    function formatNumber(value) {

        return safeCount(value).toLocaleString("en-IN");
    }

    function formatDate(value) {

        const date = value
            ? new Date(value)
            : new Date();

        if (Number.isNaN(date.getTime())) {
            return "—";
        }

        return date.toLocaleDateString("en-IN", {
            day: "2-digit",
            month: "long",
            year: "numeric"
        });
    }

    function formatDateTime(value) {

        if (!value) return "—";

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return "—";
        }

        return date.toLocaleString("en-IN", {
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        });
    }

    function normalizeKey(value) {

        return String(value || "")
            .trim()
            .toLowerCase()
            .replace(/[\s-]+/g, "_");
    }

    function formatLabel(value) {

        return String(value || "Unknown")
            .replace(/[_-]+/g, " ")
            .replace(/\b\w/g, character =>
                character.toUpperCase()
            );
    }

    /* =====================================================
       API SERVICE
    ===================================================== */

    function getApi() {

        return window.ScamShieldAPI || null;
    }

    function getErrorStatus(error) {

        return (
            error?.status ??
            error?.statusCode ??
            error?.response?.status ??
            error?.response?.data?.statusCode ??
            null
        );
    }

    function isAbortError(error) {

        return (
            error?.name === "AbortError" ||
            error?.code === "ERR_CANCELED" ||
            error?.code === "ECONNABORTED"
        );
    }

    /* =====================================================
       AUTHENTICATION
    ===================================================== */

    function extractCurrentUser(response) {

        if (
            !response ||
            typeof response !== "object"
        ) {
            return null;
        }

        let current = response;

        for (let index = 0; index < 5; index++) {

            if (
                !current ||
                typeof current !== "object"
            ) {
                break;
            }

            if (
                current._id ||
                current.id ||
                current.email ||
                current.username
            ) {
                return current;
            }

            if (current.user) {
                current = current.user;
                continue;
            }

            if (current.data) {
                current = current.data;
                continue;
            }

            break;
        }

        return null;
    }

    function redirectToLogin() {

        state.requestId++;

        if (state.controller) {
            state.controller.abort();
            state.controller = null;
        }

        state.loading = false;

        if (state.refreshTimer) {
            clearInterval(state.refreshTimer);
            state.refreshTimer = null;
        }

        window.location.replace(CONFIG.LOGIN_PAGE);
    }

    async function verifyAuthentication() {

        const api = getApi();

        if (!api) {
            throw new Error(
                "API service is not initialized."
            );
        }

        if (typeof api.getToken === "function") {

            const token = await api.getToken();

            if (!token) {
                redirectToLogin();
                return false;
            }
        }

        if (typeof api.getCurrentUser === "function") {

            const response = await api.getCurrentUser();

            const user = extractCurrentUser(response);

            if (!user) {
                redirectToLogin();
                return false;
            }

            return true;
        }

        if (typeof api.getToken === "function") {
            return true;
        }

        throw new Error(
            "Authentication methods are unavailable."
        );
    }

    async function logout() {

        try {

            const api = getApi();

            if (
                api &&
                typeof api.logout === "function"
            ) {
                await api.logout();
            }

        } catch (error) {

            console.error(
                "[Dashboard] Logout error:",
                error
            );

        } finally {

            redirectToLogin();
        }
    }

    /* =====================================================
       API RESPONSE NORMALIZATION
    ===================================================== */

    function normalizeApiResponse(response) {

        let data = response;

        if (
            data &&
            typeof data === "object" &&
            data.data &&
            (
                data.status ||
                data.statusText ||
                data.config ||
                data.headers
            )
        ) {
            data = data.data;
        }

        if (
            !data ||
            typeof data !== "object"
        ) {
            throw new Error(
                "Invalid dashboard response."
            );
        }

        if (data.success === false) {

            throw new Error(
                data.message ||
                data.error ||
                "Dashboard request failed."
            );
        }

        if (
            data.data &&
            typeof data.data === "object" &&
            !Array.isArray(data.data)
        ) {
            data = data.data;
        }

        if (
            data.dashboard &&
            typeof data.dashboard === "object"
        ) {
            data = data.dashboard;

        } else if (
            data.result &&
            typeof data.result === "object"
        ) {
            data = data.result;
        }

        if (
            !data ||
            typeof data !== "object"
        ) {
            throw new Error(
                "Dashboard data is unavailable."
            );
        }

        return data;
    }

    async function fetchDashboardData(signal) {

        const api = getApi();

        if (
            !api ||
            typeof api.get !== "function"
        ) {
            throw new Error(
                "API GET method is unavailable."
            );
        }

        const response = await api.get(
            CONFIG.ENDPOINT,
            {
                signal,
                timeout: CONFIG.REQUEST_TIMEOUT
            }
        );

        return normalizeApiResponse(response);
    }

    /* =====================================================
       DATA HELPERS
    ===================================================== */

    function getFirstDefined(
        source,
        keys,
        fallback = 0
    ) {

        if (
            !source ||
            typeof source !== "object"
        ) {
            return fallback;
        }

        for (const key of keys) {

            if (
                source[key] !== undefined &&
                source[key] !== null
            ) {
                return source[key];
            }
        }

        return fallback;
    }

    function getStatistics(data) {

        return (
            data.statistics ||
            data.stats ||
            data.overview ||
            data
        );
    }

    function getRiskDistribution(data) {

        const statistics = getStatistics(data);

        return (
            data.riskDistribution ||
            data.risk_distribution ||
            data.riskStats ||
            data.risk_stats ||
            statistics.riskDistribution ||
            statistics.risk_distribution ||
            statistics.riskStats ||
            statistics.risk_stats ||
            data.risks ||
            data
        );
    }

    /* =====================================================
       STATISTICS NORMALIZATION
    ===================================================== */

    function getTotalAnalyses(data, statistics) {

        return safeCount(
            getFirstDefined(
                statistics,
                [
                    "totalAnalyses",
                    "total_analyses",
                    "totalAnalysis",
                    "total",
                    "analyses"
                ],
                getFirstDefined(
                    data,
                    [
                        "totalAnalyses",
                        "total_analyses",
                        "total"
                    ],
                    0
                )
            )
        );
    }

    function getThreatCount(data, statistics) {

        return safeCount(
            getFirstDefined(
                statistics,
                [
                    "threatsDetected",
                    "threats_detected",
                    "totalThreats",
                    "total_threats",
                    "detectedThreats",
                    "fraudDetected"
                ],
                getFirstDefined(
                    data,
                    [
                        "threatsDetected",
                        "threats_detected",
                        "totalThreats"
                    ],
                    0
                )
            )
        );
    }

    function getRiskCount(distribution, level) {

        const aliases = {

            low: [
                "low",
                "LOW",
                "lowRisk",
                "low_risk"
            ],

            medium: [
                "medium",
                "MEDIUM",
                "mediumRisk",
                "medium_risk"
            ],

            high: [
                "high",
                "HIGH",
                "highRisk",
                "high_risk"
            ],

            critical: [
                "critical",
                "CRITICAL",
                "criticalRisk",
                "critical_risk"
            ]

        };

        const value = getFirstDefined(
            distribution,
            aliases[level],
            0
        );

        if (
            typeof value === "object" &&
            value !== null
        ) {
            return safeCount(
                value.count ??
                value.total ??
                value.value ??
                0
            );
        }

        return safeCount(value);
    }

    /* =====================================================
       STATISTICS RENDERING
    ===================================================== */

    function updateStatistics(data) {

        const statistics = getStatistics(data);

        const distribution =
            getRiskDistribution(data);

        const total =
            getTotalAnalyses(data, statistics);

        const threats =
            getThreatCount(data, statistics);

        const low =
            getRiskCount(distribution, "low");

        const medium =
            getRiskCount(distribution, "medium");

        const high =
            getRiskCount(distribution, "high");

        const critical =
            getRiskCount(distribution, "critical");

        setText(
            elements.totalAnalyses,
            formatNumber(total)
        );

        setText(
            elements.threatsDetected,
            formatNumber(threats)
        );

        setText(
            elements.lowRiskResults,
            formatNumber(low)
        );

        setText(
            elements.highRiskResults,
            formatNumber(high + critical)
        );

        setText(
            elements.lowRiskCount,
            formatNumber(low)
        );

        setText(
            elements.mediumRiskCount,
            formatNumber(medium)
        );

        setText(
            elements.highRiskCount,
            formatNumber(high)
        );

        setText(
            elements.criticalRiskCount,
            formatNumber(critical)
        );

        updateStatisticsStatus(
            "success",
            "Statistics updated"
        );
    }

    function updateStatisticsStatus(
        type,
        message
    ) {

        const element = elements.statisticsStatus;

        if (!element) return;

        element.textContent = message;

        element.classList.remove(
            "success",
            "error",
            "loading"
        );

        if (type) {
            element.classList.add(type);
        }
    }

    /* =====================================================
       RISK DISTRIBUTION CHART
    ===================================================== */

    function updateRiskChart(data) {

        const chart = elements.riskChart;

        if (!chart) return;

        const distribution =
            getRiskDistribution(data);

        const values = {

            low: getRiskCount(
                distribution,
                "low"
            ),

            medium: getRiskCount(
                distribution,
                "medium"
            ),

            high: getRiskCount(
                distribution,
                "high"
            ),

            critical: getRiskCount(
                distribution,
                "critical"
            )

        };

        const total = Object.values(values)
            .reduce(
                (sum, value) => sum + value,
                0
            );

        chart.dataset.loading = "false";
        chart.dataset.empty = String(total === 0);

        const colors = {
            low: "#34d399",
            medium: "#fbbf24",
            high: "#fb923c",
            critical: "#f87171"
        };

        if (total === 0) {

            chart.style.background = "";

            const inner = document.createElement("div");
            inner.className = "risk-chart-inner";

            const number = document.createElement("strong");
            number.textContent = "0";

            const label = document.createElement("span");
            label.textContent = "Analyses";

            inner.append(number, label);

            chart.replaceChildren(inner);

            chart.setAttribute(
                "aria-label",
                "No risk analysis data available"
            );

            return;
        }

        let currentAngle = 0;

        const segments = [];

        RISK_LEVELS.forEach(level => {

            const percentage =
                (values[level] / total) * 100;

            const nextAngle =
                currentAngle + percentage;

            segments.push(
                `${colors[level]} ${currentAngle}% ${nextAngle}%`
            );

            currentAngle = nextAngle;
        });

        chart.style.background =
            `conic-gradient(${segments.join(", ")})`;

        const inner = document.createElement("div");
        inner.className = "risk-chart-inner";

        const number = document.createElement("strong");
        number.textContent = formatNumber(total);

        const label = document.createElement("span");
        label.textContent = "Analyses";

        inner.append(number, label);

        chart.replaceChildren(inner);

        chart.setAttribute(
            "aria-label",
            `Risk distribution across ${formatNumber(total)} analyses`
        );
    }

    /* =====================================================
       FRAUD CATEGORY DATA
    ===================================================== */

    function getCategoryData(data) {

        const statistics = getStatistics(data);

        return (
            data.categories ||
            data.categoryCounts ||
            data.category_counts ||
            data.fraudCategories ||
            data.fraud_categories ||

            statistics.categories ||
            statistics.categoryCounts ||
            statistics.category_counts ||
            statistics.fraudCategories ||
            statistics.fraud_categories ||

            {}
        );
    }

    function getCategoryCount(
        categoryData,
        aliases
    ) {

        if (Array.isArray(categoryData)) {

            for (const item of categoryData) {

                const key = normalizeKey(
                    item.category ||
                    item.name ||
                    item.type
                );

                if (aliases.includes(key)) {

                    return safeCount(
                        item.count ??
                        item.total ??
                        item.value ??
                        0
                    );
                }
            }

            return 0;
        }

        if (
            !categoryData ||
            typeof categoryData !== "object"
        ) {
            return 0;
        }

        for (const alias of aliases) {

            const value = categoryData[alias];

            if (
                value !== undefined &&
                value !== null
            ) {

                if (
                    typeof value === "object"
                ) {
                    return safeCount(
                        value.count ??
                        value.total ??
                        value.value ??
                        0
                    );
                }

                return safeCount(value);
            }
        }

        return 0;
    }

    /* =====================================================
       CATEGORY COUNTS RENDERING
    ===================================================== */

    function updateCategoryCounts(data) {

        const categoryData =
            getCategoryData(data);

        /*
         * Update all 12 fraud categories.
         */

        Object.entries(CATEGORY_ALIASES)
            .forEach(([category, aliases]) => {

                const element = document.querySelector(
                    `[data-category-count="${category}"]`
                );

                if (!element) return;

                const count = getCategoryCount(
                    categoryData,
                    [category, ...aliases]
                );

                setText(
                    element,
                    formatNumber(count)
                );
            });

        /*
         * Update five major detection modules.
         */

        Object.entries(MAJOR_MODULES)
            .forEach(([module, aliases]) => {

                const element = document.querySelector(
                    `[data-module-count="${module}"]`
                );

                if (!element) return;

                const count = getCategoryCount(
                    categoryData,
                    aliases
                );

                setText(
                    element,
                    formatNumber(count)
                );
            });
    }

    /* =====================================================
       RECENT ACTIVITY DATA
    ===================================================== */

    function getRecentActivity(data) {

        const activity =
            data.recentActivity ||
            data.recent_activity ||
            data.activities ||
            data.activity ||
            [];

        if (Array.isArray(activity)) {
            return activity;
        }

        if (
            activity &&
            typeof activity === "object"
        ) {

            if (Array.isArray(activity.items)) {
                return activity.items;
            }

            if (Array.isArray(activity.data)) {
                return activity.data;
            }
        }

        return [];
    }

    function normalizeActivityStatus(status) {

        const value = normalizeKey(status);

        const allowed = [
            "open",
            "investigating",
            "resolved",
            "closed",
            "pending",
            "completed",
            "failed"
        ];

        return allowed.includes(value)
            ? value
            : "unknown";
    }

    /* =====================================================
       ACTIVITY TABLE HELPERS
    ===================================================== */

    function createCell(
        value,
        className = ""
    ) {

        const cell = document.createElement("td");

        cell.textContent =
            value === null || value === undefined
                ? "—"
                : String(value);

        if (className) {
            cell.className = className;
        }

        return cell;
    }

    function createStatusBadge(status) {

        const badge = document.createElement("span");

        const normalized =
            normalizeActivityStatus(status);

        /*
         * Matches dashboard.css:
         * .activity-status.completed
         * .activity-status.resolved
         * .activity-status.open
         * etc.
         */

        badge.className =
            `activity-status ${normalized}`;

        badge.textContent =
            formatLabel(normalized);

        return badge;
    }

    function createRiskBadge(
        riskLevel,
        riskScore
    ) {

        const badge = document.createElement("span");

        const allowedLevels = [
            "low",
            "medium",
            "high",
            "critical"
        ];

        const normalized =
            normalizeKey(riskLevel);

        const level =
            allowedLevels.includes(normalized)
                ? normalized
                : "unknown";

        /*
         * Matches dashboard CSS risk-level classes.
         */

        badge.className =
            `risk-level-cell ${level}`;

        let label = formatLabel(level);

        if (
            riskScore !== undefined &&
            riskScore !== null &&
            riskScore !== ""
        ) {
            label += ` (${safeCount(riskScore)})`;
        }

        badge.textContent = label;

        return badge;
    }

    /* =====================================================
       RECENT ACTIVITY RENDERING
    ===================================================== */

    function renderRecentActivity(data) {

        const tbody = elements.activityTableBody;

        if (!tbody) return;

        const activities = getRecentActivity(data)
            .slice(0, CONFIG.MAX_ACTIVITY);

        tbody.replaceChildren();

        if (activities.length === 0) {

            const row = document.createElement("tr");

            const cell = document.createElement("td");

            cell.colSpan = 5;
            cell.className = "empty-state-cell";

            const emptyState =
                document.createElement("div");

            emptyState.className = "empty-state";

            const icon =
                document.createElement("i");

            icon.className =
                "fas fa-folder-open";

            const heading =
                document.createElement("h3");

            heading.textContent =
                "No Recent Activity";

            const description =
                document.createElement("p");

            description.textContent =
                "Your analysis activity will appear here.";

            emptyState.append(
                icon,
                heading,
                description
            );

            cell.appendChild(emptyState);

            row.appendChild(cell);

            tbody.appendChild(row);

            return;
        }

        activities.forEach(activity => {

            const row = document.createElement("tr");

            const evidenceType =
                activity.evidenceType ||
                activity.evidence_type ||
                activity.type ||
                "Unknown";

            const category =
                activity.fraudCategory ||
                activity.fraud_category ||
                activity.detectionCategory ||
                activity.detection_category ||
                activity.category ||
                "Unknown";

            const riskLevel =
                activity.riskLevel ||
                activity.risk_level ||
                "unknown";

            const riskScore =
                activity.riskScore ??
                activity.risk_score;

            const date =
                activity.analyzedAt ||
                activity.analyzed_at ||
                activity.createdAt ||
                activity.created_at ||
                activity.date;

            const status =
                activity.status ||
                activity.caseStatus ||
                activity.case_status ||
                "unknown";

            /*
             * Evidence Type
             */

            row.appendChild(
                createCell(formatLabel(evidenceType))
            );

            /*
             * Fraud Category
             */

            row.appendChild(
                createCell(formatLabel(category))
            );

            /*
             * Risk Level
             */

            const riskCell =
                document.createElement("td");

            riskCell.appendChild(
                createRiskBadge(
                    riskLevel,
                    riskScore
                )
            );

            row.appendChild(riskCell);

            /*
             * Case / Activity Status
             */

            const statusCell =
                document.createElement("td");

            statusCell.appendChild(
                createStatusBadge(status)
            );

            row.appendChild(statusCell);

            /*
             * Analysis Date
             */

            row.appendChild(
                createCell(formatDateTime(date))
            );

            tbody.appendChild(row);
        });
    }

    /* =====================================================
       PLATFORM CONNECTION STATUS
    ===================================================== */

    function updatePlatformStatus(
        status,
        message
    ) {

        if (!elements.platformStatuses) {
            return;
        }

        elements.platformStatuses.forEach(container => {

            const indicator =
                container.querySelector(
                    ".status-indicator"
                );

            const label =
                container.querySelector(
                    ".status-text"
                );

            if (indicator) {

                indicator.classList.remove(
                    "online",
                    "offline",
                    "checking"
                );

                indicator.classList.add(status);
            }

            if (label) {

                label.textContent = message;

            } else if (!indicator) {

                container.textContent = message;
            }
        });
    }

    /* =====================================================
       REFRESH BUTTON STATE
    ===================================================== */

    function setRefreshButtonLoading(loading) {

        const button =
            elements.refreshDashboard;

        if (!button) return;

        button.classList.toggle(
            "is-loading",
            loading
        );

        button.disabled = loading;

        button.setAttribute(
            "aria-busy",
            String(loading)
        );
    }

    /* =====================================================
       DASHBOARD RENDERING
    ===================================================== */

    function applyDashboardData(data) {

        updateStatistics(data);

        updateRiskChart(data);

        updateCategoryCounts(data);

        renderRecentActivity(data);

        const updatedAt =
            data.updatedAt ||
            data.updated_at ||
            data.generatedAt ||
            data.generated_at ||
            new Date();

        setText(
            elements.dashboardDate,
            formatDate(updatedAt)
        );

        state.lastData = data;

        updatePlatformStatus(
            "online",
            "Connected"
        );
    }

    /* =====================================================
       ERROR HANDLING
    ===================================================== */

    function showDashboardError(message) {

        updateStatisticsStatus(
            "error",
            message
        );

        updatePlatformStatus(
            "offline",
            "Connection issue"
        );

        if (!state.lastData) {

            if (elements.riskChart) {

                elements.riskChart.dataset.loading =
                    "false";
            }
        }

        console.error(
            "[Dashboard]",
            message
        );
    }

    /* =====================================================
       DASHBOARD DATA LOADING
    ===================================================== */

    async function loadDashboard(options = {}) {

        /*
         * Avoid unnecessary overlapping requests.
         */

        if (
            state.loading &&
            !options.force
        ) {
            return;
        }

        /*
         * Abort the previous request when refreshing.
         */

        if (state.controller) {
            state.controller.abort();
        }

        const requestId = ++state.requestId;

        const controller =
            new AbortController();

        state.controller = controller;

        state.loading = true;

        setRefreshButtonLoading(true);

        updateStatisticsStatus(
            "loading",
            "Loading dashboard..."
        );

        updatePlatformStatus(
            "checking",
            "Connecting..."
        );

        if (elements.riskChart) {

            elements.riskChart.dataset.loading =
                "true";
        }

        let timedOut = false;

        const timeoutId = setTimeout(() => {

            timedOut = true;

            controller.abort();

        }, CONFIG.REQUEST_TIMEOUT);

        try {

            /*
             * Step 1: Authentication
             */

            const authenticated =
                await verifyAuthentication();

            if (
                !authenticated ||
                requestId !== state.requestId
            ) {
                return;
            }

            /*
             * Step 2: Fetch dashboard data
             */

            const data =
                await fetchDashboardData(
                    controller.signal
                );

            if (
                requestId !== state.requestId
            ) {
                return;
            }

            /*
             * Step 3: Render dashboard
             */

            applyDashboardData(data);

        } catch (error) {

            if (
                requestId !== state.requestId
            ) {
                return;
            }

            /*
             * Unauthorized session
             */

            if (getErrorStatus(error) === 401) {

                redirectToLogin();

                return;
            }

            /*
             * Request timeout / cancellation
             */

            if (isAbortError(error)) {

                if (timedOut) {

                    showDashboardError(
                        "Dashboard request timed out. Please try again."
                    );
                }

                return;
            }

            /*
             * General API error
             */

            showDashboardError(
                error.message ||
                "Unable to load dashboard data."
            );

        } finally {

            clearTimeout(timeoutId);

            if (
                requestId === state.requestId
            ) {

                state.loading = false;

                state.controller = null;

                setRefreshButtonLoading(false);
            }
        }
    }

    /* =====================================================
       EVENT LISTENERS
    ===================================================== */

    function setupRefreshButton() {

        const button =
            elements.refreshDashboard;

        if (!button) return;

        button.addEventListener(
            "click",
            () => {
                loadDashboard({
                    force: true
                });
            }
        );
    }

    function setupLogoutButtons() {

        if (!elements.logoutButtons) {
            return;
        }

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
       AUTOMATIC REFRESH
    ===================================================== */

    function setupAutoRefresh() {

        if (state.refreshTimer) {

            clearInterval(
                state.refreshTimer
            );
        }

        state.refreshTimer = setInterval(() => {

            if (
                document.visibilityState === "visible" &&
                !state.loading
            ) {
                loadDashboard();
            }

        }, CONFIG.REFRESH_INTERVAL);
    }

    function setupVisibilityRefresh() {

        document.addEventListener(
            "visibilitychange",
            () => {

                if (
                    document.visibilityState === "visible" &&
                    !state.loading
                ) {
                    loadDashboard();
                }
            }
        );
    }

    /* =====================================================
       INITIALIZATION
    ===================================================== */

    async function init() {

        if (state.initialized) {
            return;
        }

        state.initialized = true;

        cacheElements();

        setupRefreshButton();

        setupLogoutButtons();

        setupVisibilityRefresh();

        setupAutoRefresh();

        setText(
            elements.dashboardDate,
            formatDate(new Date())
        );

        updateStatisticsStatus(
            "loading",
            "Initializing dashboard..."
        );

        updatePlatformStatus(
            "checking",
            "Connecting..."
        );

        console.info(
            `[ScamShield Dashboard] Version ${CONFIG.VERSION} initialized.`
        );

        await loadDashboard();
    }

    /* =====================================================
       PUBLIC DASHBOARD API
    ===================================================== */

    window.ScamShieldDashboard = Object.freeze({

        init,

        refresh: () => {
            return loadDashboard({
                force: true
            });
        },

        logout,

        getVersion: () => CONFIG.VERSION,

        getLastData: () => state.lastData

    });

    /* =====================================================
       DOM READY
    ===================================================== */

    if (
        document.readyState === "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            init,
            { once: true }
        );

    } else {

        init();
    }

})();