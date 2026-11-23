"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI - EVIDENCE ANALYSIS
 * =========================================================
 *
 * File: frontend/js/analysis.js
 * Version: 3.0.0
 *
 * Features:
 * 1. Universal evidence submission
 * 2. Four-agent result integration
 * 3. Guardian authoritative risk assessment
 * 4. Intelligence indicator rendering
 * 5. Victim Safety recommendations
 * 6. Controlled Decoy status
 * 7. Gemini advisory-compatible response handling
 * 8. Risk score visualization
 * 9. JWT authentication
 * 10. Request timeout and error handling
 * 11. Accessible status feedback
 * 12. Character counter
 * 13. Safe DOM rendering
 * 14. Responsive result interactions
 *
 * API:
 * POST /api/agents/run
 *
 * Request:
 * {
 *   evidenceType: "message",
 *   evidence: "Suspicious content"
 * }
 *
 * =========================================================
 */

(() => {

    "use strict";

    /* =====================================================
       CONFIGURATION
    ===================================================== */

    const CONFIG = Object.freeze({

        VERSION: "3.0.0",

        API_BASE_URL: (
            window.SCAMSHIELD_API_URL ||
            "http://localhost:5000/api"
        ).replace(/\/+$/, ""),

        API_ENDPOINT: "/agents/run",

        TOKEN_KEY: "scamshieldToken",

        MAX_EVIDENCE_LENGTH: 20000,

        REQUEST_TIMEOUT: 45000,

        ALLOWED_EVIDENCE_TYPES: [
            "message",
            "url",
            "call",
            "transaction",
            "screenshot",
            "email"
        ],

        RISK_LEVELS: [
            "low",
            "medium",
            "high",
            "critical"
        ]

    });


    let isAnalyzing = false;

    let activeController = null;

    let originalButtonText = "Analyze Evidence";


    /* =====================================================
       DOM ELEMENTS
    ===================================================== */

    const elements = {

        form: document.getElementById("analysisForm"),

        evidenceType: document.getElementById("evidenceType"),

        evidence: document.getElementById("evidenceInput"),

        characterCount: document.getElementById("characterCount"),

        submitButton: document.getElementById("analyzeButton"),

        resetButton: document.getElementById("resetAnalysis"),

        status: document.getElementById("analysisStatus"),

        results: document.getElementById("analysisResults"),

        riskScore: document.getElementById("riskScore"),

        riskLevel: document.getElementById("riskLevel"),

        fraudCategory: document.getElementById("fraudCategory"),

        summary: document.getElementById("analysisSummary"),

        explanation: document.getElementById("analysisExplanation"),

        indicators: document.getElementById("analysisIndicators"),

        disclaimer: document.getElementById("analysisDisclaimer"),

        analysisId: document.getElementById("analysisId"),

        guardian: document.getElementById("guardianResults"),

        intelligence: document.getElementById("intelligenceResults"),

        victimSafety: document.getElementById("victimSafetyResults"),

        decoy: document.getElementById("decoyResults"),

        currentYear: document.getElementById("currentYear")

    };


    /* =====================================================
       GENERAL HELPERS
    ===================================================== */

    function isObject(value) {

        return (
            value !== null &&
            typeof value === "object" &&
            !Array.isArray(value)
        );

    }


    function hasValue(value) {

        return (
            value !== null &&
            value !== undefined &&
            value !== ""
        );

    }


    function createElement(tag, className = "", text = "") {

        const element = document.createElement(tag);

        if (className) {
            element.className = className;
        }

        if (text !== null && text !== undefined) {

            element.textContent = String(text);

        }

        return element;

    }


    function clearElement(element) {

        if (element) {

            element.replaceChildren();

        }

    }


    function updateText(element, value, fallback = "--") {

        if (!element) return;

        element.textContent = hasValue(value)
            ? String(value)
            : fallback;

    }


    function formatLabel(value) {

        if (!hasValue(value)) {
            return "Unknown";
        }

        return String(value)

            .replace(/([a-z])([A-Z])/g, "$1 $2")

            .replace(/[_-]/g, " ")

            .replace(/\b\w/g, character =>
                character.toUpperCase()
            );

    }


    /**
     * Prevent accidental [object Object] output.
     */

    function formatValue(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return "Not available";

        }


        if (typeof value === "boolean") {

            return value ? "Yes" : "No";

        }


        if (typeof value === "number") {

            return Number.isFinite(value)
                ? String(value)
                : "Not available";

        }


        if (Array.isArray(value)) {

            if (!value.length) {
                return "No records found";
            }

            return value
                .map(formatValue)
                .join(", ");

        }


        if (isObject(value)) {

            const entries = Object.entries(value)
                .filter(([, item]) => hasValue(item));

            if (!entries.length) {
                return "No details available";
            }

            return entries
                .map(([key, item]) => {

                    return `${formatLabel(key)}: ${formatValue(item)}`;

                })
                .join("\n");

        }


        return String(value);

    }


    /* =====================================================
       AUTHENTICATION
    ===================================================== */

    function getToken() {

        try {

            return (
                localStorage.getItem(CONFIG.TOKEN_KEY) ||
                sessionStorage.getItem(CONFIG.TOKEN_KEY) ||
                ""
            );

        } catch (error) {

            console.error(
                "[ScamShield] Token access failed:",
                error
            );

            return "";

        }

    }


    function clearToken() {

        try {

            localStorage.removeItem(CONFIG.TOKEN_KEY);

            sessionStorage.removeItem(CONFIG.TOKEN_KEY);

        } catch (error) {

            console.error(
                "[ScamShield] Token cleanup failed:",
                error
            );

        }

    }


    function redirectToLogin() {

        clearToken();

        if (
            window.ScamShieldApp &&
            typeof window.ScamShieldApp.showScreen === "function"
        ) {

            window.ScamShieldApp.showScreen("login");

            return;

        }

        window.location.href = "login.html";

    }


    /* =====================================================
       STATUS MANAGEMENT
    ===================================================== */

    function showStatus(message, type = "info") {

        if (!elements.status) return;

        elements.status.textContent = message;

        elements.status.dataset.state = type;

        elements.status.setAttribute("role", "status");

        elements.status.setAttribute(
            "aria-live",
            type === "error" ? "assertive" : "polite"
        );

        elements.status.setAttribute(
            "aria-atomic",
            "true"
        );

    }


    /* =====================================================
       CHARACTER COUNTER
    ===================================================== */

    function updateCharacterCount() {

        if (
            !elements.evidence ||
            !elements.characterCount
        ) {
            return;
        }


        const count = elements.evidence.value.length;


        elements.characterCount.textContent =
            `${count.toLocaleString()} / ${CONFIG.MAX_EVIDENCE_LENGTH.toLocaleString()}`;


        elements.characterCount.dataset.state =
            count > CONFIG.MAX_EVIDENCE_LENGTH
                ? "error"
                : "normal";

    }


    /* =====================================================
       BUTTON LOADING STATE
    ===================================================== */

    function setButtonLoading(loading) {

        if (!elements.submitButton) return;


        elements.submitButton.disabled = loading;

        elements.submitButton.setAttribute(
            "aria-busy",
            String(loading)
        );


        const label = elements.submitButton.querySelector("span");

        const icons = elements.submitButton.querySelectorAll("i");


        if (label) {

            label.textContent = loading
                ? "Analyzing Evidence..."
                : originalButtonText;

        }


        if (icons.length) {

            icons[0].classList.toggle(
                "fa-spin",
                loading
            );

        }

    }


    function setLoading(loading) {

        isAnalyzing = loading;


        setButtonLoading(loading);


        if (elements.evidence) {

            elements.evidence.disabled = loading;

        }


        if (elements.evidenceType) {

            elements.evidenceType.disabled = loading;

        }


        if (elements.resetButton) {

            elements.resetButton.disabled = loading;

        }


        if (elements.form) {

            elements.form.setAttribute(
                "aria-busy",
                String(loading)
            );

        }

    }


    /* =====================================================
       EVIDENCE VALIDATION
    ===================================================== */

    function validateEvidence() {

        if (
            !elements.form ||
            !elements.evidenceType ||
            !elements.evidence
        ) {

            throw new Error(
                "Analysis form is incomplete. Please refresh the page."
            );

        }


        const evidenceType =
            elements.evidenceType.value.trim();


        const evidence =
            elements.evidence.value.trim();


        if (
            !CONFIG.ALLOWED_EVIDENCE_TYPES.includes(evidenceType)
        ) {

            throw new Error(
                "Please select a supported evidence type."
            );

        }


        if (!evidence) {

            throw new Error(
                "Please enter suspicious evidence before continuing."
            );

        }


        if (evidence.length > CONFIG.MAX_EVIDENCE_LENGTH) {

            throw new Error(
                "Evidence cannot exceed 20,000 characters."
            );

        }


        if (
            evidenceType === "url" &&
            !isValidURL(evidence)
        ) {

            throw new Error(
                "Please enter a valid HTTP or HTTPS URL."
            );

        }


        return {

            evidenceType,

            evidence

        };

    }


    function isValidURL(value) {

        try {

            const parsed = new URL(value);

            return (
                ["http:", "https:"].includes(parsed.protocol) &&
                !parsed.username &&
                !parsed.password
            );

        } catch {

            return false;

        }

    }


    /* =====================================================
       API RESPONSE HELPERS
    ===================================================== */

    function extractResponseData(payload) {

        if (!isObject(payload)) {

            throw new Error(
                "The server returned an invalid response."
            );

        }


        if (isObject(payload.data)) {

            return payload.data;

        }


        if (isObject(payload.result)) {

            return payload.result;

        }


        throw new Error(
            "The server response does not contain analysis data."
        );

    }


    function getErrorMessage(payload, status) {

        if (isObject(payload)) {

            const message =
                payload.message ||
                payload.error ||
                payload.detail;

            if (typeof message === "string" && message.trim()) {

                return message;

            }

        }


        return `Analysis failed. Server status: ${status}.`;

    }


    /* =====================================================
       API REQUEST
    ===================================================== */

    async function runAnalysis(requestData) {

        const token = getToken();


        if (!token) {

            throw new Error(
                "Please login before analyzing your evidence."
            );

        }


        activeController = new AbortController();


        const timeout = setTimeout(() => {

            activeController.abort();

        }, CONFIG.REQUEST_TIMEOUT);


        try {

            const response = await fetch(

                `${CONFIG.API_BASE_URL}${CONFIG.API_ENDPOINT}`,

                {

                    method: "POST",

                    headers: {

                        "Content-Type": "application/json",

                        Accept: "application/json",

                        Authorization: `Bearer ${token}`

                    },

                    body: JSON.stringify(requestData),

                    signal: activeController.signal

                }

            );


            let payload;


            try {

                payload = await response.json();

            } catch {

                throw new Error(
                    "The server returned an invalid JSON response."
                );

            }


            if (response.status === 401) {

                redirectToLogin();

                throw new Error(
                    "Your session has expired. Please login again."
                );

            }


            if (response.status === 403) {

                throw new Error(
                    "You do not have permission to analyze this evidence."
                );

            }


            if (!response.ok || payload.success !== true) {

                throw new Error(
                    getErrorMessage(payload, response.status)
                );

            }


            return extractResponseData(payload);

        } catch (error) {

            if (error.name === "AbortError") {

                throw new Error(
                    "Analysis timed out. Please try again."
                );

            }


            if (error instanceof TypeError) {

                throw new Error(
                    "Unable to connect to ScamShield AI. Please check whether the backend server is running."
                );

            }


            throw error;

        } finally {

            clearTimeout(timeout);

            activeController = null;

        }

    }


    /* =====================================================
       RESPONSE NORMALIZATION
    ===================================================== */

    function getAnalysisData(data) {

        if (isObject(data.analysis)) {

            return data.analysis;

        }


        if (isObject(data.result)) {

            return data.result;

        }


        if (hasValue(data.fraudCategory) || hasValue(data.riskScore)) {

            return data;

        }


        return {};

    }


    function getAgentCollection(data) {

        const agents =
            isObject(data.agents)
                ? data.agents
                : {};


        const results =
            isObject(data.agent_results)
                ? data.agent_results
                : isObject(data.agentResults)
                    ? data.agentResults
                    : {};


        return {

            guardian:
                agents.guardian ||
                results.guardian ||
                data.guardian ||
                null,


            intelligence:
                agents.intelligence ||
                results.intelligence ||
                data.intelligence ||
                null,


            victimSafety:
                agents.victimSafety ||
                agents.victim_safety ||
                agents["victim-safety"] ||
                results.victimSafety ||
                results.victim_safety ||
                data.victimSafety ||
                data.victim_safety ||
                null,


            decoy:
                agents.decoy ||
                results.decoy ||
                data.decoy ||
                null

        };

    }


    function getAgentContent(agentData) {

        if (!isObject(agentData)) {

            return {};

        }


        const nested =
            isObject(agentData.result)
                ? agentData.result
                : isObject(agentData.data)
                    ? agentData.data
                    : {};


        return {

            ...nested,

            ...agentData

        };

    }


    /* =====================================================
       RISK ASSESSMENT
    ===================================================== */

    function getRiskScore(value) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return null;

        }


        const score = Number(value);


        if (
            !Number.isFinite(score) ||
            score < 0 ||
            score > 100
        ) {

            return null;

        }


        return score;

    }


    function normalizeRiskLevel(value) {

        const level = String(value || "")
            .trim()
            .toLowerCase();


        return CONFIG.RISK_LEVELS.includes(level)
            ? level
            : "unknown";

    }


    function getRiskLevelFromScore(score) {

        if (score >= 75) return "critical";

        if (score >= 50) return "high";

        if (score >= 25) return "medium";

        return "low";

    }


    function renderRiskAssessment(analysis) {

        const score = getRiskScore(
            analysis.riskScore
        );


        updateText(

            elements.riskScore,

            score === null
                ? "--"
                : `${score}/100`

        );


        const backendRisk = normalizeRiskLevel(
            analysis.riskLevel
        );


        // Guardian/backend risk level remains authoritative.
        // Score-based level is only a fallback.

        const finalRisk =
            backendRisk !== "unknown"
                ? backendRisk
                : score !== null
                    ? getRiskLevelFromScore(score)
                    : "unknown";


        updateText(

            elements.riskLevel,

            finalRisk === "unknown"
                ? "Not available"
                : formatLabel(finalRisk)

        );


        if (elements.riskLevel) {

            elements.riskLevel.dataset.risk = finalRisk;

        }


        updateText(

            elements.fraudCategory,

            formatLabel(
                analysis.fraudCategory || "Unknown"
            )

        );

    }


    /* =====================================================
       EXPLANATION RENDERING
    ===================================================== */

    function normalizeExplanation(value) {

        if (!hasValue(value)) {

            return [];

        }


        if (Array.isArray(value)) {

            return value;

        }


        if (isObject(value)) {

            return Object.entries(value).map(([key, item]) => {

                return `${formatLabel(key)}: ${formatValue(item)}`;

            });

        }


        return [value];

    }


    function renderExplanation(explanation) {

        if (!elements.explanation) return;


        clearElement(elements.explanation);


        const items = normalizeExplanation(explanation);


        if (!items.length) {

            elements.explanation.appendChild(

                createElement(
                    "p",
                    "empty-state",
                    "No explanation is available."
                )

            );

            return;

        }


        const list = createElement(
            "ul",
            "analysis-explanation-list"
        );


        items.forEach(item => {

            list.appendChild(

                createElement(
                    "li",
                    "",
                    formatValue(item)
                )

            );

        });


        elements.explanation.appendChild(list);

    }


    /* =====================================================
       INTELLIGENCE INDICATORS
    ===================================================== */

    function normalizeIndicators(value) {

        if (!hasValue(value)) {

            return [];

        }


        if (Array.isArray(value)) {

            return value;

        }


        if (isObject(value)) {

            return Object.entries(value).map(([key, item]) => {

                return {

                    type: key,

                    value: item

                };

            });

        }


        return [value];

    }


    function renderIndicators(indicators) {

        if (!elements.indicators) return;


        clearElement(elements.indicators);


        if (!indicators.length) {

            elements.indicators.appendChild(

                createElement(
                    "p",
                    "empty-state",
                    "No suspicious indicators were reported."
                )

            );

            return;

        }


        const list = createElement(
            "ul",
            "analysis-indicator-list"
        );


        indicators.forEach(indicator => {

            const item = createElement(
                "li",
                "analysis-indicator-item"
            );


            item.textContent = formatValue(indicator);


            list.appendChild(item);

        });


        elements.indicators.appendChild(list);


        const note = createElement(

            "p",

            "indicator-disclaimer",

            "Indicators are unverified observations and should be independently checked."

        );


        elements.indicators.appendChild(note);

    }


    /* =====================================================
       AGENT STATUS NORMALIZATION
    ===================================================== */

    function normalizeAgentStatus(agentData, agentName) {

        if (!isObject(agentData)) {

            return "unavailable";

        }


        const rawStatus = String(

            agentData.status ||
            agentData.execution_status ||
            agentData.executionStatus ||
            ""

        ).toLowerCase();


        if ([
            "failed",
            "error"
        ].includes(rawStatus)) {

            return "failed";

        }


        if ([
            "pending",
            "running",
            "processing"
        ].includes(rawStatus)) {

            return "pending";

        }


        if ([
            "not_configured",
            "not_started",
            "not_executed",
            "disabled",
            "skipped"
        ].includes(rawStatus)) {

            return "skipped";

        }


        if (rawStatus === "unavailable") {

            return "unavailable";

        }


        if ([
            "completed",
            "success",
            "successful",
            "available"
        ].includes(rawStatus)) {

            return "completed";

        }


        if (rawStatus === "advisory_only") {

            return hasMeaningfulAgentContent(agentData)
                ? "completed"
                : "unavailable";

        }


        if (agentName === "Decoy") {

            return "skipped";

        }


        return hasMeaningfulAgentContent(agentData)
            ? "completed"
            : "unavailable";

    }


    function hasMeaningfulAgentContent(agentData) {

        if (!isObject(agentData)) {

            return false;

        }


        const ignored = [

            "status",
            "agent",
            "agentName",
            "agent_name",
            "execution_status",
            "executionStatus",
            "available",
            "configured",
            "enabled",
            "id",
            "_id"

        ];


        return Object.entries(agentData).some(([key, value]) => {

            if (ignored.includes(key)) {

                return false;

            }


            if (value === null || value === undefined) {

                return false;

            }


            if (typeof value === "string") {

                return value.trim().length > 0;

            }


            if (Array.isArray(value)) {

                return value.length > 0;

            }


            if (isObject(value)) {

                return Object.keys(value).length > 0;

            }


            return true;

        });

    }


    /* =====================================================
       AGENT RESULT RENDERING
    ===================================================== */

    function renderAgent(container, title, agentData, options = {}) {

        if (!container) return;


        clearElement(container);


        const card = createElement(
            "div",
            "agent-result-card"
        );


        card.appendChild(

            createElement(
                "h3",
                "agent-result-title",
                title
            )

        );


        const status = normalizeAgentStatus(
            agentData,
            title === "Guardian Agent"
                ? "Guardian"
                : title === "Decoy Agent"
                    ? "Decoy"
                    : title
        );


        const badge = createElement(

            "span",

            `agent-status-badge ${status}`,

            formatLabel(status)

        );


        card.appendChild(badge);


        if (status === "failed") {

            card.appendChild(

                createElement(
                    "p",
                    "empty-state",
                    "This agent could not complete its execution."
                )

            );


            container.appendChild(card);

            return;

        }


        if (status === "pending") {

            card.appendChild(

                createElement(
                    "p",
                    "empty-state",
                    "This agent is still processing."
                )

            );


            container.appendChild(card);

            return;

        }


        if (status === "unavailable") {

            card.appendChild(

                createElement(
                    "p",
                    "empty-state",
                    "No execution result is available for this agent."
                )

            );


            container.appendChild(card);

            return;

        }


        if (status === "skipped") {

            const message =
                options.skippedMessage ||
                "This agent was not executed during this analysis.";

            card.appendChild(

                createElement(
                    "p",
                    "empty-state",
                    message
                )

            );


            container.appendChild(card);

            return;

        }


        const content = getAgentContent(agentData);


        const details = createElement(
            "div",
            "agent-result-details"
        );


        const ignoredFields = [

            "status",
            "agent",
            "agentName",
            "agent_name",
            "execution_status",
            "executionStatus",
            "id",
            "_id"

        ];


        let renderedCount = 0;


        Object.entries(content).forEach(([key, value]) => {

            if (
                ignoredFields.includes(key) ||
                value === null ||
                value === undefined
            ) {

                return;

            }


            const row = createElement(
                "div",
                "agent-detail-row"
            );


            row.append(

                createElement(
                    "strong",
                    "agent-detail-label",
                    formatLabel(key)
                ),

                createElement(
                    "span",
                    "agent-detail-value",
                    formatValue(value)
                )

            );


            details.appendChild(row);

            renderedCount++;

        });


        if (renderedCount > 0) {

            card.appendChild(details);

        } else {

            card.appendChild(

                createElement(
                    "p",
                    "empty-state",
                    "The agent completed without additional details."
                )

            );

        }


        container.appendChild(card);

    }


    /* =====================================================
       GUARDIAN RESULT
    ===================================================== */

    function renderGuardian(agentData, analysis) {

        const guardian = getAgentContent(agentData);


        const hasGuardianContent =
            hasMeaningfulAgentContent(guardian);


        const status = normalizeAgentStatus(
            agentData,
            "Guardian"
        );


        if (
            !hasGuardianContent &&
            status === "unavailable"
        ) {

            renderAgent(

                elements.guardian,

                "Guardian Agent",

                {

                    status: "completed",

                    result: {

                        fraudCategory:
                            analysis.fraudCategory,

                        riskScore:
                            analysis.riskScore,

                        riskLevel:
                            analysis.riskLevel,

                        explanation:
                            analysis.explanation

                    }

                }

            );

            return;

        }


        renderAgent(

            elements.guardian,

            "Guardian Agent",

            agentData

        );

    }


    /* =====================================================
       INTELLIGENCE RESULT
    ===================================================== */

    function renderIntelligence(agentData) {

        renderAgent(

            elements.intelligence,

            "Intelligence Agent",

            agentData

        );

    }


    /* =====================================================
       VICTIM SAFETY RESULT
    ===================================================== */

    function renderVictimSafety(agentData) {

        renderAgent(

            elements.victimSafety,

            "Victim Safety Agent",

            agentData

        );

    }


    /* =====================================================
       DECOY RESULT
    ===================================================== */

    function renderDecoy(agentData) {

        renderAgent(

            elements.decoy,

            "Decoy Agent",

            agentData,

            {

                skippedMessage:
                    "Decoy simulation was not automatically started. It requires a separate, explicitly controlled simulation session."

            }

        );

    }


    /* =====================================================
       MAIN RESULTS RENDERER
    ===================================================== */

    function renderResults(data) {

        const analysis = getAnalysisData(data);


        const agents = getAgentCollection(data);


        /* ---------------------------------------------
           ANALYSIS IDENTIFICATION
        --------------------------------------------- */

        updateText(

            elements.analysisId,

            data.analysisId ||
            analysis.analysisId ||
            analysis.id,

            "Not available"

        );


        /* ---------------------------------------------
           RISK ASSESSMENT
        --------------------------------------------- */

        renderRiskAssessment(analysis);


        /* ---------------------------------------------
           SUMMARY
        --------------------------------------------- */

        updateText(

            elements.summary,

            analysis.summary ||
            analysis.riskDescription ||
            analysis.description,

            "No summary is available."

        );


        /* ---------------------------------------------
           EXPLANATION
        --------------------------------------------- */

        renderExplanation(

            analysis.explanation ||
            analysis.explanations ||
            analysis.detectedRules

        );


        /* ---------------------------------------------
           INDICATORS
        --------------------------------------------- */

        const intelligence = getAgentContent(
            agents.intelligence
        );


        const indicators = normalizeIndicators(

            intelligence.indicators ||
            intelligence.extractedIndicators ||
            analysis.indicators

        );


        renderIndicators(indicators);


        /* ---------------------------------------------
           FOUR AGENTS
        --------------------------------------------- */

        renderGuardian(

            agents.guardian,

            analysis

        );


        renderIntelligence(

            agents.intelligence

        );


        renderVictimSafety(

            agents.victimSafety

        );


        renderDecoy(

            agents.decoy

        );


        /* ---------------------------------------------
           DISCLAIMER
        --------------------------------------------- */

        updateText(

            elements.disclaimer,

            data.disclaimer ||
            analysis.disclaimer,

            "Automated analysis provides indicative findings. Results are not proof of fraud and should not replace official verification."

        );

    }


    /* =====================================================
       RESET RESULTS
    ===================================================== */

    function clearResults() {

        if (elements.results) {

            elements.results.hidden = true;

        }


        updateText(elements.analysisId, "", "--");

        updateText(elements.riskScore, "", "--");

        updateText(elements.riskLevel, "", "--");

        updateText(elements.fraudCategory, "", "--");

        updateText(elements.summary, "", "No summary available.");

        updateText(elements.disclaimer, "", "No disclaimer available.");


        if (elements.riskLevel) {

            delete elements.riskLevel.dataset.risk;

        }


        clearElement(elements.explanation);

        clearElement(elements.indicators);

        clearElement(elements.guardian);

        clearElement(elements.intelligence);

        clearElement(elements.victimSafety);

        clearElement(elements.decoy);

    }


    /* =====================================================
       RESULT VISIBILITY
    ===================================================== */

    function showResults() {

        if (!elements.results) return;


        elements.results.hidden = false;


        const reducedMotion =

            window.matchMedia &&
            window.matchMedia(
                "(prefers-reduced-motion: reduce)"
            ).matches;


        elements.results.scrollIntoView({

            behavior: reducedMotion ? "auto" : "smooth",

            block: "start"

        });


        elements.results.setAttribute(
            "tabindex",
            "-1"
        );


        elements.results.focus({

            preventScroll: true

        });

    }


    /* =====================================================
       MAIN FORM SUBMISSION
    ===================================================== */

    async function handleAnalysis(event) {

        event.preventDefault();


        if (isAnalyzing) return;


        try {

            /* -----------------------------------------
               VALIDATE
            ----------------------------------------- */

            const requestData = validateEvidence();


            /* -----------------------------------------
               START
            ----------------------------------------- */

            clearResults();


            setLoading(true);


            showStatus(

                "Your evidence is being securely analyzed. Please wait.",

                "loading"

            );


            /* -----------------------------------------
               SINGLE API REQUEST
            ----------------------------------------- */

            const result = await runAnalysis(requestData);


            /* -----------------------------------------
               RENDER
            ----------------------------------------- */

            renderResults(result);


            showResults();


            /* -----------------------------------------
               SUCCESS
            ----------------------------------------- */

            showStatus(

                "Evidence analysis completed successfully.",

                "success"

            );


        } catch (error) {

            console.error(
                "[ScamShield] Analysis error:",
                error
            );


            showStatus(

                error.message ||
                "Unable to complete evidence analysis.",

                "error"

            );


            if (elements.evidence) {

                elements.evidence.focus();

            }

        } finally {

            setLoading(false);

        }

    }


    /* =====================================================
       FORM RESET
    ===================================================== */

    function handleReset() {

        if (isAnalyzing) return;


        clearResults();


        updateCharacterCount();


        showStatus(

            "Previous analysis cleared. You can submit new evidence.",

            "info"

        );

    }


    /* =====================================================
       CURRENT YEAR
    ===================================================== */

    function initializeCurrentYear() {

        if (elements.currentYear) {

            elements.currentYear.textContent =
                new Date().getFullYear();

        }

    }


    /* =====================================================
       ACCESSIBILITY INITIALIZATION
    ===================================================== */

    function initializeAccessibility() {

        if (elements.status) {

            elements.status.setAttribute(
                "role",
                "status"
            );

            elements.status.setAttribute(
                "aria-live",
                "polite"
            );

            elements.status.setAttribute(
                "aria-atomic",
                "true"
            );

        }


        if (elements.results) {

            elements.results.setAttribute(
                "aria-live",
                "polite"
            );

        }

    }


    /* =====================================================
       EVENT LISTENERS
    ===================================================== */

    function initializeEvents() {

        if (elements.form) {

            elements.form.addEventListener(

                "submit",

                handleAnalysis

            );


            elements.form.addEventListener(

                "reset",

                () => {

                    setTimeout(() => {

                        handleReset();

                    }, 0);

                }

            );

        }


        if (elements.evidence) {

            elements.evidence.addEventListener(

                "input",

                updateCharacterCount

            );

        }


        if (elements.resetButton) {

            elements.resetButton.addEventListener(

                "click",

                handleReset

            );

        }

    }


    /* =====================================================
       INITIALIZATION
    ===================================================== */

    function initialize() {

        initializeCurrentYear();


        initializeAccessibility();


        initializeEvents();


        updateCharacterCount();


        clearResults();


        if (elements.submitButton) {

            const label = elements.submitButton.querySelector("span");

            if (label) {

                originalButtonText = label.textContent.trim() ||
                    "Analyze Evidence";

            }

        }


        if (!elements.form) {

            console.error(
                "[ScamShield] Analysis form #analysisForm was not found."
            );

            return;

        }


        if (!elements.evidence || !elements.evidenceType) {

            console.error(
                "[ScamShield] Evidence input elements are missing."
            );

            return;

        }


        if (!elements.submitButton) {

            console.error(
                "[ScamShield] Analyze button was not found."
            );

            return;

        }


        console.log(
            `[ScamShield] Evidence Analysis v${CONFIG.VERSION} initialized.`
        );

    }


    /* =====================================================
       DOM READY
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

})();