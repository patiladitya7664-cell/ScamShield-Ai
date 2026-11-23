"use strict";

/* =====================================================
   SCAMSHIELD AI - AGENTS PAGE

   Version: 3.0.0

   Agents:
   1. Guardian
   2. Intelligence
   3. Victim Safety
   4. Decoy (controlled simulation only)
   5. Gemini (advisory only)

   Integration:
   Centralized ScamShieldAPI service

   Security:
   - Authenticated API requests
   - Safe DOM rendering
   - No innerHTML
   - Input validation
   - Request cancellation on timeout
   - No automatic Decoy execution
   - No fabricated agent execution statuses
===================================================== */

(() => {
    "use strict";

    if (window.ScamShieldAgentsInitialized) {
        return;
    }

    window.ScamShieldAgentsInitialized = true;

    document.addEventListener("DOMContentLoaded", initializeAgentsPage);

    function initializeAgentsPage() {

        /* ================================================
           1. CONFIGURATION
        ================================================ */

        const CONFIG = Object.freeze({
            VERSION: "3.0.0",

            API_ENDPOINT: "/agents/run",

            REQUEST_TIMEOUT: 45000,

            MAX_EVIDENCE_LENGTH: 20000,

            SUPPORTED_EVIDENCE_TYPES: [
                "message",
                "url",
                "call",
                "transaction",
                "screenshot",
                "email"
            ],

            REDIRECT_DELAY: 1200
        });


        /* ================================================
           2. DOM ELEMENTS
        ================================================ */

        const elements = {
            form: document.getElementById("agentsDemoForm"),

            scenario: document.getElementById("agentsDemoSample"),

            evidenceType: document.getElementById("agentsDemoType"),

            evidence: document.getElementById("agentsDemoEvidence"),

            runButton: document.getElementById("agentsDemoRun"),

            status: document.getElementById("agentsDemoStatus"),

            results: document.getElementById("agentsDemoResults")
        };


        if (!elements.form) {
            console.warn("[ScamShield Agents] Demo form not found.");
            return;
        }


        /* ================================================
           3. DEMO SCENARIOS
        ================================================ */

        const DEMO_SCENARIOS = Object.freeze({

            "bank-kyc": {
                type: "message",
                evidence:
                    "Dear Customer, your bank account will be blocked today. " +
                    "Complete your KYC immediately using this link: " +
                    "https://bank-verification.example-scam.test. " +
                    "Share your OTP to prevent account suspension."
            },

            "lottery": {
                type: "message",
                evidence:
                    "Congratulations! You have won a lottery prize of " +
                    "₹25,00,000. Pay a processing fee immediately to claim " +
                    "your prize. Share your banking details for verification."
            },

            "suspicious-url": {
                type: "url",
                evidence:
                    "https://secure-bank-verification.example-scam.test/login"
            },

            "fake-call": {
                type: "call",
                evidence:
                    "Caller claims to be a police officer and threatens " +
                    "immediate arrest unless money is transferred. " +
                    "The caller demands confidential banking information."
            },

            "upi-scam": {
                type: "transaction",
                evidence:
                    "A suspicious UPI transaction request asks the user " +
                    "to enter their UPI PIN to receive money. " +
                    "The sender claims that payment verification is required."
            },

            "suspicious-email": {
                type: "email",
                evidence:
                    "Subject: Urgent account verification\n\n" +
                    "Your account will be suspended. Verify your account " +
                    "using the supplied link and provide your login code."
            }

        });


        /* ================================================
           4. API SERVICE
        ================================================ */

        function getAPI() {
            const api = window.ScamShieldAPI;

            if (
                !api ||
                typeof api.post !== "function" ||
                typeof api.isAuthenticated !== "function"
            ) {
                throw new Error(
                    "ScamShield API service is unavailable. Please reload the page."
                );
            }

            return api;
        }


        /* ================================================
           5. SAFE VALUE HELPERS
        ================================================ */

        function safeText(value, fallback = "Not available") {
            if (
                value === null ||
                value === undefined ||
                value === ""
            ) {
                return fallback;
            }

            if (
                typeof value === "string" ||
                typeof value === "number" ||
                typeof value === "boolean"
            ) {
                return String(value);
            }

            return fallback;
        }


        function normalizeText(value, fallback = "Not available") {
            if (typeof value !== "string") {
                return fallback;
            }

            const normalized = value.trim();

            return normalized || fallback;
        }


        function safeArray(value) {
            return Array.isArray(value) ? value : [];
        }


        function isObject(value) {
            return (
                value !== null &&
                typeof value === "object" &&
                !Array.isArray(value)
            );
        }


        function getObjectValue(object, keys) {
            if (!isObject(object)) {
                return undefined;
            }

            for (const key of keys) {
                if (
                    Object.prototype.hasOwnProperty.call(object, key) &&
                    object[key] !== undefined &&
                    object[key] !== null
                ) {
                    return object[key];
                }
            }

            return undefined;
        }


        function unwrapObject(value) {
            if (!isObject(value)) {
                return {};
            }

            if (isObject(value.data)) {
                return value.data;
            }

            if (isObject(value.result)) {
                return value.result;
            }

            return value;
        }


        /* ================================================
           6. ACCESSIBILITY
        ================================================ */

        function initializeAccessibility() {
            if (elements.status) {
                elements.status.setAttribute("role", "status");
                elements.status.setAttribute("aria-live", "polite");
                elements.status.setAttribute("aria-atomic", "true");
            }

            if (elements.results) {
                elements.results.setAttribute("aria-live", "polite");
                elements.results.setAttribute("aria-atomic", "false");
            }
        }


        /* ================================================
           7. STATUS MANAGEMENT
        ================================================ */

        function showStatus(message, type = "info") {
            if (!elements.status) {
                return;
            }

            const allowedTypes = [
                "info",
                "success",
                "warning",
                "error"
            ];

            const safeType = allowedTypes.includes(type)
                ? type
                : "info";

            elements.status.textContent = String(message);

            elements.status.className =
                `agent-demo-state agent-demo-state-${safeType}`;

            elements.status.setAttribute(
                "aria-live",
                safeType === "error" ? "assertive" : "polite"
            );
        }


        function clearStatus() {
            if (!elements.status) {
                return;
            }

            elements.status.textContent = "";
            elements.status.className = "agent-demo-state";
        }


        /* ================================================
           8. SAFE DOM RENDERING
        ================================================ */

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


        function appendText(parent, tag, className, text) {
            const element = createElement(tag, className, text);

            parent.appendChild(element);

            return element;
        }


        function createSection(title, content) {
            const section = createElement(
                "section",
                "agent-demo-result-section"
            );

            appendText(
                section,
                "h4",
                "agent-demo-result-heading",
                title
            );

            section.appendChild(content);

            return section;
        }


        function createList(items) {
            const list = createElement(
                "ul",
                "agent-demo-result-list"
            );

            safeArray(items).forEach(item => {
                let value = item;

                if (isObject(item)) {
                    value = getObjectValue(item, [
                        "label",
                        "name",
                        "description",
                        "message",
                        "value",
                        "indicator",
                        "type"
                    ]);
                }

                if (
                    value === undefined ||
                    value === null ||
                    value === ""
                ) {
                    return;
                }

                appendText(
                    list,
                    "li",
                    "",
                    safeText(value, "")
                );
            });

            return list;
        }


        function createInfoCard(title, value, className = "") {
            const card = createElement(
                "div",
                `agent-demo-result-card ${className}`.trim()
            );

            appendText(
                card,
                "span",
                "agent-demo-result-label",
                title
            );

            appendText(
                card,
                "strong",
                "agent-demo-result-value",
                value
            );

            return card;
        }


        /* ================================================
           9. AGENT STATUS
        ================================================ */

        function normalizeStatus(status) {
            if (typeof status !== "string") {
                return "unknown";
            }

            const value = status
                .toLowerCase()
                .trim()
                .replace(/[\s-]+/g, "_");

            const statuses = {
                completed: "completed",
                success: "completed",
                successful: "completed",

                failed: "failed",
                error: "failed",

                pending: "pending",
                processing: "pending",
                running: "pending",
                in_progress: "pending",

                skipped: "skipped",
                not_configured: "skipped",
                not_started: "skipped",
                not_executed: "skipped",
                disabled: "skipped",

                unavailable: "unavailable"
            };

            return statuses[value] || "unknown";
        }


        /*
         * IMPORTANT:
         * An object existing does not prove that an agent
         * executed successfully.
         *
         * Only explicit execution status is trusted.
         */

        function getAgentStatus(agent, defaultStatus = "unknown") {
            if (!isObject(agent)) {
                return defaultStatus;
            }

            const explicitStatus = getObjectValue(agent, [
                "status",
                "execution_status",
                "executionStatus"
            ]);

            if (typeof explicitStatus === "string") {
                return normalizeStatus(explicitStatus);
            }

            if (
                agent.available === false ||
                agent.configured === false
            ) {
                return "unavailable";
            }

            return defaultStatus;
        }


        function renderAgentStatus(name, status) {
            const card = createElement(
                "div",
                "agent-demo-result-card"
            );

            appendText(
                card,
                "strong",
                "agent-demo-result-heading",
                name
            );

            const badge = createElement(
                "span",
                `agent-demo-status-badge status-${status}`,
                status.replace(/_/g, " ").toUpperCase()
            );

            card.appendChild(badge);

            return card;
        }


        /* ================================================
           10. SCENARIO MANAGEMENT
        ================================================ */

        function clearResults() {
            if (!elements.results) {
                return;
            }

            elements.results.replaceChildren();
            elements.results.hidden = true;
        }


        function loadDemoScenario() {
            if (
                !elements.scenario ||
                !elements.evidence ||
                !elements.evidenceType
            ) {
                return;
            }

            const scenario = DEMO_SCENARIOS[
                elements.scenario.value
            ];

            if (!scenario) {
                return;
            }

            elements.evidenceType.value = scenario.type;
            elements.evidence.value = scenario.evidence;

            clearResults();
            clearStatus();
        }


        /* ================================================
           11. GUARDIAN AGENT
        ================================================ */

        function renderGuardian(agent, analysis) {
            const section = createElement(
                "section",
                "agent-demo-result-card"
            );

            appendText(
                section,
                "h3",
                "agent-demo-result-heading",
                "Guardian Agent — Fraud Detection"
            );

            const result = unwrapObject(agent);

            const category = getObjectValue(analysis, [
                "fraudCategory",
                "fraud_category",
                "category"
            ]);

            const score = getObjectValue(analysis, [
                "riskScore",
                "risk_score"
            ]);

            const riskLevel = getObjectValue(analysis, [
                "riskLevel",
                "risk_level"
            ]);

            const summary = getObjectValue(analysis, [
                "summary",
                "message"
            ]);

            const explanation = getObjectValue(analysis, [
                "explanation",
                "reason"
            ]);

            section.appendChild(
                createInfoCard(
                    "Fraud Category",
                    safeText(category)
                )
            );

            const numericScore = Number(score);

            const validScore =
                score !== null &&
                score !== undefined &&
                score !== "" &&
                Number.isFinite(numericScore) &&
                numericScore >= 0 &&
                numericScore <= 100;

            section.appendChild(
                createInfoCard(
                    "Risk Score",
                    validScore
                        ? `${numericScore}/100`
                        : "Not available"
                )
            );

            section.appendChild(
                createInfoCard(
                    "Risk Level",
                    safeText(riskLevel)
                )
            );

            if (typeof summary === "string" && summary.trim()) {
                appendText(
                    section,
                    "p",
                    "agent-demo-description",
                    summary
                );
            }

            if (
                typeof explanation === "string" &&
                explanation.trim()
            ) {
                appendText(
                    section,
                    "p",
                    "agent-demo-description",
                    explanation
                );
            }

            const findings = getObjectValue(result, [
                "findings",
                "matchedRules",
                "matched_rules",
                "indicators",
                "reasons"
            ]);

            if (Array.isArray(findings) && findings.length) {
                section.appendChild(
                    createSection(
                        "Detection Findings",
                        createList(findings)
                    )
                );
            }

            appendText(
                section,
                "p",
                "agent-demo-disclaimer",
                "Guardian is the authoritative source for fraud category, risk score and risk level. Risk scores are not calibrated probabilities."
            );

            return section;
        }


        /* ================================================
           12. INTELLIGENCE AGENT
        ================================================ */

        function renderIntelligence(agent) {
            const section = createElement(
                "section",
                "agent-demo-result-card"
            );

            appendText(
                section,
                "h3",
                "agent-demo-result-heading",
                "Intelligence Agent — Evidence Analysis"
            );

            const result = unwrapObject(agent);

            const indicators = getObjectValue(result, [
                "indicators",
                "extractedIndicators",
                "extracted_indicators",
                "findings",
                "entities"
            ]);

            if (Array.isArray(indicators) && indicators.length) {
                section.appendChild(
                    createSection(
                        "Extracted Indicators",
                        createList(indicators)
                    )
                );
            } else {
                appendText(
                    section,
                    "p",
                    "agent-demo-description",
                    "No structured indicators were returned."
                );
            }

            const patterns = getObjectValue(result, [
                "patterns",
                "detectedPatterns",
                "detected_patterns"
            ]);

            if (Array.isArray(patterns) && patterns.length) {
                section.appendChild(
                    createSection(
                        "Identified Patterns",
                        createList(patterns)
                    )
                );
            }

            appendText(
                section,
                "p",
                "agent-demo-disclaimer",
                "Extracted indicators are unverified observations. They do not independently establish criminal activity or identity."
            );

            return section;
        }


        /* ================================================
           13. VICTIM SAFETY AGENT
        ================================================ */

        function renderVictimSafety(agent) {
            const section = createElement(
                "section",
                "agent-demo-result-card"
            );

            appendText(
                section,
                "h3",
                "Victim Safety Agent — Protection Guidance"
            );

            const result = unwrapObject(agent);

            const recommendations = getObjectValue(result, [
                "recommendations",
                "safetyTips",
                "safety_tips",
                "actions",
                "guidance"
            ]);

            if (
                Array.isArray(recommendations) &&
                recommendations.length
            ) {
                section.appendChild(
                    createSection(
                        "Safety Recommendations",
                        createList(recommendations)
                    )
                );
            } else {
                appendText(
                    section,
                    "p",
                    "agent-demo-description",
                    "No structured safety recommendations were returned."
                );
            }

            const emergencyHelp = getObjectValue(result, [
                "emergencyHelp",
                "emergency_help"
            ]);

            if (typeof emergencyHelp === "string" && emergencyHelp.trim()) {
                appendText(
                    section,
                    "p",
                    "agent-demo-description",
                    emergencyHelp
                );
            }

            appendText(
                section,
                "p",
                "agent-demo-disclaimer",
                "Recommendations are informational. ScamShield does not automatically contact authorities, freeze accounts or take action on behalf of users."
            );

            return section;
        }


        /* ================================================
           14. DECOY AGENT
        ================================================ */

        function renderDecoy(agent) {
            const section = createElement(
                "section",
                "agent-demo-result-card"
            );

            appendText(
                section,
                "h3",
                "Decoy Agent — Controlled Simulation"
            );

            const result = unwrapObject(agent);

            const status = getAgentStatus(
                result,
                "skipped"
            );

            section.appendChild(
                renderAgentStatus(
                    "Decoy Execution",
                    status
                )
            );

            const simulationEnabled =
                result.simulationEnabled === true ||
                result.simulation_enabled === true;

            appendText(
                section,
                "p",
                "agent-demo-description",
                simulationEnabled
                    ? "The backend reports that controlled simulation is enabled. This does not mean a simulation was started."
                    : "Decoy simulation was not automatically started during normal fraud analysis."
            );

            appendText(
                section,
                "p",
                "agent-demo-disclaimer",
                "Decoy interactions must be explicitly authorized and controlled. Normal fraud analysis never automatically engages suspected scammers."
            );

            return section;
        }


        /* ================================================
           15. GEMINI ADVISORY
        ================================================ */

        function renderGemini(advisory) {
            if (!isObject(advisory)) {
                return null;
            }

            const result = unwrapObject(advisory);

            const section = createElement(
                "section",
                "agent-demo-result-card"
            );

            appendText(
                section,
                "h3",
                "Gemini — Contextual AI Insights"
            );

            const status = getAgentStatus(
                result,
                "unknown"
            );

            section.appendChild(
                renderAgentStatus(
                    "Gemini Advisory",
                    status
                )
            );

            const content = getObjectValue(result, [
                "advisory",
                "insights",
                "summary",
                "response",
                "content",
                "message"
            ]);

            if (typeof content === "string" && content.trim()) {
                appendText(
                    section,
                    "p",
                    "agent-demo-description",
                    content
                );
            } else if (Array.isArray(content) && content.length) {
                section.appendChild(createList(content));
            }

            const model = getObjectValue(result, [
                "model",
                "modelName",
                "model_name"
            ]);

            if (typeof model === "string" && model.trim()) {
                appendText(
                    section,
                    "p",
                    "agent-demo-reference",
                    `Model: ${model}`
                );
            }

            appendText(
                section,
                "p",
                "agent-demo-disclaimer",
                "Gemini provides advisory-only insights. It cannot override Guardian's authoritative fraud category, risk score or risk level."
            );

            return section;
        }


        /* ================================================
           16. RESPONSE NORMALIZATION
        ================================================ */

        function normalizeResponse(payload) {
            if (!isObject(payload)) {
                throw new Error(
                    "The server returned an invalid response."
                );
            }

            if (payload.success === false) {
                throw new Error(
                    normalizeText(
                        payload.message || payload.error,
                        "Analysis request failed."
                    )
                );
            }

            const data = isObject(payload.data)
                ? payload.data
                : isObject(payload.result)
                    ? payload.result
                    : payload;

            const rawAgents = getObjectValue(data, [
                "agents",
                "agent_results",
                "agentResults"
            ]) || {};

            const analysis = getObjectValue(data, [
                "analysis"
            ]) || getObjectValue(payload, [
                "analysis"
            ]);

            if (!isObject(analysis)) {
                throw new Error(
                    "The server response does not contain a valid analysis result."
                );
            }

            const guardian = getObjectValue(rawAgents, [
                "guardian"
            ]);

            const intelligence = getObjectValue(rawAgents, [
                "intelligence"
            ]);

            const victimSafety = getObjectValue(rawAgents, [
                "victimSafety",
                "victim_safety",
                "victim-safety"
            ]);

            const decoy = getObjectValue(rawAgents, [
                "decoy"
            ]);

            const gemini = getObjectValue(data, [
                "gemini_advisory",
                "geminiAdvisory",
                "advisory"
            ]) || getObjectValue(rawAgents, [
                "gemini"
            ]);

            return {
                data,
                analysis,

                guardian: guardian || {},
                intelligence: intelligence || {},
                victimSafety: victimSafety || {},
                decoy: decoy || {},
                gemini: gemini || null,

                analysisId: getObjectValue(data, [
                    "analysisId",
                    "analysis_id"
                ]),

                evidenceId: getObjectValue(data, [
                    "evidenceId",
                    "evidence_id"
                ]),

                disclaimer: getObjectValue(data, [
                    "disclaimer"
                ])
            };
        }


        /* ================================================
           17. RESULTS RENDERING
        ================================================ */

        function renderResults(payload) {
            if (!elements.results) {
                return;
            }

            const response = normalizeResponse(payload);

            const fragment = document.createDocumentFragment();

            fragment.appendChild(
                createElement(
                    "h2",
                    "agent-demo-result-heading",
                    "ScamShield AI — Analysis Results"
                )
            );

            fragment.appendChild(
                renderGuardian(
                    response.guardian,
                    response.analysis
                )
            );

            fragment.appendChild(
                renderIntelligence(
                    response.intelligence
                )
            );

            fragment.appendChild(
                renderVictimSafety(
                    response.victimSafety
                )
            );

            fragment.appendChild(
                renderDecoy(
                    response.decoy
                )
            );

            const geminiSection = renderGemini(
                response.gemini
            );

            if (geminiSection) {
                fragment.appendChild(geminiSection);
            }

            if (response.analysisId) {
                appendText(
                    fragment,
                    "p",
                    "agent-demo-reference",
                    `Analysis ID: ${safeText(response.analysisId)}`
                );
            }

            if (response.evidenceId) {
                appendText(
                    fragment,
                    "p",
                    "agent-demo-reference",
                    `Evidence ID: ${safeText(response.evidenceId)}`
                );
            }

            appendText(
                fragment,
                "p",
                "agent-demo-disclaimer",
                safeText(
                    response.disclaimer,
                    "ScamShield AI provides automated analysis for informational purposes. Verify suspicious activity through official channels."
                )
            );

            elements.results.replaceChildren(fragment);

            elements.results.hidden = false;
        }


        /* ================================================
           18. INPUT VALIDATION
        ================================================ */

        function validateEvidence() {
            if (!elements.evidence || !elements.evidenceType) {
                throw new Error(
                    "Evidence input fields are missing."
                );
            }

            const evidence = elements.evidence.value.trim();

            const evidenceType =
                elements.evidenceType.value.trim().toLowerCase();

            if (!evidence) {
                throw new Error(
                    "Please enter evidence before starting analysis."
                );
            }

            if (evidence.length > CONFIG.MAX_EVIDENCE_LENGTH) {
                throw new Error(
                    `Evidence cannot exceed ${CONFIG.MAX_EVIDENCE_LENGTH} characters.`
                );
            }

            if (!CONFIG.SUPPORTED_EVIDENCE_TYPES.includes(evidenceType)) {
                throw new Error(
                    "This evidence type is not currently supported."
                );
            }

            if (evidenceType === "url") {
                let parsedUrl;

                try {
                    parsedUrl = new URL(evidence);
                } catch {
                    throw new Error(
                        "Please enter a valid HTTP or HTTPS URL."
                    );
                }

                if (!["http:", "https:"].includes(parsedUrl.protocol)) {
                    throw new Error(
                        "Only HTTP and HTTPS URLs are supported."
                    );
                }

                if (parsedUrl.username || parsedUrl.password) {
                    throw new Error(
                        "URLs containing embedded credentials are not allowed."
                    );
                }
            }

            return {
                evidence,
                evidenceType
            };
        }


        /* ================================================
           19. AUTHENTICATION
        ================================================ */

        function requireAuthentication() {
            let api;

            try {
                api = getAPI();
            } catch (error) {
                showStatus(error.message, "error");
                return false;
            }

            if (!api.isAuthenticated()) {
                showStatus(
                    "Please log in before running the Agents analysis.",
                    "error"
                );

                window.setTimeout(() => {
                    window.location.href = "login.html";
                }, CONFIG.REDIRECT_DELAY);

                return false;
            }

            return true;
        }


        /* ================================================
           20. API REQUEST
        ================================================ */

        async function runAgentsAnalysis(evidenceType, evidence) {
            const api = getAPI();

            const controller = new AbortController();

            const timeout = window.setTimeout(
                () => controller.abort(),
                CONFIG.REQUEST_TIMEOUT
            );

            try {
                /*
                 * The centralized API service handles:
                 * - Bearer token
                 * - JSON headers
                 * - HTTP errors
                 * - Session expiration
                 *
                 * Endpoint and payload must match the
                 * actual Express agents route/controller.
                 */

                return await api.post(
                    CONFIG.API_ENDPOINT,
                    {
                        evidenceType,
                        evidence
                    },
                    {
                        signal: controller.signal,
                        timeout: CONFIG.REQUEST_TIMEOUT
                    }
                );

            } catch (error) {
                if (controller.signal.aborted) {
                    throw new Error(
                        "Analysis timed out. Please try again."
                    );
                }

                if (error.status === 401) {
                    throw new Error(
                        "Your login session has expired. Please log in again."
                    );
                }

                if (error.status === 403) {
                    throw new Error(
                        "You do not have permission to run this analysis."
                    );
                }

                throw new Error(
                    error.message ||
                    "Unable to connect to ScamShield AI backend."
                );

            } finally {
                window.clearTimeout(timeout);
            }
        }


        /* ================================================
           21. LOADING STATE
        ================================================ */

        let originalButtonText = null;

        function setLoading(isLoading) {
            if (!elements.runButton) {
                return;
            }

            if (isLoading) {
                if (originalButtonText === null) {
                    originalButtonText =
                        elements.runButton.textContent;
                }

                elements.runButton.disabled = true;

                elements.runButton.setAttribute(
                    "aria-busy",
                    "true"
                );

                elements.runButton.textContent =
                    "Analyzing Evidence...";

            } else {
                elements.runButton.disabled = false;

                elements.runButton.removeAttribute(
                    "aria-busy"
                );

                elements.runButton.textContent =
                    originalButtonText || "Run Analysis";

                originalButtonText = null;
            }
        }


        /* ================================================
           22. FORM SUBMISSION
        ================================================ */

        async function handleFormSubmit(event) {
            event.preventDefault();

            clearResults();
            clearStatus();

            let input;

            try {
                input = validateEvidence();
            } catch (error) {
                showStatus(error.message, "error");
                return;
            }

            if (!requireAuthentication()) {
                return;
            }

            setLoading(true);

            showStatus(
                "Analyzing evidence using ScamShield AI agents...",
                "info"
            );

            try {
                const response = await runAgentsAnalysis(
                    input.evidenceType,
                    input.evidence
                );

                renderResults(response);

                showStatus(
                    "Analysis response received successfully.",
                    "success"
                );

                if (elements.results) {
                    const reducedMotion =
                        window.matchMedia &&
                        window.matchMedia(
                            "(prefers-reduced-motion: reduce)"
                        ).matches;

                    elements.results.scrollIntoView({
                        behavior: reducedMotion ? "auto" : "smooth",
                        block: "start"
                    });
                }

            } catch (error) {
                console.error(
                    "[ScamShield Agents]",
                    error
                );

                clearResults();

                showStatus(
                    error.message ||
                    "An unexpected error occurred during analysis.",
                    "error"
                );

            } finally {
                setLoading(false);
            }
        }


        /* ================================================
           23. REVEAL ANIMATIONS
        ================================================ */

        function initializeRevealAnimations() {
            const revealElements = document.querySelectorAll(
                ".agent-reveal"
            );

            if (!revealElements.length) {
                return;
            }

            const reducedMotion =
                window.matchMedia &&
                window.matchMedia(
                    "(prefers-reduced-motion: reduce)"
                ).matches;

            if (
                reducedMotion ||
                !("IntersectionObserver" in window)
            ) {
                revealElements.forEach(element => {
                    element.classList.add("agent-visible");
                });

                return;
            }

            const observer = new IntersectionObserver(
                entries => {
                    entries.forEach(entry => {
                        if (entry.isIntersecting) {
                            entry.target.classList.add("agent-visible");
                            observer.unobserve(entry.target);
                        }
                    });
                },
                {
                    threshold: 0.12
                }
            );

            revealElements.forEach(element => {
                observer.observe(element);
            });
        }


        /* ================================================
           24. CURRENT YEAR
        ================================================ */

        function initializeCurrentYear() {
            document.querySelectorAll("[data-current-year]")
                .forEach(element => {
                    element.textContent =
                        String(new Date().getFullYear());
                });
        }


        /* ================================================
           25. EVENT LISTENERS
        ================================================ */

        elements.form.addEventListener(
            "submit",
            handleFormSubmit
        );

        if (elements.scenario) {
            elements.scenario.addEventListener(
                "change",
                loadDemoScenario
            );
        }

        elements.form.addEventListener(
            "reset",
            () => {
                window.setTimeout(() => {
                    clearResults();
                    clearStatus();

                    if (
                        elements.scenario &&
                        elements.scenario.value
                    ) {
                        loadDemoScenario();
                    }
                }, 0);
            }
        );


        /* ================================================
           26. INITIALIZATION
        ================================================ */

        function initialize() {
            initializeAccessibility();

            initializeRevealAnimations();

            initializeCurrentYear();

            clearResults();

            clearStatus();

            if (
                elements.scenario &&
                elements.scenario.value
            ) {
                loadDemoScenario();
            }

            console.info(
                `[ScamShield Agents] Version ${CONFIG.VERSION} initialized.`
            );
        }

        initialize();
    }

})();