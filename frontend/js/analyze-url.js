
/*
=========================================================
SCAMSHIELD AI - URL ANALYSIS
=========================================================

File: frontend/js/analyze-url.js
Version: 3.1.0

Features:
1. URL validation and normalization.
2. Backend-compatible evidence payload.
3. Guardian-authoritative risk assessment.
4. Intelligence indicator extraction.
5. Victim Safety recommendations.
6. Gemini advisory-only results.
7. Decoy status.
8. Safe DOM rendering.
9. Mobile navigation.
10. Feedback UI.

=========================================================
*/

"use strict";

(() => {

    // =====================================================
    // CONFIGURATION
    // =====================================================

    const VERSION = "3.1.0";

    const API_ENDPOINT = "/analysis/analyze";

    const MAX_URL_LENGTH = 2048;

    const REQUEST_TIMEOUT = 120000;

    const ALLOWED_CATEGORIES = [
        "fraud_message",
        "fraud_call",
        "url_phishing",
        "email_scam",
        "investment_scam",
        "digital_arrest",
        "upi_banking_fraud",
        "card_fraud",
        "ecommerce_scam",
        "job_loan_scam",
        "sextortion_blackmail",
        "social_media_scam"
    ];

    const RISK_LEVELS = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ];


    // =====================================================
    // DOM HELPERS
    // =====================================================

    const $ = (id) => document.getElementById(id);

    function setText(id, value) {

        const element = $(id);

        if (!element) return;

        element.textContent =
            value === null || value === undefined
                ? ""
                : String(value);
    }

    function showElement(id) {

        const element = $(id);

        if (element) {
            element.hidden = false;
        }
    }

    function hideElement(id) {

        const element = $(id);

        if (element) {
            element.hidden = true;
        }
    }

    function safeObject(value) {

        return (
            value &&
            typeof value === "object" &&
            !Array.isArray(value)
        )
            ? value
            : {};
    }

    function safeArray(value) {

        return Array.isArray(value) ? value : [];
    }

    function firstString(...values) {

        for (const value of values) {

            if (
                typeof value === "string" &&
                value.trim()
            ) {
                return value.trim();
            }
        }

        return "";
    }


    // =====================================================
    // FORM ELEMENTS
    // =====================================================

    const form = $("urlAnalysisForm");

    const urlInput = $("urlInput");

    const categoryInput = $("urlFraudCategory");

    const consentInput = $("urlAnalysisConsent");

    const analyzeButton = $("analyzeUrlButton");

    const clearButton = $("clearUrlForm");

    const characterCount = $("urlCharacterCount");

    const inputError = $("urlInputError");


    // =====================================================
    // INITIALIZATION
    // =====================================================

    function initialize() {

        if (!form || !urlInput) {

            console.error(
                "[ScamShield URL Analysis] URL analysis form not found."
            );

            return;
        }

        bindEvents();

        updateCharacterCount();

        initializeMobileNavigation();

        console.info(
            `[ScamShield URL Analysis] v${VERSION} initialized.`
        );
    }


    // =====================================================
    // EVENT LISTENERS
    // =====================================================

    function bindEvents() {

        form.addEventListener(
            "submit",
            handleFormSubmit
        );

        urlInput.addEventListener(
            "input",
            updateCharacterCount
        );

        if (clearButton) {

            clearButton.addEventListener(
                "click",
                clearForm
            );
        }

        const helpfulButton = $("urlFeedbackHelpful");

        const reviewButton = $("urlFeedbackReview");

        helpfulButton?.addEventListener(
            "click",
            () => handleFeedback("helpful")
        );

        reviewButton?.addEventListener(
            "click",
            () => handleFeedback("needs_review")
        );
    }


    // =====================================================
    // CHARACTER COUNTER
    // =====================================================

    function updateCharacterCount() {

        if (!urlInput || !characterCount) return;

        const length = urlInput.value.length;

        characterCount.textContent =
            `${length} / ${MAX_URL_LENGTH}`;

        characterCount.style.color =
            length > MAX_URL_LENGTH * 0.9
                ? "#fbbf24"
                : "";
    }


    // =====================================================
    // URL VALIDATION
    // =====================================================

    function validateURL(value) {

        const input = String(value || "").trim();

        if (!input) {

            return {
                valid: false,
                message: "Please enter a website URL."
            };
        }

        if (input.length > MAX_URL_LENGTH) {

            return {
                valid: false,
                message: `URL cannot exceed ${MAX_URL_LENGTH} characters.`
            };
        }

        if (/\s/.test(input)) {

            return {
                valid: false,
                message: "URL cannot contain spaces."
            };
        }

        let normalized = input;

        if (!/^https?:\/\//i.test(normalized)) {
            normalized = `https://${normalized}`;
        }

        let parsed;

        try {

            parsed = new URL(normalized);

        } catch {

            return {
                valid: false,
                message: "Please enter a valid website URL."
            };
        }

        if (
            parsed.protocol !== "http:" &&
            parsed.protocol !== "https:"
        ) {

            return {
                valid: false,
                message: "Only HTTP and HTTPS URLs are supported."
            };
        }

        if (!parsed.hostname || !parsed.hostname.includes(".")) {

            return {
                valid: false,
                message: "Please enter a valid domain name."
            };
        }

        if (
            parsed.username ||
            parsed.password
        ) {

            return {
                valid: false,
                message: "URLs containing embedded usernames or passwords are not accepted."
            };
        }

        return {
            valid: true,
            normalized,
            hostname: parsed.hostname
        };
    }


    // =====================================================
    // FORM VALIDATION
    // =====================================================

    function validateForm() {

        clearValidationError();

        const validation = validateURL(urlInput.value);

        if (!validation.valid) {

            showValidationError(validation.message);

            urlInput.focus();

            return null;
        }

        if (!consentInput || !consentInput.checked) {

            showValidationError(
                "Please confirm the consent checkbox before analysis."
            );

            consentInput?.focus();

            return null;
        }

        const category = categoryInput
            ? categoryInput.value.trim()
            : "";

        if (
            category &&
            !ALLOWED_CATEGORIES.includes(category)
        ) {

            showValidationError(
                "Please select a valid suspected category."
            );

            categoryInput?.focus();

            return null;
        }

        return {
            url: validation.normalized,
            hostname: validation.hostname,
            category
        };
    }


    function showValidationError(message) {

        if (!inputError) return;

        inputError.textContent = message;
    }


    function clearValidationError() {

        if (!inputError) return;

        inputError.textContent = "";
    }


    // =====================================================
    // BUILD BACKEND PAYLOAD
    // =====================================================

    function buildPayload(validated) {

        /*
         * IMPORTANT:
         * analysisController.js expects evidenceType,
         * not evidence_type.
         */

        return {

            evidenceType: "url",

            evidence: validated.url,

            metadata: {
                source: "analyze-url-page",
                inputMethod: "manual_url_submission",
                hostname: validated.hostname,
                userSuggestedCategory: validated.category || null,
                pageVersion: VERSION
            }

        };
    }


    // =====================================================
    // API REQUEST
    // =====================================================

    async function requestAnalysis(payload) {

        const api = window.ScamShieldAPI;

        if (!api || typeof api.post !== "function") {

            throw new Error(
                "ScamShield API service is unavailable. Please reload the page."
            );
        }

        return api.post(
            API_ENDPOINT,
            payload,
            {
                timeout: REQUEST_TIMEOUT
            }
        );
    }


    // =====================================================
    // FORM SUBMISSION
    // =====================================================

    async function handleFormSubmit(event) {

        event.preventDefault();

        const validated = validateForm();

        if (!validated) return;

        const payload = buildPayload(validated);

        setLoadingState(true);

        hideElement("urlResults");

        showAnalysisStatus(
            "URL analysis in progress",
            "ScamShield AI is examining the submitted URL."
        );

        try {

            const response = await requestAnalysis(payload);

            const result = normalizeResponse(response);

            if (!result.success) {

                throw new Error(
                    result.message ||
                    "URL analysis could not be completed."
                );
            }

            renderResults(result);

            showElement("urlResults");

            showAnalysisStatus(
                "Analysis completed",
                "Your URL security report is ready."
            );

            console.info(
                "[ScamShield URL Analysis] Analysis completed.",
                {
                    riskScore: result.riskScore,
                    riskLevel: result.riskLevel,
                    category: result.detectionCategory
                }
            );

            $("urlResults")?.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        } catch (error) {

            console.error(
                "[ScamShield URL Analysis] Analysis error:",
                error
            );

            showAnalysisStatus(
                "Analysis failed",
                getErrorMessage(error)
            );

        } finally {

            setLoadingState(false);

        }
    }


    // =====================================================
    // RESPONSE NORMALIZATION
    // =====================================================

    function normalizeResponse(response) {

        const outer = safeObject(response);

        const data = safeObject(outer.data);

        const body = Object.keys(data).length
            ? data
            : outer;

        const result = safeObject(
            body.result ||
            body.analysis ||
            body
        );

        if (
            body.success === false ||
            result.success === false
        ) {

            return {
                success: false,
                message: firstString(
                    body.message,
                    result.message,
                    result.error?.message,
                    "URL analysis failed."
                )
            };
        }

        const agents = safeObject(result.agents);

        const agentResults = safeObject(
            result.agent_results ||
            result.agentResults
        );

        const guardian = safeObject(
            agents.guardian ||
            agentResults.guardian
        );

        const intelligence = safeObject(
            agents.intelligence ||
            agentResults.intelligence ||
            result.intelligence
        );

        const victimSafety = safeObject(
            agents.victimSafety ||
            agents.victim_safety ||
            agentResults.victim_safety ||
            agentResults.victimSafety ||
            result.victim_safety ||
            result.victimSafety
        );

        const decoy = safeObject(
            agents.decoy ||
            agentResults.decoy
        );

        const gemini = safeObject(
            result.geminiAdvisory ||
            result.gemini_advisory ||
            body.gemini_advisory
        );

        const riskScore = normalizeScore(
            result.riskScore ??
            result.risk_score
        );

        const riskLevel = normalizeRiskLevel(
            result.riskLevel ??
            result.risk_level,
            riskScore
        );

        const detectionCategory = firstString(
            result.detectionCategory,
            result.detection_category,
            result.category,
            result.fraud_category
        );

        const summary = firstString(
            result.summary,
            result.riskDescription,
            result.risk_description,
            result.explanation
        );

        return {

            success: true,

            id: firstString(
                result.id,
                result._id
            ),

            riskScore,

            riskLevel,

            detectionCategory,

            summary,

            guardian,
            intelligence,
            victimSafety,
            decoy,
            gemini,

            indicators: normalizeIndicators(
                result.indicators,
                intelligence
            ),

            recommendations: normalizeRecommendations(
                result.recommendations,
                victimSafety
            ),

            raw: result
        };
    }


    // =====================================================
    // RISK SCORE
    // =====================================================

    function normalizeScore(value) {

        const score = Number(value);

        if (
            !Number.isFinite(score) ||
            score < 0 ||
            score > 100
        ) {
            return 0;
        }

        return Math.round(score);
    }


    // =====================================================
    // RISK LEVEL
    // =====================================================

    function normalizeRiskLevel(value, score) {

        if (typeof value === "string") {

            const normalized = value.toUpperCase();

            if (RISK_LEVELS.includes(normalized)) {
                return normalized;
            }
        }

        if (score <= 24) return "LOW";

        if (score <= 49) return "MEDIUM";

        if (score <= 74) return "HIGH";

        return "CRITICAL";
    }


    // =====================================================
    // CATEGORY LABEL
    // =====================================================

    function getCategoryLabel(category) {

        if (!category) {
            return "Not classified";
        }

        const normalized = String(category)
            .trim()
            .toLowerCase();

        if (!ALLOWED_CATEGORIES.includes(normalized)) {
            return "Not classified";
        }

        return normalized
            .split("_")
            .map(word =>
                word.charAt(0).toUpperCase() + word.slice(1)
            )
            .join(" ");
    }


    // =====================================================
    // INDICATOR NORMALIZATION
    // =====================================================

    function normalizeIndicators(resultIndicators, intelligence) {

        const items = [];

        safeArray(resultIndicators).forEach(item => {

            if (typeof item === "string") {

                items.push({
                    type: "Indicator",
                    value: item,
                    verified: false
                });

                return;
            }

            const indicator = safeObject(item);

            const value = firstString(
                indicator.value,
                indicator.indicator,
                indicator.text
            );

            if (value) {

                items.push({
                    type: firstString(
                        indicator.type,
                        indicator.category,
                        "Indicator"
                    ),
                    value,
                    verified: indicator.verified === true
                });
            }
        });

        const intelligenceData = safeObject(
            intelligence.intelligence
        );

        const source = Object.keys(intelligenceData).length
            ? intelligenceData
            : intelligence;

        [
            ["URLs", "urls"],
            ["Phone Numbers", "phone_numbers"],
            ["Emails", "emails"],
            ["UPI IDs", "upi_ids"]
        ].forEach(([label, key]) => {

            safeArray(source[key]).forEach(value => {

                if (typeof value === "string") {

                    items.push({
                        type: label,
                        value,
                        verified: false
                    });
                }
            });
        });

        const seen = new Set();

        return items.filter(item => {

            const key = `${item.type}:${item.value}`;

            if (seen.has(key)) return false;

            seen.add(key);

            return true;
        });
    }


    // =====================================================
    // RECOMMENDATION NORMALIZATION
    // =====================================================

    function normalizeRecommendations(direct, safety) {

        const items = [];

        safeArray(direct).forEach(item => {

            if (
                typeof item === "string" &&
                item.trim()
            ) {
                items.push(item.trim());

            } else if (
                item &&
                typeof item === "object"
            ) {

                const message = firstString(
                    item.message,
                    item.description,
                    item.recommendation,
                    item.action
                );

                if (message) {
                    items.push(message);
                }
            }
        });

        const safetyData = safeObject(
            safety.victim_safety ||
            safety.safety ||
            safety
        );

        [
            "recommendations",
            "safety_recommendations",
            "immediate_actions",
            "actions"
        ].forEach(key => {

            safeArray(safetyData[key]).forEach(item => {

                if (
                    typeof item === "string" &&
                    item.trim()
                ) {
                    items.push(item.trim());
                }
            });
        });

        return [...new Set(items)];
    }


    // =====================================================
    // RENDER RESULTS
    // =====================================================

    function renderResults(data) {

        setText("urlRiskScore", data.riskScore);

        setText("urlRiskLevel", data.riskLevel);

        setText(
            "urlFraudCategoryResult",
            getCategoryLabel(data.detectionCategory)
        );

        setText("urlResultStatus", "Completed");

        setText(
            "urlRiskDescription",
            data.summary ||
            "Analysis completed. Review the agent findings below."
        );

        renderRiskScoreStyle(data.riskScore, data.riskLevel);

        renderGuardian(data);

        renderIntelligence(data);

        renderVictimSafety(data);

        renderGemini(data);

        renderDecoy(data);
    }


    // =====================================================
    // RISK SCORE VISUAL
    // =====================================================

    function renderRiskScoreStyle(score, level) {

        const circle = $("urlRiskScoreCircle");

        if (!circle) return;

        circle.classList.remove(
            "low",
            "medium",
            "high",
            "critical"
        );

        circle.classList.add(level.toLowerCase());

        const degrees = Math.round(
            Math.max(0, Math.min(100, score)) * 3.6
        );

        const color = getComputedStyle(circle)
            .getPropertyValue("--score-color")
            .trim() || "#42a5f5";

        circle.style.background = `
            conic-gradient(
                ${color} 0deg,
                ${color} ${degrees}deg,
                rgba(148, 163, 184, 0.15) ${degrees}deg,
                rgba(148, 163, 184, 0.15) 360deg
            )
        `;
    }


    // =====================================================
    // GUARDIAN
    // =====================================================

    function renderGuardian(data) {

        const guardian = data.guardian;

        const guardianAnalysis = safeObject(
            guardian.analysis
        );

        const status = firstString(
            guardian.agent?.status,
            guardian.status
        );

        setText(
            "urlGuardianStatus",
            status
                ? "Completed"
                : "Completed - Primary Result"
        );

        setText(
            "urlGuardianResult",
            firstString(
                guardian.summary,
                guardianAnalysis.summary,
                guardian.message,
                data.summary,
                `Guardian completed the primary assessment with a risk score of ${data.riskScore}/100.`
            )
        );
    }


    // =====================================================
    // INTELLIGENCE
    // =====================================================

    function renderIntelligence(data) {

        const intelligence = data.intelligence;

        const status = firstString(
            intelligence.agent?.status,
            intelligence.status
        );

        const successful =
            intelligence.success === true ||
            status === "completed";

        setText(
            "urlIntelligenceStatus",
            successful
                ? "Completed"
                : "Unavailable"
        );

        const summary = safeObject(
            intelligence.summary
        );

        setText(
            "urlIntelligenceResult",
            firstString(
                summary.message,
                intelligence.message,
                successful
                    ? "Intelligence indicators were processed."
                    : "Intelligence information is unavailable."
            )
        );

        renderIndicators(data.indicators);
    }


    // =====================================================
    // INDICATORS
    // =====================================================

    function renderIndicators(indicators) {

        const container = $("urlIndicators");

        if (!container) return;

        container.replaceChildren();

        if (!indicators.length) {

            const empty = document.createElement("p");

            empty.className = "indicator-item";

            empty.textContent =
                "No supported indicators were returned.";

            container.appendChild(empty);

            return;
        }

        indicators.forEach(indicator => {

            const item = document.createElement("div");

            item.className = indicator.verified
                ? "indicator-item"
                : "indicator-item unverified";

            item.textContent =
                `${indicator.type}: ${indicator.value}` +
                (
                    indicator.verified
                        ? " (Verified)"
                        : " (Unverified)"
                );

            container.appendChild(item);
        });
    }


    // =====================================================
    // VICTIM SAFETY
    // =====================================================

    function renderVictimSafety(data) {

        const safety = data.victimSafety;

        const status = firstString(
            safety.agent?.status,
            safety.status
        );

        const successful =
            safety.success === true ||
            status === "completed";

        setText(
            "urlVictimSafetyStatus",
            successful
                ? "Completed"
                : "Unavailable"
        );

        let message = firstString(
            safety.summary,
            safety.message,
            safety.explanation
        );

        if (data.recommendations.length) {

            message = data.recommendations
                .map((item, index) =>
                    `${index + 1}. ${item}`
                )
                .join("\n");
        }

        setText(
            "urlVictimSafetyResult",
            message ||
            (
                successful
                    ? "Safety analysis completed. Follow standard precautions."
                    : "No additional safety guidance was returned."
            )
        );
    }


    // =====================================================
    // GEMINI ADVISORY
    // =====================================================

    function renderGemini(data) {

        const gemini = data.gemini;

        const available =
            gemini.available === true;

        const status = firstString(
            gemini.status
        );

        const successful =
            available &&
            status.toLowerCase() !== "unavailable";

        setText(
            "urlGeminiStatus",
            successful
                ? "Available - Advisory Only"
                : "Unavailable"
        );

        const parts = [];

        const explanation = firstString(
            gemini.explanation,
            gemini.summary,
            gemini.message
        );

        if (explanation) {
            parts.push(explanation);
        }

        const tactics = safeArray(
            gemini.social_engineering_tactics
        );

        if (tactics.length) {
            parts.push(
                "Detected tactics: " + tactics.join(", ")
            );
        }

        const safetyNotes = safeArray(
            gemini.safety_notes
        );

        if (safetyNotes.length) {
            parts.push(
                "Safety notes: " + safetyNotes.join(" ")
            );
        }

        setText(
            "urlGeminiResult",
            successful
                ? (
                    parts.join("\n\n") ||
                    "Gemini advisory was received."
                )
                : firstString(
                    gemini.reason,
                    "Gemini advisory is unavailable. Guardian's primary analysis remains independent."
                )
        );
    }


    // =====================================================
    // DECOY
    // =====================================================

    function renderDecoy(data) {

        const decoy = data.decoy;

        const status = firstString(
            decoy.status
        ).toLowerCase();

        const started =
            status === "completed" ||
            status === "active";

        setText(
            "urlDecoyStatus",
            started
                ? "Completed"
                : "Not started"
        );

        setText(
            "urlDecoyResult",
            firstString(
                decoy.message,
                "Decoy simulation is a separate controlled operation and was not started automatically."
            )
        );
    }


    // =====================================================
    // ANALYSIS STATUS
    // =====================================================

    function showAnalysisStatus(title, message) {

        showElement("urlAnalysisStatus");

        setText(
            "urlAnalysisStatusTitle",
            title
        );

        setText(
            "urlAnalysisStatusMessage",
            message
        );
    }


    // =====================================================
    // LOADING STATE
    // =====================================================

    function setLoadingState(isLoading) {

        if (!analyzeButton) return;

        analyzeButton.disabled = isLoading;

        if (isLoading) {

            analyzeButton.innerHTML =
                '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing URL...';

        } else {

            analyzeButton.innerHTML =
                '<i class="fa-solid fa-shield-halved"></i> Analyze URL';

        }
    }


    // =====================================================
    // ERROR HANDLING
    // =====================================================

    function getErrorMessage(error) {

        if (!error) {
            return "An unexpected error occurred.";
        }

        if (error.name === "AbortError") {

            return "The analysis request timed out. Please try again.";
        }

        if (error.response?.data?.message) {

            return error.response.data.message;
        }

        if (error.data?.message) {

            return error.data.message;
        }

        if (typeof error.message === "string") {

            return error.message;
        }

        return "Unable to complete URL analysis. Check the backend and AI engine.";
    }


    // =====================================================
    // CLEAR FORM
    // =====================================================

    function clearForm() {

        if (!form) return;

        form.reset();

        clearValidationError();

        updateCharacterCount();

        hideElement("urlResults");

        hideElement("urlAnalysisStatus");

        const feedback = $("urlFeedbackStatus");

        if (feedback) {
            feedback.textContent = "";
        }

        urlInput?.focus();
    }


    // =====================================================
    // FEEDBACK
    // =====================================================

    function handleFeedback(type) {

        const status = $("urlFeedbackStatus");

        if (!status) return;

        /*
         * This is UI-level feedback only.
         * Persistent feedback requires a verified backend endpoint.
         */

        status.textContent =
            type === "helpful"
                ? "Thank you for your feedback."
                : "Thank you. This result has been marked for your review.";

        console.info(
            "[ScamShield URL Analysis] Feedback selected:",
            type
        );
    }


    // =====================================================
    // MOBILE NAVIGATION
    // =====================================================

    function initializeMobileNavigation() {

        const toggle = $("mobileMenuToggle");

        const navigation = $("primaryNavigation");

        if (!toggle || !navigation) return;

        toggle.addEventListener("click", () => {

            const isOpen =
                navigation.classList.toggle("open");

            toggle.setAttribute(
                "aria-expanded",
                String(isOpen)
            );

            const icon = toggle.querySelector("i");

            if (icon) {

                icon.className = isOpen
                    ? "fa-solid fa-xmark"
                    : "fa-solid fa-bars";
            }
        });

        navigation.querySelectorAll("a").forEach(link => {

            link.addEventListener("click", () => {

                navigation.classList.remove("open");

                toggle.setAttribute(
                    "aria-expanded",
                    "false"
                );

                const icon = toggle.querySelector("i");

                if (icon) {
                    icon.className = "fa-solid fa-bars";
                }
            });
        });
    }


    // =====================================================
    // PUBLIC API
    // =====================================================

    window.ScamShieldURLAnalysis = {

        version: VERSION,

        validateURL,

        validateForm,

        clearForm,

        updateCharacterCount

    };


    // =====================================================
    // START
    // =====================================================

    if (document.readyState === "loading") {

        document.addEventListener(
            "DOMContentLoaded",
            initialize
        );

    } else {

        initialize();

    }

})();
