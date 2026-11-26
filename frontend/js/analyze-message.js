
/*
=========================================================
SCAMSHIELD AI - MESSAGE ANALYSIS
=========================================================

File: frontend/js/analyze-message.js
Version: 3.0.0

Features:
1. Message input validation.
2. Evidence type aware analysis.
3. Centralized API integration.
4. Guardian-authoritative risk assessment.
5. Intelligence indicator rendering.
6. Victim Safety recommendations.
7. Gemini advisory-only rendering.
8. Controlled Decoy status.
9. Safe DOM rendering.
10. Feedback handling.
11. Mobile navigation.

=========================================================
*/

"use strict";

(() => {

    // =====================================================
    // CONFIGURATION
    // =====================================================

    const VERSION = "3.0.0";

    const API_ENDPOINT = "/analysis/analyze";

    const MAX_EVIDENCE_LENGTH = 20000;

    const REQUEST_TIMEOUT = 120000;

    const RISK_LEVELS = [
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ];

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

    function firstArray(...values) {

        for (const value of values) {

            if (
                Array.isArray(value) &&
                value.length
            ) {
                return value;
            }
        }

        return [];
    }


    // =====================================================
    // FORM ELEMENTS
    // =====================================================

    const form = $("messageAnalysisForm");

    const messageInput = $("messageContent");

    const sourceInput = $("messageSource");

    const senderInput = $("messageSender");

    const categoryInput = $("messageFraudCategory");

    const consentInput = $("messageAnalysisConsent");

    const analyzeButton = $("analyzeMessageButton");

    const clearButton = $("clearMessageForm");

    const characterCount = $("messageCharacterCount");

    const inputError = $("messageInputError");


    // =====================================================
    // INITIALIZATION
    // =====================================================

    function initialize() {

        if (!form || !messageInput) {

            console.error(
                "[ScamShield Message Analysis] Form not found."
            );

            return;
        }

        bindEvents();

        updateCharacterCount();

        initializeMobileNavigation();

        console.info(
            `[ScamShield Message Analysis] v${VERSION} initialized.`
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

        messageInput.addEventListener(
            "input",
            updateCharacterCount
        );

        if (clearButton) {

            clearButton.addEventListener(
                "click",
                clearForm
            );
        }

        const helpfulButton = $("messageFeedbackHelpful");

        const reviewButton = $("messageFeedbackReview");

        if (helpfulButton) {

            helpfulButton.addEventListener(
                "click",
                () => handleFeedback("helpful")
            );
        }

        if (reviewButton) {

            reviewButton.addEventListener(
                "click",
                () => handleFeedback("needs_review")
            );
        }

    }


    // =====================================================
    // CHARACTER COUNTER
    // =====================================================

    function updateCharacterCount() {

        if (!messageInput || !characterCount) return;

        const length = messageInput.value.length;

        characterCount.textContent =
            `${length.toLocaleString()} / ${MAX_EVIDENCE_LENGTH.toLocaleString()}`;

        characterCount.style.color =
            length > MAX_EVIDENCE_LENGTH * 0.9
                ? "#fbbf24"
                : "";

    }


    // =====================================================
    // INPUT VALIDATION
    // =====================================================

    function validateForm() {

        clearValidationError();

        const message = messageInput.value.trim();

        if (!message) {

            showValidationError(
                "Please enter the suspicious message."
            );

            messageInput.focus();

            return null;
        }

        if (message.length > MAX_EVIDENCE_LENGTH) {

            showValidationError(
                `Message cannot exceed ${MAX_EVIDENCE_LENGTH} characters.`
            );

            messageInput.focus();

            return null;
        }

        const sender = senderInput
            ? senderInput.value.trim()
            : "";

        if (sender.length > 150) {

            showValidationError(
                "Sender information is too long."
            );

            senderInput.focus();

            return null;
        }

        if (!consentInput || !consentInput.checked) {

            showValidationError(
                "Please confirm the consent checkbox before analysis."
            );

            consentInput?.focus();

            return null;
        }

        return {
            message,
            sender,
            source: sourceInput?.value || "unknown",
            category: categoryInput?.value || ""
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

        const evidenceParts = [];

        if (validated.source) {

            evidenceParts.push(
                `Message Source: ${validated.source}`
            );
        }

        if (validated.sender) {

            evidenceParts.push(
                `Sender Information: ${validated.sender}`
            );
        }

        if (validated.category) {

            evidenceParts.push(
                `User Suggested Category: ${validated.category}`
            );
        }

        evidenceParts.push(
            "Message Content:",
            validated.message
        );

        const evidence = evidenceParts.join("\n\n");

        return {

            // Backend analysisController.js expects camelCase.
            evidenceType: "message",

            evidence,

            metadata: {
                source: "analyze-message-page",
                inputMethod: "manual_message_input",
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

        showAnalysisStatus(
            "Analysis in progress",
            "Guardian and supporting agents are examining the submitted message."
        );

        hideElement("messageResults");

        try {

            const response = await requestAnalysis(payload);

            const normalized = normalizeResponse(response);

            if (!normalized.success) {

                throw new Error(
                    normalized.message ||
                    "Message analysis could not be completed."
                );
            }

            renderResults(normalized);

            showAnalysisStatus(
                "Analysis completed",
                "Your message analysis report is ready."
            );

            showElement("messageResults");

            console.info(
                "[ScamShield Message Analysis] Analysis completed.",
                {
                    riskScore: normalized.riskScore,
                    riskLevel: normalized.riskLevel,
                    category: normalized.detectionCategory
                }
            );

            $("messageResults")?.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        } catch (error) {

            console.error(
                "[ScamShield Message Analysis] API error:",
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
                    "Analysis failed."
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
            result.explanation,
            result.riskExplanation
        );

        return {

            success: true,

            id: firstString(
                result.id,
                result._id
            ),

            caseId: firstString(
                result.caseId,
                result.case_id
            ),

            riskScore,

            riskLevel,

            detectionCategory,

            summary,

            explanation: firstString(
                result.explanation,
                result.riskDescription,
                result.risk_description
            ),

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
    // SCORE NORMALIZATION
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
    // RISK LEVEL NORMALIZATION
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
    // CATEGORY NORMALIZATION
    // =====================================================

    function getCategoryLabel(category) {

        if (
            typeof category !== "string" ||
            !category.trim()
        ) {
            return "Not classified";
        }

        const normalized = category.trim().toLowerCase();

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

        const direct = safeArray(resultIndicators);

        direct.forEach(item => {

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

        const indicatorSource = Object.keys(intelligenceData).length
            ? intelligenceData
            : intelligence;

        [
            ["URLs", "urls"],
            ["Phone Numbers", "phone_numbers"],
            ["Emails", "emails"],
            ["UPI IDs", "upi_ids"]
        ].forEach(([label, key]) => {

            safeArray(indicatorSource[key]).forEach(value => {

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

            if (typeof item === "string" && item.trim()) {

                items.push(item.trim());

            } else if (item && typeof item === "object") {

                const text = firstString(
                    item.message,
                    item.description,
                    item.recommendation,
                    item.action
                );

                if (text) items.push(text);
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

                if (typeof item === "string" && item.trim()) {
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

        // Guardian remains the authoritative risk source.

        setText(
            "messageRiskScore",
            data.riskScore
        );

        setText(
            "messageRiskLevel",
            data.riskLevel
        );

        setText(
            "messageFraudCategoryResult",
            getCategoryLabel(data.detectionCategory)
        );

        setText(
            "messageResultStatus",
            "Completed"
        );

        setText(
            "messageRiskDescription",
            data.summary ||
            "Analysis completed. Review the agent findings below."
        );

        renderRiskScoreStyle(data.riskLevel);

        renderGuardian(data);

        renderIntelligence(data);

        renderVictimSafety(data);

        renderGemini(data);

        renderDecoy(data);

    }


    // =====================================================
    // RISK SCORE STYLE
    // =====================================================

    function renderRiskScoreStyle(level) {

        const circle = $("messageRiskScoreCircle");

        if (!circle) return;

        circle.classList.remove(
            "low",
            "medium",
            "high",
            "critical"
        );

        circle.classList.add(
            level.toLowerCase()
        );
    }


    // =====================================================
    // GUARDIAN RENDERING
    // =====================================================

    function renderGuardian(data) {

        const guardian = data.guardian;

        const status = firstString(
            guardian.agent?.status,
            guardian.status
        );

        setText(
            "messageGuardianStatus",
            status
                ? "Completed"
                : "Completed - Primary Result"
        );

        const guardianAnalysis = safeObject(
            guardian.analysis
        );

        const message = firstString(
            guardian.summary,
            guardianAnalysis.summary,
            guardian.message,
            data.summary
        );

        setText(
            "messageGuardianResult",
            message ||
            `Guardian completed the primary assessment with a risk score of ${data.riskScore}/100.`
        );
    }


    // =====================================================
    // INTELLIGENCE RENDERING
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
            "messageIntelligenceStatus",
            successful
                ? "Completed"
                : "Unavailable"
        );

        const summary = safeObject(
            intelligence.summary
        );

        const message = firstString(
            summary.message,
            intelligence.message
        );

        setText(
            "messageIntelligenceResult",
            message ||
            (
                successful
                    ? "Intelligence indicators were processed."
                    : "Intelligence information is unavailable for this analysis."
            )
        );

        renderIndicators(data.indicators);
    }


    // =====================================================
    // INDICATOR RENDERING
    // =====================================================

    function renderIndicators(indicators) {

        const container = $("messageIndicators");

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
                (indicator.verified ? " (Verified)" : " (Unverified)");

            container.appendChild(item);
        });
    }


    // =====================================================
    // VICTIM SAFETY RENDERING
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
            "messageVictimSafetyStatus",
            successful
                ? "Completed"
                : "Unavailable"
        );

        const recommendations = data.recommendations;

        let message = firstString(
            safety.summary,
            safety.message,
            safety.explanation
        );

        if (recommendations.length) {

            message = recommendations
                .map((item, index) =>
                    `${index + 1}. ${item}`
                )
                .join("\n");
        }

        setText(
            "messageVictimSafetyResult",
            message ||
            (
                successful
                    ? "Safety analysis completed. Follow standard precautions."
                    : "No additional safety guidance was returned."
            )
        );
    }


    // =====================================================
    // GEMINI ADVISORY RENDERING
    // =====================================================

    function renderGemini(data) {

        const gemini = data.gemini;

        const available =
            gemini.available === true;

        const status = firstString(
            gemini.status
        );

        const isSuccessful =
            available &&
            status.toLowerCase() !== "unavailable";

        setText(
            "messageGeminiStatus",
            isSuccessful
                ? "Available - Advisory Only"
                : "Unavailable"
        );

        const explanation = firstString(
            gemini.explanation,
            gemini.summary,
            gemini.message
        );

        const tactics = safeArray(
            gemini.social_engineering_tactics
        );

        const safetyNotes = safeArray(
            gemini.safety_notes
        );

        const parts = [];

        if (explanation) {
            parts.push(explanation);
        }

        if (tactics.length) {

            parts.push(
                "Detected tactics: " + tactics.join(", ")
            );
        }

        if (safetyNotes.length) {

            parts.push(
                "Safety notes: " + safetyNotes.join(" ")
            );
        }

        setText(
            "messageGeminiResult",
            isSuccessful
                ? (
                    parts.join("\n\n") ||
                    "Gemini advisory was received."
                )
                : (
                    firstString(
                        gemini.reason,
                        "Gemini advisory is unavailable. Primary Guardian analysis remains independent."
                    )
                )
        );
    }


    // =====================================================
    // DECOY RENDERING
    // =====================================================

    function renderDecoy(data) {

        const decoy = data.decoy;

        const status = firstString(
            decoy.status
        );

        const started =
            status.toLowerCase() === "completed" ||
            status.toLowerCase() === "active";

        setText(
            "messageDecoyStatus",
            started
                ? "Completed"
                : "Not started"
        );

        setText(
            "messageDecoyResult",
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

        showElement("messageAnalysisStatus");

        setText(
            "messageAnalysisStatusTitle",
            title
        );

        setText(
            "messageAnalysisStatusMessage",
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
                '<i class="fa-solid fa-spinner fa-spin"></i> Analyzing...';

        } else {

            analyzeButton.innerHTML =
                '<i class="fa-solid fa-shield-halved"></i> Analyze Message';

        }

    }


    // =====================================================
    // ERROR MESSAGE
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

        return "Unable to complete analysis. Please check your backend and AI engine.";
    }


    // =====================================================
    // CLEAR FORM
    // =====================================================

    function clearForm() {

        if (!form) return;

        form.reset();

        clearValidationError();

        updateCharacterCount();

        hideElement("messageResults");

        hideElement("messageAnalysisStatus");

        const feedback = $("messageFeedbackStatus");

        if (feedback) {
            feedback.textContent = "";
        }

        messageInput?.focus();
    }


    // =====================================================
    // FEEDBACK
    // =====================================================

    function handleFeedback(type) {

        const status = $("messageFeedbackStatus");

        if (!status) return;

        /*
         * No feedback endpoint is assumed here.
         * Persistent feedback requires a backend case/feedback API.
         */

        status.textContent =
            type === "helpful"
                ? "Thank you for your feedback."
                : "Thank you. This result has been marked for your review.";

        console.info(
            "[ScamShield Message Analysis] Feedback selected:",
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

    window.ScamShieldMessageAnalysis = {

        version: VERSION,

        clearForm,

        validateForm,

        updateCharacterCount

    };


    // =====================================================
    // START APPLICATION
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
