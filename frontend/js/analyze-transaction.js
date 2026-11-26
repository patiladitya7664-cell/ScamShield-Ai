
/*
=========================================================
 SCAMSHIELD AI - TRANSACTION ANALYSIS
 File: analyze-transaction.js
 Version: 3.0.0

 Backend:
 POST /api/analysis/analyze

 Evidence Type:
 transaction

 Responsibilities:
 1. Validate transaction information.
 2. Protect sensitive financial information.
 3. Submit transaction evidence to backend.
 4. Preserve Guardian's authoritative assessment.
 5. Display Intelligence and Victim Safety results.
 6. Display Gemini advisory separately.
 7. Never automatically start Decoy Agent.
 8. Render untrusted content safely.
=========================================================
*/

"use strict";


/* =====================================================
   CONFIGURATION
===================================================== */

const TransactionAnalysis = (() => {

    const VERSION = "3.0.0";

    const API_ENDPOINT = "/analysis/analyze";

    const MAX_EVIDENCE_LENGTH = 20000;

    const ALLOWED_TRANSACTION_TYPES = [
        "upi",
        "bank_transfer",
        "credit_card",
        "debit_card",
        "online_payment",
        "wallet",
        "other"
    ];

    const ALLOWED_DIRECTIONS = [
        "unknown",
        "sent",
        "received",
        "requested",
        "pending",
        "failed",
        "unauthorized"
    ];

    const ALLOWED_CATEGORIES = [
        "upi_banking_fraud",
        "card_fraud",
        "investment_scam",
        "digital_arrest",
        "ecommerce_scam",
        "job_loan_scam",
        "social_media_scam",
        "fraud_message"
    ];

    const CATEGORY_LABELS = {
        fraud_message: "Fraud Message",
        fraud_call: "Fraud Call",
        url_phishing: "URL Phishing",
        email_scam: "Email Scam",
        investment_scam: "Investment Scam",
        digital_arrest: "Digital Arrest",
        upi_banking_fraud: "UPI / Banking Fraud",
        card_fraud: "Card Fraud",
        ecommerce_scam: "E-commerce Scam",
        job_loan_scam: "Job / Loan Scam",
        sextortion_blackmail: "Sextortion / Blackmail",
        social_media_scam: "Social Media Scam"
    };

    const RISK_LEVELS = [
        "low",
        "medium",
        "high",
        "critical"
    ];

    let isSubmitting = false;
    let lastAnalysisId = null;
    let feedbackSelection = null;


    /* =================================================
       DOM HELPERS
    ================================================= */

    function getElement(id) {
        return document.getElementById(id);
    }


    function getValue(id) {
        const element = getElement(id);

        return element
            ? String(element.value || "").trim()
            : "";
    }


    function setText(id, value) {
        const element = getElement(id);

        if (!element) return;

        element.textContent =
            value === null || value === undefined
                ? ""
                : String(value);
    }


    function showElement(id) {
        const element = getElement(id);

        if (element) {
            element.hidden = false;
        }
    }


    function hideElement(id) {
        const element = getElement(id);

        if (element) {
            element.hidden = true;
        }
    }


    function createElement(tag, className, text) {
        const element = document.createElement(tag);

        if (className) {
            element.className = className;
        }

        if (text !== undefined && text !== null) {
            element.textContent = String(text);
        }

        return element;
    }


    function clearElement(element) {
        if (element) {
            element.replaceChildren();
        }
    }


    function normalizeString(value) {
        if (typeof value !== "string") {
            return "";
        }

        return value.trim();
    }


    function isObject(value) {
        return (
            value !== null &&
            typeof value === "object" &&
            !Array.isArray(value)
        );
    }


    function getNestedValue(object, paths) {

        for (const path of paths) {

            const value = path
                .split(".")
                .reduce((current, key) => {
                    return current && current[key] !== undefined
                        ? current[key]
                        : undefined;
                }, object);

            if (
                value !== undefined &&
                value !== null &&
                value !== ""
            ) {
                return value;
            }
        }

        return null;
    }


    /* =================================================
       FORM VALIDATION
    ================================================= */

    function showInputError(message) {

        const errorBox = getElement(
            "transactionInputError"
        );

        if (!errorBox) return;

        const messageElement = errorBox.querySelector("span");

        if (messageElement) {
            messageElement.textContent = message;
        }

        errorBox.hidden = false;

        errorBox.scrollIntoView({
            behavior: "smooth",
            block: "center"
        });
    }


    function clearInputError() {

        const errorBox = getElement(
            "transactionInputError"
        );

        if (!errorBox) return;

        const messageElement = errorBox.querySelector("span");

        if (messageElement) {
            messageElement.textContent = "";
        }

        errorBox.hidden = true;
    }


    function validateAmount(value) {

        if (!value) {
            return {
                valid: true,
                value: null
            };
        }

        const amount = Number(value);

        if (
            !Number.isFinite(amount) ||
            amount <= 0 ||
            amount > 100000000
        ) {
            return {
                valid: false,
                message: "Enter a valid transaction amount."
            };
        }

        return {
            valid: true,
            value: amount
        };
    }


    function validateReceiver(value) {

        if (value.length > 150) {
            return {
                valid: false,
                message: "Receiver name must be within 150 characters."
            };
        }

        return {
            valid: true
        };
    }


    function validateUPI(value) {

        if (!value) {
            return {
                valid: true
            };
        }

        if (value.length > 150) {
            return {
                valid: false,
                message: "UPI ID is too long."
            };
        }

        if (/\s/.test(value)) {
            return {
                valid: false,
                message: "UPI ID must not contain spaces."
            };
        }

        if (!/^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$/.test(value)) {
            return {
                valid: false,
                message: "Enter a valid UPI ID format."
            };
        }

        return {
            valid: true
        };
    }


    function validateDate(value) {

        if (!value) {
            return {
                valid: true
            };
        }

        if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
            return {
                valid: false,
                message: "Enter a valid transaction date."
            };
        }

        const parsed = new Date(value + "T00:00:00");

        if (
            Number.isNaN(parsed.getTime()) ||
            parsed.toISOString().slice(0, 10) !== value
        ) {
            return {
                valid: false,
                message: "Enter a valid transaction date."
            };
        }

        return {
            valid: true
        };
    }


    /*
      Basic protection against accidentally submitting
      actual financial authentication credentials.

      Ordinary scam messages mentioning OTP/PIN are allowed.
      The check targets values explicitly labelled as secrets.
    */

    function containsSensitiveCredentials(text) {

        const patterns = [
            /\b(?:otp|one[\s-]?time password)\s*(?:is|:|=|-)\s*\d{4,8}\b/i,

            /\b(?:upi pin|atm pin|banking pin|card pin|security pin)\s*(?:is|:|=|-)\s*\d{4,6}\b/i,

            /\b(?:cvv|cvc)\s*(?:is|:|=|-)\s*\d{3,4}\b/i,

            /\b(?:password|passcode)\s*(?:is|:|=|-)\s*[A-Za-z0-9!@#$%^&*_-]{4,}\b/i,

            /\b(?:card number|credit card number|debit card number)\s*(?:is|:|=|-)\s*(?:\d[ -]?){13,19}\b/i,

            /\b(?:account number|bank account number|a\/c number)\s*(?:is|:|=|-)\s*\d{9,18}\b/i
        ];

        return patterns.some(pattern => pattern.test(text));
    }


    function validateForm() {

        clearInputError();

        const transactionType = getValue("transactionType");

        const direction = getValue("transactionDirection");

        const amountInput = getValue("transactionAmount");

        const receiver = getValue("transactionReceiver");

        const upi = getValue("transactionUPI");

        const reference = getValue("transactionReference");

        const date = getValue("transactionDate");

        const category = getValue(
            "transactionFraudCategory"
        );

        const evidence = getValue(
            "transactionEvidence"
        );

        const consent = getElement(
            "transactionAnalysisConsent"
        );

        if (!ALLOWED_TRANSACTION_TYPES.includes(transactionType)) {
            return {
                valid: false,
                message: "Please select a valid transaction type."
            };
        }

        if (!ALLOWED_DIRECTIONS.includes(direction)) {
            return {
                valid: false,
                message: "Please select a valid transaction situation."
            };
        }

        const amountResult = validateAmount(amountInput);

        if (!amountResult.valid) {
            return {
                valid: false,
                message: amountResult.message
            };
        }

        const receiverResult = validateReceiver(receiver);

        if (!receiverResult.valid) {
            return {
                valid: false,
                message: receiverResult.message
            };
        }

        const upiResult = validateUPI(upi);

        if (!upiResult.valid) {
            return {
                valid: false,
                message: upiResult.message
            };
        }

        const dateResult = validateDate(date);

        if (!dateResult.valid) {
            return {
                valid: false,
                message: dateResult.message
            };
        }

        if (
            category &&
            !ALLOWED_CATEGORIES.includes(category)
        ) {
            return {
                valid: false,
                message: "Invalid suspected fraud category."
            };
        }

        if (reference.length > 100) {
            return {
                valid: false,
                message: "Transaction reference must be within 100 characters."
            };
        }

        if (!evidence) {
            return {
                valid: false,
                message: "Please enter the transaction message or relevant details."
            };
        }

        if (evidence.length > MAX_EVIDENCE_LENGTH) {
            return {
                valid: false,
                message: "Transaction evidence exceeds the 20,000 character limit."
            };
        }

        if (containsSensitiveCredentials(evidence)) {
            return {
                valid: false,
                message: "Your evidence appears to contain an actual OTP, PIN, CVV, password or financial credential. Remove it before submitting."
            };
        }

        if (!consent || !consent.checked) {
            return {
                valid: false,
                message: "Please confirm that sensitive financial information has been removed."
            };
        }

        return {
            valid: true,
            data: {
                transactionType,
                direction,
                amount: amountResult.value,
                receiver,
                upi,
                reference,
                date,
                category,
                evidence
            }
        };
    }


    /* =================================================
       PAYLOAD BUILDER
    ================================================= */

    function buildEvidence(data) {

        const transactionTypeLabels = {
            upi: "UPI Payment",
            bank_transfer: "Bank Transfer",
            credit_card: "Credit Card",
            debit_card: "Debit Card",
            online_payment: "Online Payment",
            wallet: "Digital Wallet",
            other: "Other"
        };

        const directionLabels = {
            unknown: "Not specified",
            sent: "Money sent",
            received: "Money received",
            requested: "Payment requested",
            pending: "Transaction pending",
            failed: "Transaction failed",
            unauthorized: "Unauthorized transaction"
        };

        const parts = [
            "TRANSACTION ANALYSIS EVIDENCE",

            `Transaction Type: ${transactionTypeLabels[data.transactionType]}`,

            `Transaction Situation: ${directionLabels[data.direction]}`
        ];

        if (data.amount !== null) {
            parts.push(
                `Transaction Amount: INR ${data.amount}`
            );
        }

        if (data.receiver) {
            parts.push(
                `Receiver / Merchant Name: ${data.receiver}`
            );
        }

        if (data.upi) {
            parts.push(
                `UPI ID: ${data.upi}`
            );
        }

        if (data.date) {
            parts.push(
                `Transaction Date: ${data.date}`
            );
        }

        /*
          Transaction reference is intentionally not sent.
          It may expose private transaction information.
        */

        if (data.category) {
            parts.push(
                `User Suspected Category: ${CATEGORY_LABELS[data.category] || data.category}`
            );
        }

        parts.push(
            "User Provided Transaction Message / Details:"
        );

        parts.push(data.evidence);

        return parts.join("\n\n");
    }


    function buildPayload(data) {

        return {
            evidenceType: "transaction",

            evidence: buildEvidence(data)
        };
    }


    /* =================================================
       API
    ================================================= */

    function getAPI() {

        if (
            !window.ScamShieldAPI ||
            typeof window.ScamShieldAPI.post !== "function"
        ) {
            throw new Error(
                "ScamShield API service is unavailable. Please refresh the page."
            );
        }

        return window.ScamShieldAPI;
    }


    async function submitAnalysis(payload) {

        const api = getAPI();

        return api.post(
            API_ENDPOINT,
            payload,
            {
                timeout: 120000
            }
        );
    }


    /* =================================================
       RESPONSE NORMALIZATION
    ================================================= */

    function normalizeResponse(response) {

        if (!isObject(response)) {
            throw new Error(
                "The server returned an invalid response."
            );
        }

        if (response.success === false) {
            throw new Error(
                response.message ||
                response.error ||
                "Transaction analysis failed."
            );
        }

        let result = response.result ||
                     response.data?.result ||
                     response.data ||
                     response;

        if (!isObject(result)) {
            throw new Error(
                "The analysis result is missing."
            );
        }

        if (result.success === false) {
            throw new Error(
                result.message ||
                result.error ||
                "The AI engine could not complete the analysis."
            );
        }

        const riskScore = Number(
            getNestedValue(result, [
                "riskScore",
                "risk_score"
            ])
        );

        const riskLevel = normalizeString(
            getNestedValue(result, [
                "riskLevel",
                "risk_level"
            ])
        ).toLowerCase();

        const detectionCategory = normalizeString(
            getNestedValue(result, [
                "detectionCategory",
                "detection_category"
            ])
        );

        const fraudCategory = normalizeString(
            getNestedValue(result, [
                "fraudCategory",
                "fraud_category"
            ])
        );

        if (
            !Number.isInteger(riskScore) ||
            riskScore < 0 ||
            riskScore > 100
        ) {
            throw new Error(
                "The server returned an invalid risk score."
            );
        }

        if (!RISK_LEVELS.includes(riskLevel)) {
            throw new Error(
                "The server returned an invalid risk level."
            );
        }

        const validCategory = Object.prototype.hasOwnProperty.call(
            CATEGORY_LABELS,
            detectionCategory
        );

        return {
            id: result.id || result.evidenceId || null,

            riskScore,

            riskLevel,

            detectionCategory: validCategory
                ? detectionCategory
                : null,

            fraudCategory,

            riskDescription:
                result.riskDescription ||
                result.risk_description ||
                result.summary ||
                "Analysis completed.",

            explanation:
                result.explanation ||
                result.summary ||
                result.riskDescription ||
                "No additional explanation was provided.",

            indicators: result.indicators || [],

            detectedRules: result.detectedRules ||
                           result.detected_rules ||
                           [],

            recommendations: result.recommendations || [],

            agents: isObject(result.agents)
                ? result.agents
                : {},

            intelligence: isObject(result.intelligence)
                ? result.intelligence
                : null,

            victimSafety: isObject(result.victimSafety)
                ? result.victimSafety
                : isObject(result.victim_safety)
                    ? result.victim_safety
                    : null,

            geminiAdvisory:
                result.geminiAdvisory ||
                result.gemini_advisory ||
                null,

            machineLearning:
                result.machineLearning ||
                result.machine_learning ||
                null,

            orchestration:
                result.orchestration || null,

            verification:
                result.verification || null,

            disclaimer:
                result.disclaimer || null,

            analyzedAt:
                result.analyzedAt ||
                result.analyzed_at ||
                null
        };
    }


    /* =================================================
       RISK DISPLAY
    ================================================= */

    function renderRisk(result) {

        setText(
            "transactionRiskScore",
            result.riskScore
        );

        setText(
            "transactionRiskLevel",
            result.riskLevel.toUpperCase()
        );

        setText(
            "transactionRiskDescription",
            result.riskDescription
        );

        const circle = getElement(
            "transactionRiskScoreCircle"
        );

        if (circle) {

            circle.classList.remove(
                "low",
                "medium",
                "high",
                "critical"
            );

            circle.classList.add(result.riskLevel);

            circle.style.setProperty(
                "--risk-progress",
                `${result.riskScore * 3.6}deg`
            );
        }

        const level = getElement(
            "transactionRiskLevel"
        );

        if (level) {

            level.classList.remove(
                "low",
                "medium",
                "high",
                "critical"
            );

            level.classList.add(result.riskLevel);
        }

        const categoryLabel = result.detectionCategory
            ? CATEGORY_LABELS[result.detectionCategory]
            : "Not classified";

        setText(
            "transactionFraudCategoryResult",
            categoryLabel
        );

        setText(
            "transactionRiskExplanation",
            result.explanation
        );
    }


    /* =================================================
       GENERIC SAFE CONTENT RENDERING
    ================================================= */

    function renderValue(container, value) {

        if (!container) return;

        clearElement(container);

        if (value === null || value === undefined || value === "") {

            container.textContent = "No additional information available.";

            return;
        }

        if (typeof value === "string" || typeof value === "number") {

            container.textContent = String(value);

            return;
        }

        if (typeof value === "boolean") {

            container.textContent = value ? "Yes" : "No";

            return;
        }

        if (Array.isArray(value)) {

            if (value.length === 0) {

                container.textContent = "No items reported.";

                return;
            }

            const list = createElement("ul");

            value.forEach(item => {

                const listItem = createElement("li");

                if (typeof item === "string" || typeof item === "number") {

                    listItem.textContent = String(item);

                } else if (isObject(item)) {

                    const label =
                        item.label ||
                        item.name ||
                        item.type ||
                        item.category ||
                        "Information";

                    const detail =
                        item.value ||
                        item.description ||
                        item.message ||
                        "";

                    listItem.textContent = detail
                        ? `${label}: ${detail}`
                        : String(label);

                } else {

                    listItem.textContent = String(item);
                }

                list.appendChild(listItem);
            });

            container.appendChild(list);

            return;
        }

        if (isObject(value)) {

            const list = createElement("ul");

            Object.entries(value).forEach(([key, item]) => {

                const listItem = createElement("li");

                const label = key
                    .replace(/_/g, " ")
                    .replace(/([A-Z])/g, " $1");

                const formattedLabel =
                    label.charAt(0).toUpperCase() +
                    label.slice(1);

                let detail;

                if (
                    typeof item === "string" ||
                    typeof item === "number" ||
                    typeof item === "boolean"
                ) {
                    detail = String(item);
                } else if (Array.isArray(item)) {
                    detail = item.map(entry => {

                        if (isObject(entry)) {
                            return JSON.stringify(entry);
                        }

                        return String(entry);

                    }).join(", ");
                } else if (isObject(item)) {
                    detail = JSON.stringify(item);
                } else {
                    detail = "Not available";
                }

                listItem.textContent =
                    `${formattedLabel}: ${detail}`;

                list.appendChild(listItem);
            });

            container.appendChild(list);

            return;
        }

        container.textContent = String(value);
    }


    /* =================================================
       AGENT STATUS
    ================================================= */

    function setAgentStatus(id, status, label) {

        const element = getElement(id);

        if (!element) return;

        element.textContent = label || status;

        element.dataset.status = status;
    }


    function getAgentStatus(agent) {

        if (!isObject(agent)) {
            return "unavailable";
        }

        if (agent.success === false) {
            return "failed";
        }

        const status = normalizeString(
            agent.status ||
            agent.agent?.status ||
            agent.metadata?.status
        ).toLowerCase();

        if (
            status === "failed" ||
            status === "error"
        ) {
            return "failed";
        }

        if (
            status === "not_started" ||
            status === "skipped"
        ) {
            return "not_started";
        }

        if (
            status === "completed" ||
            status === "success" ||
            status === "available"
        ) {
            return "completed";
        }

        return agent.success === true
            ? "completed"
            : "unknown";
    }


    function renderAgent(
        statusId,
        resultId,
        agent,
        options = {}
    ) {

        const status = getAgentStatus(agent);

        const labels = {
            completed: "Completed",
            failed: "Failed",
            unavailable: "Unavailable",
            not_started: "Not Started",
            unknown: "Status Unknown"
        };

        setAgentStatus(
            statusId,
            status,
            labels[status]
        );

        const container = getElement(resultId);

        if (!container) return;

        if (status === "unavailable") {

            renderValue(
                container,
                options.unavailableMessage ||
                "Agent information was not returned by the server."
            );

            return;
        }

        if (status === "failed") {

            renderValue(
                container,
                options.failureMessage ||
                agent?.error?.message ||
                agent?.message ||
                "Agent execution failed."
            );

            return;
        }

        if (status === "not_started") {

            renderValue(
                container,
                options.notStartedMessage ||
                agent?.message ||
                "This agent was not started."
            );

            return;
        }

        const displayData =
            options.extract
                ? options.extract(agent)
                : agent;

        renderValue(
            container,
            displayData
        );
    }


    /* =================================================
       GUARDIAN
    ================================================= */

    function renderGuardian(result) {

        const guardian = result.agents.guardian;

        renderAgent(
            "transactionGuardianStatus",
            "transactionGuardianResult",
            guardian,
            {
                unavailableMessage:
                    "Guardian agent details were not separately returned. The risk score and category shown above are the backend's primary assessment.",

                extract: agent => {

                    const analysis =
                        agent.analysis ||
                        agent.result ||
                        agent;

                    return {
                        status:
                            agent.agent?.status ||
                            agent.status ||
                            "Completed",

                        fraudCategory:
                            analysis.fraud_category ||
                            analysis.category ||
                            result.detectionCategory ||
                            "Not classified",

                        riskScore:
                            analysis.risk_score ??
                            analysis.riskScore ??
                            result.riskScore,

                        riskLevel:
                            analysis.risk_level ||
                            analysis.riskLevel ||
                            result.riskLevel,

                        summary:
                            analysis.summary ||
                            result.riskDescription,

                        explanations:
                            analysis.explanations || [],

                        detectedRules:
                            analysis.detected_rules ||
                            analysis.detectedRules ||
                            result.detectedRules
                    };
                }
            }
        );
    }


    /* =================================================
       INTELLIGENCE
    ================================================= */

    function normalizeIndicators(result) {

        const collected = [];

        function add(type, value, verified = false) {

            if (
                value === null ||
                value === undefined ||
                value === ""
            ) {
                return;
            }

            if (Array.isArray(value)) {

                value.forEach(item => {
                    add(type, item, verified);
                });

                return;
            }

            if (isObject(value)) {

                const itemValue =
                    value.value ||
                    value.indicator ||
                    value.url ||
                    value.phone ||
                    value.email ||
                    value.upi_id;

                if (itemValue) {
                    collected.push({
                        type: value.type || type,
                        value: String(itemValue),
                        verified: value.verified === true
                    });
                }

                return;
            }

            collected.push({
                type,
                value: String(value),
                verified: verified === true
            });
        }


        const source = result.intelligence || {};

        const agentIntelligence =
            result.agents.intelligence;

        const nestedIntelligence =
            isObject(agentIntelligence?.intelligence)
                ? agentIntelligence.intelligence
                : {};

        const intelligence = {
            ...nestedIntelligence,
            ...source
        };

        const indicators = result.indicators;

        if (Array.isArray(indicators)) {

            indicators.forEach(item => {

                if (isObject(item)) {

                    add(
                        item.type || "indicator",
                        item.value || item.indicator,
                        item.verified === true
                    );

                } else {

                    add("indicator", item);
                }
            });

        } else if (isObject(indicators)) {

            Object.entries(indicators).forEach(([type, values]) => {
                add(type, values);
            });
        }

        add("URL", intelligence.urls || intelligence.url);

        add(
            "Phone Number",
            intelligence.phone_numbers ||
            intelligence.phoneNumbers
        );

        add(
            "Email",
            intelligence.emails ||
            intelligence.email
        );

        add(
            "UPI ID",
            intelligence.upi_ids ||
            intelligence.upiIds
        );

        const unique = new Map();

        collected.forEach(item => {

            const key =
                `${item.type}:${item.value}`.toLowerCase();

            if (!unique.has(key)) {
                unique.set(key, item);
            }
        });

        return Array.from(unique.values());
    }


    function renderIndicators(result) {

        const container = getElement(
            "transactionIndicators"
        );

        if (!container) return;

        clearElement(container);

        const indicators = normalizeIndicators(result);

        if (!indicators.length) {

            container.appendChild(
                createElement(
                    "p",
                    "field-help",
                    "No additional indicators were extracted."
                )
            );

            return;
        }

        indicators.forEach(item => {

            const chip = createElement(
                "span",
                item.verified
                    ? "indicator-item"
                    : "indicator-item unverified"
            );

            const icon = createElement("i");

            icon.className = item.verified
                ? "fa-solid fa-circle-check"
                : "fa-solid fa-circle-exclamation";

            chip.appendChild(icon);

            chip.appendChild(
                document.createTextNode(
                    `${item.type}: ${item.value}`
                )
            );

            if (!item.verified) {
                chip.title = "Unverified indicator";
            }

            container.appendChild(chip);
        });
    }


    function renderIntelligence(result) {

        let intelligence = result.agents.intelligence;

        if (
            !isObject(intelligence) ||
            Object.keys(intelligence).length === 0
        ) {
            intelligence = result.intelligence;
        }

        renderAgent(
            "transactionIntelligenceStatus",
            "transactionIntelligenceResult",
            intelligence,
            {
                unavailableMessage:
                    "Intelligence Agent information is unavailable.",

                extract: agent => {

                    const data =
                        agent.intelligence ||
                        agent;

                    return {
                        summary:
                            agent.summary?.message ||
                            agent.summary ||
                            "Indicator extraction completed.",

                        indicatorCounts:
                            agent.indicator_counts ||
                            agent.indicatorCounts ||
                            {},

                        verification:
                            agent.verification || {
                                status: "UNVERIFIED"
                            },

                        intelligence: data
                    };
                }
            }
        );

        renderIndicators(result);
    }


    /* =================================================
       VICTIM SAFETY
    ================================================= */

    function renderVictimSafety(result) {

        const safety =
            result.agents.victimSafety ||
            result.victimSafety;

        renderAgent(
            "transactionVictimSafetyStatus",
            "transactionVictimSafetyResult",
            safety,
            {
                unavailableMessage:
                    "Victim Safety guidance was not returned by the AI engine.",

                extract: agent => {

                    return (
                        agent.safety ||
                        agent.guidance ||
                        agent.result ||
                        agent
                    );
                }
            }
        );
    }


    /* =================================================
       GEMINI ADVISORY
    ================================================= */

    function renderGemini(result) {

        const advisory = result.geminiAdvisory;

        const container = getElement(
            "transactionGeminiResult"
        );

        if (!container) return;

        if (!isObject(advisory)) {

            setAgentStatus(
                "transactionGeminiStatus",
                "unavailable",
                "Unavailable"
            );

            renderValue(
                container,
                "Gemini advisory was not returned. Guardian's assessment remains valid independently."
            );

            return;
        }

        const available = advisory.available === true;

        if (!available) {

            setAgentStatus(
                "transactionGeminiStatus",
                "unavailable",
                "Unavailable"
            );

            renderValue(
                container,
                advisory.message ||
                advisory.explanation ||
                "Gemini advisory is currently unavailable."
            );

            return;
        }

        setAgentStatus(
            "transactionGeminiStatus",
            "completed",
            "Advisory Available"
        );

        const display = {
            explanation:
                advisory.explanation ||
                advisory.summary ||
                "No additional explanation provided.",

            scamIntent:
                advisory.scam_intent ||
                advisory.scamIntent ||
                null,

            socialEngineeringTactics:
                advisory.social_engineering_tactics ||
                advisory.socialEngineeringTactics ||
                [],

            contextualIndicators:
                advisory.contextual_indicators ||
                advisory.contextualIndicators ||
                [],

            supportingEvidence:
                advisory.supporting_evidence ||
                advisory.supportingEvidence ||
                [],

            alternativeInterpretations:
                advisory.alternative_interpretations ||
                advisory.alternativeInterpretations ||
                [],

            advisoryConfidence:
                advisory.advisory_confidence ||
                advisory.advisoryConfidence ||
                "Not specified",

            safetyNotes:
                advisory.safety_notes ||
                advisory.safetyNotes ||
                advisory.recommendations ||
                []
        };

        renderValue(container, display);
    }


    /* =================================================
       DECOY
    ================================================= */

    function renderDecoy(result) {

        const decoy = result.agents.decoy;

        renderAgent(
            "transactionDecoyStatus",
            "transactionDecoyResult",
            decoy,
            {
                unavailableMessage:
                    "Decoy Agent status was not returned.",

                notStartedMessage:
                    "Decoy simulation was not started. It is a separate controlled feature and does not run automatically during normal analysis."
            }
        );
    }


    /* =================================================
       FEEDBACK
    ================================================= */

    function handleFeedback(type) {

        feedbackSelection = type;

        const helpful = getElement(
            "transactionFeedbackHelpful"
        );

        const review = getElement(
            "transactionFeedbackReview"
        );

        if (helpful) {
            helpful.classList.toggle(
                "active",
                type === "helpful"
            );
        }

        if (review) {
            review.classList.toggle(
                "active",
                type === "review"
            );
        }

        setText(
            "transactionFeedbackStatus",
            type === "helpful"
                ? "Thank you for your feedback."
                : "Thank you. Your review preference has been recorded on this page."
        );

        /*
          UI-only feedback.

          No verified feedback endpoint has been established
          in the current backend contract. Do not claim that
          this feedback has been saved to the database.
        */
    }


    /* =================================================
       COMPLETE RESULT RENDERING
    ================================================= */

    function renderResults(result) {

        lastAnalysisId = result.id;

        renderRisk(result);

        renderGuardian(result);

        renderIntelligence(result);

        renderVictimSafety(result);

        renderGemini(result);

        renderDecoy(result);

        showElement("transactionResults");

        hideElement("transactionAnalysisStatus");

        const status = getElement(
            "transactionResultStatus"
        );

        if (status) {

            status.replaceChildren();

            const icon = createElement("i");

            icon.className = "fa-solid fa-circle-check";

            status.appendChild(icon);

            status.appendChild(
                document.createTextNode(" Analysis Complete")
            );
        }

        getElement("transactionResults")?.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });
    }


    /* =================================================
       LOADING STATE
    ================================================= */

    function setLoadingState(loading) {

        const button = getElement(
            "analyzeTransactionButton"
        );

        const clearButton = getElement(
            "clearTransactionForm"
        );

        if (button) {

            button.disabled = loading;

            if (loading) {

                button.replaceChildren();

                const icon = createElement("i");

                icon.className = "fa-solid fa-circle-notch fa-spin";

                button.appendChild(icon);

                button.appendChild(
                    document.createTextNode(" Analyzing...")
                );

            } else {

                button.replaceChildren();

                const icon = createElement("i");

                icon.className = "fa-solid fa-shield-halved";

                button.appendChild(icon);

                const label = createElement(
                    "span",
                    "",
                    "Analyze Transaction"
                );

                button.appendChild(label);
            }
        }

        if (clearButton) {
            clearButton.disabled = loading;
        }

        const statusTitle = getElement(
            "transactionAnalysisStatusTitle"
        );

        const statusMessage = getElement(
            "transactionAnalysisStatusMessage"
        );

        if (loading) {

            if (statusTitle) {
                statusTitle.textContent =
                    "Analyzing Transaction";
            }

            if (statusMessage) {
                statusMessage.textContent =
                    "ScamShield AI is examining transaction evidence and running the available security analysis.";
            }

            showElement("transactionAnalysisStatus");

        } else {

            hideElement("transactionAnalysisStatus");
        }
    }


    /* =================================================
       ERROR HANDLING
    ================================================= */

    function getErrorMessage(error) {

        if (!error) {
            return "An unexpected error occurred.";
        }

        if (typeof error === "string") {
            return error;
        }

        if (error.response?.data?.message) {
            return error.response.data.message;
        }

        if (error.response?.data?.error) {
            return error.response.data.error;
        }

        if (error.data?.message) {
            return error.data.message;
        }

        if (error.message) {
            return error.message;
        }

        return "Unable to complete transaction analysis. Please try again.";
    }


    function showAnalysisError(error) {

        const message = getErrorMessage(error);

        hideElement("transactionAnalysisStatus");

        showInputError(message);
    }


    /* =================================================
       ANALYSIS SUBMISSION
    ================================================= */

    async function handleSubmit(event) {

        event.preventDefault();

        if (isSubmitting) return;

        const validation = validateForm();

        if (!validation.valid) {

            showInputError(validation.message);

            return;
        }

        hideElement("transactionResults");

        feedbackSelection = null;
        lastAnalysisId = null;

        const payload = buildPayload(
            validation.data
        );

        isSubmitting = true;

        setLoadingState(true);

        try {

            const response = await submitAnalysis(
                payload
            );

            const normalized = normalizeResponse(
                response
            );

            renderResults(normalized);

        } catch (error) {

            console.error(
                `[ScamShield Transaction Analysis ${VERSION}]`,
                error
            );

            showAnalysisError(error);

        } finally {

            isSubmitting = false;

            setLoadingState(false);
        }
    }


    /* =================================================
       CHARACTER COUNTER
    ================================================= */

    function updateCharacterCount() {

        const input = getElement(
            "transactionEvidence"
        );

        const counter = getElement(
            "transactionCharacterCount"
        );

        if (!input || !counter) return;

        const length = input.value.length;

        counter.textContent =
            `${length} / ${MAX_EVIDENCE_LENGTH}`;

        counter.style.color =
            length > MAX_EVIDENCE_LENGTH * 0.9
                ? "#f87171"
                : "";
    }


    /* =================================================
       CLEAR FORM
    ================================================= */

    function clearForm() {

        if (isSubmitting) return;

        const form = getElement(
            "transactionAnalysisForm"
        );

        if (form) {
            form.reset();
        }

        clearInputError();

        updateCharacterCount();

        hideElement("transactionResults");

        hideElement("transactionAnalysisStatus");

        lastAnalysisId = null;

        feedbackSelection = null;

        [
            "transactionRiskScore",
            "transactionRiskLevel",
            "transactionRiskDescription",
            "transactionFraudCategoryResult",
            "transactionRiskExplanation",
            "transactionGuardianResult",
            "transactionIntelligenceResult",
            "transactionVictimSafetyResult",
            "transactionGeminiResult",
            "transactionDecoyResult"
        ].forEach(id => setText(id, ""));

        [
            "transactionIndicators",
            "transactionRiskScoreCircle"
        ].forEach(id => {

            const element = getElement(id);

            if (element) {
                clearElement(element);
            }
        });

        [
            "transactionGuardianStatus",
            "transactionIntelligenceStatus",
            "transactionVictimSafetyStatus",
            "transactionGeminiStatus",
            "transactionDecoyStatus"
        ].forEach(id => setText(id, "Pending"));

        [
            "transactionFeedbackHelpful",
            "transactionFeedbackReview"
        ].forEach(id => {

            const element = getElement(id);

            if (element) {
                element.classList.remove("active");
            }
        });

        setText(
            "transactionFeedbackStatus",
            ""
        );
    }


    /* =================================================
       MOBILE NAVIGATION
    ================================================= */

    function initializeMobileNavigation() {

        const toggle = getElement(
            "mobileMenuToggle"
        );

        const navigation = getElement(
            "primaryNavigation"
        );

        if (!toggle || !navigation) return;

        toggle.addEventListener("click", () => {

            const isOpen = navigation.classList.toggle("open");

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

        document.addEventListener("click", event => {

            if (
                !navigation.contains(event.target) &&
                !toggle.contains(event.target)
            ) {

                navigation.classList.remove("open");

                toggle.setAttribute(
                    "aria-expanded",
                    "false"
                );

                const icon = toggle.querySelector("i");

                if (icon) {
                    icon.className = "fa-solid fa-bars";
                }
            }
        });
    }


    /* =================================================
       INITIALIZATION
    ================================================= */

    function initialize() {

        const form = getElement(
            "transactionAnalysisForm"
        );

        const evidence = getElement(
            "transactionEvidence"
        );

        const clearButton = getElement(
            "clearTransactionForm"
        );

        const helpfulButton = getElement(
            "transactionFeedbackHelpful"
        );

        const reviewButton = getElement(
            "transactionFeedbackReview"
        );

        if (!form) {
            console.error(
                "Transaction Analysis: Form element not found."
            );

            return;
        }

        form.addEventListener(
            "submit",
            handleSubmit
        );

        if (evidence) {

            evidence.addEventListener(
                "input",
                updateCharacterCount
            );
        }

        if (clearButton) {
            clearButton.addEventListener(
                "click",
                clearForm
            );
        }

        if (helpfulButton) {

            helpfulButton.addEventListener(
                "click",
                () => handleFeedback("helpful")
            );
        }

        if (reviewButton) {

            reviewButton.addEventListener(
                "click",
                () => handleFeedback("review")
            );
        }

        initializeMobileNavigation();

        updateCharacterCount();

        console.info(
            `ScamShield Transaction Analysis v${VERSION} initialized.`
        );
    }


    /* =================================================
       PUBLIC API
    ================================================= */

    return {
        initialize,
        validateForm,
        buildPayload,
        normalizeResponse,
        clearForm
    };

})();


/* =====================================================
   START APPLICATION
===================================================== */

if (document.readyState === "loading") {

    document.addEventListener(
        "DOMContentLoaded",
        TransactionAnalysis.initialize
    );

} else {

    TransactionAnalysis.initialize();
}
