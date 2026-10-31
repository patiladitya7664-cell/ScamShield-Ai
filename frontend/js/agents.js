"use strict";

document.addEventListener("DOMContentLoaded", () => {


// =====================================================
// 1. AGENT CARD REVEAL ANIMATION
// =====================================================

const revealElements = document.querySelectorAll(
    ".overview-item, .agent-detail-card, .flow-card"
);

const reduceMotion = window.matchMedia(
    "(prefers-reduced-motion: reduce)"
).matches;

if ("IntersectionObserver" in window && !reduceMotion) {

    const observer = new IntersectionObserver(
        (entries, observerInstance) => {

            entries.forEach((entry) => {

                if (entry.isIntersecting) {

                    entry.target.classList.add("agent-visible");

                    observerInstance.unobserve(entry.target);

                }

            });

        },
        {
            threshold: 0.12,
            rootMargin: "0px 0px -30px 0px"
        }
    );

    revealElements.forEach((element) => {

        element.classList.add("agent-reveal");

        observer.observe(element);

    });

} else {

    revealElements.forEach((element) => {

        element.classList.add("agent-visible");

    });

}


// =====================================================
// 2. CURRENT YEAR
// =====================================================

const yearElement = document.querySelector("[data-current-year]");

if (yearElement) {

    yearElement.textContent = new Date().getFullYear();

}


// =====================================================
// 3. AGENT CARD ACCESSIBILITY
// =====================================================

document.querySelectorAll(".agent-detail-card").forEach((card) => {

    card.removeAttribute("tabindex");

});


// =====================================================
// 4. DEMO ELEMENTS
// =====================================================

const demoForm = document.getElementById("agentsDemoForm");

const demoSample = document.getElementById("agentsDemoSample");

const demoEvidence = document.getElementById("agentsDemoEvidence");

const demoType = document.getElementById("agentsDemoType");

const demoButton = document.getElementById("agentsDemoRun");

const demoStatus = document.getElementById("agentsDemoStatus");

const demoResults = document.getElementById("agentsDemoResults");


// =====================================================
// 5. DEMO SCENARIOS
// =====================================================

const demoScenarios = {

    "bank-kyc": {
        type: "message",
        evidence:
            "URGENT: Your bank account will be blocked today. Complete your KYC immediately using this link: http://example-scam.test/verify. Share your OTP to complete verification."
    },

    "lottery": {
        type: "message",
        evidence:
            "Congratulations! You have won Rs. 25,00,000 in our lucky draw. Pay a processing fee immediately to claim your prize. Do not delay your claim."
    },

    "suspicious-url": {
        type: "url",
        evidence:
            "http://example-scam.test/verify-account"
    },

    "fake-call": {
        type: "call",
        evidence:
            "Caller: Hello, I am calling from your bank's customer care department. Your account has a security problem. Please tell me the OTP received on your phone so I can protect your account."
    },

    "upi-scam": {
        type: "transaction",
        evidence:
            "Transaction Type: Suspicious UPI payment request. Message: Your payment verification is pending. Approve this UPI request and enter your UPI PIN to receive your refund."
    }

};


// =====================================================
// 6. DEMO HELPERS
// =====================================================

const getToken = () => {

    return (
        localStorage.getItem("scamshieldToken") ||
        sessionStorage.getItem("scamshieldToken")
    );

};


const getApiBase = () => {

    return (
        window.SCAMSHIELD_API_URL ||
        "http://localhost:5000/api"
    ).replace(/\/+$/, "");

};


const showStatus = (message) => {

    if (!demoStatus) return;

    demoStatus.textContent = message;

};


const showLoginPrompt = () => {

    if (!demoStatus) return;

    demoStatus.replaceChildren();

    demoStatus.append(
        document.createTextNode(
            "Please sign in before running the protected agent demonstration. "
        )
    );

    const link = document.createElement("a");

    link.href = "login.html";

    link.textContent = "Go to Login";

    demoStatus.append(link);

};


const addText = (
    parent,
    tag,
    value,
    className = ""
) => {

    const element = document.createElement(tag);

    if (className) {

        element.className = className;

    }

    element.textContent =
        value === null || value === undefined || value === ""
            ? "Not available"
            : String(value);

    parent.appendChild(element);

    return element;

};


const normalizeStatus = (status) => {

    const value = String(status || "").toLowerCase();

    if (
        ["completed", "success", "complete", "active"].includes(value)
    ) {

        return "completed";

    }

    if (
        ["pending", "processing", "running"].includes(value)
    ) {

        return "pending";

    }

    return "unavailable";

};


// =====================================================
// 7. AGENT RESULT CARD
// =====================================================

const addAgentCard = (
    container,
    title,
    status,
    details
) => {

    const card = document.createElement("article");

    card.className = "agent-demo-result-card";

    const heading = document.createElement("div");

    heading.className = "agent-demo-result-heading";

    addText(heading, "h3", title);

    const normalizedStatus = normalizeStatus(status);

    const statusLabel = {
        completed: "Completed",
        pending: "Processing",
        unavailable: "Unavailable"
    };

    addText(
        heading,
        "span",
        statusLabel[normalizedStatus],
        `agent-demo-state ${
            normalizedStatus === "completed"
                ? "is-complete"
                : "is-pending"
        }`
    );

    card.appendChild(heading);

    if (normalizedStatus === "unavailable") {

        addText(
            card,
            "p",
            "This agent did not return an available result."
        );

    } else if (typeof details === "function") {

        details(card);

    }

    container.appendChild(card);

    return card;

};


// =====================================================
// 8. LOAD SELECTED DEMO SCENARIO
// =====================================================

const loadDemoScenario = () => {

    if (!demoSample || !demoEvidence || !demoType) return;

    const scenario = demoScenarios[demoSample.value];

    if (!scenario) return;

    demoEvidence.value = scenario.evidence;

    demoType.value = scenario.type;

    showStatus(
        "Sample scenario loaded. You can edit the evidence before analysis."
    );

};


if (demoSample) {

    demoSample.addEventListener("change", loadDemoScenario);

}


// =====================================================
// 9. RESET DEMO
// =====================================================

if (demoForm) {

    demoForm.addEventListener("reset", () => {

        window.setTimeout(() => {

            if (demoResults) {

                demoResults.replaceChildren();

                demoResults.hidden = true;

            }

            if (demoSample) {

                loadDemoScenario();

            }

            showStatus(
                "Demo has been reset. Select a scenario to continue."
            );

        }, 0);

    });

}


// =====================================================
// 10. RENDER GUARDIAN RESULT
// =====================================================

const renderGuardian = (container, agent, analysis) => {

    addAgentCard(
        container,
        agent?.agent || "Guardian Agent",
        agent?.status,
        (card) => {

            addText(
                card,
                "p",
                `${analysis?.fraudCategory || "Unknown category"} · ${
                    Number.isFinite(Number(analysis?.riskScore))
                        ? `${analysis.riskScore}/100`
                        : "Score unavailable"
                } · ${
                    analysis?.riskLevel
                        ? String(analysis.riskLevel).toUpperCase()
                        : "UNKNOWN RISK"
                }`,
                "agent-demo-risk"
            );

            addText(
                card,
                "p",
                agent?.summary ||
                analysis?.summary ||
                "No summary was returned."
            );

            const rules = Array.isArray(agent?.detectedRules)
                ? agent.detectedRules
                : [];

            if (rules.length) {

                addText(card, "h4", "Matched Rules");

                const list = document.createElement("ul");

                rules.forEach((rule) => {

                    const label =
                        typeof rule === "string"
                            ? rule
                            : rule?.label || rule?.name || "Unnamed rule";

                    addText(list, "li", label);

                });

                card.appendChild(list);

            }

        }
    );

};


// =====================================================
// 11. RENDER INTELLIGENCE RESULT
// =====================================================

const renderIntelligence = (container, agent) => {

    addAgentCard(
        container,
        agent?.agent || "Intelligence Agent",
        agent?.status,
        (card) => {

            const indicators = Array.isArray(agent?.indicators)
                ? agent.indicators
                : [];

            addText(
                card,
                "p",
                `${agent?.totalIndicators ?? indicators.length} unverified clue(s) extracted.`
            );

            if (indicators.length) {

                const list = document.createElement("ul");

                indicators.forEach((item) => {

                    const type = item?.type || "Indicator";

                    const value = item?.value || "Not provided";

                    addText(
                        list,
                        "li",
                        `${type}: ${value} · Unverified`
                    );

                });

                card.appendChild(list);

            }

        }
    );

};


// =====================================================
// 12. RENDER VICTIM SAFETY RESULT
// =====================================================

const renderVictimSafety = (container, agent) => {

    addAgentCard(
        container,
        agent?.agent || "Victim Safety Agent",
        agent?.status,
        (card) => {

            const recommendations = Array.isArray(
                agent?.recommendations
            )
                ? agent.recommendations
                : [];

            if (!recommendations.length) {

                addText(
                    card,
                    "p",
                    "No safety recommendations were returned."
                );

                return;

            }

            addText(card, "h4", "Safety Recommendations");

            const list = document.createElement("ul");

            recommendations.forEach((tip) => {

                addText(list, "li", tip);

            });

            card.appendChild(list);

        }
    );

};


// =====================================================
// 13. RENDER DECOY RESULT
// =====================================================

const renderDecoy = (container, agent) => {

    addAgentCard(
        container,
        agent?.agent || "Decoy Agent",
        agent?.status,
        (card) => {

            addText(
                card,
                "p",
                agent?.message ||
                "No simulation result is currently available."
            );

        }
    );

};


// =====================================================
// 14. RENDER ALL AGENTS
// =====================================================

const renderAgentResults = (payload) => {

    if (!demoResults) return;

    const data = payload?.data;

    if (!data || typeof data !== "object") {

        throw new Error(
            "The backend returned an invalid analysis response."
        );

    }

    const agents = data.agents || {};

    const analysis = data.analysis || {};

    renderGuardian(
        demoResults,
        agents.guardian,
        analysis
    );

    renderIntelligence(
        demoResults,
        agents.intelligence
    );

    renderVictimSafety(
        demoResults,
        agents.victimSafety
    );

    renderDecoy(
        demoResults,
        agents.decoy
    );

    addText(
        demoResults,
        "p",
        data.disclaimer ||
        "This assessment is informational and is not proof of fraud.",
        "agent-demo-disclaimer"
    );

    demoResults.hidden = false;

};


// =====================================================
// 15. RUN AGENT DEMO
// =====================================================

if (
    demoForm &&
    demoEvidence &&
    demoType &&
    demoButton &&
    demoStatus &&
    demoResults
) {

    demoForm.addEventListener("submit", async (event) => {

        event.preventDefault();

        // Authentication

        const token = getToken();

        if (!token) {

            demoResults.replaceChildren();

            demoResults.hidden = true;

            showLoginPrompt();

            return;

        }


        // Input validation

        const evidence = demoEvidence.value.trim();

        const evidenceType = demoType.value;

        const allowedTypes = [
            "message",
            "url",
            "call",
            "transaction"
        ];

        if (!evidence) {

            showStatus("Please enter sample evidence before continuing.");

            demoEvidence.focus();

            return;

        }

        if (!allowedTypes.includes(evidenceType)) {

            showStatus("Please select a valid evidence type.");

            demoType.focus();

            return;

        }

        if (evidence.length > 20000) {

            showStatus("Evidence must be shorter than 20,000 characters.");

            demoEvidence.focus();

            return;

        }

        if (
            evidenceType === "url" &&
            !/^https?:\/\/\S+$/i.test(evidence)
        ) {

            showStatus(
                "Please enter a valid HTTP or HTTPS website URL."
            );

            demoEvidence.focus();

            return;

        }


        // Loading state

        demoButton.disabled = true;

        demoForm.setAttribute("aria-busy", "true");

        demoResults.replaceChildren();

        demoResults.hidden = true;

        showStatus(
            "Running the agent workflow. Please wait..."
        );


        try {

            const response = await fetch(
                `${getApiBase()}/agents/run`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json",
                        Authorization: `Bearer ${token}`
                    },

                    body: JSON.stringify({
                        evidenceType,
                        evidence
                    })

                }
            );


            const payload = await response.json().catch(() => ({}));


            if (
                !response.ok ||
                !payload.success ||
                !payload.data
            ) {

                const requestError = new Error(
                    payload.message ||
                    `Request failed with status ${response.status}.`
                );

                requestError.status = response.status;

                throw requestError;

            }


            // Render actual backend results

            renderAgentResults(payload);


            showStatus(
                "Analysis completed. Review the results returned by the connected agents."
            );


            // Move focus to results for keyboard users

            demoResults.setAttribute("tabindex", "-1");

            demoResults.focus({ preventScroll: false });

        } catch (error) {

            console.error(
                "ScamShield AI Agent Demo Error:",
                error
            );

            demoResults.replaceChildren();

            demoResults.hidden = true;


            if (error.status === 401 || error.status === 403) {

                showLoginPrompt();

            } else if (error instanceof TypeError) {

                showStatus(
                    "Unable to connect to the server. Please check your internet connection and backend status."
                );

            } else {

                showStatus(
                    error.message ||
                    "Something went wrong. Please try again."
                );

            }

        } finally {

            demoButton.disabled = false;

            demoForm.removeAttribute("aria-busy");

        }

    });

}


// =====================================================
// 16. INITIALIZE DEFAULT DEMO
// =====================================================

if (demoSample && demoEvidence && demoType) {

    loadDemoScenario();

}


console.log(
    "ScamShield AI | Agents page initialized successfully."
);


});
