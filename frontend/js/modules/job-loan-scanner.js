"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI
 * JOB & LOAN FRAUD INDICATOR ANALYZER
 *
 * Version: 3.0.0
 *
 * Detects potential indicators:
 * 1. Recruitment and registration fee requests
 * 2. Guaranteed job claims
 * 3. Unrealistic salary promises
 * 4. Advance loan fee requests
 * 5. Guaranteed loan claims
 * 6. Sensitive credential requests
 * 7. Identity document collection requests
 * 8. Urgent payment pressure
 *
 * IMPORTANT:
 * - Rule-based indicator analysis only.
 * - Does not verify employers or recruiters.
 * - Does not verify lenders or loan approvals.
 * - Does not verify URLs or application portals.
 * - Guardian Agent controls final classification.
 * =========================================================
 */

const MAX_JOB_LOAN_INPUT_LENGTH = 15000;

const JOB_LOAN_RULES = [
    {
        id: "job_registration_fee",
        label: "Advance registration, interview or training fee request",
        severity: "high",
        patterns: [
            /\b(pay|send|transfer|deposit)\b.{0,45}\b(registration fee|interview fee|job fee|training fee|security deposit)\b/i,

            /\b(job|interview|training)\b.{0,35}\b(fee|deposit|charge)\b.{0,25}\b(pay|send|transfer)\b/i,

            /\b(job ke liye|interview ke liye|training ke liye)\b.{0,30}\b(fee|paise|deposit)\b/i
        ]
    },

    {
        id: "guaranteed_job",
        label: "Guaranteed employment or hiring without normal selection",
        severity: "medium",
        patterns: [
            /\b(guaranteed job|job confirmed|no interview required|instant hiring)\b/i,

            /\b(bina interview|guaranteed naukri|job pakki)\b/i
        ]
    },

    {
        id: "unrealistic_salary",
        label: "Unusually high salary or easy-income claims",
        severity: "medium",
        patterns: [
            /\b(earn \d+ daily|high salary for simple work|easy money|earn \d+ per hour)\b/i,

            /\b(ghar baithe|rozana kamai|aasaan kaam|bahut zyada salary)\b/i,

            /\b(no skills required)\b.{0,35}\b(high salary|daily income|easy money)\b/i
        ]
    },

    {
        id: "loan_upfront_fee",
        label: "Advance processing or release fee request for a loan",
        severity: "high",
        patterns: [
            /\b(loan|credit)\b.{0,45}\b(processing fee|release fee|insurance fee|advance fee|file charge)\b/i,

            /\b(pay|send|transfer|deposit)\b.{0,45}\b(processing fee|loan fee|release charge|advance fee)\b/i,

            /\b(loan ke liye|loan release|loan approve)\b.{0,35}\b(fee|paise|deposit|charge)\b/i
        ]
    },

    {
        id: "guaranteed_loan",
        label: "Guaranteed loan approval without normal checks",
        severity: "medium",
        patterns: [
            /\b(guaranteed loan|loan approved instantly|no credit check|loan without documents)\b/i,

            /\b(bina cibil|bina documents|turant loan|guaranteed loan)\b/i
        ]
    },

    {
        id: "sensitive_data_request",
        label: "Request for OTP, PIN, password or card security details",
        severity: "critical",
        patterns: [
            /\b(otp|one.time.password|pin|password|cvv)\b.{0,45}\b(share|send|tell|confirm|provide)\b/i,

            /\b(share|send|tell|confirm|provide)\b.{0,45}\b(otp|one.time.password|pin|password|cvv)\b/i,

            /\b(otp|pin|password)\b.{0,35}\b(batao|bhejo|share karo)\b/i
        ]
    },

    {
        id: "identity_document_misuse",
        label: "Request to send identity or bank documents to an unverified contact",
        severity: "high",
        patterns: [
            /\b(send|share|upload)\b.{0,40}\b(aadhaar|pan card|bank statement|passbook|identity proof)\b/i,

            /\b(aadhaar|pan card|bank statement|passbook)\b.{0,35}\b(whatsapp|telegram|personal email)\b/i
        ]
    },

    {
        id: "urgent_pressure",
        label: "Pressure to make an immediate payment or decision",
        severity: "medium",
        patterns: [
            /\b(only today|limited seats|offer expires|pay immediately|last chance)\b/i,

            /\b(sirf aaj|abhi fees bharo|offer khatam|turant decide)\b/i
        ]
    },

    {
        id: "application_link_request",
        label: "Application or loan-processing link instruction",
        severity: "low",
        patterns: [
            /\b(click|open|visit)\b.{0,35}\b(application link|loan link|registration link)\b/i,

            /\b(apply now|complete your application|verify your loan)\b/i
        ]
    }
];

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeJobLoanInput(input) {
    if (typeof input === "string") {
        return input.trim();
    }

    if (input && typeof input === "object" && !Array.isArray(input)) {
        return [
            input.message,
            input.offer,
            input.details
        ]
            .filter((part) => typeof part === "string")
            .join("\n")
            .trim();
    }

    return "";
}

/* =========================================================
   EVIDENCE EXTRACTION
========================================================= */

function extractJobLoanEvidence(text, patterns) {
    for (const pattern of patterns) {
        const match = text.match(pattern);

        if (match) {
            return match[0].trim().slice(0, 300);
        }
    }

    return null;
}

/* =========================================================
   SAFETY RECOMMENDATIONS
========================================================= */

function generateJobLoanAdvice(findings) {
    const ids = new Set(
        findings.map((finding) => finding.id)
    );

    const advice = [
        "Job ya loan ke naam par advance payment karne se pehle organization ko independently verify karein.",
        "Employer ya lender ke official website aur verified contact details se offer confirm karein.",
        "OTP, PIN, password ya card security code recruiter ya lender ke saath share na karein."
    ];

    if (ids.has("job_registration_fee")) {
        advice.push(
            "Recruitment, interview ya training fee ki request ko employer ke official HR contact se independently verify karein."
        );
    }

    if (ids.has("loan_upfront_fee")) {
        advice.push(
            "Loan processing ya release fee ko lender ke official channels se verify kiye bina payment na karein."
        );
    }

    if (ids.has("guaranteed_job")) {
        advice.push(
            "Selection process, job description aur employer details independently check karein."
        );
    }

    if (ids.has("guaranteed_loan")) {
        advice.push(
            "Loan approval terms, eligibility conditions aur lender ki identity independently verify karein."
        );
    }

    if (ids.has("identity_document_misuse")) {
        advice.push(
            "Aadhaar, PAN aur bank documents sirf verified official application channels par hi submit karein."
        );
    }

    if (ids.has("application_link_request")) {
        advice.push(
            "Application link ko independently verify karein; unknown links par identity ya banking details enter na karein."
        );
    }

    if (ids.has("urgent_pressure")) {
        advice.push(
            "Urgency ke pressure mein payment ya sensitive information share karne se pehle offer verify karein."
        );
    }

    return advice;
}

/* =========================================================
   MAIN JOB & LOAN INDICATOR ANALYZER
========================================================= */

/**
 * @param {string|{message?:string,offer?:string,details?:string}} input
 * @returns {Object}
 */

function scanJobLoan(input) {
    const text = normalizeJobLoanInput(input);

    if (!text) {
        throw new TypeError(
            "Scan karne ke liye job ya loan offer ka text enter karein."
        );
    }

    if (text.length > MAX_JOB_LOAN_INPUT_LENGTH) {
        throw new RangeError(
            `Input maximum ${MAX_JOB_LOAN_INPUT_LENGTH} characters ka ho sakta hai.`
        );
    }

    const findings = [];

    for (const rule of JOB_LOAN_RULES) {
        const evidence = extractJobLoanEvidence(
            text,
            rule.patterns
        );

        if (!evidence) {
            continue;
        }

        findings.push({
            id: rule.id,
            label: rule.label,
            severity: rule.severity,
            evidence
        });
    }

    return {
        type: "indicator_analysis",

        categoryHint: "job_loan_scam",

        detected: findings.length > 0,

        findings,

        totalFindings: findings.length,

        summary: findings.length > 0
            ? `${findings.length} potential job or loan fraud indicators identified.`
            : "No matching job or loan fraud indicators identified.",

        advice: generateJobLoanAdvice(findings),

        classification: {
            authoritative: false,
            finalCategory: null,
            riskScore: null,
            riskLevel: null,
            authority: "Guardian Agent"
        },

        metadata: {
            detector: "ScamShield Job & Loan Fraud Indicator Analyzer",
            version: "3.0.0",
            detectionMethod: "rule_based",
            evidenceType: "job_or_loan_offer",
            rulesChecked: JOB_LOAN_RULES.length,
            employerVerified: false,
            recruiterVerified: false,
            lenderVerified: false,
            loanApprovalVerified: false,
            analyzedAt: new Date().toISOString()
        }
    };
}

/* =========================================================
   EXPORTS
========================================================= */

if (
    typeof module !== "undefined" &&
    module.exports
) {
    module.exports = {
        scanJobLoan,
        normalizeJobLoanInput,
        extractJobLoanEvidence,
        generateJobLoanAdvice
    };
}

if (typeof window !== "undefined") {
    window.ScamShieldJobLoanScanner = {
        scanJobLoan,
        normalizeJobLoanInput,
        extractJobLoanEvidence,
        generateJobLoanAdvice
    };
}