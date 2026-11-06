"use strict";

/**
 * Job offer ya loan message mein common scam warning signs check karta hai.
 * Yeh employer, recruiter, lender ya loan offer ko verify nahi karta.
 */

const JOB_LOAN_RULES = [
  {
    id: "job_registration_fee",
    label: "Job, interview ya training ke liye pehle fee maangi gayi hai",
    points: 28,
    patterns: [
      /\b(pay|send|transfer|deposit)\b.{0,45}\b(registration fee|interview fee|job fee|training fee|security deposit)\b/i,
      /\b(job|interview|training)\b.{0,35}\b(fee|deposit|charge)\b.{0,25}\b(pay|send|transfer)\b/i,
      /\b(job ke liye|interview ke liye|training ke liye)\b.{0,30}\b(fee|paise|deposit)\b/i
    ]
  },
  {
    id: "guaranteed_job",
    label: "Bina interview ya qualification ke guaranteed job ka wada",
    points: 20,
    patterns: [
      /\b(guaranteed job|job confirmed|no interview required|no experience needed|instant hiring)\b/i,
      /\b(bina interview|guaranteed naukri|job pakki|bina experience)\b/i
    ]
  },
  {
    id: "unrealistic_salary",
    label: "Kam kaam ke liye asambhav roop se zyada salary",
    points: 18,
    patterns: [
      /\b(easy money|work from home|earn \d+ daily|high salary for simple work|earn from home)\b/i,
      /\b(ghar baithe|rozana kamai|aasaan kaam|bahut zyada salary)\b/i
    ]
  },
  {
    id: "loan_upfront_fee",
    label: "Loan approve ya release karne se pehle fee maangi gayi hai",
    points: 28,
    patterns: [
      /\b(loan|credit)\b.{0,45}\b(processing fee|release fee|insurance fee|advance fee|file charge)\b/i,
      /\b(pay|send|transfer|deposit)\b.{0,45}\b(processing fee|loan fee|release charge|advance fee)\b/i,
      /\b(loan ke liye|loan release|loan approve)\b.{0,35}\b(fee|paise|deposit|charge)\b/i
    ]
  },
  {
    id: "guaranteed_loan",
    label: "Credit check ya documents ke bina guaranteed loan ka wada",
    points: 20,
    patterns: [
      /\b(guaranteed loan|loan approved instantly|no credit check|loan without documents)\b/i,
      /\b(bina cibil|bina documents|turant loan|guaranteed loan)\b/i
    ]
  },
  {
    id: "sensitive_data_request",
    label: "OTP, PIN, password ya card security details maangi gayi hain",
    points: 32,
    patterns: [
      /\b(otp|one.time.password|pin|password|cvv)\b.{0,45}\b(share|send|tell|confirm|provide)\b/i,
      /\b(share|send|tell|confirm|provide)\b.{0,45}\b(otp|one.time.password|pin|password|cvv)\b/i
    ]
  },
  {
    id: "identity_document_misuse",
    label: "Sensitive identity ya bank documents unknown contact ko bhejne ko kaha gaya hai",
    points: 18,
    patterns: [
      /\b(send|share|upload)\b.{0,40}\b(aadhaar|pan card|bank statement|passbook|identity proof)\b/i,
      /\b(aadhaar|pan card|bank statement|passbook)\b.{0,35}\b(whatsapp|telegram|personal email)\b/i
    ]
  },
  {
    id: "urgent_pressure",
    label: "Offer khone ki dhamki dekar turant decision ka pressure",
    points: 15,
    patterns: [
      /\b(only today|limited seats|offer expires|pay immediately|last chance)\b/i,
      /\b(sirf aaj|abhi fees bharo|offer khatam|turant decide)\b/i
    ]
  },
  {
    id: "unknown_link",
    label: "Application ya loan processing ke liye link diya gaya hai",
    points: 12,
    patterns: [
      /https?:\/\/[^\s<>()]+/i,
      /\b(apply now|complete your application|verify your loan)\b/i
    ]
  }
];

function getRiskLevel(score) {
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

/**
 * @param {string|{message?: string, offer?: string, details?: string}} input
 */
function scanJobLoan(input) {
  let text = "";

  if (typeof input === "string") {
    text = input.trim();
  } else if (input && typeof input === "object") {
    text = [input.message, input.offer, input.details]
      .filter((part) => typeof part === "string")
      .join("\n")
      .trim();
  }

  if (!text) {
    throw new TypeError("Scan karne ke liye job ya loan offer ka text enter karein.");
  }

  const findings = [];

  for (const rule of JOB_LOAN_RULES) {
    if (rule.patterns.some((pattern) => pattern.test(text))) {
      findings.push({
        id: rule.id,
        label: rule.label,
        points: rule.points
      });
    }
  }

  const score = Math.min(
    findings.reduce((total, finding) => total + finding.points, 0),
    100
  );

  const advice = [
    "Job ya loan ke naam par advance payment karne se pehle organization ko independently verify karein.",
    "Official company website ya lender ke verified contact details se offer confirm karein.",
    "OTP, PIN, password ya card security code recruiter ya lender ko na dein."
  ];

  if (findings.some((finding) => finding.id === "identity_document_misuse")) {
    advice.push("Identity documents sirf verified official application channel par share karein.");
  }

  return {
    type: "job-loan",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanJobLoan };
}

if (typeof window !== "undefined") {
  window.ScamShieldJobLoanScanner = { scanJobLoan };
}