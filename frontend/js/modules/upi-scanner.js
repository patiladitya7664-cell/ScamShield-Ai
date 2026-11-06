"use strict";

/**
 * UPI ya banking message mein common fraud warning signs check karta hai.
 * Yeh kisi transaction ya bank account ko verify nahi karta.
 */

const UPI_RULES = [
  {
    id: "collect_request",
    label: "Paise receive karne ke naam par UPI request approve karne ko kaha gaya hai",
    points: 28,
    patterns: [
      /\b(collect request|payment request|upi request)\b/i,
      /\b(approve|accept|authorize)\b.{0,40}\b(upi|collect|payment request)\b/i,
      /\b(collect request|upi request)\b.{0,40}\b(approve|accept|authorize)\b/i
    ]
  },
  {
    id: "upi_pin_request",
    label: "UPI PIN, OTP ya banking password maanga gaya hai",
    points: 32,
    patterns: [
      /\b(upi pin|otp|banking password|transaction pin|debit card pin)\b.{0,45}\b(share|tell|send|enter|confirm)\b/i,
      /\b(share|tell|send|enter|confirm)\b.{0,45}\b(upi pin|otp|banking password|transaction pin|debit card pin)\b/i,
      /\b(upi pin|otp|pin)\b.{0,35}\b(batao|bhejo|share karo)\b/i
    ]
  },
  {
    id: "receive_money_pin",
    label: "Paise receive karne ke liye PIN daalne ko kaha gaya hai",
    points: 25,
    patterns: [
      /\b(receive|get|accept)\b.{0,35}\b(money|payment|refund)\b.{0,50}\b(enter|type|use)\b.{0,20}\b(pin|upi pin)\b/i,
      /\b(paise receive|refund receive)\b.{0,40}\b(pin daalo|upi pin daalo)\b/i
    ]
  },
  {
    id: "remote_access",
    label: "Banking help ke naam par remote access app install karne ko kaha gaya hai",
    points: 25,
    patterns: [
      /\b(install|download)\b.{0,45}\b(anydesk|teamviewer|remote access|screen sharing)\b/i,
      /\b(anydesk|teamviewer|remote access|screen sharing)\b.{0,45}\b(bank|upi|payment)\b/i
    ]
  },
  {
    id: "account_block_threat",
    label: "Bank account ya KYC block karne ki dhamki",
    points: 20,
    patterns: [
      /\b(bank account|account|kyc|debit card)\b.{0,45}\b(block|suspend|freeze|expire|deactivate)\b/i,
      /\b(kyc|account)\b.{0,40}\b(update|verify)\b.{0,35}\b(block|suspend|freeze)\b/i
    ]
  },
  {
    id: "unexpected_refund",
    label: "Unexpected refund ya cashback ka claim",
    points: 15,
    patterns: [
      /\b(refund|cashback|reward)\b.{0,40}\b(approved|pending|claim|receive|credited)\b/i,
      /\b(claim|receive)\b.{0,30}\b(refund|cashback|reward)\b/i
    ]
  },
  {
    id: "urgent_transfer",
    label: "Jaldi paise transfer karne ka pressure",
    points: 20,
    patterns: [
      /\b(transfer|send|pay)\b.{0,35}\b(now|immediately|urgent|within \d+ minutes?)\b/i,
      /\b(abhi paise bhejo|turant transfer|payment karo warna)\b/i
    ]
  },
  {
    id: "unfamiliar_payment_link",
    label: "Payment ya bank verification ke liye link diya gaya hai",
    points: 12,
    patterns: [
      /https?:\/\/[^\s<>()]+/i,
      /\b(click|open|visit)\b.{0,30}\b(bank|upi|payment|kyc)\b/i
    ]
  }
];

function getRiskLevel(score) {
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

/**
 * @param {string|{message?: string, details?: string}} input
 */
function scanUpiBanking(input) {
  let text = "";

  if (typeof input === "string") {
    text = input.trim();
  } else if (input && typeof input === "object") {
    text = [input.message, input.details]
      .filter((part) => typeof part === "string")
      .join("\n")
      .trim();
  }

  if (!text) {
    throw new TypeError("Scan karne ke liye UPI ya banking message enter karein.");
  }

  const findings = [];

  for (const rule of UPI_RULES) {
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
    "Paise receive karne ke liye UPI PIN enter karne ki zaroorat nahi hoti.",
    "UPI PIN ya OTP kisi caller, message, ya support agent ko na batayein.",
    "Bank se baat karne ke liye card ya official bank website par diya number use karein."
  ];

  if (findings.some((finding) => finding.id === "collect_request")) {
    advice.push("Approve karne se pehle UPI app mein request ka amount aur receiver naam check karein.");
  }

  if (findings.some((finding) => finding.id === "remote_access")) {
    advice.push("Banking help ke naam par remote access app install ya screen share na karein.");
  }

  return {
    type: "upi-banking",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanUpiBanking };
}

if (typeof window !== "undefined") {
  window.ScamShieldUpiScanner = { scanUpiBanking };
}