"use strict";

/**
 * Card-related message ya call transcript mein scam warning signs check karta hai.
 * Yeh card, bank ya transaction ko verify nahi karta.
 */

const CARD_RULES = [
  {
    id: "cvv_or_pin_request",
    label: "CVV, card PIN, OTP ya password maanga gaya hai",
    points: 32,
    patterns: [
      /\b(cvv|card pin|debit pin|credit card pin|otp|one.time.password|password)\b.{0,45}\b(share|tell|send|read|confirm|provide)\b/i,
      /\b(share|tell|send|read|confirm|provide)\b.{0,45}\b(cvv|card pin|debit pin|credit card pin|otp|password)\b/i,
      /\b(cvv|card pin|otp)\b.{0,35}\b(batao|bhejo|share karo|padho)\b/i
    ]
  },
  {
    id: "card_block_threat",
    label: "Card block ya suspend karne ki dhamki",
    points: 20,
    patterns: [
      /\b(card|credit card|debit card)\b.{0,40}\b(block|suspend|deactivate|close|expire)\b/i,
      /\b(block|suspend|deactivate)\b.{0,35}\b(card|credit card|debit card)\b/i
    ]
  },
  {
    id: "unknown_transaction",
    label: "Unknown transaction ya suspicious charge ka claim",
    points: 18,
    patterns: [
      /\b(unknown|unauthorized|suspicious|unusual)\b.{0,40}\b(transaction|charge|purchase|payment)\b/i,
      /\b(transaction|charge|purchase|payment)\b.{0,40}\b(unknown|unauthorized|suspicious|unusual)\b/i
    ]
  },
  {
    id: "refund_or_reversal",
    label: "Refund ya charge reversal ke liye details maangi gayi hain",
    points: 18,
    patterns: [
      /\b(refund|chargeback|reversal)\b.{0,45}\b(card number|cvv|otp|pin|link|details)\b/i,
      /\b(card number|cvv|otp|pin)\b.{0,40}\b(refund|chargeback|reversal)\b/i
    ]
  },
  {
    id: "remote_access",
    label: "Card ya bank support ke naam par remote access app install karne ko kaha gaya hai",
    points: 25,
    patterns: [
      /\b(install|download)\b.{0,45}\b(anydesk|teamviewer|remote access|screen sharing)\b/i,
      /\b(anydesk|teamviewer|remote access|screen sharing)\b.{0,45}\b(card|bank|transaction)\b/i
    ]
  },
  {
    id: "urgent_action",
    label: "Jaldi action lene ka pressure",
    points: 15,
    patterns: [
      /\b(act now|immediately|urgent|within \d+ minutes?|final warning)\b/i,
      /\b(abhi|turant|jaldi action|warna card band)\b/i
    ]
  },
  {
    id: "payment_link",
    label: "Card verification ya refund ke liye link diya gaya hai",
    points: 12,
    patterns: [
      /https?:\/\/[^\s<>()]+/i,
      /\b(click|open|visit)\b.{0,30}\b(verify|refund|card|payment)\b/i
    ]
  }
];

function getRiskLevel(score) {
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

/**
 * @param {string|{message?: string, transcript?: string, details?: string}} input
 */
function scanCardFraud(input) {
  let text = "";

  if (typeof input === "string") {
    text = input.trim();
  } else if (input && typeof input === "object") {
    text = [input.message, input.transcript, input.details]
      .filter((part) => typeof part === "string")
      .join("\n")
      .trim();
  }

  if (!text) {
    throw new TypeError("Scan karne ke liye card se sambandhit message enter karein.");
  }

  const findings = [];

  for (const rule of CARD_RULES) {
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
    "CVV, card PIN, OTP ya full card details call, SMS ya email par share na karein.",
    "Transaction verify karne ke liye bank ki official app ya card ke pichhe diye number ka use karein.",
    "Agar transaction unauthorized lagta hai, bank ko jaldi contact karke card block karne ya dispute raise karne ke official steps follow karein."
  ];

  if (findings.some((finding) => finding.id === "payment_link")) {
    advice.push("Message ke link par card details enter karne ke bajay bank ki official app kholen.");
  }

  return {
    type: "card",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanCardFraud };
}

if (typeof window !== "undefined") {
  window.ScamShieldCardScanner = { scanCardFraud };
}