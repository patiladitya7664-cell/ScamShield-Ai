"use strict";

/**
 * Message ya call transcript mein digital-arrest scam ke common signs check karta hai.
 * Yeh police ya kisi authority ki identity verify nahi karta.
 */

const DIGITAL_ARREST_RULES = [
  {
    id: "digital_arrest_claim",
    label: "Digital arrest ya online custody ka claim",
    points: 35,
    patterns: [
      /\b(digital arrest|online arrest|virtual arrest|under digital custody)\b/i,
      /\b(digital giraftari|online giraftar|video call par arrest)\b/i
    ]
  },
  {
    id: "authority_impersonation",
    label: "Police, CBI, court ya government agency banne ka claim",
    points: 20,
    patterns: [
      /\b(police|cbi|cyd|customs|court|supreme court|enforcement directorate|government agency)\b/i,
      /\b(police|cbi|court|customs|sarkari agency)\b.{0,50}\b(speaking|calling|bol raha|bol rahi)\b/i
    ]
  },
  {
    id: "video_call_surveillance",
    label: "Video call par rehne ya camera on rakhne ka order",
    points: 22,
    patterns: [
      /\b(stay on the video call|do not disconnect|keep your camera on|video surveillance)\b/i,
      /\b(video call mat kaato|camera on rakho|call par bane raho)\b/i
    ]
  },
  {
    id: "arrest_or_case_threat",
    label: "Giraftari ya criminal case ki dhamki",
    points: 22,
    patterns: [
      /\b(arrest warrant|you will be arrested|criminal case|custody|police will come)\b/i,
      /\b(giraftar|arrest warrant|criminal case|police ghar aayegi|custody)\b/i
    ]
  },
  {
    id: "money_for_clearance",
    label: "Case band karne ya verification ke liye paise maange gaye hain",
    points: 30,
    patterns: [
      /\b(pay|transfer|deposit|send)\b.{0,50}\b(security deposit|clearance fee|verification fee|case settlement|bail)\b/i,
      /\b(case khatam|verification|bail|clearance)\b.{0,40}\b(paise|payment|deposit|transfer)\b/i
    ]
  },
  {
    id: "bank_transfer_instruction",
    label: "Paise ko kisi account mein transfer karne ka order",
    points: 28,
    patterns: [
      /\b(transfer|move|send)\b.{0,45}\b(money|funds|savings|bank balance)\b/i,
      /\b(account safe|verification account|government account)\b.{0,40}\b(transfer|deposit|send)\b/i
    ]
  },
  {
    id: "secret_instruction",
    label: "Family, bank ya police se baat na karne ko kaha gaya hai",
    points: 18,
    patterns: [
      /\b(do not tell your family|do not contact your bank|keep this confidential|tell no one)\b/i,
      /\b(family ko mat batao|bank ko phone mat karo|kisi ko mat batao|secret rakho)\b/i
    ]
  },
  {
    id: "identity_details_request",
    label: "Sensitive personal ya banking details maangi gayi hain",
    points: 25,
    patterns: [
      /\b(share|tell|send|confirm)\b.{0,45}\b(otp|pin|password|aadhaar|pan|bank details|cvv)\b/i,
      /\b(otp|pin|password|aadhaar|pan|bank details|cvv)\b.{0,45}\b(bhejo|batao|share karo)\b/i
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
function scanDigitalArrest(input) {
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
    throw new TypeError("Scan karne ke liye message ya call transcript enter karein.");
  }

  const findings = [];

  for (const rule of DIGITAL_ARREST_RULES) {
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
    "Ghabrahat mein paise transfer na karein aur OTP, PIN ya password share na karein.",
    "Call disconnect karke police ya sambandhit agency ke official public number par khud verify karein.",
    "Kisi bharosemand family member ko batayein aur messages, phone numbers aur payment details ka record sambhal kar rakhein."
  ];

  if (findings.some((finding) => finding.id === "video_call_surveillance")) {
    advice.push("Koi caller aapko video call par rakhkar ya camera on karwa kar arrest nahi kar sakta.");
  }

  return {
    type: "digital-arrest",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanDigitalArrest };
}

if (typeof window !== "undefined") {
  window.ScamShieldDigitalArrestScanner = { scanDigitalArrest };
}