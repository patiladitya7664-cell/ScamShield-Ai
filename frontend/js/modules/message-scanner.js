"use strict";

/**
 * Message scam ke common warning signs check karta hai.
 * Yeh rule-based screening hai, AI verdict ya fraud ki guarantee nahi.
 */

const MESSAGE_RULES = [
  {
    id: "otp_request",
    label: "OTP, PIN, password ya CVV maanga gaya hai",
    points: 30,
    patterns: [
      /\b(otp|one.time.password|pin|password|cvv)\b.{0,50}\b(send|share|tell|confirm|verify|provide)\b/i,
      /\b(send|share|tell|confirm|verify|provide)\b.{0,50}\b(otp|one.time.password|pin|password|cvv)\b/i,
      /\b(otp|pin|password|cvv)\b.{0,40}\b(bhejo|batao|share karo|confirm karo)\b/i
    ]
  },
  {
    id: "urgent_threat",
    label: "Jaldi action lene ka pressure ya dhamki",
    points: 20,
    patterns: [
      /\b(act now|immediately|urgent|final warning|within \d+ hours?|account will be blocked|account will be suspended)\b/i,
      /\b(abhi|turant|jaldi|aaj hi|account band ho jayega|block ho jayega|suspend ho jayega)\b/i
    ]
  },
  {
    id: "payment_demand",
    label: "Unexpected payment, fee ya money transfer maanga gaya hai",
    points: 25,
    patterns: [
      /\b(pay|transfer|send)\b.{0,45}\b(fee|fine|tax|deposit|charge|money|amount)\b/i,
      /\b(upi|payment|collect request)\b.{0,35}\b(request|approve|accept|pay)\b/i,
      /\b(paise bhejo|payment karo|fine bharo|deposit karo|request approve karo)\b/i
    ]
  },
  {
    id: "prize_refund",
    label: "Prize, lottery, cashback ya refund ka claim",
    points: 15,
    patterns: [
      /\b(you have won|winner|lottery|cashback|refund approved|claim your prize|claim reward)\b/i,
      /\b(aap jeet|inaam|lottery|cashback|refund mil|reward claim)\b/i
    ]
  },
  {
    id: "account_kyc",
    label: "Account, SIM ya KYC band karne ki warning",
    points: 20,
    patterns: [
      /\b(account|bank account|sim|card|connection)\b.{0,40}\b(block|suspend|expire|close|deactivate)\b/i,
      /\b(kyc|pan|aadhaar)\b.{0,45}\b(update|verify|blocked|suspended|expired)\b/i
    ]
  },
  {
    id: "link_present",
    label: "Message mein website link diya gaya hai",
    points: 12,
    patterns: [
      /https?:\/\/[^\s]+/i,
      /\bwww\.[^\s]+/i,
      /\b(click|tap|open)\b.{0,25}\b(link|here|below)\b/i
    ]
  },
  {
    id: "secrecy",
    label: "Kisi ko na batane ya baat secret rakhne ko kaha gaya hai",
    points: 15,
    patterns: [
      /\b(do not tell anyone|keep this secret|don't inform anyone|do not discuss)\b/i,
      /\b(kisi ko mat batao|secret rakho|kisi se share mat karo)\b/i
    ]
  }
];

function getRiskLevel(score) {
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

/**
 * @param {string} message User ka pasted SMS ya message
 * @returns {{
 *   type: string,
 *   score: number,
 *   risk: "low" | "medium" | "high",
 *   findings: Array<{id: string, label: string, points: number}>,
 *   advice: string[]
 * }}
 */
function scanMessage(message) {
  if (typeof message !== "string" || message.trim().length === 0) {
    throw new TypeError("Scan karne ke liye message text enter karein.");
  }

  const normalizedMessage = message.trim();
  const findings = [];

  for (const rule of MESSAGE_RULES) {
    const matched = rule.patterns.some((pattern) =>
      pattern.test(normalizedMessage)
    );

    if (matched) {
      findings.push({
        id: rule.id,
        label: rule.label,
        points: rule.points
      });
    }
  }

  const totalPoints = findings.reduce(
    (total, finding) => total + finding.points,
    0
  );

  const score = Math.min(totalPoints, 100);
  const advice = [
    "OTP, PIN, password ya CVV kisi ke saath share na karein.",
    "Paise bhejne se pehle bank ya sambandhit company ke official number par khud contact karke verify karein."
  ];

  if (findings.some((finding) => finding.id === "link_present")) {
    advice.push(
      "Message ke link par click karne ke bajay official website ka address khud type karke kholen."
    );
  }

  return {
    type: "message",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanMessage };
}

if (typeof window !== "undefined") {
  window.ScamShieldMessageScanner = { scanMessage };
}