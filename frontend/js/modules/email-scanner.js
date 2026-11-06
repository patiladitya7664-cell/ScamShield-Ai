"use strict";

/**
 * Email ke subject, sender aur body mein common scam signs check karta hai.
 * Yeh email address ya sender ki asli identity verify nahi karta.
 */

const EMAIL_RULES = [
  {
    id: "credential_request",
    label: "Password, OTP ya account login details maangi gayi hain",
    points: 25,
    patterns: [
      /\b(password|otp|one.time.password|pin|login details|credentials)\b.{0,50}\b(send|share|confirm|verify|provide|reply)\b/i,
      /\b(send|share|confirm|verify|provide|reply)\b.{0,50}\b(password|otp|one.time.password|pin|login details|credentials)\b/i
    ]
  },
  {
    id: "urgent_threat",
    label: "Account band ya suspend hone ki urgent warning",
    points: 18,
    patterns: [
      /\b(account|mailbox|subscription|payment)\b.{0,45}\b(suspended|blocked|closed|deactivated|expire)\b/i,
      /\b(action required|urgent action|final notice|within \d+ hours?)\b/i
    ]
  },
  {
    id: "unexpected_payment",
    label: "Unexpected payment, invoice ya refund ka zikr",
    points: 18,
    patterns: [
      /\b(unpaid invoice|payment failed|refund approved|you owe|outstanding balance|wire transfer)\b/i,
      /\b(pay now|make a payment|confirm payment|claim your refund)\b/i
    ]
  },
  {
    id: "prize_or_reward",
    label: "Prize, lottery ya unexpected reward ka claim",
    points: 15,
    patterns: [
      /\b(you have won|winner|lottery|claim your prize|claim your reward|gift card)\b/i
    ]
  },
  {
    id: "sensitive_attachment",
    label: "Email mein unexpected attachment kholne ko kaha gaya hai",
    points: 12,
    patterns: [
      /\b(open|download|enable content|enable macros)\b.{0,40}\b(attachment|document|invoice|file)\b/i
    ]
  },
  {
    id: "secrecy_or_bypass",
    label: "Normal approval process ko bypass karne ya baat secret rakhne ko kaha gaya hai",
    points: 18,
    patterns: [
      /\b(keep this confidential|do not tell anyone|bypass approval|don't contact your manager)\b/i
    ]
  },
  {
    id: "link_present",
    label: "Email text mein link hai",
    points: 10,
    patterns: [
      /https?:\/\/[^\s<>()]+/i,
      /\bwww\.[^\s<>()]+/i
    ]
  },
  {
    id: "sender_mismatch",
    label: "Sender ka display name aur email domain alag ho sakte hain",
    points: 20,
    check: (email) => {
      const sender = String(email.sender || "").trim();
      const match = sender.match(/<([^>]+)>/);
      const address = match ? match[1] : sender;
      const domain = address.split("@")[1];

      if (!domain || !email.senderName) return false;

      const normalizedName = String(email.senderName)
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");

      const normalizedDomain = domain
        .toLowerCase()
        .split(".")
        .slice(0, -1)
        .join("")
        .replace(/[^a-z0-9]/g, "");

      const commonBrands = [
        "google", "microsoft", "apple", "amazon", "paypal",
        "netflix", "facebook", "instagram", "sbi", "hdfc", "icici"
      ];

      return commonBrands.some((brand) =>
        normalizedName.includes(brand) && !normalizedDomain.includes(brand)
      );
    }
  }
];

function getRiskLevel(score) {
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

/**
 * @param {{
 *   subject?: string,
 *   sender?: string,
 *   senderName?: string,
 *   body: string
 * }} email
 */
function scanEmail(email) {
  if (!email || typeof email !== "object") {
    throw new TypeError("Email details object ke roop mein dein.");
  }

  if (typeof email.body !== "string" || !email.body.trim()) {
    throw new TypeError("Scan karne ke liye email body enter karein.");
  }

  const content = `${email.subject || ""}\n${email.body}`;
  const findings = [];

  for (const rule of EMAIL_RULES) {
    const matched = rule.check
      ? rule.check(email)
      : rule.patterns.some((pattern) => pattern.test(content));

    if (matched) {
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
    "Sender ka poora email address aur domain dhyan se verify karein.",
    "Email ke link se login karne ke bajay official website khud type karke kholen.",
    "Unexpected attachment ko tab tak na kholen jab tak sender se alag channel par confirm na kar lein."
  ];

  if (findings.some((finding) => finding.id === "credential_request")) {
    advice.push("Email reply mein password, OTP ya PIN kabhi na bhejein.");
  }

  return {
    type: "email",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanEmail };
}

if (typeof window !== "undefined") {
  window.ScamShieldEmailScanner = { scanEmail };
}