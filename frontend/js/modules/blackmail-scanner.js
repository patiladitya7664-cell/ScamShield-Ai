
"use strict";

/* =========================================================
   SCAMSHIELD AI
   BLACKMAIL & SEXTORTION DETECTOR
   Rule-Based Detection + Evidence Analysis
========================================================= */

const BLACKMAIL_RULES = [
  {
    id: "intimate_content_threat",
    label: "Private photo or video exposure threat",
    points: 30,
    severity: "critical",
    patterns: [
      /\b(leak|publish|post|share|send|expose|release)\b.{0,60}\b(your\s+)?(private|intimate|explicit|nude|personal)\s+(photo|picture|video|image|content)\b/i,
      /\b(your\s+)?(private|intimate|explicit|nude|personal)\s+(photo|picture|video|image|content)\b.{0,60}\b(leak|publish|post|share|expose|release)\b/i,
      /\b(nudes?|private photos?|intimate videos?)\b.{0,50}\b(leak|share|publish|send)\b/i,
      /\b(photo|video|nude)\s+(leak|viral)\s+(karunga|kar dunga|kar denge|bhej dunga|share karunga)\b/i,
      /\b(tumhari|teri)\s+(private|personal|nude)\s+(photo|video)\b.{0,50}\b(leak|viral|share)\b/i
    ]
  },

  {
    id: "payment_demand",
    label: "Money or cryptocurrency demanded through threats",
    points: 28,
    severity: "critical",
    patterns: [
      /\b(pay|send|transfer)\b.{0,45}\b(money|bitcoin|crypto|gift card|ransom|payment)\b/i,
      /\b(money|bitcoin|crypto|gift card|ransom)\b.{0,45}\b(or i will|otherwise i will|warna|nahi to)\b/i,
      /\b(paise bhejo|payment karo|paisa transfer karo|crypto bhejo)\b/i,
      /\b\d+\s*(rupees?|rs\.?|inr)\b.{0,40}\b(pay|send|transfer|bhejo)\b/i,
      /\b(upI|bank account|wallet)\b.{0,40}\b(payment|transfer|send money)\b/i
    ]
  },

  {
    id: "exposure_threat",
    label: "Threat to expose information to family or public",
    points: 22,
    severity: "high",
    patterns: [
      /\b(send|show|share|expose|contact|inform)\b.{0,45}\b(your family|your friends|your employer|everyone|the public|your contacts)\b/i,
      /\b(tumhare family|tumhare doston|tumhare office|sabko|gharwalon ko)\b.{0,45}\b(bata|bhej|dikha|share|contact)\b/i,
      /\b(viral kar dunga|sabko bhej dunga|family ko bata dunga)\b/i
    ]
  },

  {
    id: "account_hacking_claim",
    label: "Device or account hacking claim",
    points: 20,
    severity: "high",
    patterns: [
      /\b(i hacked|we hacked|access to your device|your camera is|your account is compromised)\b/i,
      /\b(hacked|camera access|device access|phone access)\b.{0,45}\b(pay|send|money|bitcoin|crypto)\b/i,
      /\b(tumhara phone hack|camera hack|account hack|device hack)\b/i
    ]
  },

  {
    id: "deadline_pressure",
    label: "Urgent payment deadline or countdown pressure",
    points: 18,
    severity: "high",
    patterns: [
      /\b(within \d+ hours?|within \d+ minutes?|you have \d+ hours?|deadline|pay now|immediately)\b/i,
      /\b(24 hours|48 hours|one hour|aaj raat tak|abhi payment|turant paise)\b/i,
      /\b(last warning|final warning|time is running out)\b/i
    ]
  },

  {
    id: "secrecy",
    label: "Victim discouraged from seeking help",
    points: 15,
    severity: "medium",
    patterns: [
      /\b(do not tell anyone|don't contact police|keep this secret|tell no one)\b/i,
      /\b(kisi ko mat batao|police ko mat batao|secret rakho|madad mat lo)\b/i,
      /\b(don't inform your family|do not seek help)\b/i
    ]
  },

  {
    id: "payment_link",
    label: "Payment link or cryptocurrency wallet reference",
    points: 12,
    severity: "medium",
    patterns: [
      /https?:\/\/[^\s<>()]+/i,
      /\b(send|pay|transfer)\b.{0,35}\b(this link|wallet address|crypto wallet)\b/i,
      /\b(upi id|wallet address|bitcoin address)\b/i
    ]
  }
];

/* =========================================================
   RISK CLASSIFICATION
========================================================= */

function getRiskLevel(score, findings) {
  const hasCriticalThreat = findings.some(
    (finding) =>
      finding.id === "intimate_content_threat" ||
      finding.id === "payment_demand"
  );

  if (score >= 70 || (hasCriticalThreat && score >= 50)) {
    return "critical";
  }

  if (score >= 50) {
    return "high";
  }

  if (score >= 25) {
    return "medium";
  }

  return "low";
}

/* =========================================================
   INPUT NORMALIZATION
========================================================= */

function normalizeInput(input) {
  if (typeof input === "string") {
    return input.trim();
  }

  if (input && typeof input === "object") {
    return [
      input.message,
      input.email,
      input.details
    ]
      .filter((part) => typeof part === "string")
      .join("\n")
      .trim();
  }

  return "";
}

/* =========================================================
   BLACKMAIL DETECTION
========================================================= */

/**
 * @param {string|object} input
 * @returns {object}
 */

function scanBlackmail(input) {
  const text = normalizeInput(input);

  if (!text) {
    throw new TypeError(
      "Blackmail message ya email enter karein."
    );
  }

  if (text.length > 15000) {
    throw new RangeError(
      "Input maximum 15000 characters ka ho sakta hai."
    );
  }

  const findings = [];

  /* RULE MATCHING */

  for (const rule of BLACKMAIL_RULES) {
    const matchedPattern = rule.patterns.find(
      (pattern) => pattern.test(text)
    );

    if (matchedPattern) {
      findings.push({
        id: rule.id,
        label: rule.label,
        points: rule.points,
        severity: rule.severity,
        evidence: matchedPattern.source
      });
    }
  }

  /* RISK SCORING */

  let score = findings.reduce(
    (total, finding) => total + finding.points,
    0
  );

  score = Math.min(score, 100);

  const risk = getRiskLevel(score, findings);

  /* SAFETY RECOMMENDATIONS */

  const advice = [
    "Do not send money to the threatening sender.",
    "Do not share OTPs, passwords or additional personal information.",
    "Preserve messages, emails, usernames and payment details as evidence.",
    "Avoid opening links or downloading attachments from the sender.",
    "Seek help from a trusted person or appropriate reporting service."
  ];

  if (
    findings.some(
      (finding) =>
        finding.id === "intimate_content_threat"
    )
  ) {
    advice.push(
      "Do not forward or repost intimate images.",
      "Preserve evidence of the threat and report the incident through appropriate channels."
    );
  }

  if (
    findings.some(
      (finding) =>
        finding.id === "account_hacking_claim"
    )
  ) {
    advice.push(
      "Change passwords using official websites or applications.",
      "Enable two-factor authentication.",
      "Review active account sessions and revoke unfamiliar sessions."
    );
  }

  if (
    findings.some(
      (finding) =>
        finding.id === "payment_demand"
    )
  ) {
    advice.push(
      "If money has already been transferred in India, contact your bank immediately and report financial cyber fraud through 1930."
    );
  }

  /* FINAL RESULT */

  return {
    type: "blackmail",

    category: "Sextortion & Blackmail",

    score,

    risk,

    findings,

    totalFindings: findings.length,

    detected: findings.length > 0,

    summary:
      findings.length > 0
        ? `${findings.length} potential blackmail indicators detected.`
        : "No matching blackmail indicators detected.",

    advice,

    metadata: {
      engine: "ScamShield Blackmail Detector",
      detectionMethod: "Rule-Based Pattern Matching",
      evidenceLength: text.length,
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
    scanBlackmail,
    getRiskLevel
  };
}

if (typeof window !== "undefined") {
  window.ScamShieldBlackmailScanner = {
    scanBlackmail,
    getRiskLevel
  };
}
