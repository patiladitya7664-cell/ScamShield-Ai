"use strict";

/**
 * =========================================================
 * SCAMSHIELD AI - CALL FRAUD DETECTOR
 * Rule-based call transcript screening
 *
 * Detects:
 * 1. Authority impersonation
 * 2. Digital arrest threats
 * 3. OTP / PIN / password theft
 * 4. Remote access scams
 * 5. Money transfer pressure
 * 6. Urgency and threats
 * 7. Secrecy instructions
 * 8. Fake KYC / account blocking
 * 9. UPI collect request scams
 *
 * NOTE:
 * This detector analyses text/transcripts only.
 * It does not independently verify caller identity.
 * =========================================================
 */

const MAX_INPUT_LENGTH = 15000;

const CALL_RULES = [
  {
    id: "authority_impersonation",
    label: "Police, government ya bank officer banne ka claim",
    points: 20,
    severity: "medium",
    patterns: [
      /\b(police|cbi|court|customs|income tax|rbi|bank officer|government officer)\b/i,
      /\b(speaking|calling|bol raha|bol rahi)\b.{0,50}\b(police|cbi|bank|court|customs)\b/i,
      /\b(main|hum)\b.{0,30}\b(police|cbi|bank|government|customs)\b.{0,30}\b(se|ki taraf se|department se)\b/i,
      /\b(sarkari adhikari|police adhikari|bank adhikari)\b/i
    ]
  },

  {
    id: "digital_arrest_threat",
    label: "Digital arrest ya giraftari ki dhamki",
    points: 35,
    severity: "critical",
    patterns: [
      /\b(digital arrest|you are under arrest|arrest warrant|police case against you)\b/i,
      /\b(you will be arrested|arrest kar liya jayega|giraftar kar lenge)\b/i,
      /\b(video call|online)\b.{0,50}\b(arrest|giraftar|investigation)\b/i,
      /\b(aapke khilaf)\b.{0,40}\b(case|warrant|arrest)\b/i,
      /\b(court order|police custody|investigation officer)\b/i
    ]
  },

  {
    id: "otp_or_pin",
    label: "OTP, PIN, password ya CVV maanga gaya hai",
    points: 35,
    severity: "critical",
    patterns: [
      /\b(otp|one.time.password|pin|password|cvv)\b.{0,60}\b(tell|share|read|send|confirm|provide|batao|padho|bhejo)\b/i,
      /\b(tell|share|read|send|confirm|provide|batao|padho|bhejo)\b.{0,60}\b(otp|one.time.password|pin|password|cvv)\b/i,
      /\b(otp|pin|password|cvv)\b.{0,40}\b(batao|padho|bhejo|share karo)\b/i,
      /\b(otp bataiye|otp boliye|secret code batao)\b/i
    ]
  },

  {
    id: "remote_access",
    label: "Remote access ya screen-sharing app install karne ko kaha gaya",
    points: 30,
    severity: "high",
    patterns: [
      /\b(install|download)\b.{0,60}\b(anydesk|teamviewer|remote access|screen sharing|quick support)\b/i,
      /\b(anydesk|teamviewer|remote access|screen sharing|quick support)\b.{0,60}\b(install|download|open|allow|permission)\b/i,
      /\b(screen share|screen sharing|remote control)\b.{0,50}\b(phone|mobile|device|karna|karo)\b/i
    ]
  },

  {
    id: "money_transfer",
    label: "Paise transfer ya payment approve karne ka pressure",
    points: 30,
    severity: "high",
    patterns: [
      /\b(transfer|send|pay|deposit)\b.{0,50}\b(money|funds|amount|fee|fine|tax|account)\b/i,
      /\b(approve|accept)\b.{0,40}\b(upi|collect|payment|request)\b/i,
      /\b(paise bhejo|amount transfer|payment approve|collect request accept)\b/i,
      /\b(account mein)\b.{0,40}\b(paise|amount|money)\b.{0,30}\b(transfer|bhejo|jama)\b/i,
      /\b(safe account|verification account)\b.{0,50}\b(transfer|money|paise)\b/i
    ]
  },

  {
    id: "urgent_threat",
    label: "Turant action lene ki dhamki ya pressure",
    points: 20,
    severity: "medium",
    patterns: [
      /\b(immediately|right now|within \d+ minutes?|last chance|otherwise you will be arrested)\b/i,
      /\b(abhi|turant|isi waqt|warna giraftar|case darj ho jayega)\b/i,
      /\b(within \d+ hours?|account will be blocked immediately)\b/i,
      /\b(10 minute|15 minute|30 minute)\b.{0,40}\b(transfer|pay|share|confirm)\b/i
    ]
  },

  {
    id: "secrecy",
    label: "Call ya investigation kisi se share na karne ko kaha gaya",
    points: 20,
    severity: "high",
    patterns: [
      /\b(do not tell anyone|keep this confidential|do not disconnect|don't contact your bank)\b/i,
      /\b(kisi ko mat batao|call mat kaato|bank ko phone mat karo|secret rakho)\b/i,
      /\b(family|friend|relative)\b.{0,40}\b(do not tell|mat batao|contact mat karo)\b/i
    ]
  },

  {
    id: "fake_kyc",
    label: "Fake KYC ya account block hone ka claim",
    points: 25,
    severity: "high",
    patterns: [
      /\b(kyc|know your customer)\b.{0,50}\b(expire|expired|update|block|suspend|verify)\b/i,
      /\b(account|bank account)\b.{0,50}\b(block|freeze|suspend| बंद|band)\b/i,
      /\b(kyc update karo|account band ho jayega|bank account block ho jayega)\b/i,
      /\b(pan card|aadhaar card)\b.{0,50}\b(update|verify|link|share)\b/i
    ]
  },

  {
    id: "upi_collect_scam",
    label: "UPI collect request ya payment approval fraud",
    points: 30,
    severity: "high",
    patterns: [
      /\b(upi collect request|collect request|payment request)\b/i,
      /\b(upi pin)\b.{0,40}\b(enter|dalna|batao|share|confirm)\b/i,
      /\b(request accept|payment approve)\b.{0,40}\b(upi|phonepe|google pay|paytm)\b/i,
      /\b(paise receive karne)\b.{0,50}\b(upi pin|payment approve|request accept)\b/i
    ]
  }
];

/**
 * Calculate risk level.
 */
function getRiskLevel(score) {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";

  return "low";
}

/**
 * Extract matched evidence.
 */
function extractEvidence(text, patterns) {
  for (const pattern of patterns) {
    const match = text.match(pattern);

    if (match) {
      return match[0].trim();
    }
  }

  return null;
}

/**
 * Generate safety advice.
 */
function generateAdvice(findings) {
  const ids = new Set(findings.map((item) => item.id));

  const advice = [
    "OTP, UPI PIN, CVV ya password kisi caller ke saath share na karein.",
    "Unknown caller ke kehne par paise transfer na karein.",
    "Call disconnect karein aur organization ko uske official contact number se verify karein.",
    "Suspicious call ka phone number, time aur available evidence save karein."
  ];

  if (ids.has("remote_access")) {
    advice.push(
      "Caller ke kehne par AnyDesk, TeamViewer ya koi remote access application install na karein."
    );
  }

  if (ids.has("digital_arrest_threat")) {
    advice.push(
      "Digital arrest ki dhamki par bharosa na karein. Police ya official government channel se independently verify karein."
    );
  }

  if (ids.has("upi_collect_scam")) {
    advice.push(
      "UPI par paise receive karne ke liye UPI PIN enter karne ki zaroorat nahi hoti."
    );
  }

  if (ids.has("fake_kyc")) {
    advice.push(
      "KYC update sirf bank ki official application, website ya branch se karein."
    );
  }

  return advice;
}

/**
 * Main call transcript scanner.
 *
 * @param {string} transcript
 * @returns {Object}
 */
function scanCallTranscript(transcript) {
  if (
    typeof transcript !== "string" ||
    transcript.trim().length === 0
  ) {
    throw new TypeError(
      "Scan karne ke liye call transcript ya notes enter karein."
    );
  }

  const text = transcript.trim();

  if (text.length > MAX_INPUT_LENGTH) {
    throw new RangeError(
      `Call transcript ${MAX_INPUT_LENGTH} characters se zyada nahi hona chahiye.`
    );
  }

  const findings = [];

  for (const rule of CALL_RULES) {
    const evidence = extractEvidence(text, rule.patterns);

    if (evidence) {
      findings.push({
        id: rule.id,
        label: rule.label,
        points: rule.points,
        severity: rule.severity,
        evidence
      });
    }
  }

  const rawScore = findings.reduce(
    (total, finding) => total + finding.points,
    0
  );

  const score = Math.min(rawScore, 100);
  const risk = getRiskLevel(score);

  return {
    type: "call",
    detected: findings.length > 0,
    score,
    risk,

    summary:
      findings.length > 0
        ? `${findings.length} suspicious call warning sign(s) detected.`
        : "No known call scam warning signs detected.",

    findings,

    advice: generateAdvice(findings),

    metadata: {
      detector: "ScamShield Call Detector",
      version: "2.0.0",
      detectionMethod: "rule_based",
      rulesChecked: CALL_RULES.length
    }
  };
}

// =========================================================
// EXPORTS
// =========================================================

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    scanCallTranscript,
    getRiskLevel
  };
}

if (typeof window !== "undefined") {
  window.ScamShieldCallScanner = {
    scanCallTranscript,
    getRiskLevel
  };
}