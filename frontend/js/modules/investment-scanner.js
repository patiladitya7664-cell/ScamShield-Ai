"use strict";

/**
 * Investment proposal mein common scam warning signs check karta hai.
 * Yeh financial advice nahi hai aur investment ki legitimacy verify nahi karta.
 */

const INVESTMENT_RULES = [
  {
    id: "guaranteed_returns",
    label: "Guaranteed ya risk-free munafe ka wada",
    points: 30,
    patterns: [
      /\b(guaranteed|guarantee|risk.free|no risk|fixed return|assured return)\b.{0,50}\b(profit|return|income|growth)\b/i,
      /\b(double|triple|10x|100%)\b.{0,30}\b(your money|investment|capital|returns)\b/i,
      /\b(pakka munafa|guaranteed profit|bina risk|fixed return)\b/i
    ]
  },
  {
    id: "unrealistic_returns",
    label: "Bahut zyada ya jaldi return ka wada",
    points: 25,
    patterns: [
      /\b\d{1,3}\s*%\s*(daily|weekly|monthly|per month|every day)\b/i,
      /\b(double your money|quick profits|instant returns|high returns)\b/i,
      /\b(rozana|har din|har mahine)\b.{0,30}\b(munafa|return|profit)\b/i
    ]
  },
  {
    id: "urgent_investment",
    label: "Turant invest karne ka pressure",
    points: 18,
    patterns: [
      /\b(invest now|limited time|offer expires|last chance|only today|act immediately)\b/i,
      /\b(abhi invest|sirf aaj|mauka haath se|turant paisa lagao)\b/i
    ]
  },
  {
    id: "recruitment_scheme",
    label: "Naye members laane par income ka wada",
    points: 22,
    patterns: [
      /\b(refer|recruit|bring|add)\b.{0,40}\b(members|people|investors|friends)\b/i,
      /\b(downline|referral income|network marketing|multi.level|pyramid scheme)\b/i,
      /\b(log jodo|member banao|referral se kamai)\b/i
    ]
  },
  {
    id: "crypto_or_trading_claim",
    label: "Crypto ya trading bot se pakke munafe ka claim",
    points: 18,
    patterns: [
      /\b(crypto|bitcoin|forex|trading bot|signals)\b.{0,50}\b(guaranteed|risk.free|fixed profit|sure returns)\b/i,
      /\b(crypto|bitcoin|forex)\b.{0,50}\b(double your money|daily income|assured return)\b/i
    ]
  },
  {
    id: "personal_account_payment",
    label: "Personal account ya wallet mein investment bhejne ko kaha gaya hai",
    points: 25,
    patterns: [
      /\b(send|transfer|deposit|pay)\b.{0,50}\b(personal account|private wallet|individual account|personal upi)\b/i,
      /\b(personal upi|private wallet|personal account)\b.{0,40}\b(paisa|payment|transfer|deposit)\b/i
    ]
  },
  {
    id: "withdrawal_fee",
    label: "Paise nikalne ke liye extra fee maangi gayi hai",
    points: 22,
    patterns: [
      /\b(pay|deposit|send)\b.{0,40}\b(withdrawal fee|release fee|unlock fee|tax to withdraw)\b/i,
      /\b(withdraw|release|unlock)\b.{0,40}\b(fee|tax|charge|deposit)\b/i
    ]
  },
  {
    id: "unregistered_claim",
    label: "Registration ya official details ke bina investment offer",
    points: 12,
    patterns: [
      /\b(no paperwork|no documents|no registration|secret investment|private investment group)\b/i
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
 * @returns {{
 *   type: string,
 *   score: number,
 *   risk: "low" | "medium" | "high",
 *   findings: Array<{id: string, label: string, points: number}>,
 *   advice: string[]
 * }}
 */
function scanInvestment(input) {
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
    throw new TypeError("Scan karne ke liye investment offer ya message enter karein.");
  }

  const findings = [];

  for (const rule of INVESTMENT_RULES) {
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
    "Invest karne se pehle company aur product ko apne official regulator ke records mein independently verify karein.",
    "Sirf promised returns dekhkar invest na karein; fees, withdrawal rules aur risk documents padhein.",
    "Personal UPI ya private wallet mein paisa bhejne se pehle company ke official payment details verify karein."
  ];

  if (findings.some((finding) => finding.id === "recruitment_scheme")) {
    advice.push("Agar kamai naye members lane par depend karti hai, toh scheme ko bahut saavdhani se jaanchein.");
  }

  return {
    type: "investment",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanInvestment };
}

if (typeof window !== "undefined") {
  window.ScamShieldInvestmentScanner = { scanInvestment };
}