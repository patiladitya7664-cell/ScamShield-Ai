"use strict";

/**
 * Social media message, post ya profile text mein common scam signs check karta hai.
 * Yeh account ki asli identity ya platform par uski legitimacy verify nahi karta.
 */

const SOCIAL_MEDIA_RULES = [
  {
    id: "impersonation",
    label: "Known person, brand ya support team banne ka claim",
    points: 20,
    patterns: [
      /\b(official support|customer support|admin team|verified account)\b/i,
      /\b(i am|we are|this is)\b.{0,35}\b(your friend|your relative|platform support|bank support)\b/i,
      /\b(main|hum)\b.{0,35}\b(official support|customer care|admin team)\b/i
    ]
  },
  {
    id: "account_threat",
    label: "Account ban, verification failure ya suspension ki dhamki",
    points: 20,
    patterns: [
      /\b(your account|profile|page)\b.{0,45}\b(will be banned|suspended|disabled|restricted|verified)\b/i,
      /\b(verify your account|appeal now|account violation|copyright violation)\b/i
    ]
  },
  {
    id: "credential_request",
    label: "Password, login code ya OTP maanga gaya hai",
    points: 30,
    patterns: [
      /\b(password|login code|verification code|otp|two.factor code)\b.{0,45}\b(send|share|tell|reply|confirm)\b/i,
      /\b(send|share|tell|reply|confirm)\b.{0,45}\b(password|login code|verification code|otp)\b/i
    ]
  },
  {
    id: "giveaway_or_prize",
    label: "Unexpected giveaway, prize ya lottery jeetne ka claim",
    points: 18,
    patterns: [
      /\b(you have won|winner|giveaway|claim your prize|free gift|lottery winner)\b/i,
      /\b(aap jeet gaye|inaam jeeta|free gift|prize claim)\b/i
    ]
  },
  {
    id: "advance_payment",
    label: "Prize, promotion ya collaboration ke liye advance payment maangi gayi hai",
    points: 24,
    patterns: [
      /\b(pay|send|transfer)\b.{0,45}\b(processing fee|release fee|delivery fee|collaboration fee|verification fee)\b/i,
      /\b(prize|giveaway|brand deal)\b.{0,40}\b(fee|deposit|payment)\b/i
    ]
  },
  {
    id: "investment_promotion",
    label: "Social post mein guaranteed investment profit ka dawa",
    points: 22,
    patterns: [
      /\b(guaranteed|risk.free|sure)\b.{0,35}\b(profit|returns|income|crypto gains)\b/i,
      /\b(double your money|daily profit|investment opportunity|crypto signals)\b/i
    ]
  },
  {
    id: "urgent_private_contact",
    label: "Turant private chat ya doosre app par jaane ka pressure",
    points: 12,
    patterns: [
      /\b(message me privately|dm me now|move to whatsapp|contact me urgently)\b/i,
      /\b(private mein message|abhi dm karo|whatsapp par aao|turant contact karo)\b/i
    ]
  },
  {
    id: "suspicious_link",
    label: "Login, verification ya prize claim karne ke liye link diya gaya hai",
    points: 14,
    patterns: [
      /https?:\/\/[^\s<>()]+/i,
      /\b(click|tap|open)\b.{0,30}\b(link|bio|here)\b/i
    ]
  },
  {
    id: "secrecy",
    label: "Offer ya conversation ko secret rakhne ko kaha gaya hai",
    points: 12,
    patterns: [
      /\b(keep this between us|do not tell anyone|private offer|secret deal)\b/i,
      /\b(kisi ko mat batao|secret deal|sirf tumhare liye)\b/i
    ]
  }
];

function getRiskLevel(score) {
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

/**
 * @param {string|{message?: string, post?: string, profileText?: string}} input
 */
function scanSocialMedia(input) {
  let text = "";

  if (typeof input === "string") {
    text = input.trim();
  } else if (input && typeof input === "object") {
    text = [input.message, input.post, input.profileText]
      .filter((part) => typeof part === "string")
      .join("\n")
      .trim();
  }

  if (!text) {
    throw new TypeError("Scan karne ke liye social media message ya post enter karein.");
  }

  const findings = [];

  for (const rule of SOCIAL_MEDIA_RULES) {
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
    "Profile ka username aur contact details independently verify karein.",
    "Password, OTP ya login code kisi DM ya comment mein share na karein.",
    "Prize ya promotion ke liye advance payment karne se pehle brand ke official account se confirm karein."
  ];

  if (findings.some((finding) => finding.id === "account_threat")) {
    advice.push("Account warning ko message link se nahi, platform ki official app ya website par check karein.");
  }

  if (findings.some((finding) => finding.id === "suspicious_link")) {
    advice.push("Unknown link par login details enter na karein.");
  }

  return {
    type: "social-media",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanSocialMedia };
}

if (typeof window !== "undefined") {
  window.ScamShieldSocialMediaScanner = { scanSocialMedia };
}
