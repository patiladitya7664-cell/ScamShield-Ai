"use strict";

/**
 * Online shopping offer, seller message ya listing mein common scam signs check karta hai.
 * Yeh seller, product ya website ko independently verify nahi karta.
 */

const ECOMMERCE_RULES = [
  {
    id: "unrealistic_discount",
    label: "Bahut zyada discount ya asambhav roop se kam price",
    points: 22,
    patterns: [
      /\b(up to )?(90|95|99)\s*%\s*(off|discount)\b/i,
      /\b(too good to be true|lowest price ever|almost free|unbelievable deal)\b/i,
      /\b(90|95|99)\s*%\s*(chhoot|discount)\b/i
    ]
  },
  {
    id: "off_platform_payment",
    label: "Marketplace ke bahar payment bhejne ko kaha gaya hai",
    points: 28,
    patterns: [
      /\b(pay|transfer|send)\b.{0,45}\b(outside the platform|directly to my account|personal account|personal upi)\b/i,
      /\b(whatsapp|telegram)\b.{0,40}\b(payment|pay|transfer|order)\b/i,
      /\b(platform ke bahar|personal upi|direct account)\b.{0,40}\b(payment|paise|bhejo)\b/i
    ]
  },
  {
    id: "advance_fee",
    label: "Delivery se pehle extra fee, customs ya insurance maangi gayi hai",
    points: 22,
    patterns: [
      /\b(pay|send|transfer)\b.{0,40}\b(delivery fee|customs fee|insurance fee|release fee|parcel charge)\b/i,
      /\b(delivery|parcel|package)\b.{0,40}\b(customs|insurance|release)\b.{0,30}\b(fee|payment|charge)\b/i
    ]
  },
  {
    id: "fake_delivery_link",
    label: "Delivery ya parcel update ke liye unexpected link diya gaya hai",
    points: 16,
    patterns: [
      /\b(delivery|parcel|package|shipment)\b.{0,45}\b(track|reschedule|confirm address|delivery fee)\b/i,
      /https?:\/\/[^\s<>()]+/i
    ]
  },
  {
    id: "payment_or_otp_request",
    label: "OTP, card PIN ya CVV maanga gaya hai",
    points: 32,
    patterns: [
      /\b(otp|one.time.password|cvv|card pin|upi pin)\b.{0,45}\b(share|send|tell|confirm|provide)\b/i,
      /\b(share|send|tell|confirm|provide)\b.{0,45}\b(otp|one.time.password|cvv|card pin|upi pin)\b/i
    ]
  },
  {
    id: "urgent_offer",
    label: "Turant payment ya order karne ka pressure",
    points: 15,
    patterns: [
      /\b(only today|limited time|pay now|last chance|offer expires soon|hurry)\b/i,
      /\b(sirf aaj|abhi order|jaldi payment|offer khatam)\b/i
    ]
  },
  {
    id: "fake_refund",
    label: "Refund claim karne ke liye payment ya bank details maangi gayi hain",
    points: 25,
    patterns: [
      /\b(refund|cashback)\b.{0,45}\b(pay|fee|otp|pin|cvv|bank details|click)\b/i,
      /\b(pay|share|enter)\b.{0,40}\b(refund|cashback)\b/i
    ]
  }
];

function getRiskLevel(score) {
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}

/**
 * @param {string|{message?: string, listing?: string, details?: string}} input
 */
function scanEcommerce(input) {
  let text = "";

  if (typeof input === "string") {
    text = input.trim();
  } else if (input && typeof input === "object") {
    text = [input.message, input.listing, input.details]
      .filter((part) => typeof part === "string")
      .join("\n")
      .trim();
  }

  if (!text) {
    throw new TypeError("Scan karne ke liye product listing ya seller message enter karein.");
  }

  const findings = [];

  for (const rule of ECOMMERCE_RULES) {
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
    "Payment platform ke official checkout ke andar hi karein.",
    "Seller reviews, return policy aur official contact details independently check karein.",
    "OTP, UPI PIN, card PIN ya CVV seller ya delivery agent ko na batayein."
  ];

  if (findings.some((finding) => finding.id === "off_platform_payment")) {
    advice.push("Marketplace ke bahar payment karne se buyer protection khatam ho sakti hai.");
  }

  if (findings.some((finding) => finding.id === "fake_delivery_link")) {
    advice.push("Parcel status courier ki official website ya app par khud check karein.");
  }

  return {
    type: "ecommerce",
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanEcommerce };
}

if (typeof window !== "undefined") {
  window.ScamShieldEcommerceScanner = { scanEcommerce };
}