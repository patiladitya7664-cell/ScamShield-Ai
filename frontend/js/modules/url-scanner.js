"use strict";

/**
 * URL mein kuch common phishing indicators check karta hai.
 * Yeh website ko visit nahi karta aur URL safe hone ki guarantee nahi deta.
 */

const SHORTENER_HOSTS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "cutt.ly",
  "rb.gy",
  "shorturl.at",
  "rebrand.ly"
]);

const SUSPICIOUS_TLDS = new Set([
  "zip",
  "mov",
  "top",
  "click",
  "work",
  "country",
  "gq",
  "tk",
  "ml",
  "cf"
]);

const URL_RULES = [
  {
    id: "non_https",
    label: "Link HTTPS ke bajay HTTP use karta hai",
    points: 12
  },
  {
    id: "ip_address_host",
    label: "Website domain ki jagah IP address use ho raha hai",
    points: 25
  },
  {
    id: "userinfo_present",
    label: "URL mein @ sign ke pehle extra login text hai",
    points: 25
  },
  {
    id: "punycode_domain",
    label: "Domain mein encoded international characters hain",
    points: 20
  },
  {
    id: "many_subdomains",
    label: "Domain mein bahut saare subdomains hain",
    points: 12
  },
  {
    id: "suspicious_tld",
    label: "Domain ka ending less-common TLD hai",
    points: 10
  },
  {
    id: "shortened_url",
    label: "Link URL-shortening service ka hai",
    points: 12
  },
  {
    id: "brand_in_subdomain",
    label: "Popular brand ka naam subdomain mein dikh raha hai",
    points: 18
  }
];

const KNOWN_BRANDS = [
  "google",
  "microsoft",
  "apple",
  "amazon",
  "paypal",
  "facebook",
  "instagram",
  "whatsapp",
  "netflix",
  "telegram",
  "sbi",
  "hdfc",
  "icici",
  "axisbank",
  "paytm"
];

function normalizeUrl(input) {
  const trimmed = input.trim();

  if (!trimmed) {
    throw new TypeError("Scan karne ke liye URL enter karein.");
  }

  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `https://${trimmed}`;

  let parsed;

  try {
    parsed = new URL(candidate);
  } catch {
    throw new TypeError("Yeh valid URL nahi lagta. URL ko dobara check karein.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new TypeError("Sirf HTTP ya HTTPS links scan kiye ja sakte hain.");
  }

  return parsed;
}

function isIpv4(hostname) {
  const parts = hostname.split(".");
  return (
    parts.length === 4 &&
    parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  );
}

function getRiskLevel(score) {
  if (score >= 45) return "high";
  if (score >= 20) return "medium";
  return "low";
}

/**
 * @param {string} input URL, domain, ya pasted link
 * @returns {{
 *   type: string,
 *   input: string,
 *   hostname: string,
 *   score: number,
 *   risk: "low" | "medium" | "high",
 *   findings: Array<{id: string, label: string, points: number}>,
 *   advice: string[]
 * }}
 */
function scanUrl(input) {
  if (typeof input !== "string") {
    throw new TypeError("URL text ke roop mein enter karein.");
  }

  const parsed = normalizeUrl(input);
  const hostname = parsed.hostname.toLowerCase();
  const labels = hostname.split(".").filter(Boolean);
  const findings = [];

  const addFinding = (id) => {
    const rule = URL_RULES.find((item) => item.id === id);
    if (rule) findings.push({ id: rule.id, label: rule.label, points: rule.points });
  };

  if (parsed.protocol !== "https:") addFinding("non_https");
  if (isIpv4(hostname)) addFinding("ip_address_host");
  if (parsed.username || parsed.password || parsed.href.includes("@")) {
    addFinding("userinfo_present");
  }
  if (hostname.includes("xn--")) addFinding("punycode_domain");
  if (labels.length >= 5) addFinding("many_subdomains");

  const domainParts = hostname.split(".");
  const tld = domainParts[domainParts.length - 1];
  if (SUSPICIOUS_TLDS.has(tld)) addFinding("suspicious_tld");

  if (SHORTENER_HOSTS.has(hostname)) addFinding("shortened_url");

  const subdomain = labels.slice(0, -2).join(".");
  if (KNOWN_BRANDS.some((brand) => subdomain.includes(brand))) {
    addFinding("brand_in_subdomain");
  }

  const score = Math.min(
    findings.reduce((total, finding) => total + finding.points, 0),
    100
  );

  const advice = [
    "Link kholne se pehle domain spelling ko dhyan se check karein.",
    "Password, OTP, PIN ya payment details link par tabhi enter karein jab aapne official website khud open ki ho."
  ];

  if (findings.some((finding) => finding.id === "shortened_url")) {
    advice.push("Shortened link ka final destination yahan verify nahi kiya gaya hai.");
  }

  return {
    type: "url",
    input: input.trim(),
    hostname,
    score,
    risk: getRiskLevel(score),
    findings,
    advice
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { scanUrl };
}

if (typeof window !== "undefined") {
  window.ScamShieldUrlScanner = { scanUrl };
}