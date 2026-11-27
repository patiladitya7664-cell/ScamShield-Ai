"use strict";

// =====================================================
// SCAMSHIELD AI - REPORTS CONTROLLER
// Version: 2.1.0
//
// Data Source: Analysis Model
// =====================================================

const mongoose = require("mongoose");
const Analysis = require("../models/analysis");

// =====================================================
// 1. CONSTANTS
// =====================================================

const VALID_RISK_LEVELS = [
  "low",
  "medium",
  "high",
  "critical",
];

const VALID_STATUSES = [
  "pending",
  "processing",
  "completed",
  "failed",
];

const VALID_CATEGORIES = [
  "fraud_message",
  "fraud_call",
  "url_phishing",
  "email_scam",
  "investment_scam",
  "digital_arrest",
  "upi_banking_fraud",
  "card_fraud",
  "ecommerce_scam",
  "job_loan_scam",
  "sextortion_blackmail",
  "social_media_scam",
];

const VALID_FRAUD_MODULES = [
  "investment",
  "digitalArrest",
  "creditCard",
  "sextortion",
  "ecommerce",
  "other",
  "unclassified",
];

const VALID_EVIDENCE_TYPES = [
  "message",
  "url",
  "call",
  "transaction",
  "screenshot",
  "email",
];

const VALID_DATE_RANGES = [
  "all",
  "today",
  "7days",
  "30days",
];

const DEFAULT_LIMIT = 8;
const MAX_LIMIT = 50;
const MAX_PAGE = 10000;
const MAX_EXPORT_RECORDS = 10000;
const MAX_SEARCH_LENGTH = 80;

// =====================================================
// 2. ERROR HELPER
// =====================================================

const createError = (message, statusCode = 400) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};

// =====================================================
// 3. USER VALIDATION
// =====================================================

const getUserId = (req) => {
  const userId = req.user?._id;

  if (
    !userId ||
    !mongoose.Types.ObjectId.isValid(String(userId))
  ) {
    return null;
  }

  return new mongoose.Types.ObjectId(String(userId));
};

// =====================================================
// 4. QUERY VALIDATION
// =====================================================

const getStringQuery = (value, fieldName) => {
  if (value === undefined) {
    return "";
  }

  if (typeof value !== "string") {
    throw createError(`Invalid ${fieldName} parameter.`);
  }

  return value.trim();
};

const validateEnum = (value, allowedValues, fieldName) => {
  if (!value) {
    return "";
  }

  if (!allowedValues.includes(value)) {
    throw createError(`Invalid ${fieldName} filter.`);
  }

  return value;
};

const escapeRegex = (value) =>
  value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// =====================================================
// 5. DATE HELPERS
// =====================================================

const parseDate = (value, fieldName, endOfDay = false) => {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw createError(`Invalid ${fieldName} date.`);
  }

  const date = new Date(`${value}T00:00:00.000Z`);

  if (
    Number.isNaN(date.getTime()) ||
    date.toISOString().slice(0, 10) !== value
  ) {
    throw createError(`Invalid ${fieldName} date.`);
  }

  if (endOfDay) {
    date.setUTCHours(23, 59, 59, 999);
  }

  return date;
};

const getDateFilter = (query) => {
  const filter = {};

  const dateRange = getStringQuery(
    query.dateRange,
    "dateRange"
  ).toLowerCase();

  const selectedRange = validateEnum(
    dateRange,
    VALID_DATE_RANGES,
    "date range"
  );

  const now = new Date();

  if (selectedRange === "today") {
    const start = new Date(now);
    start.setUTCHours(0, 0, 0, 0);

    filter.$gte = start;
  }

  if (selectedRange === "7days") {
    const start = new Date(now);
    start.setUTCDate(start.getUTCDate() - 7);

    filter.$gte = start;
  }

  if (selectedRange === "30days") {
    const start = new Date(now);
    start.setUTCDate(start.getUTCDate() - 30);

    filter.$gte = start;
  }

  const fromValue = getStringQuery(query.from, "from");
  const toValue = getStringQuery(query.to, "to");

  if (fromValue) {
    const from = parseDate(fromValue, "from");

    if (!filter.$gte || from > filter.$gte) {
      filter.$gte = from;
    }
  }

  if (toValue) {
    filter.$lte = parseDate(toValue, "to", true);
  }

  if (
    filter.$gte &&
    filter.$lte &&
    filter.$gte > filter.$lte
  ) {
    throw createError("Invalid date range.");
  }

  return Object.keys(filter).length
    ? { createdAt: filter }
    : {};
};

// =====================================================
// 6. REPORT FILTER BUILDER
// =====================================================

const buildReportsFilter = (userId, query = {}) => {
  const filter = {
    user: userId,
  };

  const riskLevel = getStringQuery(
    query.riskLevel,
    "riskLevel"
  ).toLowerCase();

  const category = getStringQuery(
    query.category,
    "category"
  ).toLowerCase();

  const status = getStringQuery(
    query.status,
    "status"
  ).toLowerCase();

  const evidenceType = getStringQuery(
    query.evidenceType,
    "evidenceType"
  ).toLowerCase();

  const validRisk = validateEnum(
    riskLevel,
    VALID_RISK_LEVELS,
    "risk level"
  );

  const validCategory = validateEnum(
    category,
    VALID_CATEGORIES,
    "category"
  );

  const validStatus = validateEnum(
    status,
    VALID_STATUSES,
    "status"
  );

  const validEvidenceType = validateEnum(
    evidenceType,
    VALID_EVIDENCE_TYPES,
    "evidence type"
  );

  if (validRisk) {
    filter.riskLevel = validRisk;
  }

  // Individual detection category.
  // fraudCategory is the separate major module field.
  if (validCategory) {
    filter.detectionCategory = validCategory;
  }

  if (validStatus) {
    filter.status = validStatus;
  }

  if (validEvidenceType) {
    filter.evidenceType = validEvidenceType;
  }

  const search = getStringQuery(
    query.search,
    "search"
  ).slice(0, MAX_SEARCH_LENGTH);

  if (search) {
    const safeSearch = escapeRegex(search);

    filter.$or = [
      {
        evidenceId: {
          $regex: safeSearch,
          $options: "i",
        },
      },
      {
        fraudCategory: {
          $regex: safeSearch,
          $options: "i",
        },
      },
      {
        detectionCategory: {
          $regex: safeSearch,
          $options: "i",
        },
      },
      {
        evidenceType: {
          $regex: safeSearch,
          $options: "i",
        },
      },
      {
        status: {
          $regex: safeSearch,
          $options: "i",
        },
      },
      {
        summary: {
          $regex: safeSearch,
          $options: "i",
        },
      },
      {
        "detectedRules.label": {
          $regex: safeSearch,
          $options: "i",
        },
      },
    ];
  }

  return {
    ...filter,
    ...getDateFilter(query),
  };
};

// =====================================================
// 7. SENSITIVE INFORMATION REDACTION
// =====================================================

const redactSensitiveText = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  let text = value;

  // Passwords, PINs, OTPs, CVVs, tokens and secrets.
  text = text.replace(
    /\b(otp|one[\s-]?time[\s-]?password|upi[\s-]?pin|pin|password|passcode|cvv|cvc|security[\s-]?code|access[\s-]?token|refresh[\s-]?token|api[\s_-]?key|secret)\b\s*(?:is|:|=|-)?\s*[A-Z0-9@#$%^&*!._-]{3,}/gi,
    "$1: [REDACTED CREDENTIAL]"
  );

  // Email addresses.
  text = text.replace(
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
    "[REDACTED EMAIL]"
  );

  // Indian mobile numbers.
  text = text.replace(
    /(?:\+91[\s-]?)?[6-9]\d{9}\b/g,
    "[REDACTED PHONE]"
  );

  // Aadhaar, card and long numeric identifiers.
  text = text.replace(
    /\b\d{12,19}\b/g,
    "[REDACTED NUMBER]"
  );

  // OTP-like six digit values when explicitly labelled.
  text = text.replace(
    /\b(?:otp|verification code|security code)\s*[:=-]?\s*\d{4,8}\b/gi,
    "[REDACTED OTP]"
  );

  return text;
};

// =====================================================
// 8. SAFE INDICATOR FORMATTER
// =====================================================

const formatIndicators = (indicators) => {
  if (!Array.isArray(indicators)) {
    return [];
  }

  return indicators.slice(0, 50).map((indicator) => ({
    type: String(
      indicator?.type || "unknown"
    ).slice(0, 30),

    value: redactSensitiveText(
      String(indicator?.value || "").slice(0, 500)
    ),

    verified: indicator?.verified === true,
  }));
};

// =====================================================
// 9. SAFE DETECTED RULE FORMATTER
// =====================================================

const formatDetectedRules = (rules) => {
  if (!Array.isArray(rules)) {
    return [];
  }

  return rules.slice(0, 100).map((rule) => ({
    category: String(
      rule?.category || "unclassified"
    ).slice(0, 50),

    label: redactSensitiveText(
      String(rule?.label || "").slice(0, 200)
    ),

    weight:
      typeof rule?.weight === "number" &&
      Number.isFinite(rule.weight)
        ? Math.max(0, Math.min(100, rule.weight))
        : 0,
  }));
};

// =====================================================
// 10. REPORT FORMATTER
// =====================================================

const formatReport = (report) => ({
  _id: report._id,

  reportId: report.evidenceId || "",

  evidenceId: report.evidenceId || "",

  evidenceType: report.evidenceType || "message",

  // Major fraud module.
  fraudCategory: report.fraudCategory || "unclassified",

  // Individual detection category.
  detectionCategory: report.detectionCategory || null,

  riskScore:
    typeof report.riskScore === "number"
      ? Math.max(0, Math.min(100, report.riskScore))
      : 0,

  riskLevel: report.riskLevel || "low",

  status: report.status || "pending",

  summary: redactSensitiveText(
    report.summary || ""
  ),

  indicators: formatIndicators(
    report.indicators
  ),

  detectedRules: formatDetectedRules(
    report.detectedRules
  ),

  analyzedAt: report.analyzedAt || null,

  createdAt: report.createdAt || null,
});

// =====================================================
// 11. PAGINATION VALIDATION
// =====================================================

const getPagination = (query) => {
  const rawPage = query.page;
  const rawLimit = query.limit;

  if (
    rawPage !== undefined &&
    !/^\d+$/.test(String(rawPage))
  ) {
    throw createError("Invalid page number.");
  }

  if (
    rawLimit !== undefined &&
    !/^\d+$/.test(String(rawLimit))
  ) {
    throw createError("Invalid page limit.");
  }

  const page = rawPage === undefined
    ? 1
    : Number(rawPage);

  const requestedLimit = rawLimit === undefined
    ? DEFAULT_LIMIT
    : Number(rawLimit);

  if (
    !Number.isSafeInteger(page) ||
    page < 1 ||
    page > MAX_PAGE
  ) {
    throw createError("Page number is out of range.");
  }

  if (
    !Number.isSafeInteger(requestedLimit) ||
    requestedLimit < 1
  ) {
    throw createError("Invalid page limit.");
  }

  const limit = Math.min(requestedLimit, MAX_LIMIT);

  return {
    page,
    limit,
    skip: (page - 1) * limit,
  };
};

// =====================================================
// 12. GET REPORTS
// GET /api/reports
// =====================================================

const getReports = async (req, res, next) => {
  try {
    const userId = getUserId(req);

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const { page, limit, skip } = getPagination(
      req.query
    );

    const filter = buildReportsFilter(
      userId,
      req.query
    );

    const [reports, totalRecords] = await Promise.all([
      Analysis.find(filter)
        .select(
          "evidenceId evidenceType fraudCategory detectionCategory riskScore riskLevel status summary indicators detectedRules analyzedAt createdAt"
        )
        .sort({
          createdAt: -1,
          _id: -1,
        })
        .skip(skip)
        .limit(limit)
        .lean(),

      Analysis.countDocuments(filter),
    ]);

    const totalPages = Math.ceil(totalRecords / limit);

    return res.status(200).json({
      success: true,

      message: "Reports fetched successfully.",

      data: {
        reports: reports.map(formatReport),

        pagination: {
          currentPage: page,
          limit,
          totalRecords,
          totalPages,

          hasNextPage: page < totalPages,

          hasPreviousPage: page > 1,
        },
      },
    });
  } catch (error) {
    return next(error);
  }
};

// =====================================================
// 13. GET REPORT STATISTICS
// GET /api/reports/stats
// =====================================================

const getReportStats = async (req, res, next) => {
  try {
    const userId = getUserId(req);

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const userFilter = {
      user: userId,
    };

    const [
      total,
      highRisk,
      underReview,
      completed,
      failed,
      riskDistribution,
      categoryDistribution,
      moduleDistribution,
      evidenceDistribution,
    ] = await Promise.all([
      Analysis.countDocuments(userFilter),

      Analysis.countDocuments({
        ...userFilter,
        riskLevel: {
          $in: ["high", "critical"],
        },
      }),

      Analysis.countDocuments({
        ...userFilter,
        status: {
          $in: ["pending", "processing"],
        },
      }),

      Analysis.countDocuments({
        ...userFilter,
        status: "completed",
      }),

      Analysis.countDocuments({
        ...userFilter,
        status: "failed",
      }),

      Analysis.aggregate([
        { $match: userFilter },
        {
          $group: {
            _id: "$riskLevel",
            count: { $sum: 1 },
          },
        },
      ]),

      Analysis.aggregate([
        { $match: userFilter },
        {
          $group: {
            _id: "$detectionCategory",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
      ]),

      Analysis.aggregate([
        { $match: userFilter },
        {
          $group: {
            _id: "$fraudCategory",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
      ]),

      Analysis.aggregate([
        { $match: userFilter },
        {
          $group: {
            _id: "$evidenceType",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
      ]),
    ]);

    const riskCounts = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };

    riskDistribution.forEach((item) => {
      if (
        Object.prototype.hasOwnProperty.call(
          riskCounts,
          item._id
        )
      ) {
        riskCounts[item._id] = item.count;
      }
    });

    return res.status(200).json({
      success: true,

      message: "Report statistics fetched successfully.",

      data: {
        total,
        highRisk,
        underReview,
        completed,
        failed,

        riskDistribution: riskCounts,

        categoryDistribution: categoryDistribution.map(
          (item) => ({
            category: item._id || "unclassified",
            count: item.count,
          })
        ),

        moduleDistribution: moduleDistribution.map(
          (item) => ({
            module: item._id || "unclassified",
            count: item.count,
          })
        ),

        evidenceDistribution: evidenceDistribution.map(
          (item) => ({
            evidenceType: item._id || "unknown",
            count: item.count,
          })
        ),
      },
    });
  } catch (error) {
    return next(error);
  }
};

// =====================================================
// 14. GET REPORT BY ID
// GET /api/reports/:id
// =====================================================

const getReportById = async (req, res, next) => {
  try {
    const userId = getUserId(req);

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const { id } = req.params;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      throw createError("Invalid report ID.");
    }

    const report = await Analysis.findOne({
      _id: id,
      user: userId,
    })
      .select(
        "evidenceId evidenceType fraudCategory detectionCategory riskScore riskLevel status summary indicators detectedRules analyzedAt createdAt"
      )
      .lean();

    if (!report) {
      return res.status(404).json({
        success: false,
        message: "Report not found.",
      });
    }

    return res.status(200).json({
      success: true,

      message: "Report details fetched successfully.",

      data: {
        report: formatReport(report),
      },
    });
  } catch (error) {
    return next(error);
  }
};

// =====================================================
// 15. CSV EXPORT
// GET /api/reports/export
// =====================================================

const exportReports = async (req, res, next) => {
  try {
    const userId = getUserId(req);

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Authentication required.",
      });
    }

    const filter = buildReportsFilter(
      userId,
      req.query
    );

    const totalRecords = await Analysis.countDocuments(
      filter
    );

    if (totalRecords > MAX_EXPORT_RECORDS) {
      return res.status(413).json({
        success: false,

        message:
          "Export contains too many records. Apply additional filters.",

        data: {
          totalRecords,
          maximumAllowed: MAX_EXPORT_RECORDS,
        },
      });
    }

    const reports = await Analysis.find(filter)
      .select(
        "evidenceId evidenceType fraudCategory detectionCategory riskScore riskLevel status summary analyzedAt createdAt"
      )
      .sort({
        createdAt: -1,
        _id: -1,
      })
      .limit(MAX_EXPORT_RECORDS)
      .lean();

    const columns = [
      "Report ID",
      "Evidence Type",
      "Fraud Module",
      "Detection Category",
      "Risk Score",
      "Risk Level",
      "Status",
      "Summary",
      "Analyzed At",
    ];

    const escapeCSV = (value) => {
      let text = String(value ?? "");

      // Spreadsheet formula injection protection.
      if (/^[\s]*[=+\-@]/.test(text)) {
        text = `'${text}`;
      }

      return `"${text.replace(/"/g, '""')}"`;
    };

    const rows = reports.map((report) => [
      report.evidenceId,
      report.evidenceType,
      report.fraudCategory,
      report.detectionCategory,
      report.riskScore,
      report.riskLevel,
      report.status,
      redactSensitiveText(report.summary || ""),
      report.analyzedAt || report.createdAt,
    ]);

    const csv = [
      columns.map(escapeCSV).join(","),

      ...rows.map((row) =>
        row.map(escapeCSV).join(",")
      ),
    ].join("\r\n");

    res.setHeader(
      "Content-Type",
      "text/csv; charset=utf-8"
    );

    res.setHeader(
      "Content-Disposition",
      'attachment; filename="scamshield-reports.csv"'
    );

    res.setHeader("Cache-Control", "no-store");

    res.setHeader("X-Content-Type-Options", "nosniff");

    return res.status(200).send("\uFEFF" + csv);
  } catch (error) {
    return next(error);
  }
};

// =====================================================
// 16. EXPORT CONTROLLERS
// =====================================================

module.exports = {
  getReports,
  getReportStats,
  getReportById,
  exportReports,
};