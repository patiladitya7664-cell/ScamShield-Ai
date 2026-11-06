"use strict";

// =====================================================
// SCAMSHIELD AI - RATE LIMIT MIDDLEWARE
// Protects APIs against excessive requests and abuse
// =====================================================

const { rateLimit } = require("express-rate-limit");

// =====================================================
// COMMON RATE LIMIT RESPONSE
// =====================================================

const rateLimitResponse = (message) => ({
    success: false,
    status: "error",
    message,
});

// =====================================================
// 1. GLOBAL API RATE LIMIT
// Applies to general API requests
// =====================================================

const globalRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,

    limit: 200,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    message: rateLimitResponse(
        "Too many requests. Please try again after some time."
    ),

    handler: (req, res) => {
        return res.status(429).json(
            rateLimitResponse(
                "Too many requests. Please try again after 15 minutes."
            )
        );
    },
});

// =====================================================
// 2. AUTH RATE LIMIT
// Protects login and registration endpoints
// =====================================================

const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,

    limit: 10,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    skipSuccessfulRequests: true,

    handler: (req, res) => {
        return res.status(429).json(
            rateLimitResponse(
                "Too many authentication attempts. Please try again later."
            )
        );
    },
});

// =====================================================
// 3. ANALYSIS RATE LIMIT
// Controls repeated AI analysis requests
// =====================================================

const analysisRateLimiter = rateLimit({
    windowMs: 60 * 1000,

    limit: 20,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    handler: (req, res) => {
        return res.status(429).json(
            rateLimitResponse(
                "Analysis request limit exceeded. Please try again after one minute."
            )
        );
    },
});

// =====================================================
// 4. AGENT RATE LIMIT
// Controls agent execution requests
// =====================================================

const agentRateLimiter = rateLimit({
    windowMs: 60 * 1000,

    limit: 10,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    handler: (req, res) => {
        return res.status(429).json(
            rateLimitResponse(
                "Agent execution limit exceeded. Please try again later."
            )
        );
    },
});

// =====================================================
// 5. PASSWORD / SENSITIVE ACTION RATE LIMIT
// Protects sensitive authentication operations
// =====================================================

const sensitiveActionRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,

    limit: 5,

    standardHeaders: "draft-8",
    legacyHeaders: false,

    skipSuccessfulRequests: true,

    handler: (req, res) => {
        return res.status(429).json(
            rateLimitResponse(
                "Too many attempts. Please try again after 15 minutes."
            )
        );
    },
});

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    globalRateLimiter,
    authRateLimiter,
    analysisRateLimiter,
    agentRateLimiter,
    sensitiveActionRateLimiter,
};