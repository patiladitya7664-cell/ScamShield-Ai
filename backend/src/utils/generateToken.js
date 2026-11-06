"use strict";

// =====================================================
// SCAMSHIELD AI - JWT TOKEN GENERATOR
// Secure Authentication Token Utility
// =====================================================

const jwt = require("jsonwebtoken");

const config = require("../config/config");

// =====================================================
// GENERATE JWT TOKEN
// =====================================================

const generateToken = (userId) => {
    if (!userId) {
        throw new Error("User ID is required to generate token.");
    }

    const jwtSecret = config.auth.jwtSecret;

    if (!jwtSecret || jwtSecret.length < 32) {
        throw new Error(
            "JWT_SECRET is missing or too weak. Configure a secure secret in .env."
        );
    }

    const expiresIn = config.auth.jwtExpiresIn || "7d";

    return jwt.sign(
        {
            id: userId.toString(),
        },
        jwtSecret,
        {
            expiresIn,
            issuer: "scamshield-ai",
            audience: "scamshield-ai-users",
        }
    );
};

// =====================================================
// EXPORT
// =====================================================

module.exports = generateToken;