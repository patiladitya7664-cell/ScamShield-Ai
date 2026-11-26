
"use strict";

// =====================================================
// SCAMSHIELD AI - AUTHENTICATION MIDDLEWARE
// Version: 2.0.0
//
// Features:
// 1. Centralized JWT configuration.
// 2. Secure JWT verification.
// 3. Algorithm enforcement.
// 4. Issuer and audience verification.
// 5. User database verification.
// 6. Account status validation.
// 7. Secure request authentication.
// =====================================================

const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const User = require("../models/User");
const config = require("../config/config");

// =====================================================
// JWT CONFIGURATION
// =====================================================

const JWT_ALGORITHM = "HS256";

// =====================================================
// PROTECT MIDDLEWARE
// =====================================================

const protect = async (req, res, next) => {
    try {

        // ---------------------------------------------
        // 1. VALIDATE JWT CONFIGURATION
        // ---------------------------------------------

        const jwtSecret = config.auth.jwtSecret;

        if (
            typeof jwtSecret !== "string" ||
            !jwtSecret.trim() ||
            Buffer.byteLength(jwtSecret, "utf8") < 32
        ) {
            const error = new Error(
                "JWT configuration is invalid."
            );

            error.statusCode = 500;

            return next(error);
        }

        // ---------------------------------------------
        // 2. READ AUTHORIZATION HEADER
        // ---------------------------------------------

        const authorization = req.headers.authorization;

        if (
            !authorization ||
            typeof authorization !== "string"
        ) {
            return res.status(401).json({
                success: false,
                message: "Authentication required. Please login.",
            });
        }

        // ---------------------------------------------
        // 3. EXTRACT BEARER TOKEN
        // ---------------------------------------------

        const parts = authorization.trim().split(/\s+/);

        if (
            parts.length !== 2 ||
            parts[0].toLowerCase() !== "bearer" ||
            !parts[1]
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication header.",
            });
        }

        const token = parts[1];

        // ---------------------------------------------
        // 4. VERIFY JWT
        // ---------------------------------------------

        let decoded;

        try {

            decoded = jwt.verify(
                token,
                jwtSecret,
                {
                    algorithms: [JWT_ALGORITHM],

                    issuer: config.auth.jwtIssuer,

                    audience: config.auth.jwtAudience,
                }
            );

        } catch (error) {

            if (
                error.name === "JsonWebTokenError" ||
                error.name === "TokenExpiredError" ||
                error.name === "NotBeforeError"
            ) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid or expired authentication token.",
                });
            }

            throw error;
        }

        // ---------------------------------------------
        // 5. VALIDATE TOKEN PAYLOAD
        // ---------------------------------------------

        if (
            !decoded ||
            typeof decoded !== "object" ||
            typeof decoded.id !== "string" ||
            !mongoose.isValidObjectId(decoded.id)
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token payload.",
            });
        }

        // ---------------------------------------------
        // 6. FIND AUTHENTICATED USER
        // ---------------------------------------------

        const user = await User.findById(decoded.id);

        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: "User account not found or inactive.",
            });
        }

        // ---------------------------------------------
        // 7. ATTACH USER TO REQUEST
        // ---------------------------------------------

        req.user = user;

        return next();

    } catch (error) {

        console.error(
            "Authentication Middleware Error:",
            error.message
        );

        return next(error);
    }
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    protect,
};
