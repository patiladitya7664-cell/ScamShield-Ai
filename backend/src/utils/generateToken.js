
"use strict";

// =====================================================
// SCAMSHIELD AI - JWT TOKEN GENERATOR
// Version: 2.0.0
//
// Responsibilities:
// 1. Validate user identity.
// 2. Validate JWT configuration.
// 3. Generate signed authentication tokens.
// 4. Enforce signing algorithm.
// 5. Configure issuer, audience and expiration.
//
// SECURITY:
// - JWT secret must be configured securely.
// - Never expose the JWT secret.
// - Never include passwords or sensitive information
//   inside the JWT payload.
// =====================================================

const jwt = require("jsonwebtoken");

const config = require("../config/config");


// =====================================================
// 1. CONSTANTS
// =====================================================

const JWT_ISSUER = "scamshield-ai";

const JWT_AUDIENCE = "scamshield-ai-users";

const JWT_ALGORITHM = "HS256";

const DEFAULT_EXPIRATION = "7d";

const MIN_SECRET_LENGTH = 32;


// =====================================================
// 2. VALIDATE USER ID
// =====================================================

const validateUserId = (userId) => {
    if (
        userId === null ||
        userId === undefined
    ) {
        throw new Error(
            "User ID is required to generate token."
        );
    }

    const normalizedUserId = String(userId).trim();

    if (
        !normalizedUserId ||
        normalizedUserId.length > 128
    ) {
        throw new Error(
            "Invalid user ID."
        );
    }

    return normalizedUserId;
};


// =====================================================
// 3. VALIDATE JWT SECRET
// =====================================================

const validateJwtSecret = () => {
    const jwtSecret = config?.auth?.jwtSecret;

    if (
        typeof jwtSecret !== "string" ||
        !jwtSecret.trim()
    ) {
        throw new Error(
            "JWT_SECRET is missing. Configure it in your environment."
        );
    }

    if (
        Buffer.byteLength(jwtSecret, "utf8") <
        MIN_SECRET_LENGTH
    ) {
        throw new Error(
            "JWT_SECRET is too weak. Use a securely generated secret of at least 32 bytes."
        );
    }

    return jwtSecret;
};


// =====================================================
// 4. VALIDATE TOKEN EXPIRATION
// =====================================================

const getTokenExpiration = () => {
    const expiresIn =
        config?.auth?.jwtExpiresIn ||
        DEFAULT_EXPIRATION;

    if (
        !(
            typeof expiresIn === "string" ||
            (
                typeof expiresIn === "number" &&
                Number.isFinite(expiresIn) &&
                expiresIn > 0
            )
        )
    ) {
        throw new Error(
            "Invalid JWT expiration configuration."
        );
    }

    if (
        typeof expiresIn === "string" &&
        !expiresIn.trim()
    ) {
        throw new Error(
            "JWT expiration cannot be empty."
        );
    }

    return expiresIn;
};


// =====================================================
// 5. GENERATE JWT TOKEN
// =====================================================

const generateToken = (userId) => {
    const normalizedUserId = validateUserId(userId);

    const jwtSecret = validateJwtSecret();

    const expiresIn = getTokenExpiration();

    const payload = {
        id: normalizedUserId,
    };

    const options = {
        algorithm: JWT_ALGORITHM,

        expiresIn,

        issuer: JWT_ISSUER,

        audience: JWT_AUDIENCE,
    };

    return jwt.sign(
        payload,
        jwtSecret,
        options
    );
};


// =====================================================
// 6. EXPORT
// =====================================================

module.exports = generateToken;
