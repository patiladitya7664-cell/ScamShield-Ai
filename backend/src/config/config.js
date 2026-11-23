"use strict";

// =====================================================
// SCAMSHIELD AI - APPLICATION CONFIGURATION
// Centralized and validated environment configuration
// =====================================================

const getNumber = (value, fallback, name, min, max) => {
    if (value === undefined || value === "") {
        return fallback;
    }

    const parsed = Number(value);

    if (
        !Number.isFinite(parsed) ||
        parsed < min ||
        parsed > max
    ) {
        throw new Error(
            `Invalid ${name}. Expected a number between ${min} and ${max}.`
        );
    }

    return parsed;
};

const normalizeUrl = (value) => {
    return String(value).trim().replace(/\/+$/, "");
};

const environment = process.env.NODE_ENV || "development";

const frontendUrl =
    process.env.FRONTEND_URL ||
    process.env.CLIENT_URL ||
    "http://localhost:5500";

const config = {
    // -------------------------------------------------
    // APPLICATION
    // -------------------------------------------------

    app: {
        name: "ScamShield AI",
        environment,
        port: getNumber(
            process.env.PORT,
            5000,
            "PORT",
            1,
            65535
        ),
        host: process.env.HOST || "0.0.0.0",
        isDevelopment: environment === "development",
        isProduction: environment === "production",
        isTest: environment === "test",
    },

    // -------------------------------------------------
    // DATABASE
    // -------------------------------------------------

    database: {
        uri:
            process.env.MONGO_URI ||
            "mongodb://127.0.0.1:27017/scamshield_ai",
    },

    // -------------------------------------------------
    // AUTHENTICATION
    // -------------------------------------------------

    auth: {
        jwtSecret: process.env.JWT_SECRET || "",
        jwtExpiresIn: process.env.JWT_EXPIRES_IN || "7d",
        jwtIssuer: "scamshield-ai",
        jwtAudience: "scamshield-ai-users",
    },

    // -------------------------------------------------
    // AI ENGINE
    // -------------------------------------------------

    ai: {
        engineUrl: normalizeUrl(
            process.env.AI_ENGINE_URL ||
            "http://127.0.0.1:8000"
        ),

        timeout: getNumber(
            process.env.AI_ENGINE_TIMEOUT,
            30000,
            "AI_ENGINE_TIMEOUT",
            1000,
            120000
        ),
    },

    // -------------------------------------------------
    // CORS
    // -------------------------------------------------

    cors: {
        origin: frontendUrl
            .split(",")
            .map((origin) => origin.trim())
            .filter(Boolean),
    },

    // -------------------------------------------------
    // SECURITY
    // -------------------------------------------------

    security: {
        bcryptRounds: getNumber(
            process.env.BCRYPT_ROUNDS,
            12,
            "BCRYPT_ROUNDS",
            10,
            14
        ),
    },
};

// -----------------------------------------------------
// IMMUTABLE CONFIGURATION
// -----------------------------------------------------

Object.freeze(config.app);
Object.freeze(config.database);
Object.freeze(config.auth);
Object.freeze(config.ai);
Object.freeze(config.cors.origin);
Object.freeze(config.cors);
Object.freeze(config.security);
Object.freeze(config);

module.exports = config;