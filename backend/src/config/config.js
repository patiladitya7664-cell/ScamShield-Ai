"use strict";

// =====================================================
// SCAMSHIELD AI - APPLICATION CONFIGURATION
// Centralized environment configuration
// =====================================================

const config = {
    // -------------------------------------------------
    // APPLICATION
    // -------------------------------------------------
    app: {
        name: "ScamShield AI",
        environment: process.env.NODE_ENV || "development",
        port: Number(process.env.PORT) || 5000,
        isDevelopment: (process.env.NODE_ENV || "development") === "development",
        isProduction: process.env.NODE_ENV === "production",
    },

    // -------------------------------------------------
    // DATABASE
    // -------------------------------------------------
    database: {
        uri: process.env.MONGO_URI || "mongodb://127.0.0.1:27017/scamshield_ai",
    },

    // -------------------------------------------------
    // AUTHENTICATION
    // -------------------------------------------------
    auth: {
        jwtSecret: process.env.JWT_SECRET,
        jwtExpiresIn: process.env.JWT_EXPIRES_IN || "7d",
    },

    // -------------------------------------------------
    // AI ENGINE
    // -------------------------------------------------
    ai: {
        engineUrl: process.env.AI_ENGINE_URL || "http://127.0.0.1:8000",
        timeout: Number(process.env.AI_ENGINE_TIMEOUT) || 30000,
    },

    // -------------------------------------------------
    // CORS
    // -------------------------------------------------
    cors: {
        origin: process.env.CLIENT_URL || "http://localhost:5500",
    },

    // -------------------------------------------------
    // SECURITY
    // -------------------------------------------------
    security: {
        bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || 12,
    },
};

// Prevent accidental configuration modification.
Object.freeze(config);
Object.freeze(config.app);
Object.freeze(config.database);
Object.freeze(config.auth);
Object.freeze(config.ai);
Object.freeze(config.cors);
Object.freeze(config.security);

module.exports = config;