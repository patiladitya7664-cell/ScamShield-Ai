"use strict";

// =====================================================
// SCAMSHIELD AI - EXPRESS APPLICATION
// Central application configuration
// =====================================================

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const mongoose = require("mongoose");
const path = require("path");

// =====================================================
// ENVIRONMENT CONFIGURATION
// =====================================================

dotenv.config({
    path: path.resolve(__dirname, "../../.env"),
});

// =====================================================
// ROUTE IMPORTS
// =====================================================

const authRoutes = require("./routes/authRoutes");
const analysisRoutes = require("./routes/analysisRoutes");
const caseRoutes = require("./routes/caseRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const intelligenceRoutes = require("./routes/intelligenceRoutes");
const notificationRoutes = require("./routes/notificationRoutes");
const agentsRoutes = require("./routes/agentsRoutes");

// =====================================================
// MIDDLEWARE IMPORTS
// =====================================================

const errorMiddleware = require("./middleware/errorMiddleware");

// =====================================================
// EXPRESS APPLICATION
// =====================================================

const app = express();

app.disable("x-powered-by");

// =====================================================
// SECURITY MIDDLEWARE
// =====================================================

app.use(helmet());

const allowedOrigins = (
    process.env.FRONTEND_URL || "http://127.0.0.1:5500"
)
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);

app.use(
    cors({
        origin(origin, callback) {
            // Allow requests without Origin (Postman, server-to-server).
            if (!origin || allowedOrigins.includes(origin)) {
                return callback(null, true);
            }

            return callback(
                new Error("CORS policy: Origin not allowed.")
            );
        },
        credentials: true,
    })
);

// =====================================================
// REQUEST LOGGING
// =====================================================

if (process.env.NODE_ENV !== "test") {
    app.use(morgan("dev"));
}

// =====================================================
// BODY PARSING
// =====================================================

app.use(
    express.json({
        limit: "1mb",
    })
);

app.use(
    express.urlencoded({
        extended: true,
        limit: "1mb",
    })
);

// =====================================================
// ROOT ROUTE
// =====================================================

app.get("/", (req, res) => {
    return res.status(200).json({
        success: true,
        message: "Welcome to ScamShield AI API",
        application: "ScamShield AI",
        version: "1.0.0",
    });
});

// =====================================================
// HEALTH CHECK
// =====================================================

app.get("/api/health", (req, res) => {
    const databaseState = mongoose.connection.readyState;

    const databaseStatus = {
        0: "Disconnected",
        1: "Connected",
        2: "Connecting",
        3: "Disconnecting",
    }[databaseState] || "Unknown";

    const isDatabaseConnected = databaseState === 1;

    return res.status(isDatabaseConnected ? 200 : 503).json({
        success: isDatabaseConnected,
        message: "ScamShield AI Backend health check",
        server: "Running",
        database: databaseStatus,
        timestamp: new Date().toISOString(),
    });
});

// =====================================================
// API ROUTES
// =====================================================

const API_PREFIX = "/api";

app.use(`${API_PREFIX}/auth`, authRoutes);

app.use(`${API_PREFIX}/analysis`, analysisRoutes);

app.use(`${API_PREFIX}/cases`, caseRoutes);

app.use(`${API_PREFIX}/dashboard`, dashboardRoutes);

app.use(`${API_PREFIX}/intelligence`, intelligenceRoutes);

app.use(`${API_PREFIX}/notifications`, notificationRoutes);

app.use(`${API_PREFIX}/agents`, agentsRoutes);

// =====================================================
// 404 - ROUTE NOT FOUND
// Must be registered after all API routes.
// =====================================================

app.use((req, res, next) => {
    const error = new Error(
        `Route not found: ${req.method} ${req.originalUrl}`
    );

    error.statusCode = 404;
    error.status = "fail";

    return next(error);
});

// =====================================================
// GLOBAL ERROR HANDLER
// Must be the last middleware.
// =====================================================

app.use(errorMiddleware);

// =====================================================
// EXPORT APPLICATION
// No server starts from this file.
// =====================================================

module.exports = app;