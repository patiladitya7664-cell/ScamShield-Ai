"use strict";

// =====================================================
// SCAMSHIELD AI - EXPRESS APPLICATION
// Version: 2.0.0
//
// Responsibilities:
// 1. Configure Express.
// 2. Load environment variables.
// 3. Configure security middleware.
// 4. Configure CORS.
// 5. Parse incoming requests.
// 6. Register API routes.
// 7. Provide health endpoints.
// 8. Handle 404 and application errors.
//
// IMPORTANT:
// This file configures the application only.
// Server startup belongs in server.js.
// =====================================================

// =====================================================
// 1. IMPORT DEPENDENCIES
// =====================================================

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const mongoose = require("mongoose");
const path = require("path");

// =====================================================
// 2. LOAD ENVIRONMENT VARIABLES
// =====================================================

dotenv.config({
  path: path.resolve(__dirname, "../../.env"),
});

// =====================================================
// 3. ROUTE IMPORTS
// =====================================================

const authRoutes = require("./routes/authRoutes");
const analysisRoutes = require("./routes/analysisRoutes");
const caseRoutes = require("./routes/caseRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const intelligenceRoutes = require("./routes/intelligenceRoutes");
const notificationRoutes = require("./routes/notificationRoutes");

// Verify that this filename matches the actual file.
const agentsRoutes = require("./routes/agentsRoutes");

// =====================================================
// 4. ERROR MIDDLEWARE
// =====================================================

const errorMiddleware = require("./middleware/errorMiddleware");

// =====================================================
// 5. EXPRESS APPLICATION
// =====================================================

const app = express();

app.disable("x-powered-by");

// =====================================================
// 6. SECURITY MIDDLEWARE
// =====================================================

app.use(helmet());

// =====================================================
// 7. CORS CONFIGURATION
// =====================================================

const allowedOrigins = (process.env.FRONTEND_URL || "http://127.0.0.1:5500")
  .split(",")
  .map((origin) => origin.trim().replace(/\/+$/, ""))
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, true);
      }

      const normalizedOrigin = origin.trim().replace(/\/+$/, "");

      if (allowedOrigins.includes(normalizedOrigin)) {
        return callback(null, true);
      }

      const error = new Error("CORS policy: Origin not allowed.");

      error.statusCode = 403;
      error.code = "CORS_ORIGIN_DENIED";

      return callback(error);
    },

    credentials: true,

    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],

    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "Accept",
      "Cache-Control",
      "Pragma",
    ],

    optionsSuccessStatus: 204,
  }),
);

// =====================================================
// 8. REQUEST LOGGING
// =====================================================

if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

// =====================================================
// 9. BODY PARSING
// =====================================================

app.use(
  express.json({
    limit: "1mb",
    strict: true,
  }),
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb",
    parameterLimit: 100,
  }),
);

// =====================================================
// 10. ROOT ROUTE
// =====================================================

app.get("/", (req, res) => {
  return res.status(200).json({
    success: true,

    status: "success",

    message: "Welcome to ScamShield AI API",

    application: "ScamShield AI",

    version: "2.0.0",
  });
});

// =====================================================
// 11. HEALTH CHECK
// =====================================================

app.get("/api/health", (req, res) => {
  const databaseState = mongoose.connection.readyState;

  const databaseStatus =
    {
      0: "Disconnected",
      1: "Connected",
      2: "Connecting",
      3: "Disconnecting",
    }[databaseState] || "Unknown";

  const isDatabaseConnected = databaseState === 1;

  const isHealthy = isDatabaseConnected;

  return res.status(isHealthy ? 200 : 503).json({
    success: isHealthy,

    status: isHealthy ? "healthy" : "degraded",

    message: "ScamShield AI Backend health check",

    server: "Running",

    database: databaseStatus,

    timestamp: new Date().toISOString(),
  });
});

// =====================================================
// 12. API ROUTES
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
// 13. API ROUTE NOT FOUND
// =====================================================

app.use((req, res, next) => {
  const error = new Error(`Route not found: ${req.method} ${req.path}`);

  error.statusCode = 404;

  error.status = "fail";

  next(error);
});

// =====================================================
// 14. GLOBAL ERROR HANDLER
// Must remain the final middleware.
// =====================================================

app.use(errorMiddleware);

// =====================================================
// 15. EXPORT APPLICATION
// =====================================================

// Do not start the HTTP server here.
// server.js handles database connection and startup.

module.exports = app;
