"use strict";

const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const path = require("path");
const mongoose = require("mongoose");

// ================================================
// ENVIRONMENT CONFIGURATION
// ================================================

dotenv.config({
  path: path.resolve(__dirname, "../../.env"),
});

// ================================================
// DATABASE
// ================================================

const connectDB = require("./config/db");

// ================================================
// ROUTES
// ================================================

const authRoutes = require("./routes/authRoutes");
const analysisRoutes = require("./routes/analysisRoutes");
const caseRoutes = require("./routes/caseRoutes");
const dashboardRoutes = require("./routes/dashboardRoutes");
const intelligenceRoutes = require("./routes/intelligenceRoutes");
const notificationRoutes = require("./routes/notificationRoutes");
const agentsRoutes = require("./routes/agentsRoutes");

// ================================================
// ERROR HANDLING
// ================================================

const errorMiddleware = require("./middleware/errorMiddleware");

// ================================================
// EXPRESS APP
// ================================================

const app = express();

app.disable("x-powered-by");

// ================================================
// SECURITY MIDDLEWARE
// ================================================

app.use(helmet());

app.use(
  cors({
    origin: process.env.FRONTEND_URL || "http://127.0.0.1:5500",
    credentials: true,
  }),
);

// ================================================
// REQUEST LOGGING
// ================================================

app.use(morgan("dev"));

// ================================================
// BODY PARSING
// ================================================

app.use(express.json({ limit: "1mb" }));

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb",
  }),
);

// ================================================
// ROOT ROUTE
// ================================================

app.get("/", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Welcome to ScamShield AI API",
  });
});

// ================================================
// HEALTH CHECK
// ================================================

app.get("/api/health", (req, res) => {
  const databaseState = mongoose.connection.readyState;

  const databaseStatus =
    databaseState === 1
      ? "Connected"
      : databaseState === 2
        ? "Connecting"
        : databaseState === 3
          ? "Disconnecting"
          : "Disconnected";

  return res.status(databaseState === 1 ? 200 : 503).json({
    success: databaseState === 1,
    message: "ScamShield AI Backend health check",
    server: "Running",
    database: databaseStatus,
    timestamp: new Date().toISOString(),
  });
});

// ================================================
// API ROUTES
// ================================================

app.use("/api/auth", authRoutes);

app.use("/api/analysis", analysisRoutes);

app.use("/api/cases", caseRoutes);

app.use("/api/dashboard", dashboardRoutes);

app.use("/api/intelligence", intelligenceRoutes);

app.use("/api/notifications", notificationRoutes);

app.use("/api/agents", agentsRoutes);

// ================================================
// 404 HANDLER
// ================================================

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    message: `Route not found: ${req.method} ${req.originalUrl}`,
  });
});

// ================================================
// GLOBAL ERROR HANDLER
// ================================================

app.use(errorMiddleware);

// ================================================
// SERVER CONFIGURATION
// ================================================

const PORT = process.env.PORT || 5000;

// ================================================
// START SERVER
// ================================================

const startServer = async () => {
  try {
    await connectDB();

    const server = app.listen(PORT, () => {
      console.log("");
      console.log("====================================");
      console.log("       SCAMSHIELD AI BACKEND");
      console.log("====================================");

      console.log(`Server:        http://localhost:${PORT}`);
      console.log(`Health:        http://localhost:${PORT}/api/health`);
      console.log(`Auth:          http://localhost:${PORT}/api/auth`);
      console.log(`Analysis:      http://localhost:${PORT}/api/analysis`);
      console.log(`Cases:         http://localhost:${PORT}/api/cases`);
      console.log(`Dashboard:     http://localhost:${PORT}/api/dashboard`);
      console.log(`Intelligence:  http://localhost:${PORT}/api/intelligence`);
      console.log(`Notifications: http://localhost:${PORT}/api/notifications`);
      console.log(`Agents:        http://localhost:${PORT}/api/agents`);

      console.log("====================================");
      console.log("Backend is ready.");
      console.log("");
    });

    server.on("error", (error) => {
      console.error("Server startup error:", error.message);

      if (error.code === "EADDRINUSE") {
        console.error(`Port ${PORT} is already in use.`);
      }

      process.exit(1);
    });

    const shutdown = (signal) => {
      console.log(`\n${signal} received. Closing server...`);

      server.close(async () => {
        try {
          await mongoose.connection.close();
          console.log("Database connection closed.");
          process.exit(0);
        } catch (error) {
          console.error("Shutdown Error:", error.message);
          process.exit(1);
        }
      });
    };

    process.once("SIGINT", () => shutdown("SIGINT"));
    process.once("SIGTERM", () => shutdown("SIGTERM"));
  } catch (error) {
    console.error("====================================");
    console.error("BACKEND STARTUP FAILED");
    console.error("====================================");
    console.error(error.message);

    process.exit(1);
  }
};

startServer();
