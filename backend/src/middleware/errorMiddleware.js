"use strict";

// =====================================================
// SCAMSHIELD AI - GLOBAL ERROR HANDLER
// Version: 2.0.0
//
// Handles:
// 1. Application errors
// 2. MongoDB errors
// 3. Mongoose validation errors
// 4. JWT authentication errors
// 5. Invalid JSON
// 6. Unexpected server errors
// =====================================================

const errorMiddleware = (err, req, res, next) => {
    console.error("====================================");
    console.error("SCAMSHIELD AI - API ERROR");
    console.error("====================================");
    console.error("Method:", req.method);
    console.error("URL:", req.originalUrl);
    console.error("Error:", err.message);
    console.error("====================================");

    let statusCode = Number(err.statusCode || err.status || 500);

    // Prevent invalid HTTP status codes.
    if (
        !Number.isInteger(statusCode) ||
        statusCode < 400 ||
        statusCode > 599
    ) {
        statusCode = 500;
    }

    let message =
        statusCode >= 500
            ? "Internal Server Error."
            : err.message || "Request failed.";

    // =================================================
    // MONGODB DUPLICATE KEY
    // =================================================

    if (err.code === 11000) {
        statusCode = 409;
        message = "A record with this information already exists.";
    }

    // =================================================
    // MONGOOSE VALIDATION
    // =================================================

    if (err.name === "ValidationError") {
        statusCode = 400;

        message = Object.values(err.errors || {})
            .map((item) => item.message)
            .join(", ") || "Invalid data provided.";
    }

    // =================================================
    // INVALID MONGODB OBJECT ID
    // =================================================

    if (err.name === "CastError") {
        statusCode = 400;
        message = "Invalid resource identifier.";
    }

    // =================================================
    // JWT ERRORS
    // =================================================

    if (err.name === "JsonWebTokenError") {
        statusCode = 401;
        message = "Invalid authentication token.";
    }

    if (err.name === "TokenExpiredError") {
        statusCode = 401;
        message = "Authentication token has expired.";
    }

    // =================================================
    // INVALID JSON BODY
    // =================================================

    if (
        err instanceof SyntaxError &&
        err.status === 400 &&
        "body" in err
    ) {
        statusCode = 400;
        message = "Invalid JSON request body.";
    }

    // =================================================
    // REQUEST ENTITY TOO LARGE
    // =================================================

    if (
        err.type === "entity.too.large" ||
        err.status === 413
    ) {
        statusCode = 413;
        message = "Request payload is too large.";
    }

    // =================================================
    // CORS ERROR
    // =================================================

    if (
        typeof err.message === "string" &&
        err.message.startsWith("CORS policy:")
    ) {
        statusCode = 403;
        message = "Request origin is not allowed.";
    }

    // =================================================
    // RESPONSE
    // =================================================

    const response = {
        success: false,
        message,
    };

    if (process.env.NODE_ENV === "development") {
        response.error = err.name || "Error";
        response.stack = err.stack;
    }

    return res.status(statusCode).json(response);
};

module.exports = errorMiddleware;