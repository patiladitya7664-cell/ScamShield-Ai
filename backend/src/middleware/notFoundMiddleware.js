"use strict";

// =====================================================
// SCAMSHIELD AI - NOT FOUND MIDDLEWARE
// Handles undefined API routes
// =====================================================

const notFoundMiddleware = (req, res, next) => {
    const error = new Error(
        `Route not found: ${req.method} ${req.originalUrl}`
    );

    error.statusCode = 404;
    error.status = "fail";

    next(error);
};

module.exports = notFoundMiddleware;