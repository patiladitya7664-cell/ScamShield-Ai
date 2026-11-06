"use strict";

// =====================================================
// SCAMSHIELD AI - ASYNC HANDLER
// Centralized Async Error Handling
// =====================================================

/**
 * Wraps an asynchronous Express controller.
 *
 * Automatically forwards rejected promises
 * to Express error-handling middleware.
 *
 * @param {Function} requestHandler - Express controller
 * @returns {Function} Express middleware
 */

const asyncHandler = (requestHandler) => {
    if (typeof requestHandler !== "function") {
        throw new TypeError(
            "asyncHandler expects a function."
        );
    }

    return (req, res, next) => {
        Promise.resolve(
            requestHandler(req, res, next)
        ).catch(next);
    };
};

// =====================================================
// EXPORT
// =====================================================

module.exports = asyncHandler;