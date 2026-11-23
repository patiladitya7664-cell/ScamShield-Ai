
"use strict";

// =====================================================
// SCAMSHIELD AI - ASYNC HANDLER
// Version: 2.0.0
//
// Centralized asynchronous Express error handling.
//
// Responsibilities:
// 1. Validate controller functions.
// 2. Handle synchronous exceptions.
// 3. Handle rejected promises.
// 4. Forward errors to Express error middleware.
//
// Compatible with Express 4 and Express 5.
// =====================================================

/**
 * Wrap an asynchronous Express controller.
 *
 * @param {Function} requestHandler
 * @returns {Function}
 */

const asyncHandler = (requestHandler) => {
    if (typeof requestHandler !== "function") {
        throw new TypeError(
            "asyncHandler expects a function."
        );
    }

    return function wrappedAsyncHandler(req, res, next) {
        try {
            return Promise.resolve(
                requestHandler(req, res, next)
            ).catch(next);
        } catch (error) {
            return next(error);
        }
    };
};


// =====================================================
// EXPORT
// =====================================================

module.exports = asyncHandler;
