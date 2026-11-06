"use strict";

// =====================================================
// SCAMSHIELD AI - API RESPONSE UTILITY
// Standardized API Response Handler
// =====================================================

/**
 * Send a successful API response.
 *
 * @param {Object} res - Express response object
 * @param {String} message - Response message
 * @param {*} data - Response payload
 * @param {Number} statusCode - HTTP status code
 * @param {Object|null} meta - Optional metadata
 */

const successResponse = (
    res,
    message = "Request successful.",
    data = null,
    statusCode = 200,
    meta = null
) => {
    const response = {
        success: true,
        status: "success",
        message,
        data,
    };

    if (meta !== null) {
        response.meta = meta;
    }

    return res.status(statusCode).json(response);
};

/**
 * Send an error API response.
 *
 * @param {Object} res - Express response object
 * @param {String} message - Error message
 * @param {Number} statusCode - HTTP status code
 * @param {*} errors - Optional validation errors
 */

const errorResponse = (
    res,
    message = "Something went wrong.",
    statusCode = 500,
    errors = null
) => {
    const response = {
        success: false,
        status: "error",
        message,
    };

    if (errors !== null) {
        response.errors = errors;
    }

    return res.status(statusCode).json(response);
};

/**
 * Send a paginated API response.
 *
 * @param {Object} res - Express response object
 * @param {String} message - Response message
 * @param {Array} data - Response data
 * @param {Number} page - Current page
 * @param {Number} limit - Items per page
 * @param {Number} total - Total records
 * @param {Number} statusCode - HTTP status code
 */

const paginatedResponse = (
    res,
    message,
    data,
    page,
    limit,
    total,
    statusCode = 200
) => {
    const currentPage = Math.max(1, Number(page) || 1);
    const pageLimit = Math.max(1, Number(limit) || 20);
    const totalRecords = Math.max(0, Number(total) || 0);

    return res.status(statusCode).json({
        success: true,
        status: "success",
        message,
        data,
        pagination: {
            currentPage,
            limit: pageLimit,
            totalRecords,
            totalPages: Math.ceil(totalRecords / pageLimit),
            hasNextPage:
                currentPage < Math.ceil(totalRecords / pageLimit),
            hasPreviousPage: currentPage > 1,
        },
    });
};

/**
 * Send a created resource response.
 */

const createdResponse = (
    res,
    message = "Resource created successfully.",
    data = null
) => {
    return successResponse(
        res,
        message,
        data,
        201
    );
};

/**
 * Send a no-content response.
 */

const noContentResponse = (res) => {
    return res.status(204).send();
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    successResponse,
    errorResponse,
    paginatedResponse,
    createdResponse,
    noContentResponse,
};