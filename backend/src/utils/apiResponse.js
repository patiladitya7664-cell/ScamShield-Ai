
"use strict";

// =====================================================
// SCAMSHIELD AI - API RESPONSE UTILITY
// Version: 2.0.0
//
// Responsibilities:
// 1. Standard success responses.
// 2. Standard error responses.
// 3. Paginated responses.
// 4. Resource creation responses.
// 5. No-content responses.
//
// Standard response format:
//
// SUCCESS:
// {
//   success: true,
//   status: "success",
//   message: "...",
//   data: {},
//   meta: {}
// }
//
// ERROR:
// {
//   success: false,
//   status: "error",
//   message: "...",
//   errors: []
// }
// =====================================================


// =====================================================
// 1. CONSTANTS
// =====================================================

const DEFAULT_SUCCESS_MESSAGE = "Request successful.";

const DEFAULT_ERROR_MESSAGE = "Something went wrong.";

const DEFAULT_PAGE_LIMIT = 20;

const MAX_PAGE_LIMIT = 100;


// =====================================================
// 2. VALIDATION HELPERS
// =====================================================

const normalizeStatusCode = (
    statusCode,
    fallback = 200
) => {
    const code = Number(statusCode);

    if (
        !Number.isInteger(code) ||
        code < 200 ||
        code > 599 ||
        code === 204 ||
        code === 304
    ) {
        return fallback;
    }

    return code;
};


const normalizeMessage = (
    message,
    fallback
) => {
    if (
        typeof message !== "string" ||
        !message.trim()
    ) {
        return fallback;
    }

    return message.trim().slice(0, 500);
};


const normalizePaginationNumber = (
    value,
    fallback,
    maximum = Number.MAX_SAFE_INTEGER
) => {
    const number = Number(value);

    if (
        !Number.isSafeInteger(number) ||
        number < 1
    ) {
        return fallback;
    }

    return Math.min(number, maximum);
};


const normalizeTotal = (value) => {
    const number = Number(value);

    if (
        !Number.isSafeInteger(number) ||
        number < 0
    ) {
        return 0;
    }

    return number;
};


// =====================================================
// 3. SUCCESS RESPONSE
// =====================================================

const successResponse = (
    res,
    message = DEFAULT_SUCCESS_MESSAGE,
    data = null,
    statusCode = 200,
    meta = null
) => {
    const response = {
        success: true,

        status: "success",

        message: normalizeMessage(
            message,
            DEFAULT_SUCCESS_MESSAGE
        ),

        data,
    };

    if (
        meta !== null &&
        meta !== undefined
    ) {
        response.meta = meta;
    }

    return res
        .status(normalizeStatusCode(statusCode))
        .json(response);
};


// =====================================================
// 4. ERROR RESPONSE
// =====================================================

const errorResponse = (
    res,
    message = DEFAULT_ERROR_MESSAGE,
    statusCode = 500,
    errors = null
) => {
    const response = {
        success: false,

        status: "error",

        message: normalizeMessage(
            message,
            DEFAULT_ERROR_MESSAGE
        ),
    };

    if (
        errors !== null &&
        errors !== undefined
    ) {
        response.errors = errors;
    }

    return res
        .status(
            normalizeStatusCode(statusCode, 500)
        )
        .json(response);
};


// =====================================================
// 5. PAGINATED RESPONSE
// =====================================================

const paginatedResponse = (
    res,
    message = DEFAULT_SUCCESS_MESSAGE,
    data = [],
    page = 1,
    limit = DEFAULT_PAGE_LIMIT,
    total = 0,
    statusCode = 200
) => {
    const currentPage = normalizePaginationNumber(
        page,
        1
    );

    const pageLimit = normalizePaginationNumber(
        limit,
        DEFAULT_PAGE_LIMIT,
        MAX_PAGE_LIMIT
    );

    const totalRecords = normalizeTotal(total);

    const totalPages = Math.ceil(
        totalRecords / pageLimit
    );

    const validData = Array.isArray(data)
        ? data
        : [];

    return res
        .status(normalizeStatusCode(statusCode))
        .json({
            success: true,

            status: "success",

            message: normalizeMessage(
                message,
                DEFAULT_SUCCESS_MESSAGE
            ),

            data: validData,

            pagination: {
                currentPage,

                limit: pageLimit,

                totalRecords,

                totalPages,

                hasNextPage:
                    currentPage < totalPages,

                hasPreviousPage:
                    currentPage > 1,
            },
        });
};


// =====================================================
// 6. CREATED RESPONSE
// =====================================================

const createdResponse = (
    res,
    message = "Resource created successfully.",
    data = null,
    meta = null
) => {
    return successResponse(
        res,
        message,
        data,
        201,
        meta
    );
};


// =====================================================
// 7. NO CONTENT RESPONSE
// =====================================================

const noContentResponse = (res) => {
    return res.status(204).end();
};


// =====================================================
// 8. EXPORTS
// =====================================================

module.exports = {
    successResponse,

    errorResponse,

    paginatedResponse,

    createdResponse,

    noContentResponse,
};
