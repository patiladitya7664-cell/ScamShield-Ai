
"use strict";

// =====================================================
// SCAMSHIELD AI - NOTIFICATION SERVICE
// Version: 2.0.0
//
// Responsibilities:
// 1. Create notifications.
// 2. Create bulk notifications.
// 3. Retrieve user notifications.
// 4. Retrieve unread notification count.
// 5. Mark notifications as read.
// 6. Delete individual notifications.
// 7. Delete read notifications.
// 8. Retrieve notification by ID.
//
// SECURITY:
// - Every read/update/delete operation is scoped to user.
// - No raw evidence or credentials should be stored
//   in notification metadata.
// - Notification delivery is not implied by DB creation.
// =====================================================

const mongoose = require("mongoose");

const Notification = require("../models/Notification");

// =====================================================
// 1. CONSTANTS
// =====================================================

const MAX_TITLE_LENGTH = 150;
const MAX_MESSAGE_LENGTH = 2000;
const MAX_METADATA_SIZE = 10 * 1024;

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;


// =====================================================
// 2. ERROR HELPER
// =====================================================

const createError = (message, statusCode = 400) => {
    const error = new Error(message);
    error.statusCode = statusCode;
    return error;
};


// =====================================================
// 3. VALIDATION HELPERS
// =====================================================

const isPlainObject = (value) => {
    if (
        value === null ||
        typeof value !== "object" ||
        Array.isArray(value)
    ) {
        return false;
    }

    const prototype = Object.getPrototypeOf(value);

    return (
        prototype === Object.prototype ||
        prototype === null
    );
};

const validateObjectId = (value, label) => {
    if (
        !value ||
        !mongoose.Types.ObjectId.isValid(value)
    ) {
        throw createError(`Valid ${label} is required.`);
    }

    return value;
};

const normalizeText = (value, label, maxLength) => {
    if (
        typeof value !== "string" ||
        !value.trim()
    ) {
        throw createError(`${label} is required.`);
    }

    const normalized = value.trim();

    if (normalized.length > maxLength) {
        throw createError(
            `${label} cannot exceed ${maxLength} characters.`
        );
    }

    return normalized;
};

const normalizeMetadata = (metadata = {}) => {
    if (!isPlainObject(metadata)) {
        throw createError(
            "Notification metadata must be an object."
        );
    }

    let serialized;

    try {
        serialized = JSON.stringify(metadata);
    } catch {
        throw createError(
            "Notification metadata is invalid."
        );
    }

    if (
        Buffer.byteLength(serialized || "{}", "utf8") >
        MAX_METADATA_SIZE
    ) {
        throw createError(
            "Notification metadata is too large."
        );
    }

    return metadata;
};

const normalizePagination = (options = {}) => {
    const requestedPage = Number(options.page);
    const requestedLimit = Number(options.limit);

    const page =
        Number.isSafeInteger(requestedPage) &&
        requestedPage > 0
            ? requestedPage
            : DEFAULT_PAGE;

    const limit =
        Number.isSafeInteger(requestedLimit) &&
        requestedLimit > 0
            ? Math.min(requestedLimit, MAX_LIMIT)
            : DEFAULT_LIMIT;

    return {
        page,
        limit,
        skip: (page - 1) * limit,
    };
};

const normalizeOptionalEnum = (
    value,
    label,
    allowedValues
) => {
    if (value === undefined || value === null || value === "") {
        return undefined;
    }

    if (
        typeof value !== "string" ||
        !allowedValues.includes(value)
    ) {
        throw createError(`Invalid ${label}.`);
    }

    return value;
};


// =====================================================
// 4. CREATE NOTIFICATION
// =====================================================

const createNotification = async (data = {}) => {
    if (!isPlainObject(data)) {
        throw createError(
            "Invalid notification data."
        );
    }

    const {
        userId,
        title,
        message,
        type = "system",
        priority = "normal",
        relatedAnalysis = null,
        relatedCase = null,
        metadata = {},
    } = data;

    validateObjectId(userId, "user ID");

    const normalizedTitle = normalizeText(
        title,
        "Notification title",
        MAX_TITLE_LENGTH
    );

    const normalizedMessage = normalizeText(
        message,
        "Notification message",
        MAX_MESSAGE_LENGTH
    );

    if (
        typeof type !== "string" ||
        !type.trim()
    ) {
        throw createError(
            "Valid notification type is required."
        );
    }

    if (
        typeof priority !== "string" ||
        !priority.trim()
    ) {
        throw createError(
            "Valid notification priority is required."
        );
    }

    if (relatedAnalysis !== null) {
        validateObjectId(
            relatedAnalysis,
            "related analysis ID"
        );
    }

    if (relatedCase !== null) {
        validateObjectId(
            relatedCase,
            "related case ID"
        );
    }

    const normalizedMetadata = normalizeMetadata(
        metadata
    );

    return Notification.create({
        user: userId,

        title: normalizedTitle,

        message: normalizedMessage,

        type: type.trim(),

        priority: priority.trim(),

        relatedAnalysis,

        relatedCase,

        metadata: normalizedMetadata,

        isRead: false,
    });
};


// =====================================================
// 5. CREATE BULK NOTIFICATIONS
// =====================================================

const createBulkNotifications = async (
    userIds,
    notificationData = {}
) => {
    if (
        !Array.isArray(userIds) ||
        userIds.length === 0
    ) {
        throw createError(
            "At least one user ID is required."
        );
    }

    if (userIds.length > 500) {
        throw createError(
            "Bulk notification limit exceeded."
        );
    }

    if (!isPlainObject(notificationData)) {
        throw createError(
            "Invalid bulk notification data."
        );
    }

    const {
        title,
        message,
        type = "system",
        priority = "normal",
        metadata = {},
    } = notificationData;

    const normalizedTitle = normalizeText(
        title,
        "Notification title",
        MAX_TITLE_LENGTH
    );

    const normalizedMessage = normalizeText(
        message,
        "Notification message",
        MAX_MESSAGE_LENGTH
    );

    if (
        typeof type !== "string" ||
        !type.trim()
    ) {
        throw createError(
            "Valid notification type is required."
        );
    }

    if (
        typeof priority !== "string" ||
        !priority.trim()
    ) {
        throw createError(
            "Valid notification priority is required."
        );
    }

    const normalizedMetadata = normalizeMetadata(
        metadata
    );

    // Validate and deduplicate user IDs.
    const uniqueUserIds = new Map();

    for (const userId of userIds) {
        validateObjectId(userId, "user ID");

        uniqueUserIds.set(
            String(userId),
            userId
        );
    }

    const notifications = Array.from(
        uniqueUserIds.values()
    ).map((userId) => ({
        user: userId,

        title: normalizedTitle,

        message: normalizedMessage,

        type: type.trim(),

        priority: priority.trim(),

        metadata: normalizedMetadata,

        isRead: false,
    }));

    return Notification.insertMany(
        notifications,
        {
            ordered: true,
        }
    );
};


// =====================================================
// 6. GET USER NOTIFICATIONS
// =====================================================

const getUserNotifications = async (
    userId,
    options = {}
) => {
    validateObjectId(userId, "user ID");

    if (!isPlainObject(options)) {
        throw createError(
            "Invalid notification query options."
        );
    }

    const {
        page,
        limit,
        skip,
    } = normalizePagination(options);

    const query = {
        user: userId,
    };

    if (typeof options.isRead === "boolean") {
        query.isRead = options.isRead;
    }

    // Model enum validation remains the final authority
    // for accepted notification types.
    if (options.type !== undefined) {
        if (
            typeof options.type !== "string" ||
            !options.type.trim()
        ) {
            throw createError(
                "Invalid notification type filter."
            );
        }

        query.type = options.type.trim();
    }

    const [
        notifications,
        total,
    ] = await Promise.all([
        Notification.find(query)
            .sort({
                createdAt: -1,
                _id: -1,
            })
            .skip(skip)
            .limit(limit)
            .lean(),

        Notification.countDocuments(query),
    ]);

    return {
        notifications,

        pagination: {
            total,
            page,
            limit,
            totalPages: Math.ceil(total / limit),
        },
    };
};


// =====================================================
// 7. GET UNREAD NOTIFICATION COUNT
// =====================================================

const getUnreadCount = async (userId) => {
    validateObjectId(userId, "user ID");

    return Notification.countDocuments({
        user: userId,
        isRead: false,
    });
};


// =====================================================
// 8. MARK NOTIFICATION AS READ
// =====================================================

const markNotificationAsRead = async (
    notificationId,
    userId
) => {
    validateObjectId(
        notificationId,
        "notification ID"
    );

    validateObjectId(userId, "user ID");

    const notification = await Notification.findOneAndUpdate(
        {
            _id: notificationId,
            user: userId,
        },
        {
            $set: {
                isRead: true,
                readAt: new Date(),
            },
        },
        {
            new: true,
            runValidators: true,
        }
    );

    if (!notification) {
        throw createError(
            "Notification not found.",
            404
        );
    }

    return notification;
};


// =====================================================
// 9. MARK ALL NOTIFICATIONS AS READ
// =====================================================

const markAllNotificationsAsRead = async (userId) => {
    validateObjectId(userId, "user ID");

    return Notification.updateMany(
        {
            user: userId,
            isRead: false,
        },
        {
            $set: {
                isRead: true,
                readAt: new Date(),
            },
        },
        {
            runValidators: true,
        }
    );
};


// =====================================================
// 10. DELETE NOTIFICATION
// =====================================================

const deleteNotification = async (
    notificationId,
    userId
) => {
    validateObjectId(
        notificationId,
        "notification ID"
    );

    validateObjectId(userId, "user ID");

    const notification = await Notification.findOneAndDelete({
        _id: notificationId,
        user: userId,
    });

    if (!notification) {
        throw createError(
            "Notification not found.",
            404
        );
    }

    return notification;
};


// =====================================================
// 11. DELETE ALL READ NOTIFICATIONS
// =====================================================

const deleteReadNotifications = async (userId) => {
    validateObjectId(userId, "user ID");

    return Notification.deleteMany({
        user: userId,
        isRead: true,
    });
};


// =====================================================
// 12. GET NOTIFICATION BY ID
// =====================================================

const getNotificationById = async (
    notificationId,
    userId
) => {
    validateObjectId(
        notificationId,
        "notification ID"
    );

    validateObjectId(userId, "user ID");

    const notification = await Notification.findOne({
        _id: notificationId,
        user: userId,
    });

    if (!notification) {
        throw createError(
            "Notification not found.",
            404
        );
    }

    return notification;
};


// =====================================================
// 13. EXPORTS
// =====================================================

module.exports = {
    createNotification,
    createBulkNotifications,
    getUserNotifications,
    getUnreadCount,
    markNotificationAsRead,
    markAllNotificationsAsRead,
    deleteNotification,
    deleteReadNotifications,
    getNotificationById,
};
