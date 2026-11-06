"use strict";

// =====================================================
// SCAMSHIELD AI - NOTIFICATION SERVICE
// User Notification Management
// =====================================================

const Notification = require("../models/Notification");

// =====================================================
// 1. CREATE NOTIFICATION
// =====================================================

const createNotification = async (data) => {
    const {
        userId,
        title,
        message,
        type = "system",
        priority = "normal",
        relatedAnalysis = null,
        relatedCase = null,
        metadata = {},
    } = data || {};

    if (!userId || !title || !message) {
        throw new Error(
            "User ID, notification title and message are required."
        );
    }

    return Notification.create({
        user: userId,
        title: title.trim(),
        message: message.trim(),
        type,
        priority,
        relatedAnalysis,
        relatedCase,
        metadata,
        isRead: false,
    });
};

// =====================================================
// 2. CREATE BULK NOTIFICATIONS
// =====================================================

const createBulkNotifications = async (userIds, notificationData) => {
    if (!Array.isArray(userIds) || userIds.length === 0) {
        throw new Error("At least one user ID is required.");
    }

    const {
        title,
        message,
        type = "system",
        priority = "normal",
        metadata = {},
    } = notificationData || {};

    if (!title || !message) {
        throw new Error("Notification title and message are required.");
    }

    const notifications = userIds.map((userId) => ({
        user: userId,
        title: title.trim(),
        message: message.trim(),
        type,
        priority,
        metadata,
        isRead: false,
    }));

    return Notification.insertMany(notifications);
};

// =====================================================
// 3. GET USER NOTIFICATIONS
// =====================================================

const getUserNotifications = async (
    userId,
    options = {}
) => {
    if (!userId) {
        throw new Error("User ID is required.");
    }

    const page = Math.max(1, Number(options.page) || 1);
    const limit = Math.min(
        100,
        Math.max(1, Number(options.limit) || 20)
    );

    const query = {
        user: userId,
    };

    if (typeof options.isRead === "boolean") {
        query.isRead = options.isRead;
    }

    if (options.type) {
        query.type = options.type;
    }

    const [notifications, total] = await Promise.all([
        Notification.find(query)
            .sort({ createdAt: -1 })
            .skip((page - 1) * limit)
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
// 4. GET UNREAD NOTIFICATION COUNT
// =====================================================

const getUnreadCount = async (userId) => {
    if (!userId) {
        throw new Error("User ID is required.");
    }

    return Notification.countDocuments({
        user: userId,
        isRead: false,
    });
};

// =====================================================
// 5. MARK NOTIFICATION AS READ
// =====================================================

const markNotificationAsRead = async (
    notificationId,
    userId
) => {
    if (!notificationId || !userId) {
        throw new Error(
            "Notification ID and user ID are required."
        );
    }

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
        const error = new Error("Notification not found.");
        error.statusCode = 404;
        throw error;
    }

    return notification;
};

// =====================================================
// 6. MARK ALL NOTIFICATIONS AS READ
// =====================================================

const markAllNotificationsAsRead = async (userId) => {
    if (!userId) {
        throw new Error("User ID is required.");
    }

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
        }
    );
};

// =====================================================
// 7. DELETE NOTIFICATION
// =====================================================

const deleteNotification = async (
    notificationId,
    userId
) => {
    if (!notificationId || !userId) {
        throw new Error(
            "Notification ID and user ID are required."
        );
    }

    const notification = await Notification.findOneAndDelete({
        _id: notificationId,
        user: userId,
    });

    if (!notification) {
        const error = new Error("Notification not found.");
        error.statusCode = 404;
        throw error;
    }

    return notification;
};

// =====================================================
// 8. DELETE ALL READ NOTIFICATIONS
// =====================================================

const deleteReadNotifications = async (userId) => {
    if (!userId) {
        throw new Error("User ID is required.");
    }

    return Notification.deleteMany({
        user: userId,
        isRead: true,
    });
};

// =====================================================
// 9. GET NOTIFICATION BY ID
// =====================================================

const getNotificationById = async (
    notificationId,
    userId
) => {
    if (!notificationId || !userId) {
        throw new Error(
            "Notification ID and user ID are required."
        );
    }

    const notification = await Notification.findOne({
        _id: notificationId,
        user: userId,
    });

    if (!notification) {
        const error = new Error("Notification not found.");
        error.statusCode = 404;
        throw error;
    }

    return notification;
};

// =====================================================
// EXPORTS
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