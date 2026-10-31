"use strict";

const express = require("express");

const {
  getNotifications,
  markAsRead,
  markAllAsRead,
  deleteNotification,
} = require("../controllers/notificationController");

const { protect } = require("../middleware/authMiddleware");

const router = express.Router();

// All notification routes require authentication
router.use(protect);

// Get logged-in user's notifications
router.get("/", getNotifications);

// Mark a notification as read
router.patch("/:id/read", markAsRead);

// Mark all notifications as read
router.patch("/read-all", markAllAsRead);

// Delete a notification
router.delete("/:id", deleteNotification);

module.exports = router;