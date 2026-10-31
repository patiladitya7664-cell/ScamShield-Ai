"use strict";

const express = require("express");
const { rateLimit } = require("express-rate-limit");

const {
    registerUser,
    loginUser,
    getMe
} = require("../controllers/authController");

const { protect } = require("../middleware/authMiddleware");

const router = express.Router();

const createAuthLimiter = (limit, message) =>
    rateLimit({
        windowMs: 15 * 60 * 1000,
        limit,
        standardHeaders: "draft-7",
        legacyHeaders: false,
        message: {
            success: false,
            message,
        },
    });

const loginLimiter = createAuthLimiter(
    10,
    "Too many login attempts. Please try again in 15 minutes.",
);

const registrationLimiter = createAuthLimiter(
    5,
    "Too many registration attempts. Please try again in 15 minutes.",
);

// Public routes
router.post("/register", registrationLimiter, registerUser);
router.post("/login", loginLimiter, loginUser);

// Protected routes
router.get("/me", protect, getMe);

module.exports = router;
