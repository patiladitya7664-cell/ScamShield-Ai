"use strict";

/*
=========================================================
SCAMSHIELD AI - AUTH CONTROLLER
Version: 3.0.0

Features:
1. Secure user registration.
2. Secure login.
3. Automatic password hashing through User model.
4. Centralized JWT generation.
5. Safe user responses.
6. Account status validation.
7. Role escalation prevention.
8. Authenticated user profile.

SECURITY:
- Password is never returned.
- Password is hashed only by User model.
- Public registration always creates USER role.
- Login uses generic invalid credentials response.
=========================================================
*/

const User = require("../models/User");

const {
    generateToken,
} = require("../utils/generateToken");

// =====================================================
// CONSTANTS
// =====================================================

const MAX_PASSWORD_BYTES = 72;

const EMAIL_PATTERN =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// =====================================================
// SAFE USER RESPONSE
// =====================================================

const formatUser = (user) => ({
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    role: user.role,
    isActive: user.isActive,
    createdAt: user.createdAt,
});

// =====================================================
// REGISTER USER
// POST /api/auth/register
// =====================================================

const registerUser = async (req, res, next) => {
    try {
        const {
            name,
            email,
            password,
        } = req.body || {};

        // ---------------------------------------------
        // INPUT TYPE VALIDATION
        // ---------------------------------------------

        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Please provide valid name, email and password.",
            });
        }

        const cleanName = name.trim();
        const cleanEmail = email.trim().toLowerCase();

        // ---------------------------------------------
        // REQUIRED FIELDS
        // ---------------------------------------------

        if (
            !cleanName ||
            !cleanEmail ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Please provide name, email and password.",
            });
        }

        // ---------------------------------------------
        // NAME VALIDATION
        // ---------------------------------------------

        if (
            cleanName.length < 2 ||
            cleanName.length > 60
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Name must contain between 2 and 60 characters.",
            });
        }

        // ---------------------------------------------
        // EMAIL VALIDATION
        // ---------------------------------------------

        if (
            cleanEmail.length > 254 ||
            !EMAIL_PATTERN.test(cleanEmail)
        ) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email address.",
            });
        }

        // ---------------------------------------------
        // PASSWORD VALIDATION
        // ---------------------------------------------

        const passwordBytes = Buffer.byteLength(
            password,
            "utf8"
        );

        if (
            password.length < 8 ||
            passwordBytes > MAX_PASSWORD_BYTES ||
            !/[A-Z]/.test(password) ||
            !/[a-z]/.test(password) ||
            !/[0-9]/.test(password)
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Password must contain at least 8 characters, one uppercase letter, one lowercase letter and one number. Maximum length is 72 UTF-8 bytes.",
            });
        }

        // ---------------------------------------------
        // CHECK EXISTING USER
        // ---------------------------------------------

        const existingUser = await User.findOne({
            email: cleanEmail,
        }).select("_id");

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message:
                    "An account with this email already exists.",
            });
        }

        // ---------------------------------------------
        // CREATE USER
        // ---------------------------------------------
        // IMPORTANT:
        // Do not hash password here.
        // User.js pre-save middleware handles hashing.
        //
        // Never accept role from public registration.
        // ---------------------------------------------

        const user = await User.create({
            name: cleanName,
            email: cleanEmail,
            password,
            role: "user",
        });

        // ---------------------------------------------
        // RESPONSE
        // ---------------------------------------------

        return res.status(201).json({
            success: true,
            message: "Account created successfully.",
            user: formatUser(user),
        });

    } catch (error) {
        // Handle concurrent duplicate registration.

        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message:
                    "An account with this email already exists.",
            });
        }

        return next(error);
    }
};

// =====================================================
// LOGIN USER
// POST /api/auth/login
// =====================================================

const loginUser = async (req, res, next) => {
    try {
        const {
            email,
            password,
        } = req.body || {};

        // ---------------------------------------------
        // INPUT VALIDATION
        // ---------------------------------------------

        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Please provide email and password.",
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        if (
            cleanEmail.length > 254 ||
            !EMAIL_PATTERN.test(cleanEmail) ||
            Buffer.byteLength(password, "utf8") >
                MAX_PASSWORD_BYTES
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password.",
            });
        }

        // ---------------------------------------------
        // FIND USER
        // ---------------------------------------------
        // Password has select:false in User.js.
        // Explicitly include it for authentication.
        // ---------------------------------------------

        const user = await User.findOne({
            email: cleanEmail,
        }).select("+password");

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password.",
            });
        }

        // ---------------------------------------------
        // ACCOUNT STATUS
        // ---------------------------------------------

        if (!user.isActive) {
            return res.status(403).json({
                success: false,
                message:
                    "Your account is currently inactive.",
            });
        }

        // ---------------------------------------------
        // PASSWORD VERIFICATION
        // ---------------------------------------------
        // Use User model's comparePassword method.
        // ---------------------------------------------

        const isPasswordValid =
            await user.comparePassword(password);

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password.",
            });
        }

        // ---------------------------------------------
        // GENERATE JWT
        // ---------------------------------------------

        const token = generateToken(user._id);

        // ---------------------------------------------
        // RESPONSE
        // ---------------------------------------------

        return res.status(200).json({
            success: true,
            message: "Login successful.",
            token,
            user: formatUser(user),
        });

    } catch (error) {
        return next(error);
    }
};

// =====================================================
// GET LOGGED-IN USER
// GET /api/auth/me
// =====================================================

const getMe = async (req, res, next) => {
    try {
        if (!req.user || !req.user._id) {
            return res.status(401).json({
                success: false,
                message: "Authentication required.",
            });
        }

        return res.status(200).json({
            success: true,
            message:
                "User profile fetched successfully.",
            user: formatUser(req.user),
        });

    } catch (error) {
        return next(error);
    }
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    registerUser,
    loginUser,
    getMe,
};