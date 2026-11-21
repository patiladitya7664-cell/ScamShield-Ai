"use strict";

const User = require("../models/User");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

/* =========================================
   CONSTANTS
========================================= */

const BCRYPT_ROUNDS = 12;
const MAX_PASSWORD_BYTES = 72;

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* =========================================
   TOKEN GENERATOR
========================================= */

const generateToken = (userId) => {
    const jwtSecret = process.env.JWT_SECRET;

    if (!jwtSecret) {
        const error = new Error(
            "JWT_SECRET is missing in environment variables."
        );

        error.statusCode = 500;
        throw error;
    }

    return jwt.sign(
        { id: userId.toString() },
        jwtSecret,
        {
            algorithm: "HS256",
            expiresIn: process.env.JWT_EXPIRES_IN || "7d"
        }
    );
};

/* =========================================
   SAFE USER RESPONSE
========================================= */

const formatUser = (user) => ({
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    role: user.role
});

/* =========================================
   REGISTER USER
   POST /api/auth/register
========================================= */

const registerUser = async (req, res, next) => {
    try {
        const { name, email, password } = req.body || {};

        // Validate input types
        if (
            typeof name !== "string" ||
            typeof email !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                success: false,
                message: "Please provide valid name, email and password."
            });
        }

        const cleanName = name.trim();
        const cleanEmail = email.trim().toLowerCase();

        // Required fields
        if (!cleanName || !cleanEmail || !password) {
            return res.status(400).json({
                success: false,
                message: "Please provide name, email and password."
            });
        }

        // Name validation
        if (cleanName.length < 2 || cleanName.length > 60) {
            return res.status(400).json({
                success: false,
                message: "Name must contain between 2 and 60 characters."
            });
        }

        // Email validation
        if (
            cleanEmail.length > 254 ||
            !EMAIL_PATTERN.test(cleanEmail)
        ) {
            return res.status(400).json({
                success: false,
                message: "Please enter a valid email address."
            });
        }

        // Password validation
        const passwordBytes = Buffer.byteLength(password, "utf8");

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
                    "Password must contain at least 8 characters, one uppercase letter, one lowercase letter and one number. Maximum length is 72 UTF-8 bytes."
            });
        }

        // Check existing account
        const existingUser = await User.findOne({
            email: cleanEmail
        }).select("_id");

        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(
            password,
            BCRYPT_ROUNDS
        );

        // Create account
        const user = await User.create({
            name: cleanName,
            email: cleanEmail,
            password: hashedPassword
        });

        return res.status(201).json({
            success: true,
            message: "Account created successfully.",
            user: formatUser(user)
        });

    } catch (error) {
        if (error.code === 11000) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists."
            });
        }

        return next(error);
    }
};

/* =========================================
   LOGIN USER
   POST /api/auth/login
========================================= */

const loginUser = async (req, res, next) => {
    try {
        const { email, password } = req.body || {};

        // Validate input
        if (
            typeof email !== "string" ||
            typeof password !== "string" ||
            !email.trim() ||
            !password
        ) {
            return res.status(400).json({
                success: false,
                message: "Please provide email and password."
            });
        }

        const cleanEmail = email.trim().toLowerCase();

        if (
            cleanEmail.length > 254 ||
            !EMAIL_PATTERN.test(cleanEmail) ||
            Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        // Find account
        const user = await User.findOne({
            email: cleanEmail
        }).select("+password");

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        // Check account status
        if (!user.isActive) {
            return res.status(403).json({
                success: false,
                message: "Your account is currently inactive."
            });
        }

        // Verify password
        const isPasswordValid = await bcrypt.compare(
            password,
            user.password
        );

        if (!isPasswordValid) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password."
            });
        }

        // Generate authentication token
        const token = generateToken(user._id);

        return res.status(200).json({
            success: true,
            message: "Login successful.",
            token,
            user: formatUser(user)
        });

    } catch (error) {
        return next(error);
    }
};

/* =========================================
   GET LOGGED-IN USER
   GET /api/auth/me
========================================= */

const getMe = async (req, res, next) => {
    try {
        if (!req.user) {
            return res.status(401).json({
                success: false,
                message: "Authentication required."
            });
        }

        return res.status(200).json({
            success: true,
            message: "User profile fetched successfully.",
            user: {
                id: req.user._id.toString(),
                name: req.user.name,
                email: req.user.email,
                role: req.user.role,
                createdAt: req.user.createdAt
            }
        });

    } catch (error) {
        return next(error);
    }
};

/* =========================================
   EXPORT CONTROLLERS
========================================= */

module.exports = {
    registerUser,
    loginUser,
    getMe
};