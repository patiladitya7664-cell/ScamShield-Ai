"use strict";

const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const User = require("../models/User");

const protect = async (req, res, next) => {
    try {
        // Validate JWT configuration
        const jwtSecret = process.env.JWT_SECRET;

        if (!jwtSecret) {
            const error = new Error(
                "JWT_SECRET is not configured."
            );

            error.statusCode = 500;

            return next(error);
        }

        // Read Authorization header
        const authorization = req.headers.authorization;

        if (!authorization || typeof authorization !== "string") {
            return res.status(401).json({
                success: false,
                message: "Authentication required. Please login."
            });
        }

        // Extract Bearer token
        const parts = authorization.trim().split(/\s+/);

        if (
            parts.length !== 2 ||
            parts[0].toLowerCase() !== "bearer" ||
            !parts[1]
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication header."
            });
        }

        const token = parts[1];

        // Verify JWT
        let decoded;

        try {
            decoded = jwt.verify(token, jwtSecret, {
                algorithms: ["HS256"]
            });
        } catch (error) {
            if (
                error.name === "JsonWebTokenError" ||
                error.name === "TokenExpiredError" ||
                error.name === "NotBeforeError"
            ) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid or expired authentication token."
                });
            }

            throw error;
        }

        // Validate token payload
        if (
            !decoded ||
            typeof decoded !== "object" ||
            typeof decoded.id !== "string" ||
            !mongoose.isValidObjectId(decoded.id)
        ) {
            return res.status(401).json({
                success: false,
                message: "Invalid authentication token payload."
            });
        }

        // Find authenticated user
        const user = await User.findById(decoded.id)
            .select("-password");

        if (!user || !user.isActive) {
            return res.status(401).json({
                success: false,
                message: "User account not found or inactive."
            });
        }

        // Attach authenticated user
        req.user = user;

        return next();

    } catch (error) {
        console.error(
            "Authentication Middleware Error:",
            error.message
        );

        return next(error);
    }
};

module.exports = {
    protect
};