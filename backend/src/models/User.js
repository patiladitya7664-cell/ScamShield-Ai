"use strict";

const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        // User's full name
        name: {
            type: String,
            required: [true, "Name is required"],
            trim: true,
            minlength: [2, "Name must contain at least 2 characters"],
            maxlength: [60, "Name cannot exceed 60 characters"]
        },

        // Unique account email
        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
            lowercase: true,
            trim: true,
            maxlength: 254,
            match: [
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                "Please enter a valid email address"
            ]
        },

        // Hashed password
        password: {
            type: String,
            required: [true, "Password is required"],
            minlength: 8,
            maxlength: 72,
            select: false
        },

        // Account permissions
        role: {
            type: String,
            enum: ["user", "analyst", "admin"],
            default: "user",
            required: true
        },

        // Account status
        isActive: {
            type: Boolean,
            default: true,
            required: true
        }
    },
    {
        timestamps: true,
        versionKey: false,
        strict: true
    }
);

// Explicit unique email index
userSchema.index(
    { email: 1 },
    { unique: true, name: "unique_user_email" }
);

// Export User model
module.exports = mongoose.model("User", userSchema);