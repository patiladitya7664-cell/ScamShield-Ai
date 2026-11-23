"use strict";

// =====================================================
// SCAMSHIELD AI - USER MODEL
// Version: 2.0.0
//
// Features:
// 1. Secure password hashing.
// 2. Email normalization.
// 3. Centralized role validation.
// 4. Account status management.
// 5. Password comparison.
// 6. Sensitive field protection.
// =====================================================

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const config = require("../config/config");
const { ROLES, ROLE_VALUES } = require("../constants/roles");

// =====================================================
// USER SCHEMA
// =====================================================

const userSchema = new mongoose.Schema(
    {
        // ---------------------------------------------
        // USER NAME
        // ---------------------------------------------

        name: {
            type: String,
            required: [true, "Name is required"],
            trim: true,
            minlength: [2, "Name must contain at least 2 characters"],
            maxlength: [60, "Name cannot exceed 60 characters"],
        },

        // ---------------------------------------------
        // EMAIL
        // ---------------------------------------------

        email: {
            type: String,
            required: [true, "Email is required"],
            unique: true,
            lowercase: true,
            trim: true,
            maxlength: 254,
            match: [
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                "Please enter a valid email address",
            ],
        },

        // ---------------------------------------------
        // PASSWORD
        // ---------------------------------------------

        password: {
            type: String,
            required: [true, "Password is required"],
            minlength: 8,
            maxlength: 72,
            select: false,
        },

        // ---------------------------------------------
        // USER ROLE
        // ---------------------------------------------

        role: {
            type: String,
            enum: ROLE_VALUES,
            default: ROLES.USER,
            required: true,
        },

        // ---------------------------------------------
        // ACCOUNT STATUS
        // ---------------------------------------------

        isActive: {
            type: Boolean,
            default: true,
            required: true,
        },
    },
    {
        timestamps: true,
        versionKey: false,
        strict: true,
    }
);

// =====================================================
// UNIQUE EMAIL INDEX
// =====================================================

userSchema.index(
    { email: 1 },
    {
        unique: true,
        name: "unique_user_email",
    }
);

// =====================================================
// PASSWORD HASHING
// =====================================================

userSchema.pre("save", async function () {
    if (!this.isModified("password")) {
        return;
    }

    if (
        typeof this.password !== "string" ||
        this.password.length < 8 ||
        Buffer.byteLength(this.password, "utf8") > 72
    ) {
        throw new Error("Password must contain 8–72 UTF-8 bytes.");
    }

    const rounds = config.security.bcryptRounds;

    this.password = await bcrypt.hash(
        this.password,
        rounds
    );
});

// =====================================================
// PASSWORD COMPARISON
// =====================================================

userSchema.methods.comparePassword = async function (
    candidatePassword
) {
    if (
        typeof candidatePassword !== "string" ||
        !this.password
    ) {
        return false;
    }

    return bcrypt.compare(
        candidatePassword,
        this.password
    );
};

// =====================================================
// SAFE USER OBJECT
// =====================================================

userSchema.methods.toSafeObject = function () {
    return {
        id: this._id,
        name: this.name,
        email: this.email,
        role: this.role,
        isActive: this.isActive,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt,
    };
};

// =====================================================
// EXPORT
// =====================================================

module.exports = mongoose.model("User", userSchema);