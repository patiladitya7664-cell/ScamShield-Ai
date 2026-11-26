"use strict";

// =====================================================
// SCAMSHIELD AI - USER MODEL
// Version: 2.1.0
// =====================================================

const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const config = require("../config/config");
const { ROLES, ROLE_VALUES } = require("../constants/roles");

// =====================================================
// CONFIGURATION
// =====================================================

const BCRYPT_ROUNDS = Number(
    config?.security?.bcryptRounds ?? 12
);

if (
    !Number.isInteger(BCRYPT_ROUNDS) ||
    BCRYPT_ROUNDS < 10 ||
    BCRYPT_ROUNDS > 15
) {
    throw new Error("Invalid bcrypt configuration.");
}

if (
    !ROLES ||
    !Array.isArray(ROLE_VALUES) ||
    ROLE_VALUES.length === 0
) {
    throw new Error("Invalid user role configuration.");
}

// =====================================================
// USER SCHEMA
// =====================================================

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, "Name is required"],
            trim: true,
            minlength: [2, "Name must contain at least 2 characters"],
            maxlength: [60, "Name cannot exceed 60 characters"],
        },

        email: {
            type: String,
            required: [true, "Email is required"],
            lowercase: true,
            trim: true,
            maxlength: 254,
            match: [
                /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
                "Please enter a valid email address",
            ],
        },

        password: {
            type: String,
            required: [true, "Password is required"],
            minlength: 8,
            maxlength: 72,
            select: false,
        },

        role: {
            type: String,
            enum: ROLE_VALUES,
            default: ROLES.USER,
            required: true,
        },

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
        throw new Error(
            "Password must contain 8–72 UTF-8 bytes."
        );
    }

    this.password = await bcrypt.hash(
        this.password,
        BCRYPT_ROUNDS
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
        id: this._id.toString(),
        name: this.name,
        email: this.email,
        role: this.role,
        isActive: this.isActive,
        createdAt: this.createdAt,
        updatedAt: this.updatedAt,
    };
};

// =====================================================
// EXPORT MODEL
// =====================================================

module.exports =
    mongoose.models.User ||
    mongoose.model("User", userSchema);