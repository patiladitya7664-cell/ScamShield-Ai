"use strict";

// =====================================================
// SCAMSHIELD AI - DATABASE CONFIGURATION
// Version: 2.0.0
//
// Responsibilities:
// 1. Validate MongoDB configuration.
// 2. Connect to MongoDB.
// 3. Configure connection pool.
// 4. Handle connection errors.
// 5. Allow server.js to manage startup failures.
// =====================================================

const mongoose = require("mongoose");

// =====================================================
// DATABASE CONNECTION
// =====================================================

const connectDB = async () => {
    const mongoURI = process.env.MONGODB_URI;

    // ---------------------------------------------
    // STEP 1: VALIDATE ENVIRONMENT VARIABLE
    // ---------------------------------------------

    if (!mongoURI || !mongoURI.trim()) {
        throw new Error(
            "MONGODB_URI is missing from environment configuration."
        );
    }

    try {
        // ---------------------------------------------
        // STEP 2: CONNECT TO MONGODB
        // ---------------------------------------------

        const connection = await mongoose.connect(mongoURI, {
            serverSelectionTimeoutMS: 10000,
            connectTimeoutMS: 10000,
            socketTimeoutMS: 45000,
            maxPoolSize: 10,
            minPoolSize: 1,
        });

        // ---------------------------------------------
        // STEP 3: CONNECTION INFORMATION
        // ---------------------------------------------

        console.log("");
        console.log("====================================");
        console.log("SCAMSHIELD AI - DATABASE CONNECTED");
        console.log("====================================");
        console.log(
            `MongoDB Host: ${connection.connection.host}`
        );
        console.log(
            `Database: ${connection.connection.name}`
        );
        console.log(
            `Connection State: ${connection.connection.readyState === 1 ? "Connected" : "Disconnected"}`
        );
        console.log("====================================");
        console.log("");

        return connection;

    } catch (error) {
        console.error("");
        console.error("====================================");
        console.error("SCAMSHIELD AI - DATABASE CONNECTION FAILED");
        console.error("====================================");
        console.error("Error:", error.message);
        console.error("====================================");

        // Let server.js handle startup failure and cleanup.
        throw error;
    }
};

// =====================================================
// EXPORT
// =====================================================

module.exports = connectDB;