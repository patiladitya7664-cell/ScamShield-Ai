"use strict";

// =====================================================
// SCAMSHIELD AI - DATABASE CONFIGURATION
// Version: 3.0.0
//
// Responsibilities:
// 1. Read centralized MongoDB configuration.
// 2. Connect to MongoDB.
// 3. Configure connection pool.
// 4. Handle connection lifecycle events.
// 5. Propagate startup failures to server.js.
// =====================================================

const mongoose = require("mongoose");
const config = require("./config");

// =====================================================
// CONNECTION OPTIONS
// =====================================================

const CONNECTION_OPTIONS = Object.freeze({
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    minPoolSize: 1,
});

// =====================================================
// CONNECTION EVENT HANDLERS
// =====================================================

let listenersRegistered = false;

const registerConnectionListeners = () => {
    if (listenersRegistered) {
        return;
    }

    mongoose.connection.on("connected", () => {
        console.log("[DATABASE] MongoDB connected.");
    });

    mongoose.connection.on("disconnected", () => {
        console.warn("[DATABASE] MongoDB disconnected.");
    });

    mongoose.connection.on("error", (error) => {
        console.error(
            "[DATABASE] MongoDB connection error:",
            error.message
        );
    });

    listenersRegistered = true;
};

// =====================================================
// DATABASE CONNECTION
// =====================================================

const connectDB = async () => {
    const mongoURI = config.database.uri;

    // ---------------------------------------------
    // STEP 1: VALIDATE CONFIGURATION
    // ---------------------------------------------

    if (
        typeof mongoURI !== "string" ||
        !mongoURI.trim()
    ) {
        throw new Error(
            "MongoDB connection URI is missing."
        );
    }

    // ---------------------------------------------
    // STEP 2: PREVENT DUPLICATE CONNECTIONS
    // ---------------------------------------------

    if (mongoose.connection.readyState === 1) {
        return mongoose;
    }

    if (mongoose.connection.readyState === 2) {
        await mongoose.connection.asPromise();
        return mongoose;
    }

    // ---------------------------------------------
    // STEP 3: REGISTER CONNECTION EVENTS
    // ---------------------------------------------

    registerConnectionListeners();

    try {
        // -----------------------------------------
        // STEP 4: CONNECT TO MONGODB
        // -----------------------------------------

        const connection = await mongoose.connect(
            mongoURI,
            CONNECTION_OPTIONS
        );

        // -----------------------------------------
        // STEP 5: CONNECTION INFORMATION
        // -----------------------------------------

        console.log("");
        console.log("====================================");
        console.log("SCAMSHIELD AI - DATABASE READY");
        console.log("====================================");
        console.log(
            `MongoDB Host: ${connection.connection.host}`
        );
        console.log(
            `Database: ${connection.connection.name}`
        );
        console.log(
            `Connection State: ${
                connection.connection.readyState === 1
                    ? "Connected"
                    : "Disconnected"
            }`
        );
        console.log("====================================");
        console.log("");

        return connection;

    } catch (error) {
        console.error(
            "[DATABASE] Initial connection failed:",
            error.message
        );

        // server.js handles application startup failure.
        throw error;
    }
};

// =====================================================
// EXPORT
// =====================================================

module.exports = connectDB;