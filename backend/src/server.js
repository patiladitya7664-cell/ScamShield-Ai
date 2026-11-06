"use strict";

// =====================================================
// SCAMSHIELD AI
// SERVER ENTRY POINT
//
// Responsibilities:
// 1. Load environment variables.
// 2. Connect MongoDB.
// 3. Start HTTP server.
// 4. Handle server errors.
// 5. Gracefully shut down resources.
//
// Express configuration and API routes are managed
// separately inside app.js.
// =====================================================

const path = require("path");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const http = require("http");

// =====================================================
// 1. ENVIRONMENT CONFIGURATION
// =====================================================

dotenv.config({
path: path.resolve(__dirname, "../../.env"),
});

// =====================================================
// 2. DATABASE CONFIGURATION
// =====================================================

const connectDB = require("./config/db");

// =====================================================
// 3. EXPRESS APPLICATION
// =====================================================

const app = require("./app");

// =====================================================
// 4. SERVER CONFIGURATION
// =====================================================

const PORT = Number(process.env.PORT) || 5000;
const HOST = process.env.HOST || "0.0.0.0";

let server = null;
let isStarting = false;
let isShuttingDown = false;

// =====================================================
// 5. SERVER INFORMATION
// =====================================================

const displayServerInfo = (port) => {
console.log("");
console.log("================================================");
console.log("              SCAMSHIELD AI");
console.log("             BACKEND SERVER");
console.log("================================================");


console.log(`Environment:    ${process.env.NODE_ENV || "development"}`);
console.log(`Server:         http://localhost:${port}`);
console.log(`Health Check:   http://localhost:${port}/api/health`);

console.log("");
console.log("---------------- API MODULES ----------------");

console.log(`Authentication: http://localhost:${port}/api/auth`);
console.log(`Analysis:       http://localhost:${port}/api/analysis`);
console.log(`Cases:          http://localhost:${port}/api/cases`);
console.log(`Dashboard:      http://localhost:${port}/api/dashboard`);
console.log(`Intelligence:   http://localhost:${port}/api/intelligence`);
console.log(`Notifications:  http://localhost:${port}/api/notifications`);
console.log(`Agents:         http://localhost:${port}/api/agents`);

console.log("================================================");
console.log("Backend started successfully.");
console.log("");


};

// =====================================================
// 6. CLOSE DATABASE CONNECTION
// =====================================================

const closeDatabase = async () => {
if (mongoose.connection.readyState !== 0) {
await mongoose.connection.close();
console.log("MongoDB connection closed.");
}
};

// =====================================================
// 7. START HTTP SERVER
// =====================================================

const listen = (port, host) => {
return new Promise((resolve, reject) => {
const httpServer = http.createServer(app);


    const handleError = (error) => {
        httpServer.removeListener("listening", handleListening);
        reject(error);
    };

    const handleListening = () => {
        httpServer.removeListener("error", handleError);
        resolve(httpServer);
    };

    httpServer.once("error", handleError);
    httpServer.once("listening", handleListening);

    httpServer.listen(port, host);
});


};

// =====================================================
// 8. START APPLICATION
// =====================================================

const startServer = async () => {
if (isStarting || server) {
throw new Error("Server is already starting or running.");
}


isStarting = true;

try {
    console.log("");
    console.log("Starting ScamShield AI Backend...");

    // ---------------------------------------------
    // STEP 1: CONNECT DATABASE
    // ---------------------------------------------

    console.log("Connecting to MongoDB...");

    await connectDB();

    if (mongoose.connection.readyState !== 1) {
        throw new Error("MongoDB connection could not be established.");
    }

    console.log("MongoDB connected successfully.");

    // ---------------------------------------------
    // STEP 2: START HTTP SERVER
    // ---------------------------------------------

    console.log("Starting HTTP server...");

    server = await listen(PORT, HOST);

    // ---------------------------------------------
    // STEP 3: DISPLAY SERVER INFORMATION
    // ---------------------------------------------

    const address = server.address();

    const activePort =
        address && typeof address === "object"
            ? address.port
            : PORT;

    displayServerInfo(activePort);

    return server;

} catch (error) {
    console.error("");
    console.error("================================================");
    console.error("           BACKEND STARTUP FAILED");
    console.error("================================================");
    console.error(error.message);
    console.error("================================================");

    // Close partially started HTTP server.
    if (server) {
        await new Promise((resolve) => {
            server.close(() => resolve());
        });

        server = null;
    }

    // Release database connection after startup failure.
    try {
        await closeDatabase();
    } catch (dbError) {
        console.error("Database cleanup failed:", dbError.message);
    }

    throw error;

} finally {
    isStarting = false;
}


};

// =====================================================
// 9. GRACEFUL SHUTDOWN
// =====================================================

const shutdown = async (signal = "SHUTDOWN") => {
if (isShuttingDown) {
return;
}


isShuttingDown = true;

console.log("");
console.log("================================================");
console.log(`${signal} received.`);
console.log("Graceful shutdown initiated...");
console.log("================================================");

let shutdownError = null;

try {
    // ---------------------------------------------
    // STEP 1: STOP ACCEPTING NEW HTTP CONNECTIONS
    // ---------------------------------------------

    if (server && server.listening) {
        await new Promise((resolve, reject) => {
            server.close((error) => {
                if (error) {
                    return reject(error);
                }

                resolve();
            });
        });

        console.log("HTTP server closed.");
    }

    server = null;

    // ---------------------------------------------
    // STEP 2: CLOSE MONGODB CONNECTION
    // ---------------------------------------------

    await closeDatabase();

    console.log("Graceful shutdown completed.");

} catch (error) {
    shutdownError = error;
    console.error("Shutdown error:", error.message);

} finally {
    isShuttingDown = false;
}

if (shutdownError) {
    process.exitCode = 1;
}


};

// =====================================================
// 10. PROCESS SIGNAL HANDLERS
// =====================================================

const registerProcessHandlers = () => {
process.once("SIGINT", () => {
shutdown("SIGINT");
});


process.once("SIGTERM", () => {
    shutdown("SIGTERM");
});


};

// =====================================================
// 11. APPLICATION ENTRY POINT
// =====================================================

// Start the server only when this file is executed
// directly. Importing it in tests will not start it.

if (require.main === module) {
registerProcessHandlers();


startServer().catch(() => {
    process.exitCode = 1;
});


}

// =====================================================
// 12. EXPORTS
// =====================================================

module.exports = {
startServer,
shutdown,
getServer: () => server,
};
