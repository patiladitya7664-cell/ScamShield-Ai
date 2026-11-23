
"use strict";

// =====================================================
// SCAMSHIELD AI
// SERVER ENTRY POINT
//
// Version: 2.0.0
//
// Responsibilities:
// 1. Load environment variables.
// 2. Connect MongoDB.
// 3. Start HTTP server.
// 4. Handle runtime server errors.
// 5. Gracefully shut down resources.
// 6. Prevent duplicate startup/shutdown.
//
// Express configuration and API routes are managed
// separately inside app.js.
// =====================================================


// =====================================================
// 1. IMPORT DEPENDENCIES
// =====================================================

const path = require("path");
const dotenv = require("dotenv");
const mongoose = require("mongoose");
const http = require("http");


// =====================================================
// 2. ENVIRONMENT CONFIGURATION
// =====================================================

dotenv.config({
    path: path.resolve(__dirname, "../../.env"),
});


// =====================================================
// 3. DATABASE CONFIGURATION
// =====================================================

const connectDB = require("./config/db");


// =====================================================
// 4. EXPRESS APPLICATION
// =====================================================

const app = require("./app");


// =====================================================
// 5. SERVER CONFIGURATION
// =====================================================

const rawPort = process.env.PORT || "5000";

const PORT = Number(rawPort);

const HOST = process.env.HOST || "0.0.0.0";

const SHUTDOWN_TIMEOUT = 10000;


// Validate server port.

if (
    !Number.isInteger(PORT) ||
    PORT < 0 ||
    PORT > 65535
) {
    throw new Error(
        "Invalid PORT configuration. Expected an integer between 0 and 65535."
    );
}

if (
    typeof HOST !== "string" ||
    !HOST.trim()
) {
    throw new Error(
        "Invalid HOST configuration."
    );
}


// =====================================================
// 6. SERVER STATE
// =====================================================

let server = null;

let isStarting = false;

let isShuttingDown = false;

let startupPromise = null;

let shutdownPromise = null;


// =====================================================
// 7. SERVER INFORMATION
// =====================================================

const displayServerInfo = (port) => {
    const baseURL = `http://localhost:${port}`;

    console.log("");

    console.log("================================================");

    console.log("              SCAMSHIELD AI");

    console.log("             BACKEND SERVER");

    console.log("================================================");

    console.log(
        `Environment:    ${process.env.NODE_ENV || "development"}`
    );

    console.log(
        `Server:         ${baseURL}`
    );

    console.log(
        `Health Check:   ${baseURL}/api/health`
    );

    console.log("");

    console.log("---------------- API MODULES ----------------");

    console.log(
        `Authentication: ${baseURL}/api/auth`
    );

    console.log(
        `Analysis:       ${baseURL}/api/analysis`
    );

    console.log(
        `Cases:          ${baseURL}/api/cases`
    );

    console.log(
        `Dashboard:      ${baseURL}/api/dashboard`
    );

    console.log(
        `Intelligence:   ${baseURL}/api/intelligence`
    );

    console.log(
        `Notifications:  ${baseURL}/api/notifications`
    );

    console.log(
        `Agents:         ${baseURL}/api/agents`
    );

    console.log("================================================");

    console.log("Backend started successfully.");

    console.log("");
};


// =====================================================
// 8. DATABASE CLEANUP
// =====================================================

const closeDatabase = async () => {
    const state = mongoose.connection.readyState;

    if (state !== 0) {
        await mongoose.connection.close();

        console.log(
            "MongoDB connection closed."
        );
    }
};


// =====================================================
// 9. HTTP SERVER LISTENER
// =====================================================

const listen = (port, host) => {
    return new Promise((resolve, reject) => {
        const httpServer = http.createServer(app);

        const handleError = (error) => {
            httpServer.removeListener(
                "listening",
                handleListening
            );

            reject(error);
        };

        const handleListening = () => {
            httpServer.removeListener(
                "error",
                handleError
            );

            resolve(httpServer);
        };

        httpServer.once(
            "error",
            handleError
        );

        httpServer.once(
            "listening",
            handleListening
        );

        httpServer.listen(port, host);
    });
};


// =====================================================
// 10. RUNTIME SERVER ERROR HANDLER
// =====================================================

const registerServerErrorHandler = (httpServer) => {
    httpServer.on("error", (error) => {
        console.error(
            "HTTP server runtime error:",
            error.message
        );

        // A server that has failed should not continue
        // accepting traffic as if it were healthy.

        if (
            error.code === "EADDRINUSE" ||
            error.code === "EACCES"
        ) {
            console.error(
                "Server cannot continue because of a port or permission error."
            );

            process.exitCode = 1;

            shutdown("SERVER_ERROR").catch(() => {
                process.exitCode = 1;
            });
        }
    });
};


// =====================================================
// 11. START APPLICATION
// =====================================================

const startServer = async () => {
    if (isShuttingDown) {
        throw new Error(
            "Cannot start server during shutdown."
        );
    }

    if (server) {
        return server;
    }

    if (startupPromise) {
        return startupPromise;
    }

    startupPromise = (async () => {
        isStarting = true;

        try {
            console.log("");

            console.log(
                "Starting ScamShield AI Backend..."
            );

            // -----------------------------------------
            // STEP 1: CONNECT DATABASE
            // -----------------------------------------

            console.log(
                "Connecting to MongoDB..."
            );

            await connectDB();

            if (
                mongoose.connection.readyState !== 1
            ) {
                throw new Error(
                    "MongoDB connection could not be established."
                );
            }

            console.log(
                "MongoDB connected successfully."
            );

            // -----------------------------------------
            // STEP 2: CHECK SHUTDOWN STATE
            // -----------------------------------------

            if (isShuttingDown) {
                throw new Error(
                    "Startup cancelled because shutdown was requested."
                );
            }

            // -----------------------------------------
            // STEP 3: START HTTP SERVER
            // -----------------------------------------

            console.log(
                "Starting HTTP server..."
            );

            const httpServer = await listen(
                PORT,
                HOST
            );

            if (isShuttingDown) {
                await new Promise((resolve) => {
                    httpServer.close(resolve);
                });

                throw new Error(
                    "Startup cancelled during shutdown."
                );
            }

            server = httpServer;

            registerServerErrorHandler(server);

            // -----------------------------------------
            // STEP 4: DISPLAY SERVER INFORMATION
            // -----------------------------------------

            const address = server.address();

            const activePort =
                address &&
                typeof address === "object"
                    ? address.port
                    : PORT;

            displayServerInfo(activePort);

            return server;

        } catch (error) {
            console.error("");

            console.error(
                "================================================"
            );

            console.error(
                "           BACKEND STARTUP FAILED"
            );

            console.error(
                "================================================"
            );

            console.error(error.message);

            console.error(
                "================================================"
            );

            // -----------------------------------------
            // CLEANUP PARTIALLY STARTED SERVER
            // -----------------------------------------

            if (server) {
                await new Promise((resolve) => {
                    server.close(() => resolve());
                });

                server = null;
            }

            // -----------------------------------------
            // CLEANUP DATABASE
            // -----------------------------------------

            try {
                await closeDatabase();
            } catch (dbError) {
                console.error(
                    "Database cleanup failed:",
                    dbError.message
                );
            }

            throw error;

        } finally {
            isStarting = false;
            startupPromise = null;
        }
    })();

    return startupPromise;
};


// =====================================================
// 12. CLOSE HTTP SERVER
// =====================================================

const closeHTTPServer = async () => {
    if (!server || !server.listening) {
        server = null;
        return;
    }

    const activeServer = server;

    console.log(
        "Stopping HTTP server..."
    );

    await new Promise((resolve, reject) => {
        let settled = false;

        const finish = (error) => {
            if (settled) {
                return;
            }

            settled = true;

            clearTimeout(timeout);

            if (error) {
                reject(error);
            } else {
                resolve();
            }
        };

        const timeout = setTimeout(() => {
            console.error(
                "HTTP shutdown timeout reached. Closing remaining connections."
            );

            activeServer.closeAllConnections();

        }, SHUTDOWN_TIMEOUT);

        activeServer.close((error) => {
            finish(error);
        });

        // Close idle keep-alive connections immediately.
        if (
            typeof activeServer.closeIdleConnections === "function"
        ) {
            activeServer.closeIdleConnections();
        }
    });

    server = null;

    console.log(
        "HTTP server closed."
    );
};


// =====================================================
// 13. GRACEFUL SHUTDOWN
// =====================================================

const shutdown = async (
    signal = "SHUTDOWN"
) => {
    if (shutdownPromise) {
        return shutdownPromise;
    }

    shutdownPromise = (async () => {
        isShuttingDown = true;

        console.log("");

        console.log(
            "================================================"
        );

        console.log(
            `${signal} received.`
        );

        console.log(
            "Graceful shutdown initiated..."
        );

        console.log(
            "================================================"
        );

        let shutdownError = null;

        try {
            // -----------------------------------------
            // STEP 1: WAIT FOR STARTUP TO FINISH
            // -----------------------------------------

            if (startupPromise) {
                try {
                    await startupPromise;
                } catch {
                    // Startup failure cleanup is handled
                    // by startServer().
                }
            }

            // -----------------------------------------
            // STEP 2: CLOSE HTTP SERVER
            // -----------------------------------------

            await closeHTTPServer();

            // -----------------------------------------
            // STEP 3: CLOSE DATABASE
            // -----------------------------------------

            await closeDatabase();

            console.log("");

            console.log(
                "Graceful shutdown completed."
            );

        } catch (error) {
            shutdownError = error;

            console.error(
                "Shutdown error:",
                error.message
            );

        } finally {
            if (shutdownError) {
                process.exitCode = 1;
            }
        }

        return !shutdownError;
    })();

    return shutdownPromise;
};


// =====================================================
// 14. PROCESS SIGNAL HANDLERS
// =====================================================

const registerProcessHandlers = () => {
    process.once(
        "SIGINT",
        () => {
            shutdown("SIGINT").catch(() => {
                process.exitCode = 1;
            });
        }
    );

    process.once(
        "SIGTERM",
        () => {
            shutdown("SIGTERM").catch(() => {
                process.exitCode = 1;
            });
        }
    );
};


// =====================================================
// 15. APPLICATION ENTRY POINT
// =====================================================

// Start the server only when this file is executed
// directly.
//
// Importing this module in tests must not start
// the HTTP server automatically.

if (require.main === module) {
    registerProcessHandlers();

    startServer().catch(() => {
        process.exitCode = 1;
    });
}


// =====================================================
// 16. EXPORTS
// =====================================================

module.exports = {
    startServer,

    shutdown,

    getServer: () => server,

    isStarting: () => isStarting,

    isShuttingDown: () => isShuttingDown,
};
