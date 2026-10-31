"use strict";

/**
 * GLOBAL ERROR HANDLER
 * Centralized Express error handling.
 */

const errorMiddleware = (err, req, res, next) => {
  console.error("====================================");
  console.error("SCAMSHIELD AI - API ERROR");
  console.error("====================================");
  console.error("Method:", req.method);
  console.error("URL:", req.originalUrl);
  console.error("Message:", err.message);
  console.error("====================================");

  let statusCode = err.statusCode || err.status || 500;
  let message = err.message || "Internal Server Error";

  // MongoDB duplicate key
  if (err.code === 11000) {
    statusCode = 409;
    message = "A record with this information already exists.";
  }

  // MongoDB validation
  if (err.name === "ValidationError") {
    statusCode = 400;
    message = Object.values(err.errors)
      .map((item) => item.message)
      .join(", ");
  }

  // Invalid MongoDB ObjectId
  if (err.name === "CastError") {
    statusCode = 400;
    message = "Invalid resource identifier.";
  }

  // Invalid JSON
  if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
    statusCode = 400;
    message = "Invalid JSON request body.";
  }

  return res.status(statusCode).json({
    success: false,
    message,
    ...(process.env.NODE_ENV === "development" && {
      stack: err.stack,
    }),
  });
};

module.exports = errorMiddleware;
