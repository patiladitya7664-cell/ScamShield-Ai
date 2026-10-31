"use strict";

/*
=========================================================
 SCAMSHIELD AI - ANALYSIS ROUTES
=========================================================

 POST /api/analysis/analyze
 GET  /api/analysis/health

 All analysis routes require authentication.

=========================================================
*/

const express = require("express");

const {
  analyzeUserEvidence,
} = require("../controllers/analysisController");

const {
  protect,
} = require("../middleware/authMiddleware");

const router = express.Router();

// Check whether analysis routes are available.
router.get("/health", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Analysis routes are available.",
  });
});

// Analyze submitted evidence.
router.post(
  "/analyze",
  protect,
  analyzeUserEvidence
);

module.exports = router;