"use strict";

const express = require("express");
const { analyzeIndicator } = require("../controllers/intelligenceController");
const { protect } = require("../middleware/authMiddleware");

const router = express.Router();

router.get("/health", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Intelligence lookup route is available.",
  });
});

router.post("/analyze", protect, analyzeIndicator);

module.exports = router;
