const express = require("express");

const router = express.Router();

const {
  getReports,
  getReportStats,
  getReportById,
  exportReports,
} = require("../controllers/reportController");

const { protect } = require("../middleware/authMiddleware");

// All Reports APIs require authentication.
router.use(protect);

// Specific routes first.
router.get("/stats", getReportStats);
router.get("/export", exportReports);

// Reports listing and individual details.
router.get("/", getReports);
router.get("/:id", getReportById);

module.exports = router;