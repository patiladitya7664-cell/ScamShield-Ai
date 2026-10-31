"use strict";

const express = require("express");

const { runAgents } = require("../controllers/agentsController");

const { protect } = require("../middleware/authMiddleware");

const router = express.Router();

// All agent routes require authentication.
router.use(protect);

// Execute all ScamShield AI agents.
router.post("/run", runAgents);

module.exports = router;
