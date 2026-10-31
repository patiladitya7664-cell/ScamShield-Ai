"use strict";

/*
=========================================================
 SCAMSHIELD AI - CASE ROUTES
=========================================================

 POST   /api/cases       Create a case
 GET    /api/cases       Get all user cases
 GET    /api/cases/:id   Get a single case
 PATCH  /api/cases/:id   Update a case
 DELETE /api/cases/:id   Delete a case

 All routes require authentication.

=========================================================
*/

const express = require("express");

const {
  createCase,
  getUserCases,
  getCaseById,
  updateCase,
  deleteCase,
} = require("../controllers/caseController");

const { protect } = require("../middleware/authMiddleware");

const router = express.Router();

// Protect every case endpoint.
router.use(protect);

// Create a new case.
router.post("/", createCase);

// Get all cases belonging to the logged-in user.
router.get("/", getUserCases);

// Get one case by ID.
router.get("/:id", getCaseById);

// Update an existing case.
router.patch("/:id", updateCase);

// Delete an existing case.
router.delete("/:id", deleteCase);

module.exports = router;
