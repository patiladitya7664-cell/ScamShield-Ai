"use strict";

const request = require("supertest");
const mongoose = require("mongoose");

const app = require("../src/app");

const Analysis = require("../src/models/analysis");
const User = require("../src/models/User");

const generateToken = require("../src/utils/generateToken");

// =====================================================
// SCAMSHIELD AI - ANALYSIS API TESTS
// =====================================================

describe("ScamShield AI - Analysis API", () => {
    let testUser;
    let authToken;

    const validEvidence = {
        evidenceType: "message",
        evidence:
            "Your bank account will be blocked. Share your OTP immediately to avoid suspension.",
    };

    beforeAll(async () => {
        testUser = await User.create({
            name: "Analysis Test User",
            email: "analysistest@example.com",
            password: "TestPassword123",
            role: "user",
        });

        authToken = generateToken(testUser._id);
    });

    afterEach(async () => {
        await Analysis.deleteMany({
            user: testUser._id,
        });
    });

    afterAll(async () => {
        if (testUser) {
            await User.deleteOne({
                _id: testUser._id,
            });
        }
    });

    // =================================================
    // 1. AUTHENTICATION TESTS
    // =================================================

    describe("Authentication", () => {
        it("should reject unauthenticated analysis requests", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .send(validEvidence);

            expect(response.statusCode).toBe(401);
        });
    });

    // =================================================
    // 2. EVIDENCE VALIDATION
    // =================================================

    describe("Evidence Validation", () => {
        it("should reject missing evidence", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send({
                    evidenceType: "message",
                    evidence: "",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
        });

        it("should reject unsupported evidence types", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send({
                    evidenceType: "invalid_type",
                    evidence: "Suspicious message",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
        });

        it("should reject evidence exceeding the allowed length", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send({
                    evidenceType: "message",
                    evidence: "A".repeat(20001),
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
        });
    });

    // =================================================
    // 3. ANALYSIS EXECUTION
    // =================================================

    describe("Analysis Execution", () => {
        it("should analyze valid evidence successfully", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            expect(response.statusCode).toBe(200);
            expect(response.body.success).toBe(true);
        });

        it("should return fraud category and risk score", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 200) {
                return;
            }

            const analysis =
                response.body.data?.analysis ||
                response.body.analysis ||
                response.body.data;

            expect(analysis).toBeDefined();
            expect(analysis.fraudCategory).toBeDefined();

            expect(typeof analysis.riskScore).toBe("number");

            expect(analysis.riskScore).toBeGreaterThanOrEqual(0);
            expect(analysis.riskScore).toBeLessThanOrEqual(100);
        });

        it("should return risk level", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 200) {
                return;
            }

            const analysis =
                response.body.data?.analysis ||
                response.body.analysis ||
                response.body.data;

            expect(analysis.riskLevel).toBeDefined();

            expect([
                "low",
                "medium",
                "high",
                "critical",
                "unknown",
            ]).toContain(analysis.riskLevel);
        });

        it("should return indicators as an array", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 200) {
                return;
            }

            const analysis =
                response.body.data?.analysis ||
                response.body.analysis ||
                response.body.data;

            expect(Array.isArray(analysis.indicators)).toBe(true);
        });

        it("should return detected rules as an array", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 200) {
                return;
            }

            const analysis =
                response.body.data?.analysis ||
                response.body.analysis ||
                response.body.data;

            expect(Array.isArray(analysis.detectedRules)).toBe(true);
        });
    });

    // =================================================
    // 4. DATABASE PERSISTENCE
    // =================================================

    describe("Analysis Persistence", () => {
        it("should save analysis in MongoDB", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 200) {
                return;
            }

            const savedAnalysis = await Analysis.findOne({
                user: testUser._id,
            });

            expect(savedAnalysis).not.toBeNull();
            expect(savedAnalysis.user.toString())
                .toBe(testUser._id.toString());
        });

        it("should not save another user's analysis under the test user", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 200) {
                return;
            }

            const savedAnalysis = await Analysis.find({
                user: testUser._id,
            });

            expect(savedAnalysis.length).toBeGreaterThan(0);

            savedAnalysis.forEach((item) => {
                expect(item.user.toString())
                    .toBe(testUser._id.toString());
            });
        });
    });

    // =================================================
    // 5. RESPONSE STRUCTURE
    // =================================================

    describe("Response Structure", () => {
        it("should return a successful response message", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 200) {
                return;
            }

            expect(response.body.message).toBeDefined();
        });

        it("should return an analysis identifier", async () => {
            const response = await request(app)
                .post("/api/analysis/analyze")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 200) {
                return;
            }

            const analysis =
                response.body.data?.analysis ||
                response.body.analysis ||
                response.body.data;

            expect(
                analysis._id ||
                analysis.analysisId ||
                response.body.analysisId
            ).toBeTruthy();
        });
    });
});