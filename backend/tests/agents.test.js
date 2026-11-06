"use strict";

const request = require("supertest");
const mongoose = require("mongoose");

const app = require("../src/app");

const Analysis = require("../src/models/analysis");
const User = require("../src/models/User");

const { generateToken } = require("../src/utils/generateToken");

// =====================================================
// SCAMSHIELD AI - AGENTS API TESTS
// =====================================================

describe("ScamShield AI - Agents API", () => {
    let testUser;
    let authToken;

    const validEvidence = {
        evidenceType: "message",
        evidence:
            "Your bank account will be blocked. Share your OTP immediately to avoid suspension.",
    };

    beforeAll(async () => {
        testUser = await User.create({
            name: "Agent Test User",
            email: "agenttest@example.com",
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
    // 1. AUTHENTICATION
    // =================================================

    describe("Authentication", () => {
        it("should reject requests without authentication", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .send(validEvidence);

            expect(response.statusCode).toBe(401);
        });
    });

    // =================================================
    // 2. REQUEST VALIDATION
    // =================================================

    describe("Request Validation", () => {
        it("should reject missing evidence", async () => {
            const response = await request(app)
                .post("/api/agents/run")
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
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send({
                    evidenceType: "unsupported_type",
                    evidence: "Suspicious message",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
        });
    });

    // =================================================
    // 3. AGENT EXECUTION
    // =================================================

    describe("Agent Execution", () => {
        it("should return all four agent results for valid evidence", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            expect(response.statusCode).toBe(201);

            expect(response.body).toHaveProperty("agents");

            expect(response.body.agents).toHaveProperty("guardian");
            expect(response.body.agents).toHaveProperty("intelligence");
            expect(response.body.agents).toHaveProperty("victimSafety");
            expect(response.body.agents).toHaveProperty("decoy");
        });

        it("should return Guardian Agent results", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 201) {
                return;
            }

            expect(response.body.agents.guardian.agent)
                .toBe("Guardian Agent");

            expect(response.body.agents.guardian.status)
                .toBe("completed");

            expect(response.body.agents.guardian)
                .toHaveProperty("riskScore");
        });

        it("should return Intelligence Agent results", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 201) {
                return;
            }

            expect(response.body.agents.intelligence.agent)
                .toBe("Intelligence Agent");

            expect(response.body.agents.intelligence.status)
                .toBe("completed");

            expect(response.body.agents.intelligence)
                .toHaveProperty("indicators");
        });

        it("should return Victim Safety recommendations", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 201) {
                return;
            }

            expect(response.body.agents.victimSafety.agent)
                .toBe("Victim Safety Agent");

            expect(response.body.agents.victimSafety.status)
                .toBe("completed");

            expect(
                response.body.agents.victimSafety.recommendations
            ).toBeInstanceOf(Array);

            expect(
                response.body.agents.victimSafety.recommendations.length
            ).toBeGreaterThan(0);
        });

        it("should keep Decoy Agent disabled when not configured", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 201) {
                return;
            }

            expect(response.body.agents.decoy.agent)
                .toBe("Decoy Agent");

            expect(response.body.agents.decoy.status)
                .toBe("not_configured");

            expect(response.body.agents.decoy.simulationEnabled)
                .toBe(false);
        });
    });

    // =================================================
    // 4. DATABASE PERSISTENCE
    // =================================================

    describe("Analysis Persistence", () => {
        it("should save completed analysis in MongoDB", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 201) {
                return;
            }

            const savedAnalysis = await Analysis.findOne({
                user: testUser._id,
            });

            expect(savedAnalysis).not.toBeNull();

            expect(savedAnalysis.status).toBe("completed");

            expect(savedAnalysis.agents).toBeDefined();
        });
    });

    // =================================================
    // 5. RESPONSE VALIDATION
    // =================================================

    describe("Response Validation", () => {
        it("should return an analysis ID", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 201) {
                return;
            }

            expect(response.body).toHaveProperty("analysisId");
            expect(response.body.analysisId).toBeTruthy();
        });

        it("should return a disclaimer", async () => {
            const response = await request(app)
                .post("/api/agents/run")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validEvidence);

            if (response.statusCode !== 201) {
                return;
            }

            expect(response.body).toHaveProperty("disclaimer");
            expect(typeof response.body.disclaimer).toBe("string");
        });
    });
});