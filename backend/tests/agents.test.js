
"use strict";

const request = require("supertest");
const mongoose = require("mongoose");

const app = require("../src/app");

const Analysis = require("../src/models/analysis");
const User = require("../src/models/User");

const { generateToken } = require("../src/utils/generateToken");

// =====================================================
// SCAMSHIELD AI - AGENTS API INTEGRATION TESTS
//
// Requirements:
// 1. MongoDB must be connected.
// 2. Python AI engine must be running.
// 3. Backend environment must be configured.
// 4. Test user must be isolated.
// =====================================================

describe("ScamShield AI - Agents API", () => {
    let testUser;
    let authToken;
    let analysisResponse;

    const validEvidence = {
        evidenceType: "message",

        evidence:
            "Your bank account will be blocked. Share your OTP immediately to avoid suspension.",
    };

    const endpoint = "/api/agents/run";

    const authenticatedRequest = () => {
        return request(app)
            .post(endpoint)
            .set("Authorization", `Bearer ${authToken}`);
    };

    // =================================================
    // 1. TEST SETUP
    // =================================================

    beforeAll(async () => {
        if (mongoose.connection.readyState !== 1) {
            throw new Error(
                "MongoDB must be connected before running Agents API tests."
            );
        }

        testUser = await User.create({
            name: "Agent Test User",
            email: `agenttest-${Date.now()}@example.com`,
            password: "TestPassword123",
            role: "user",
        });

        authToken = generateToken(testUser._id);

        // Execute the real AI integration request once.
        // All successful-response tests reuse this result.

        analysisResponse = await authenticatedRequest()
            .send(validEvidence);
    });

    // =================================================
    // 2. TEST CLEANUP
    // =================================================

    afterAll(async () => {
        if (testUser) {
            await Analysis.deleteMany({
                user: testUser._id,
            });

            await User.deleteOne({
                _id: testUser._id,
            });
        }

        // Do not close the shared MongoDB connection here.
        // The Jest test environment owns its lifecycle.
    });

    // =================================================
    // 3. AUTHENTICATION
    // =================================================

    describe("Authentication", () => {
        it("should reject requests without authentication", async () => {
            const response = await request(app)
                .post(endpoint)
                .send(validEvidence);

            expect(response.statusCode).toBe(401);
        });

        it("should reject invalid authentication tokens", async () => {
            const response = await request(app)
                .post(endpoint)
                .set("Authorization", "Bearer invalid-token")
                .send(validEvidence);

            expect(response.statusCode).toBe(401);
        });
    });

    // =================================================
    // 4. REQUEST VALIDATION
    // =================================================

    describe("Request Validation", () => {
        it("should reject missing evidence", async () => {
            const response = await authenticatedRequest()
                .send({
                    evidenceType: "message",
                    evidence: "",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
        });

        it("should reject unsupported evidence types", async () => {
            const response = await authenticatedRequest()
                .send({
                    evidenceType: "unsupported_type",
                    evidence: "Suspicious message",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
        });

        it("should reject evidence exceeding the allowed length", async () => {
            const response = await authenticatedRequest()
                .send({
                    evidenceType: "message",
                    evidence: "A".repeat(20001),
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
        });
    });

    // =================================================
    // 5. AI ENGINE INTEGRATION
    // =================================================

    describe("AI Engine Integration", () => {
        it("should successfully analyze valid evidence", () => {
            expect(analysisResponse.statusCode).toBe(201);

            expect(analysisResponse.body.success).toBe(true);
        });

        it("should return the unified analysis response", () => {
            const data = analysisResponse.body.data;

            expect(data).toBeDefined();

            expect(data.analysisId).toBeTruthy();

            expect(data.evidenceId).toBeTruthy();

            expect(data.analysis).toBeDefined();
        });

        it("should return a valid risk score", () => {
            const analysis = analysisResponse.body.data.analysis;

            expect(typeof analysis.riskScore).toBe("number");

            expect(analysis.riskScore).toBeGreaterThanOrEqual(0);

            expect(analysis.riskScore).toBeLessThanOrEqual(100);
        });

        it("should return a valid risk level", () => {
            const analysis = analysisResponse.body.data.analysis;

            const validRiskLevels = [
                "low",
                "medium",
                "high",
                "critical",
            ];

            expect(validRiskLevels).toContain(
                analysis.riskLevel
            );
        });
    });

    // =================================================
    // 6. FOUR AGENT RESULTS
    // =================================================

    describe("Agent Execution", () => {
        it("should return all four agent results", () => {
            const agents = analysisResponse.body.data.agents;

            expect(agents).toBeDefined();

            expect(agents).toHaveProperty("guardian");

            expect(agents).toHaveProperty("intelligence");

            expect(agents).toHaveProperty("victimSafety");

            expect(agents).toHaveProperty("decoy");
        });

        it("should return Guardian Agent results", () => {
            const guardian =
                analysisResponse.body.data.agents.guardian;

            expect(guardian.agent).toBe("Guardian Agent");

            expect(guardian).toHaveProperty("status");

            expect(guardian).toHaveProperty("riskScore");

            expect(typeof guardian.riskScore).toBe("number");
        });

        it("should return Intelligence Agent results", () => {
            const intelligence =
                analysisResponse.body.data.agents.intelligence;

            expect(intelligence.agent).toBe("Intelligence Agent");

            expect(intelligence).toHaveProperty("status");

            expect(intelligence.indicators).toBeInstanceOf(Array);

            // Intelligence indicators must not be treated
            // as independently verified threats.

            intelligence.indicators.forEach((indicator) => {
                expect(indicator.verified).toBe(false);
            });
        });

        it("should return Victim Safety recommendations", () => {
            const victimSafety =
                analysisResponse.body.data.agents.victimSafety;

            expect(victimSafety.agent).toBe(
                "Victim Safety Agent"
            );

            expect(victimSafety).toHaveProperty("status");

            expect(
                victimSafety.recommendations
            ).toBeInstanceOf(Array);

            expect(
                victimSafety.recommendations.length
            ).toBeGreaterThan(0);
        });

        it("should not automatically start the Decoy Agent", () => {
            const decoy =
                analysisResponse.body.data.agents.decoy;

            expect(decoy.agent).toBe("Decoy Agent");

            expect([
                "not_started",
                "not_configured",
            ]).toContain(decoy.status);

            expect(decoy.simulationEnabled).toBe(false);
        });
    });

    // =================================================
    // 7. DATABASE PERSISTENCE
    // =================================================

    describe("Analysis Persistence", () => {
        it("should save the analysis in MongoDB", async () => {
            const savedAnalysis = await Analysis.findOne({
                user: testUser._id,
                evidenceId:
                    analysisResponse.body.data.evidenceId,
            });

            expect(savedAnalysis).not.toBeNull();
        });

        it("should save analysis with completed lifecycle status", async () => {
            const savedAnalysis = await Analysis.findOne({
                user: testUser._id,
                evidenceId:
                    analysisResponse.body.data.evidenceId,
            });

            expect(savedAnalysis.status).toBe("completed");
        });

        it("should persist agent results", async () => {
            const savedAnalysis = await Analysis.findOne({
                user: testUser._id,
                evidenceId:
                    analysisResponse.body.data.evidenceId,
            });

            expect(savedAnalysis.agents).toBeDefined();

            expect(savedAnalysis.agents.guardian).toBeDefined();

            expect(savedAnalysis.agents.intelligence).toBeDefined();

            expect(savedAnalysis.agents.victimSafety).toBeDefined();

            expect(savedAnalysis.agents.decoy).toBeDefined();
        });
    });

    // =================================================
    // 8. RESPONSE VALIDATION
    // =================================================

    describe("Response Validation", () => {
        it("should return a valid analysis ID", () => {
            const analysisId =
                analysisResponse.body.data.analysisId;

            expect(analysisId).toBeTruthy();

            expect(
                mongoose.isValidObjectId(analysisId)
            ).toBe(true);
        });

        it("should return an analysis disclaimer", () => {
            const disclaimer =
                analysisResponse.body.data.disclaimer;

            expect(typeof disclaimer).toBe("string");

            expect(disclaimer.trim().length).toBeGreaterThan(0);
        });

        it("should not expose raw evidence in the response", () => {
            const serializedResponse = JSON.stringify(
                analysisResponse.body
            );

            expect(serializedResponse).not.toContain(
                validEvidence.evidence
            );
        });
    });
});
