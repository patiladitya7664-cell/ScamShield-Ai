
"use strict";

// =====================================================
// SCAMSHIELD AI - ANALYSIS API INTEGRATION TESTS
//
// Requirements:
// 1. MongoDB must be connected.
// 2. Python AI engine must be running.
// 3. Backend environment must be configured.
// 4. Analysis API must be mounted.
// =====================================================

const request = require("supertest");
const mongoose = require("mongoose");

const app = require("../src/app");

const Analysis = require("../src/models/analysis");
const User = require("../src/models/User");

const generateToken = require("../src/utils/generateToken");


// =====================================================
// TEST SUITE
// =====================================================

describe("ScamShield AI - Analysis API", () => {
    let testUser;
    let authToken;
    let analysisResponse;

    const endpoint = "/api/analysis/analyze";

    const validEvidence = {
        evidenceType: "message",

        evidence:
            "Your bank account will be blocked. Share your OTP immediately to avoid suspension.",
    };


    // =================================================
    // REQUEST HELPER
    // =================================================

    const authenticatedRequest = () => {
        return request(app)
            .post(endpoint)
            .set("Authorization", `Bearer ${authToken}`);
    };


    // =================================================
    // RESPONSE HELPER
    // =================================================

    const getAnalysisData = (response) => {
        const body = response.body;

        const data = body?.data;

        return (
            data?.analysis ||
            data?.result ||
            body?.analysis ||
            data
        );
    };


    // =================================================
    // TEST SETUP
    // =================================================

    beforeAll(async () => {
        if (mongoose.connection.readyState !== 1) {
            throw new Error(
                "MongoDB must be connected before Analysis API tests."
            );
        }

        testUser = await User.create({
            name: "Analysis Test User",

            email: `analysistest-${Date.now()}@example.com`,

            password: "TestPassword123",

            role: "user",
        });

        authToken = generateToken(testUser._id);

        // Execute one real AI integration request.
        // Successful-response tests reuse this result.

        analysisResponse = await authenticatedRequest()
            .send(validEvidence);
    });


    // =================================================
    // TEST CLEANUP
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

        // MongoDB connection is managed by the Jest
        // test environment, not this test file.
    });


    // =================================================
    // 1. AUTHENTICATION
    // =================================================

    describe("Authentication", () => {
        it("should reject unauthenticated analysis requests", async () => {
            const response = await request(app)
                .post(endpoint)
                .send(validEvidence);

            expect(response.statusCode).toBe(401);
        });


        it("should reject invalid authentication tokens", async () => {
            const response = await request(app)
                .post(endpoint)
                .set(
                    "Authorization",
                    "Bearer invalid-token"
                )
                .send(validEvidence);

            expect(response.statusCode).toBe(401);
        });
    });


    // =================================================
    // 2. EVIDENCE VALIDATION
    // =================================================

    describe("Evidence Validation", () => {
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
                    evidenceType: "invalid_type",
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


        it("should reject unsupported evidence formats", async () => {
            const response = await authenticatedRequest()
                .send({
                    evidenceType: "phone",
                    evidence: "9876543210",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });
    });


    // =================================================
    // 3. ANALYSIS EXECUTION
    // =================================================

    describe("Analysis Execution", () => {
        it("should successfully analyze valid evidence", () => {
            expect(analysisResponse.statusCode).toBe(200);

            expect(analysisResponse.body.success).toBe(true);
        });


        it("should return a valid analysis object", () => {
            const analysis = getAnalysisData(
                analysisResponse
            );

            expect(analysis).toBeDefined();

            expect(analysis).toBeInstanceOf(Object);
        });


        it("should return a valid risk score", () => {
            const analysis = getAnalysisData(
                analysisResponse
            );

            expect(typeof analysis.riskScore).toBe("number");

            expect(analysis.riskScore).toBeGreaterThanOrEqual(0);

            expect(analysis.riskScore).toBeLessThanOrEqual(100);
        });


        it("should return a valid risk level", () => {
            const analysis = getAnalysisData(
                analysisResponse
            );

            expect([
                "low",
                "medium",
                "high",
                "critical",
            ]).toContain(analysis.riskLevel);
        });


        it("should return a valid fraud module classification", () => {
            const analysis = getAnalysisData(
                analysisResponse
            );

            const validModules = [
                "investment",
                "digitalArrest",
                "creditCard",
                "sextortion",
                "ecommerce",
                "other",
                "unclassified",
            ];

            expect(validModules).toContain(
                analysis.fraudCategory
            );
        });


        it("should return indicators as an array", () => {
            const analysis = getAnalysisData(
                analysisResponse
            );

            expect(
                Array.isArray(analysis.indicators)
            ).toBe(true);
        });


        it("should return detected rules as an array", () => {
            const analysis = getAnalysisData(
                analysisResponse
            );

            expect(
                Array.isArray(analysis.detectedRules)
            ).toBe(true);
        });
    });


    // =================================================
    // 4. CATEGORY VALIDATION
    // =================================================

    describe("Detection Category", () => {
        it("should return a canonical detection category when classified", () => {
            const analysis = getAnalysisData(
                analysisResponse
            );

            const validCategories = [
                "fraud_message",
                "fraud_call",
                "url_phishing",
                "email_scam",
                "investment_scam",
                "digital_arrest",
                "upi_banking_fraud",
                "card_fraud",
                "ecommerce_scam",
                "job_loan_scam",
                "sextortion_blackmail",
                "social_media_scam",
            ];

            if (analysis.detectionCategory === null) {
                expect(analysis.fraudCategory).toBe(
                    "unclassified"
                );

                return;
            }

            expect(validCategories).toContain(
                analysis.detectionCategory
            );
        });
    });


    // =================================================
    // 5. DATABASE PERSISTENCE
    // =================================================

    describe("Analysis Persistence", () => {
        it("should save analysis in MongoDB", async () => {
            const responseData =
                analysisResponse.body.data;

            const analysisId =
                responseData?.analysisId ||
                responseData?.analysis?._id ||
                responseData?._id;

            expect(analysisId).toBeTruthy();

            const savedAnalysis = await Analysis.findOne({
                _id: analysisId,
                user: testUser._id,
            });

            expect(savedAnalysis).not.toBeNull();
        });


        it("should associate the analysis with the authenticated user", async () => {
            const responseData =
                analysisResponse.body.data;

            const analysisId =
                responseData?.analysisId ||
                responseData?.analysis?._id ||
                responseData?._id;

            const savedAnalysis = await Analysis.findById(
                analysisId
            );

            expect(savedAnalysis).not.toBeNull();

            expect(
                savedAnalysis.user.toString()
            ).toBe(
                testUser._id.toString()
            );
        });


        it("should persist the completed analysis lifecycle status", async () => {
            const responseData =
                analysisResponse.body.data;

            const analysisId =
                responseData?.analysisId ||
                responseData?.analysis?._id ||
                responseData?._id;

            const savedAnalysis = await Analysis.findById(
                analysisId
            );

            expect(savedAnalysis.status).toBe("completed");
        });


        it("should not persist raw evidence in the Analysis document", async () => {
            const responseData =
                analysisResponse.body.data;

            const analysisId =
                responseData?.analysisId ||
                responseData?.analysis?._id ||
                responseData?._id;

            const savedAnalysis = await Analysis.findById(
                analysisId
            );

            expect(savedAnalysis).not.toBeNull();

            const storedDocument =
                savedAnalysis.toObject();

            expect(storedDocument).not.toHaveProperty(
                "evidence"
            );

            expect(storedDocument).not.toHaveProperty(
                "rawEvidence"
            );
        });
    });


    // =================================================
    // 6. RESPONSE STRUCTURE
    // =================================================

    describe("Response Structure", () => {
        it("should return a successful response message", () => {
            expect(
                typeof analysisResponse.body.message
            ).toBe("string");

            expect(
                analysisResponse.body.message.length
            ).toBeGreaterThan(0);
        });


        it("should return an analysis identifier", () => {
            const responseData =
                analysisResponse.body.data;

            const analysisId =
                responseData?.analysisId ||
                responseData?.analysis?._id ||
                responseData?._id;

            expect(analysisId).toBeTruthy();

            expect(
                mongoose.isValidObjectId(analysisId)
            ).toBe(true);
        });


        it("should return a disclaimer", () => {
            const responseData =
                analysisResponse.body.data;

            const disclaimer =
                responseData?.disclaimer ||
                responseData?.analysis?.disclaimer;

            expect(typeof disclaimer).toBe("string");

            expect(disclaimer.trim().length).toBeGreaterThan(0);
        });


        it("should not expose raw evidence in the API response", () => {
            const serializedResponse = JSON.stringify(
                analysisResponse.body
            );

            expect(serializedResponse).not.toContain(
                validEvidence.evidence
            );
        });
    });
});
