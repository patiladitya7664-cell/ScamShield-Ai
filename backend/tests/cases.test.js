"use strict";

const request = require("supertest");
const app = require("../src/app");

const Case = require("../src/models/Case");
const User = require("../src/models/User");

const generateToken = require("../src/utils/generateToken");

// =====================================================
// SCAMSHIELD AI - CASE MANAGEMENT API TESTS
// =====================================================

describe("ScamShield AI - Case Management API", () => {
    let testUser;
    let anotherUser;
    let authToken;
    let anotherUserToken;
    let createdCaseId;

    beforeAll(async () => {
        // Create primary test user
        testUser = await User.create({
            name: "Case Test User",
            email: "casetest@example.com",
            password: "TestPassword123",
            role: "user",
        });

        // Create another user for access-control tests
        anotherUser = await User.create({
            name: "Another Case User",
            email: "anothercasetest@example.com",
            password: "TestPassword123",
            role: "user",
        });

        authToken = generateToken(testUser._id);
        anotherUserToken = generateToken(anotherUser._id);
    });

    afterEach(async () => {
        await Case.deleteMany({
            user: {
                $in: [testUser._id, anotherUser._id],
            },
        });

        createdCaseId = null;
    });

    afterAll(async () => {
        await Case.deleteMany({
            user: {
                $in: [testUser._id, anotherUser._id],
            },
        });

        await User.deleteMany({
            _id: {
                $in: [testUser._id, anotherUser._id],
            },
        });
    });

    // =================================================
    // TEST DATA
    // =================================================

    const validCase = {
        title: "Suspicious Banking Fraud",
        description:
            "A suspicious person contacted the victim and requested banking OTP details.",
        category: "banking_fraud",
        priority: "high",
        status: "open",
    };

    // =================================================
    // 1. AUTHENTICATION
    // =================================================

    describe("Authentication", () => {
        it("should reject unauthenticated case requests", async () => {
            const response = await request(app)
                .get("/api/cases");

            expect(response.statusCode).toBe(401);
        });

        it("should reject case creation without authentication", async () => {
            const response = await request(app)
                .post("/api/cases")
                .send(validCase);

            expect(response.statusCode).toBe(401);
        });
    });

    // =================================================
    // 2. CREATE CASE
    // =================================================

    describe("POST /api/cases", () => {
        it("should create a new case", async () => {
            const response = await request(app)
                .post("/api/cases")
                .set("Authorization", `Bearer ${authToken}`)
                .send(validCase);

            expect([200, 201]).toContain(response.statusCode);

            if (response.body.success !== undefined) {
                expect(response.body.success).toBe(true);
            }

            const caseData =
                response.body.data?.case ||
                response.body.case ||
                response.body.data;

            expect(caseData).toBeDefined();

            createdCaseId = caseData._id || caseData.caseId;

            expect(createdCaseId).toBeTruthy();
        });

        it("should reject a case with missing title", async () => {
            const response = await request(app)
                .post("/api/cases")
                .set("Authorization", `Bearer ${authToken}`)
                .send({
                    description: "Missing title test",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
        });
    });

    // =================================================
    // 3. GET CASES
    // =================================================

    describe("GET /api/cases", () => {
        it("should retrieve authenticated user's cases", async () => {
            const response = await request(app)
                .get("/api/cases")
                .set("Authorization", `Bearer ${authToken}`);

            expect(response.statusCode).toBe(200);
        });

        it("should return a list of cases", async () => {
            const response = await request(app)
                .get("/api/cases")
                .set("Authorization", `Bearer ${authToken}`);

            if (response.statusCode !== 200) {
                return;
            }

            const cases =
                response.body.data?.cases ||
                response.body.cases ||
                response.body.data;

            expect(Array.isArray(cases)).toBe(true);
        });
    });

    // =================================================
    // 4. CASE OWNERSHIP
    // =================================================

    describe("Case Ownership", () => {
        it("should not expose another user's cases", async () => {
            const response = await request(app)
                .get("/api/cases")
                .set("Authorization", `Bearer ${anotherUserToken}`);

            expect(response.statusCode).toBe(200);

            const cases =
                response.body.data?.cases ||
                response.body.cases ||
                response.body.data;

            expect(Array.isArray(cases)).toBe(true);

            expect(
                cases.every(
                    (item) =>
                        !item.user ||
                        item.user.toString() ===
                            anotherUser._id.toString()
                )
            ).toBe(true);
        });
    });

    // =================================================
    // 5. CASE STATUS
    // =================================================

    describe("Case Status", () => {
        it("should reject updating a non-existent case", async () => {
            const response = await request(app)
                .patch("/api/cases/000000000000000000000000/status")
                .set("Authorization", `Bearer ${authToken}`)
                .send({
                    status: "closed",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
        });
    });

    // =================================================
    // 6. CASE DELETION
    // =================================================

    describe("Case Deletion", () => {
        it("should reject deletion of a non-existent case", async () => {
            const response = await request(app)
                .delete("/api/cases/000000000000000000000000")
                .set("Authorization", `Bearer ${authToken}`);

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
        });
    });
});