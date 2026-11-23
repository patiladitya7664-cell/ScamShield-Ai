
"use strict";

// =====================================================
// SCAMSHIELD AI - CASE MANAGEMENT API TESTS
//
// Coverage:
// 1. Authentication
// 2. Case creation
// 3. Case retrieval
// 4. User ownership
// 5. Case status updates
// 6. Case deletion
//
// Requirements:
// MongoDB must be connected before running tests.
// =====================================================

const request = require("supertest");
const mongoose = require("mongoose");

const app = require("../src/app");

const Case = require("../src/models/Case");
const User = require("../src/models/User");

const generateToken = require("../src/utils/generateToken");


// =====================================================
// TEST SUITE
// =====================================================

describe("ScamShield AI - Case Management API", () => {
    let testUser;
    let anotherUser;

    let authToken;
    let anotherUserToken;

    let createdCaseId;
    let anotherUsersCaseId;

    const uniqueId = `${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 8)}`;

    const validCase = {
        title: "Suspicious Banking Fraud",

        description:
            "A suspicious person contacted the victim and requested banking OTP details.",

        // Confirm this value against Case.js enum.
        category: "banking_fraud",

        priority: "high",

        status: "open",
    };

    const endpoint = "/api/cases";


    // =================================================
    // REQUEST HELPERS
    // =================================================

    const authenticatedRequest = (token = authToken) => {
        return request(app)
            .get(endpoint)
            .set("Authorization", `Bearer ${token}`);
    };

    const createCaseRequest = (
        data = validCase,
        token = authToken
    ) => {
        return request(app)
            .post(endpoint)
            .set("Authorization", `Bearer ${token}`)
            .send(data);
    };

    const extractCase = (body) => {
        return (
            body?.data?.case ||
            body?.case ||
            body?.data
        );
    };

    const extractCases = (body) => {
        return (
            body?.data?.cases ||
            body?.cases ||
            body?.data
        );
    };


    // =================================================
    // 1. TEST SETUP
    // =================================================

    beforeAll(async () => {
        if (mongoose.connection.readyState !== 1) {
            throw new Error(
                "MongoDB must be connected before Case API tests."
            );
        }

        testUser = await User.create({
            name: "Case Test User",

            email: `casetest-${uniqueId}@example.com`,

            password: "TestPassword123",

            role: "user",
        });

        anotherUser = await User.create({
            name: "Another Case User",

            email: `anothercase-${uniqueId}@example.com`,

            password: "TestPassword123",

            role: "user",
        });

        authToken = generateToken(testUser._id);

        anotherUserToken = generateToken(
            anotherUser._id
        );

        // Create one case for each user through the API.
        // These records are reused by retrieval and
        // ownership tests.

        const primaryResponse = await createCaseRequest();

        expect([200, 201]).toContain(
            primaryResponse.statusCode
        );

        expect(primaryResponse.body.success).toBe(true);

        const primaryCase = extractCase(
            primaryResponse.body
        );

        expect(primaryCase).toBeDefined();

        createdCaseId =
            primaryCase._id ||
            primaryCase.caseId;

        expect(
            mongoose.isValidObjectId(createdCaseId)
        ).toBe(true);


        const secondaryResponse = await createCaseRequest(
            {
                ...validCase,

                title: "Another User's Test Case",
            },
            anotherUserToken
        );

        expect([200, 201]).toContain(
            secondaryResponse.statusCode
        );

        expect(secondaryResponse.body.success).toBe(true);

        const secondaryCase = extractCase(
            secondaryResponse.body
        );

        expect(secondaryCase).toBeDefined();

        anotherUsersCaseId =
            secondaryCase._id ||
            secondaryCase.caseId;

        expect(
            mongoose.isValidObjectId(anotherUsersCaseId)
        ).toBe(true);
    });


    // =================================================
    // 2. TEST CLEANUP
    // =================================================

    afterAll(async () => {
        if (testUser && anotherUser) {
            await Case.deleteMany({
                user: {
                    $in: [
                        testUser._id,
                        anotherUser._id,
                    ],
                },
            });

            await User.deleteMany({
                _id: {
                    $in: [
                        testUser._id,
                        anotherUser._id,
                    ],
                },
            });
        }

        // Shared MongoDB connection is managed by Jest.
    });


    // =================================================
    // 3. AUTHENTICATION
    // =================================================

    describe("Authentication", () => {
        it("should reject unauthenticated case retrieval", async () => {
            const response = await request(app)
                .get(endpoint);

            expect(response.statusCode).toBe(401);
        });


        it("should reject case creation without authentication", async () => {
            const response = await request(app)
                .post(endpoint)
                .send(validCase);

            expect(response.statusCode).toBe(401);
        });
    });


    // =================================================
    // 4. CASE CREATION
    // =================================================

    describe("POST /api/cases", () => {
        it("should create a case for the authenticated user", async () => {
            const response = await createCaseRequest({
                ...validCase,

                title: "Additional Case Creation Test",
            });

            expect([200, 201]).toContain(
                response.statusCode
            );

            expect(response.body.success).toBe(true);

            const caseData = extractCase(
                response.body
            );

            expect(caseData).toBeDefined();

            expect(
                caseData._id || caseData.caseId
            ).toBeTruthy();
        });


        it("should reject a case with a missing title", async () => {
            const response = await createCaseRequest({
                description: "Missing title test",

                category: validCase.category,

                priority: "high",
            });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });


        it("should reject an invalid priority", async () => {
            const response = await createCaseRequest({
                ...validCase,

                title: "Invalid Priority Test",

                priority: "extreme",
            });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });
    });


    // =================================================
    // 5. CASE RETRIEVAL
    // =================================================

    describe("GET /api/cases", () => {
        it("should retrieve the authenticated user's cases", async () => {
            const response = await authenticatedRequest();

            expect(response.statusCode).toBe(200);

            expect(response.body.success).toBe(true);
        });


        it("should return a cases array", async () => {
            const response = await authenticatedRequest();

            expect(response.statusCode).toBe(200);

            const cases = extractCases(
                response.body
            );

            expect(Array.isArray(cases)).toBe(true);
        });


        it("should include the primary user's case", async () => {
            const response = await authenticatedRequest();

            expect(response.statusCode).toBe(200);

            const cases = extractCases(
                response.body
            );

            const matchingCase = cases.find(
                (item) =>
                    String(item._id || item.caseId) ===
                    String(createdCaseId)
            );

            expect(matchingCase).toBeDefined();
        });
    });


    // =================================================
    // 6. CASE OWNERSHIP
    // =================================================

    describe("Case Ownership", () => {
        it("should not expose another user's case in the case list", async () => {
            const response = await authenticatedRequest();

            expect(response.statusCode).toBe(200);

            const cases = extractCases(
                response.body
            );

            const foreignCase = cases.find(
                (item) =>
                    String(item._id || item.caseId) ===
                    String(anotherUsersCaseId)
            );

            expect(foreignCase).toBeUndefined();
        });


        it("should not allow another user to update the primary user's case", async () => {
            const response = await request(app)
                .patch(
                    `${endpoint}/${createdCaseId}/status`
                )
                .set(
                    "Authorization",
                    `Bearer ${anotherUserToken}`
                )
                .send({
                    status: "closed",
                });

            expect([
                403,
                404,
            ]).toContain(response.statusCode);

            const unchangedCase = await Case.findById(
                createdCaseId
            );

            expect(unchangedCase).not.toBeNull();

            expect(unchangedCase.status).toBe("open");
        });


        it("should not allow another user to delete the primary user's case", async () => {
            const response = await request(app)
                .delete(
                    `${endpoint}/${createdCaseId}`
                )
                .set(
                    "Authorization",
                    `Bearer ${anotherUserToken}`
                );

            expect([
                403,
                404,
            ]).toContain(response.statusCode);

            const existingCase = await Case.findById(
                createdCaseId
            );

            expect(existingCase).not.toBeNull();
        });
    });


    // =================================================
    // 7. CASE STATUS
    // =================================================

    describe("Case Status", () => {
        it("should update a case to investigating", async () => {
            const response = await request(app)
                .patch(
                    `${endpoint}/${createdCaseId}/status`
                )
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                )
                .send({
                    status: "investigating",
                });

            expect(response.statusCode).toBe(200);

            expect(response.body.success).toBe(true);

            const updatedCase = await Case.findById(
                createdCaseId
            );

            expect(updatedCase.status).toBe(
                "investigating"
            );
        });


        it("should reject an invalid case status", async () => {
            const response = await request(app)
                .patch(
                    `${endpoint}/${createdCaseId}/status`
                )
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                )
                .send({
                    status: "unknown_status",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });


        it("should reject updating a non-existent case", async () => {
            const response = await request(app)
                .patch(
                    `${endpoint}/000000000000000000000000/status`
                )
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                )
                .send({
                    status: "closed",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
        });
    });


    // =================================================
    // 8. CASE DELETION
    // =================================================

    describe("Case Deletion", () => {
        it("should reject deletion of a non-existent case", async () => {
            const response = await request(app)
                .delete(
                    `${endpoint}/000000000000000000000000`
                )
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                );

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
        });


        it("should delete a case owned by the authenticated user", async () => {
            // Create a dedicated case for deletion.

            const createResponse = await createCaseRequest({
                ...validCase,

                title: "Case Deletion Test",
            });

            expect([200, 201]).toContain(
                createResponse.statusCode
            );

            const caseData = extractCase(
                createResponse.body
            );

            const deletionCaseId =
                caseData._id ||
                caseData.caseId;

            expect(deletionCaseId).toBeTruthy();

            const response = await request(app)
                .delete(
                    `${endpoint}/${deletionCaseId}`
                )
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                );

            expect(response.statusCode).toBe(200);

            const deletedCase = await Case.findById(
                deletionCaseId
            );

            expect(deletedCase).toBeNull();
        });
    });
});
