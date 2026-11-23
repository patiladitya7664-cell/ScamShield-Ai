
"use strict";

// =====================================================
// SCAMSHIELD AI - INTELLIGENCE API TESTS
//
// Coverage:
// 1. Authentication
// 2. Indicator creation
// 3. Indicator validation
// 4. Indicator retrieval
// 5. Indicator verification
// 6. Duplicate handling
// 7. User ownership and isolation
//
// MongoDB must be connected before running tests.
// =====================================================

const request = require("supertest");
const mongoose = require("mongoose");

const app = require("../src/app");

const User = require("../src/models/User");
const Intelligence = require("../src/models/Intelligence");

const tokenModule = require("../src/utils/generateToken");

const generateToken =
    typeof tokenModule === "function"
        ? tokenModule
        : tokenModule.generateToken;


// =====================================================
// TEST SUITE
// =====================================================

describe("ScamShield AI - Intelligence API", () => {
    let testUser;
    let anotherUser;

    let authToken;
    let anotherUserToken;

    let createdIndicatorId;

    const uniqueId = `${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 8)}`;

    const endpoint = "/api/intelligence";

    const validIndicator = {
        type: "url",
        value: `https://suspicious-${uniqueId}.example.com`,
        source: "test",
        confidence: 85,
        riskLevel: "high",
        description: "Suspicious URL detected during testing."
    };


    // =================================================
    // HELPERS
    // =================================================

    const authenticatedRequest = (token = authToken) => {
        return request(app)
            .get(endpoint)
            .set("Authorization", `Bearer ${token}`);
    };

    const createIndicatorRequest = (
        data = validIndicator,
        token = authToken
    ) => {
        return request(app)
            .post(endpoint)
            .set("Authorization", `Bearer ${token}`)
            .send(data);
    };

    const extractData = (body) => {
        return body?.data?.indicator ||
            body?.indicator ||
            body?.data;
    };

    const extractIndicators = (body) => {
        return body?.data?.indicators ||
            body?.indicators ||
            body?.data;
    };


    // =================================================
    // SETUP
    // =================================================

    beforeAll(async () => {
        if (mongoose.connection.readyState !== 1) {
            throw new Error(
                "MongoDB must be connected before Intelligence API tests."
            );
        }

        if (typeof generateToken !== "function") {
            throw new Error(
                "generateToken utility is not correctly exported."
            );
        }

        testUser = await User.create({
            name: "Intelligence Test User",
            email: `intelligence-${uniqueId}@example.com`,
            password: "TestPassword123",
            role: "user"
        });

        anotherUser = await User.create({
            name: "Another Intelligence User",
            email: `another-intelligence-${uniqueId}@example.com`,
            password: "TestPassword123",
            role: "user"
        });

        authToken = generateToken(testUser._id);

        anotherUserToken = generateToken(
            anotherUser._id
        );
    });


    afterEach(async () => {
        if (testUser && anotherUser) {
            await Intelligence.deleteMany({
                user: {
                    $in: [
                        testUser._id,
                        anotherUser._id
                    ]
                }
            });
        }

        createdIndicatorId = null;
    });


    afterAll(async () => {
        if (testUser && anotherUser) {
            await Intelligence.deleteMany({
                user: {
                    $in: [
                        testUser._id,
                        anotherUser._id
                    ]
                }
            });

            await User.deleteMany({
                _id: {
                    $in: [
                        testUser._id,
                        anotherUser._id
                    ]
                }
            });
        }
    });


    // =================================================
    // 1. AUTHENTICATION
    // =================================================

    describe("Authentication", () => {
        it("should reject indicator retrieval without authentication", async () => {
            const response = await request(app)
                .get(endpoint);

            expect(response.statusCode).toBe(401);
        });

        it("should reject indicator creation without authentication", async () => {
            const response = await request(app)
                .post(endpoint)
                .send(validIndicator);

            expect(response.statusCode).toBe(401);
        });

        it("should reject invalid authentication tokens", async () => {
            const response = await request(app)
                .get(endpoint)
                .set(
                    "Authorization",
                    "Bearer invalid-token"
                );

            expect(response.statusCode).toBe(401);
        });
    });


    // =================================================
    // 2. CREATE INDICATOR
    // =================================================

    describe("POST /api/intelligence", () => {
        it("should create a valid intelligence indicator", async () => {
            const response = await createIndicatorRequest();

            expect([200, 201]).toContain(
                response.statusCode
            );

            expect(response.body.success).toBe(true);

            const indicator = extractData(
                response.body
            );

            expect(indicator).toBeDefined();

            createdIndicatorId =
                indicator._id ||
                indicator.indicatorId;

            expect(
                mongoose.isValidObjectId(
                    createdIndicatorId
                )
            ).toBe(true);

            expect(indicator.type).toBe("url");

            expect(indicator.verified).toBe(false);
        });

        it("should associate the indicator with the authenticated user", async () => {
            const response = await createIndicatorRequest();

            expect([200, 201]).toContain(
                response.statusCode
            );

            const indicator = extractData(
                response.body
            );

            const savedIndicator =
                await Intelligence.findById(
                    indicator._id || indicator.indicatorId
                );

            expect(savedIndicator).not.toBeNull();

            expect(
                savedIndicator.user.toString()
            ).toBe(testUser._id.toString());
        });

        it("should reject an indicator with missing type", async () => {
            const response = await createIndicatorRequest({
                value: "https://example.com",
                source: "test"
            });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });

        it("should reject an indicator with missing value", async () => {
            const response = await createIndicatorRequest({
                type: "url",
                source: "test"
            });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });

        it("should reject an unsupported indicator type", async () => {
            const response = await createIndicatorRequest({
                type: "unknown_type",
                value: "suspicious-value",
                source: "test"
            });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });

        it("should reject an invalid confidence score", async () => {
            const response = await createIndicatorRequest({
                ...validIndicator,
                confidence: 150
            });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });

        it("should not allow clients to mark an indicator as verified", async () => {
            const response = await createIndicatorRequest({
                ...validIndicator,
                verified: true
            });

            if ([200, 201].includes(response.statusCode)) {
                const indicator = extractData(
                    response.body
                );

                expect(indicator.verified).toBe(false);
            } else {
                expect(response.statusCode).toBeGreaterThanOrEqual(400);
            }
        });
    });


    // =================================================
    // 3. GET INDICATORS
    // =================================================

    describe("GET /api/intelligence", () => {
        it("should retrieve authenticated user's indicators", async () => {
            const createResponse =
                await createIndicatorRequest();

            expect([200, 201]).toContain(
                createResponse.statusCode
            );

            const response =
                await authenticatedRequest();

            expect(response.statusCode).toBe(200);

            expect(response.body.success).toBe(true);
        });

        it("should return indicators as an array", async () => {
            const createResponse =
                await createIndicatorRequest();

            expect([200, 201]).toContain(
                createResponse.statusCode
            );

            const response =
                await authenticatedRequest();

            expect(response.statusCode).toBe(200);

            const indicators = extractIndicators(
                response.body
            );

            expect(Array.isArray(indicators)).toBe(true);
        });
    });


    // =================================================
    // 4. INDICATOR OWNERSHIP
    // =================================================

    describe("Indicator Ownership", () => {
        it("should not expose another user's indicators", async () => {
            const createResponse =
                await createIndicatorRequest(
                    validIndicator,
                    anotherUserToken
                );

            expect([200, 201]).toContain(
                createResponse.statusCode
            );

            const response =
                await authenticatedRequest(authToken);

            expect(response.statusCode).toBe(200);

            const indicators = extractIndicators(
                response.body
            );

            expect(Array.isArray(indicators)).toBe(true);

            const foreignIndicator = indicators.find(
                (item) =>
                    item.value === validIndicator.value
            );

            expect(foreignIndicator).toBeUndefined();
        });
    });


    // =================================================
    // 5. INDICATOR VERIFICATION
    // =================================================

    describe("Indicator Verification", () => {
        it("should reject verification of a non-existent indicator", async () => {
            const response = await request(app)
                .patch(
                    `${endpoint}/000000000000000000000000/verify`
                )
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                )
                .send({
                    verified: true
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
        });

        it("should not allow another user to verify an indicator", async () => {
            const createResponse =
                await createIndicatorRequest();

            expect([200, 201]).toContain(
                createResponse.statusCode
            );

            const indicator = extractData(
                createResponse.body
            );

            const indicatorId =
                indicator._id ||
                indicator.indicatorId;

            const response = await request(app)
                .patch(
                    `${endpoint}/${indicatorId}/verify`
                )
                .set(
                    "Authorization",
                    `Bearer ${anotherUserToken}`
                )
                .send({
                    verified: true
                });

            expect([
                403,
                404
            ]).toContain(response.statusCode);

            const unchangedIndicator =
                await Intelligence.findById(
                    indicatorId
                );

            expect(unchangedIndicator).not.toBeNull();

            expect(unchangedIndicator.verified).toBe(false);
        });
    });


    // =================================================
    // 6. DUPLICATE INDICATORS
    // =================================================

    describe("Duplicate Indicators", () => {
        it("should handle duplicate indicators safely", async () => {
            const firstResponse =
                await createIndicatorRequest();

            expect([200, 201]).toContain(
                firstResponse.statusCode
            );

            const secondResponse =
                await createIndicatorRequest();

            expect([
                200,
                201,
                409
            ]).toContain(secondResponse.statusCode);

            const count = await Intelligence.countDocuments({
                user: testUser._id,
                value: validIndicator.value
            });

            expect(count).toBe(1);
        });
    });
});
