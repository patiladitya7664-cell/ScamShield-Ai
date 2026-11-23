
"use strict";

// =====================================================
// SCAMSHIELD AI - AUTHENTICATION API TESTS
//
// Coverage:
// 1. User registration
// 2. Duplicate account protection
// 3. Input validation
// 4. Password hashing
// 5. User login
// 6. JWT authentication
// 7. Current user retrieval
// 8. Role privilege protection
// =====================================================

const request = require("supertest");
const mongoose = require("mongoose");

const app = require("../src/app");

const User = require("../src/models/User");


// =====================================================
// TEST SUITE
// =====================================================

describe("ScamShield AI - Authentication API", () => {
    const uniqueId = `${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 8)}`;

    const testUser = {
        name: "Auth Test User",

        email: `authtest-${uniqueId}@example.com`,

        password: "TestPassword123",
    };

    let authToken;
    let registeredUserId;


    // =================================================
    // RESPONSE HELPERS
    // =================================================

    const getResponseData = (body) => {
        return body?.data || body;
    };

    const getToken = (body) => {
        const data = getResponseData(body);

        return (
            body?.token ||
            data?.token ||
            data?.accessToken ||
            null
        );
    };

    const getUser = (body) => {
        const data = getResponseData(body);

        return (
            data?.user ||
            body?.user ||
            null
        );
    };


    // =================================================
    // TEST SETUP
    // =================================================

    beforeAll(async () => {
        if (mongoose.connection.readyState !== 1) {
            throw new Error(
                "MongoDB must be connected before Authentication API tests."
            );
        }

        // Ensure this unique test account does not exist.
        await User.deleteOne({
            email: testUser.email,
        });
    });


    // =================================================
    // TEST CLEANUP
    // =================================================

    afterAll(async () => {
        await User.deleteOne({
            email: testUser.email,
        });

        // Do not close the shared MongoDB connection here.
    });


    // =================================================
    // 1. USER REGISTRATION
    // =================================================

    describe("POST /api/auth/register", () => {
        it("should register a new user", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    ...testUser,
                    role: "user",
                });

            expect([200, 201]).toContain(
                response.statusCode
            );

            expect(response.body.success).toBe(true);

            const createdUser = await User.findOne({
                email: testUser.email,
            }).select("+password");

            expect(createdUser).not.toBeNull();

            registeredUserId = createdUser._id;
        });


        it("should not store the user's password as plaintext", async () => {
            const storedUser = await User.findOne({
                email: testUser.email,
            }).select("+password");

            expect(storedUser).not.toBeNull();

            expect(storedUser.password).not.toBe(
                testUser.password
            );
        });


        it("should reject duplicate email registration", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    ...testUser,
                    role: "user",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });


        it("should reject registration without an email", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Missing Email User",
                    password: "TestPassword123",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });


        it("should reject registration with an invalid email", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Invalid Email User",
                    email: "invalid-email",
                    password: "TestPassword123",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });


        it("should reject a weak password", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Weak Password User",
                    email: `weak-${uniqueId}@example.com`,
                    password: "123",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });


        it("should not allow public registration with admin privileges", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send({
                    name: "Privilege Escalation Test",
                    email: `admin-attempt-${uniqueId}@example.com`,
                    password: "TestPassword123",
                    role: "admin",
                });

            // Registration may reject the request or create
            // an ordinary user. It must never create an admin.

            if ([200, 201].includes(response.statusCode)) {
                const createdUser = await User.findOne({
                    email: `admin-attempt-${uniqueId}@example.com`,
                });

                expect(createdUser).not.toBeNull();

                expect(createdUser.role).toBe("user");

                await User.deleteOne({
                    _id: createdUser._id,
                });
            } else {
                expect(response.statusCode).toBeGreaterThanOrEqual(400);

                expect(response.statusCode).toBeLessThan(500);
            }
        });
    });


    // =================================================
    // 2. USER LOGIN
    // =================================================

    describe("POST /api/auth/login", () => {
        it("should login with valid credentials", async () => {
            const response = await request(app)
                .post("/api/auth/login")
                .send({
                    email: testUser.email,
                    password: testUser.password,
                });

            expect(response.statusCode).toBe(200);

            expect(response.body.success).toBe(true);

            authToken = getToken(response.body);

            expect(typeof authToken).toBe("string");

            expect(authToken.length).toBeGreaterThan(20);
        });


        it("should return the authenticated user", async () => {
            const response = await request(app)
                .post("/api/auth/login")
                .send({
                    email: testUser.email,
                    password: testUser.password,
                });

            expect(response.statusCode).toBe(200);

            const user = getUser(response.body);

            expect(user).toBeDefined();

            expect(user.email).toBe(testUser.email);
        });


        it("should not expose the password in the login response", async () => {
            const response = await request(app)
                .post("/api/auth/login")
                .send({
                    email: testUser.email,
                    password: testUser.password,
                });

            expect(response.statusCode).toBe(200);

            const serializedResponse = JSON.stringify(
                response.body
            );

            expect(serializedResponse).not.toContain(
                testUser.password
            );
        });


        it("should reject an incorrect password", async () => {
            const response = await request(app)
                .post("/api/auth/login")
                .send({
                    email: testUser.email,
                    password: "WrongPassword123",
                });

            expect(response.statusCode).toBe(401);
        });


        it("should reject an unknown email", async () => {
            const response = await request(app)
                .post("/api/auth/login")
                .send({
                    email: `unknown-${uniqueId}@example.com`,
                    password: "TestPassword123",
                });

            expect(response.statusCode).toBe(401);
        });


        it("should reject missing login credentials", async () => {
            const response = await request(app)
                .post("/api/auth/login")
                .send({
                    email: testUser.email,
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);

            expect(response.statusCode).toBeLessThan(500);
        });
    });


    // =================================================
    // 3. JWT AUTHENTICATION
    // =================================================

    describe("JWT Authentication", () => {
        it("should reject an invalid JWT token", async () => {
            const response = await request(app)
                .get("/api/auth/me")
                .set(
                    "Authorization",
                    "Bearer invalid-token"
                );

            expect(response.statusCode).toBe(401);
        });


        it("should reject requests without a JWT token", async () => {
            const response = await request(app)
                .get("/api/auth/me");

            expect(response.statusCode).toBe(401);
        });


        it("should reject an incorrectly formatted authorization header", async () => {
            const response = await request(app)
                .get("/api/auth/me")
                .set(
                    "Authorization",
                    "InvalidFormat"
                );

            expect(response.statusCode).toBe(401);
        });
    });


    // =================================================
    // 4. CURRENT USER
    // =================================================

    describe("GET /api/auth/me", () => {
        it("should return the authenticated user", async () => {
            expect(authToken).toBeTruthy();

            const response = await request(app)
                .get("/api/auth/me")
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                );

            expect(response.statusCode).toBe(200);

            expect(response.body.success).toBe(true);

            const user = getUser(response.body);

            expect(user).toBeDefined();

            expect(user.email).toBe(testUser.email);
        });


        it("should not expose the user's password", async () => {
            const response = await request(app)
                .get("/api/auth/me")
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                );

            expect(response.statusCode).toBe(200);

            const serializedResponse = JSON.stringify(
                response.body
            );

            expect(serializedResponse).not.toContain(
                testUser.password
            );
        });


        it("should return the correct user ID", async () => {
            const response = await request(app)
                .get("/api/auth/me")
                .set(
                    "Authorization",
                    `Bearer ${authToken}`
                );

            expect(response.statusCode).toBe(200);

            const user = getUser(response.body);

            expect(
                user._id || user.id
            ).toBe(registeredUserId.toString());
        });
    });
});
