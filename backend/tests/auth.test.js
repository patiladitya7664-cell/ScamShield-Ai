"use strict";

const request = require("supertest");
const app = require("../src/app");

const User = require("../src/models/User");

// =====================================================
// SCAMSHIELD AI - AUTHENTICATION API TESTS
// =====================================================

describe("ScamShield AI - Authentication API", () => {
    const testUser = {
        name: "Auth Test User",
        email: "authtest@example.com",
        password: "TestPassword123",
        role: "user",
    };

    beforeAll(async () => {
        // Remove an old test account, if present.
        await User.deleteOne({
            email: testUser.email,
        });
    });

    afterAll(async () => {
        // Clean up the test account.
        await User.deleteOne({
            email: testUser.email,
        });
    });

    // =================================================
    // 1. USER REGISTRATION
    // =================================================

    describe("POST /api/auth/register", () => {
        it("should register a new user", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send(testUser);

            expect([200, 201]).toContain(response.statusCode);
            expect(response.body.success).toBe(true);
        });

        it("should reject duplicate email registration", async () => {
            const response = await request(app)
                .post("/api/auth/register")
                .send(testUser);

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
                    email: "weakpassword@example.com",
                    password: "123",
                });

            expect(response.statusCode).toBeGreaterThanOrEqual(400);
            expect(response.statusCode).toBeLessThan(500);
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

            // Token may be returned in data or at the root,
            // depending on the actual controller response.
            const token =
                response.body.token ||
                response.body.data?.token;

            expect(token).toBeTruthy();
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
                    email: "unknownuser@example.com",
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
    // 3. TOKEN VALIDATION
    // =================================================

    describe("JWT Authentication", () => {
        it("should reject an invalid JWT token", async () => {
            const response = await request(app)
                .get("/api/auth/me")
                .set("Authorization", "Bearer invalid-token");

            expect(response.statusCode).toBe(401);
        });

        it("should reject requests without a JWT token", async () => {
            const response = await request(app)
                .get("/api/auth/me");

            expect(response.statusCode).toBe(401);
        });
    });
});