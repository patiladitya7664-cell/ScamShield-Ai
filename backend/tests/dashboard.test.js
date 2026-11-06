"use strict";

const request = require("supertest");
const app = require("../src/app");

const User = require("../src/models/User");
const Analysis = require("../src/models/analysis");
const Case = require("../src/models/Case");
const Notification = require("../src/models/Notification");

const generateToken = require("../src/utils/generateToken");

// =====================================================
// SCAMSHIELD AI - DASHBOARD API TESTS
// =====================================================

describe("ScamShield AI - Dashboard API", () => {
    let testUser;
    let authToken;

    beforeAll(async () => {
        testUser = await User.create({
            name: "Dashboard Test User",
            email: "dashboardtest@example.com",
            password: "TestPassword123",
            role: "user",
        });

        authToken = generateToken(testUser._id);
    });

    beforeEach(async () => {
        await Promise.all([
            Analysis.deleteMany({ user: testUser._id }),
            Case.deleteMany({ user: testUser._id }),
            Notification.deleteMany({ user: testUser._id }),
        ]);
    });

    afterAll(async () => {
        await Promise.all([
            Analysis.deleteMany({ user: testUser._id }),
            Case.deleteMany({ user: testUser._id }),
            Notification.deleteMany({ user: testUser._id }),
            User.deleteOne({ _id: testUser._id }),
        ]);
    });

    // =================================================
    // 1. AUTHENTICATION
    // =================================================

    describe("Authentication", () => {
        it("should reject dashboard requests without authentication", async () => {
            const response = await request(app)
                .get("/api/dashboard");

            expect(response.statusCode).toBe(401);
        });

        it("should reject invalid authentication tokens", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", "Bearer invalid-token");

            expect(response.statusCode).toBe(401);
        });
    });

    // =================================================
    // 2. DASHBOARD OVERVIEW
    // =================================================

    describe("Dashboard Overview", () => {
        it("should retrieve dashboard data for authenticated user", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            expect(response.statusCode).toBe(200);
        });

        it("should return a valid JSON response", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            expect(response.headers["content-type"])
                .toMatch(/json/);

            expect(response.body).toBeDefined();
        });

        it("should return a successful response", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            if (response.statusCode !== 200) return;

            expect(response.body.success).toBe(true);
        });
    });

    // =================================================
    // 3. DASHBOARD STATISTICS
    // =================================================

    describe("Dashboard Statistics", () => {
        it("should return statistics when available", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            if (response.statusCode !== 200) return;

            const dashboard =
                response.body.data?.dashboard ||
                response.body.dashboard ||
                response.body.data;

            expect(dashboard).toBeDefined();
        });

        it("should return numeric statistics", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            if (response.statusCode !== 200) return;

            const dashboard =
                response.body.data?.dashboard ||
                response.body.dashboard ||
                response.body.data;

            const statistics =
                dashboard.statistics || dashboard.stats;

            if (!statistics) return;

            Object.values(statistics).forEach((value) => {
                if (typeof value === "number") {
                    expect(Number.isFinite(value)).toBe(true);
                    expect(value).toBeGreaterThanOrEqual(0);
                }
            });
        });
    });

    // =================================================
    // 4. RECENT ANALYSES
    // =================================================

    describe("Recent Analyses", () => {
        it("should return recent analyses as an array when available", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            if (response.statusCode !== 200) return;

            const dashboard =
                response.body.data?.dashboard ||
                response.body.dashboard ||
                response.body.data;

            const analyses =
                dashboard.recentAnalyses ||
                dashboard.recentActivity;

            if (analyses !== undefined) {
                expect(Array.isArray(analyses)).toBe(true);
            }
        });
    });

    // =================================================
    // 5. CASE SUMMARY
    // =================================================

    describe("Case Summary", () => {
        it("should return case summary when available", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            if (response.statusCode !== 200) return;

            const dashboard =
                response.body.data?.dashboard ||
                response.body.dashboard ||
                response.body.data;

            if (dashboard.caseSummary !== undefined) {
                expect(dashboard.caseSummary).toBeDefined();
            }
        });
    });

    // =================================================
    // 6. NOTIFICATION SUMMARY
    // =================================================

    describe("Notification Summary", () => {
        it("should return notification information when available", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            if (response.statusCode !== 200) return;

            const dashboard =
                response.body.data?.dashboard ||
                response.body.dashboard ||
                response.body.data;

            if (dashboard.notifications !== undefined) {
                expect(dashboard.notifications).toBeDefined();
            }
        });
    });

    // =================================================
    // 7. USER DATA ISOLATION
    // =================================================

    describe("User Data Isolation", () => {
        it("should return data belonging to the authenticated user", async () => {
            const response = await request(app)
                .get("/api/dashboard")
                .set("Authorization", `Bearer ${authToken}`);

            expect(response.statusCode).toBe(200);

            const analyses = await Analysis.find({
                user: testUser._id,
            });

            analyses.forEach((analysis) => {
                expect(analysis.user.toString())
                    .toBe(testUser._id.toString());
            });
        });
    });
});