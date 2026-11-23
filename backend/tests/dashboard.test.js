
"use strict";

// =====================================================
// SCAMSHIELD AI - DASHBOARD API TESTS
//
// Coverage:
// 1. Authentication
// 2. Dashboard overview
// 3. Dashboard statistics
// 4. Recent analyses
// 5. Case summary
// 6. Notification summary
// 7. User data isolation
//
// MongoDB must be connected before running tests.
// =====================================================

const request = require("supertest");
const mongoose = require("mongoose");

const app = require("../src/app");

const User = require("../src/models/User");
const Analysis = require("../src/models/analysis");
const Case = require("../src/models/Case");
const Notification = require("../src/models/Notification");

const tokenModule = require("../src/utils/generateToken");

const generateToken =
    typeof tokenModule === "function"
        ? tokenModule
        : tokenModule.generateToken;


// =====================================================
// TEST SUITE
// =====================================================

describe("ScamShield AI - Dashboard API", () => {
    let testUser;
    let anotherUser;

    let authToken;
    let anotherUserToken;

    const uniqueId = `${Date.now()}-${Math.random()
        .toString(36)
        .slice(2, 8)}`;

    const endpoint = "/api/dashboard";


    // =================================================
    // HELPERS
    // =================================================

    const dashboardRequest = (token = authToken) => {
        return request(app)
            .get(endpoint)
            .set("Authorization", `Bearer ${token}`);
    };


    const extractDashboard = (body) => {
        return (
            body?.data?.dashboard ||
            body?.dashboard ||
            body?.data
        );
    };


    const getDashboardResponse = async (token) => {
        const response = await dashboardRequest(token);

        expect(response.statusCode).toBe(200);

        expect(response.headers["content-type"])
            .toMatch(/json/);

        expect(response.body.success).toBe(true);

        const dashboard = extractDashboard(
            response.body
        );

        expect(dashboard).toBeDefined();

        expect(typeof dashboard).toBe("object");

        expect(Array.isArray(dashboard)).toBe(false);

        return {
            response,
            dashboard,
        };
    };


    // =================================================
    // TEST SETUP
    // =================================================

    beforeAll(async () => {
        if (mongoose.connection.readyState !== 1) {
            throw new Error(
                "MongoDB must be connected before Dashboard API tests."
            );
        }

        if (typeof generateToken !== "function") {
            throw new Error(
                "generateToken utility must export a token generation function."
            );
        }

        testUser = await User.create({
            name: "Dashboard Test User",

            email: `dashboard-${uniqueId}@example.com`,

            password: "TestPassword123",

            role: "user",
        });

        anotherUser = await User.create({
            name: "Another Dashboard User",

            email: `another-dashboard-${uniqueId}@example.com`,

            password: "TestPassword123",

            role: "user",
        });

        authToken = generateToken(testUser._id);

        anotherUserToken = generateToken(
            anotherUser._id
        );
    });


    // =================================================
    // TEST DATA CLEANUP
    // =================================================

    beforeEach(async () => {
        await Promise.all([
            Analysis.deleteMany({
                user: {
                    $in: [
                        testUser._id,
                        anotherUser._id,
                    ],
                },
            }),

            Case.deleteMany({
                user: {
                    $in: [
                        testUser._id,
                        anotherUser._id,
                    ],
                },
            }),

            Notification.deleteMany({
                user: {
                    $in: [
                        testUser._id,
                        anotherUser._id,
                    ],
                },
            }),
        ]);
    });


    afterAll(async () => {
        if (testUser && anotherUser) {
            await Promise.all([
                Analysis.deleteMany({
                    user: {
                        $in: [
                            testUser._id,
                            anotherUser._id,
                        ],
                    },
                }),

                Case.deleteMany({
                    user: {
                        $in: [
                            testUser._id,
                            anotherUser._id,
                        ],
                    },
                }),

                Notification.deleteMany({
                    user: {
                        $in: [
                            testUser._id,
                            anotherUser._id,
                        ],
                    },
                }),

                User.deleteMany({
                    _id: {
                        $in: [
                            testUser._id,
                            anotherUser._id,
                        ],
                    },
                }),
            ]);
        }
    });


    // =================================================
    // 1. AUTHENTICATION
    // =================================================

    describe("Authentication", () => {
        it("should reject dashboard requests without authentication", async () => {
            const response = await request(app)
                .get(endpoint);

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


        it("should reject malformed authorization headers", async () => {
            const response = await request(app)
                .get(endpoint)
                .set(
                    "Authorization",
                    "InvalidHeader"
                );

            expect(response.statusCode).toBe(401);
        });
    });


    // =================================================
    // 2. DASHBOARD OVERVIEW
    // =================================================

    describe("Dashboard Overview", () => {
        it("should retrieve dashboard data for an authenticated user", async () => {
            const {
                response,
                dashboard,
            } = await getDashboardResponse(authToken);

            expect(response.body.success).toBe(true);

            expect(dashboard).toBeDefined();
        });


        it("should return valid JSON", async () => {
            const response = await dashboardRequest();

            expect(response.statusCode).toBe(200);

            expect(response.headers["content-type"])
                .toMatch(/json/);

            expect(response.body).toBeDefined();

            expect(typeof response.body).toBe("object");
        });


        it("should return a successful API response", async () => {
            const response = await dashboardRequest();

            expect(response.statusCode).toBe(200);

            expect(response.body.success).toBe(true);
        });
    });


    // =================================================
    // 3. DASHBOARD STATISTICS
    // =================================================

    describe("Dashboard Statistics", () => {
        it("should return a statistics object", async () => {
            const { dashboard } =
                await getDashboardResponse(authToken);

            const statistics =
                dashboard.statistics ||
                dashboard.stats;

            expect(statistics).toBeDefined();

            expect(typeof statistics).toBe("object");

            expect(Array.isArray(statistics)).toBe(false);
        });


        it("should return finite non-negative numeric statistics", async () => {
            const { dashboard } =
                await getDashboardResponse(authToken);

            const statistics =
                dashboard.statistics ||
                dashboard.stats;

            expect(statistics).toBeDefined();

            const numericValues = Object.values(
                statistics
            ).filter(
                (value) => typeof value === "number"
            );

            expect(numericValues.length).toBeGreaterThan(0);

            numericValues.forEach((value) => {
                expect(Number.isFinite(value)).toBe(true);

                expect(value).toBeGreaterThanOrEqual(0);
            });
        });
    });


    // =================================================
    // 4. RECENT ANALYSES
    // =================================================

    describe("Recent Analyses", () => {
        it("should return recent analyses as an array", async () => {
            const { dashboard } =
                await getDashboardResponse(authToken);

            const analyses =
                dashboard.recentAnalyses ||
                dashboard.recentActivity;

            expect(Array.isArray(analyses)).toBe(true);
        });
    });


    // =================================================
    // 5. CASE SUMMARY
    // =================================================

    describe("Case Summary", () => {
        it("should return a valid case summary", async () => {
            const { dashboard } =
                await getDashboardResponse(authToken);

            expect(dashboard.caseSummary).toBeDefined();

            expect(typeof dashboard.caseSummary).toBe("object");

            expect(
                Array.isArray(dashboard.caseSummary)
            ).toBe(false);
        });
    });


    // =================================================
    // 6. NOTIFICATION SUMMARY
    // =================================================

    describe("Notification Summary", () => {
        it("should return notification summary information", async () => {
            const { dashboard } =
                await getDashboardResponse(authToken);

            expect(dashboard.notifications).toBeDefined();

            expect(typeof dashboard.notifications).toBe("object");
        });
    });


    // =================================================
    // 7. USER DATA ISOLATION
    // =================================================

    describe("User Data Isolation", () => {
        it("should return a dashboard for the primary user", async () => {
            const {
                response,
                dashboard,
            } = await getDashboardResponse(authToken);

            expect(response.statusCode).toBe(200);

            expect(dashboard).toBeDefined();
        });


        it("should return a separate dashboard for another user", async () => {
            const {
                response,
                dashboard,
            } = await getDashboardResponse(
                anotherUserToken
            );

            expect(response.statusCode).toBe(200);

            expect(dashboard).toBeDefined();
        });


        it("should not expose another user's analysis records", async () => {
            const foreignAnalysis = await Analysis.create({
                user: anotherUser._id,

                evidenceId: new mongoose.Types.ObjectId().toString(),

                evidenceType: "message",

                fraudCategory: "unclassified",

                detectionCategory: null,

                riskScore: 10,

                riskLevel: "low",

                status: "completed",

                summary: "Isolation test analysis",

                indicators: [],

                detectedRules: [],

                agents: {},
            });

            const {
                dashboard,
            } = await getDashboardResponse(authToken);

            const analyses =
                dashboard.recentAnalyses ||
                dashboard.recentActivity;

            expect(Array.isArray(analyses)).toBe(true);

            const exposedForeignAnalysis = analyses.find(
                (item) =>
                    String(item._id || item.analysisId) ===
                    String(foreignAnalysis._id)
            );

            expect(exposedForeignAnalysis).toBeUndefined();
        });
    });
});
