"use strict";

// =====================================================
// SCAMSHIELD AI - USER ROLES
// Version: 2.0.0
//
// Centralized Role-Based Access Control (RBAC).
// =====================================================

// =====================================================
// 1. ROLE DEFINITIONS
// =====================================================

const ROLES = Object.freeze({
    ADMIN: "admin",
    ANALYST: "analyst",
    USER: "user",
});

// =====================================================
// 2. ROLE VALUES
// =====================================================

const ROLE_VALUES = Object.freeze(
    Object.values(ROLES)
);

// =====================================================
// 3. PERMISSION DEFINITIONS
// =====================================================

const PERMISSIONS = Object.freeze({

    // User management
    MANAGE_USERS: "manage_users",
    MANAGE_ROLES: "manage_roles",

    // Analysis
    CREATE_ANALYSIS: "create_analysis",
    VIEW_ALL_ANALYSES: "view_all_analyses",
    VIEW_OWN_ANALYSES: "view_own_analyses",

    // Cases
    MANAGE_ALL_CASES: "manage_all_cases",
    MANAGE_CASES: "manage_cases",
    CREATE_CASE: "create_case",
    VIEW_OWN_CASES: "view_own_cases",

    // Dashboard and analytics
    VIEW_DASHBOARD: "view_dashboard",
    VIEW_ANALYTICS: "view_analytics",

    // Intelligence
    MANAGE_INTELLIGENCE: "manage_intelligence",
    VIEW_INTELLIGENCE: "view_intelligence",

    // Agents
    MANAGE_AGENTS: "manage_agents",
    VIEW_AGENTS: "view_agents",

    // Notifications
    MANAGE_NOTIFICATIONS: "manage_notifications",
    VIEW_OWN_NOTIFICATIONS: "view_own_notifications",

    // Settings
    MANAGE_SETTINGS: "manage_settings",
});

// =====================================================
// 4. ROLE PERMISSIONS
// =====================================================

const ROLE_PERMISSIONS = Object.freeze({

    [ROLES.ADMIN]: Object.freeze([
        PERMISSIONS.MANAGE_USERS,
        PERMISSIONS.MANAGE_ROLES,
        PERMISSIONS.VIEW_ALL_ANALYSES,
        PERMISSIONS.MANAGE_ALL_CASES,
        PERMISSIONS.VIEW_DASHBOARD,
        PERMISSIONS.VIEW_ANALYTICS,
        PERMISSIONS.MANAGE_INTELLIGENCE,
        PERMISSIONS.MANAGE_AGENTS,
        PERMISSIONS.MANAGE_NOTIFICATIONS,
        PERMISSIONS.MANAGE_SETTINGS,
    ]),

    [ROLES.ANALYST]: Object.freeze([
        PERMISSIONS.VIEW_ALL_ANALYSES,
        PERMISSIONS.CREATE_ANALYSIS,
        PERMISSIONS.VIEW_DASHBOARD,
        PERMISSIONS.VIEW_ANALYTICS,
        PERMISSIONS.MANAGE_CASES,
        PERMISSIONS.VIEW_INTELLIGENCE,
        PERMISSIONS.VIEW_AGENTS,
        PERMISSIONS.MANAGE_NOTIFICATIONS,
    ]),

    [ROLES.USER]: Object.freeze([
        PERMISSIONS.CREATE_ANALYSIS,
        PERMISSIONS.VIEW_OWN_ANALYSES,
        PERMISSIONS.CREATE_CASE,
        PERMISSIONS.VIEW_OWN_CASES,
        PERMISSIONS.VIEW_OWN_NOTIFICATIONS,
    ]),
});

// =====================================================
// 5. VALIDATE ROLE
// =====================================================

const isValidRole = (role) => {
    return (
        typeof role === "string" &&
        ROLE_VALUES.includes(role)
    );
};

// =====================================================
// 6. VALIDATE PERMISSION
// =====================================================

const isValidPermission = (permission) => {
    return (
        typeof permission === "string" &&
        Object.values(PERMISSIONS).includes(permission)
    );
};

// =====================================================
// 7. CHECK USER ROLE
// =====================================================

const hasRole = (userRole, allowedRoles = []) => {

    if (
        !isValidRole(userRole) ||
        !Array.isArray(allowedRoles) ||
        allowedRoles.length === 0
    ) {
        return false;
    }

    return (
        allowedRoles.every(isValidRole) &&
        allowedRoles.includes(userRole)
    );
};

// =====================================================
// 8. CHECK ROLE PERMISSION
// =====================================================

const hasPermission = (role, permission) => {

    if (
        !isValidRole(role) ||
        !isValidPermission(permission)
    ) {
        return false;
    }

    return ROLE_PERMISSIONS[role].includes(permission);
};

// =====================================================
// 9. GET ROLE PERMISSIONS
// =====================================================

const getRolePermissions = (role) => {

    if (!isValidRole(role)) {
        return [];
    }

    return [...ROLE_PERMISSIONS[role]];
};

// =====================================================
// 10. EXPORTS
// =====================================================

module.exports = {
    ROLES,
    ROLE_VALUES,
    PERMISSIONS,
    ROLE_PERMISSIONS,

    isValidRole,
    isValidPermission,
    hasRole,
    hasPermission,
    getRolePermissions,
};