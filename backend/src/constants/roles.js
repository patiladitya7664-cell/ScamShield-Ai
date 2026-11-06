"use strict";

// =====================================================
// SCAMSHIELD AI - USER ROLES
// Centralized role definitions and authorization helpers
// =====================================================

const ROLES = Object.freeze({
    ADMIN: "admin",
    ANALYST: "analyst",
    USER: "user",
});

// =====================================================
// ROLE VALUES
// =====================================================

const ROLE_VALUES = Object.freeze(
    Object.values(ROLES)
);

// =====================================================
// ROLE PERMISSIONS
// =====================================================

const ROLE_PERMISSIONS = Object.freeze({
    [ROLES.ADMIN]: Object.freeze([
        "manage_users",
        "manage_roles",
        "view_all_analyses",
        "manage_all_cases",
        "view_dashboard",
        "view_analytics",
        "manage_intelligence",
        "manage_agents",
        "manage_notifications",
        "manage_settings",
    ]),

    [ROLES.ANALYST]: Object.freeze([
        "view_all_analyses",
        "create_analysis",
        "view_dashboard",
        "view_analytics",
        "manage_cases",
        "view_intelligence",
        "view_agents",
        "manage_notifications",
    ]),

    [ROLES.USER]: Object.freeze([
        "create_analysis",
        "view_own_analyses",
        "create_case",
        "view_own_cases",
        "view_own_notifications",
    ]),
});

// =====================================================
// HELPER FUNCTIONS
// =====================================================

/**
 * Check whether a role is valid.
 */
const isValidRole = (role) => {
    return typeof role === "string" && ROLE_VALUES.includes(role);
};

/**
 * Check whether a user has a specific role.
 */
const hasRole = (userRole, allowedRoles = []) => {
    if (!isValidRole(userRole) || !Array.isArray(allowedRoles)) {
        return false;
    }

    return allowedRoles.includes(userRole);
};

/**
 * Check whether a role has a specific permission.
 */
const hasPermission = (role, permission) => {
    if (!isValidRole(role) || typeof permission !== "string") {
        return false;
    }

    return ROLE_PERMISSIONS[role].includes(permission);
};

/**
 * Get permissions assigned to a role.
 */
const getRolePermissions = (role) => {
    if (!isValidRole(role)) {
        return [];
    }

    return [...ROLE_PERMISSIONS[role]];
};

// =====================================================
// EXPORTS
// =====================================================

module.exports = {
    ROLES,
    ROLE_VALUES,
    ROLE_PERMISSIONS,
    isValidRole,
    hasRole,
    hasPermission,
    getRolePermissions,
};