"use strict";

/*
=========================================================
SCAMSHIELD AI - ROLE AUTHORIZATION MIDDLEWARE
=========================================================

Supported roles:
1. user
2. analyst
3. admin

Usage:
router.get("/admin", protect, authorize("admin"), controller);

=========================================================
*/

const authorize = (...allowedRoles) => {
    return (req, res, next) => {
        try {
            // Authentication check
            if (!req.user) {
                return res.status(401).json({
                    success: false,
                    message: "Authentication required."
                });
            }

            // Validate allowed roles configuration
            const validRoles = ["user", "analyst", "admin"];

            if (
                allowedRoles.length === 0 ||
                allowedRoles.some(
                    (role) => !validRoles.includes(role)
                )
            ) {
                return res.status(500).json({
                    success: false,
                    message: "Invalid authorization configuration."
                });
            }

            // Check user role
            if (!allowedRoles.includes(req.user.role)) {
                return res.status(403).json({
                    success: false,
                    message: "You do not have permission to access this resource."
                });
            }

            return next();

        } catch (error) {
            return next(error);
        }
    };
};

module.exports = {
    authorize
};