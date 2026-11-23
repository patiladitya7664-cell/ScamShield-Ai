"use strict";

/* ==========================================
   SCAMSHIELD AI - SIDEBAR MANAGER
   Version: 2.1.0

   Sidebar is intentionally disabled.

   Navigation architecture:
   - Horizontal navbar: main.js
   - Active navigation: navigation.js
   - Mobile navigation: main.js
========================================== */

(function (window) {
    const ScamShieldSidebar = {
        initialized: false,
        enabled: false,

        init() {
            if (this.initialized) {
                return;
            }

            this.initialized = true;

            // Sidebar is intentionally disabled.
            // Do not create sidebar elements.
            // Do not attach navigation listeners.

            return true;
        },

        isEnabled() {
            return this.enabled;
        }
    };

    window.ScamShieldSidebar = ScamShieldSidebar;

})(window);