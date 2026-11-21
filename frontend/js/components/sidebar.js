
"use strict";

/* ==========================================
   SCAMSHIELD AI - SIDEBAR MANAGER
   Version: 2.0.0

   Sidebar is intentionally disabled.
   Horizontal navbar is managed by main.js.
========================================== */

(function (window) {
    const ScamShieldSidebar = {
        initialized: false,

        init() {
            if (this.initialized) return;

            this.initialized = true;

            // No sidebar required.
            // Mobile navigation is handled by main.js.
        },
    };

    window.ScamShieldSidebar = ScamShieldSidebar;

})(window);
