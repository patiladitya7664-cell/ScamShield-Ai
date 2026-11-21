
"use strict";

/* =====================================================
   SCAMSHIELD AI - HELPER UTILITIES
   Version: 2.0.0

   Responsibilities:
   1. HTML escaping
   2. Date and time formatting
   3. Relative time formatting
   4. Text utilities
   5. User initials
   6. Debounce
   7. Safe localStorage operations
   8. Toast notifications
   9. Email and URL validation
   10. Risk score utilities
===================================================== */

(function (window, document) {

    const ScamShieldHelpers = {

        /* ================================================
           HTML ESCAPING
        ================================================ */

        escapeHTML(value = "") {

            const entities = {
                "&": "&amp;",
                "<": "&lt;",
                ">": "&gt;",
                '"': "&quot;",
                "'": "&#039;"
            };

            return String(value).replace(
                /[&<>"']/g,
                character => entities[character]
            );
        },

        /* ================================================
           DATE FORMATTING
        ================================================ */

        formatDate(date, options = {}) {

            const parsedDate = new Date(date);

            if (Number.isNaN(parsedDate.getTime())) {
                return "Invalid date";
            }

            return parsedDate.toLocaleDateString("en-IN", {
                day: "2-digit",
                month: "short",
                year: "numeric",
                ...options
            });
        },

        /* ================================================
           DATE AND TIME FORMATTING
        ================================================ */

        formatDateTime(date) {

            const parsedDate = new Date(date);

            if (Number.isNaN(parsedDate.getTime())) {
                return "Invalid date";
            }

            return parsedDate.toLocaleString("en-IN", {
                day: "2-digit",
                month: "short",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit"
            });
        },

        /* ================================================
           RELATIVE TIME
        ================================================ */

        timeAgo(date) {

            const parsedDate = new Date(date);

            if (Number.isNaN(parsedDate.getTime())) {
                return "Unknown";
            }

            const seconds = Math.floor(
                (Date.now() - parsedDate.getTime()) / 1000
            );

            if (seconds < 60) {
                return "Just now";
            }

            if (seconds < 3600) {
                return `${Math.floor(seconds / 60)} min ago`;
            }

            if (seconds < 86400) {
                return `${Math.floor(seconds / 3600)} hours ago`;
            }

            if (seconds < 604800) {
                return `${Math.floor(seconds / 86400)} days ago`;
            }

            return this.formatDate(parsedDate);
        },

        /* ================================================
           TEXT TRUNCATION
        ================================================ */

        truncateText(text = "", maxLength = 100) {

            const value = String(text);
            const limit = Math.max(0, Number(maxLength) || 0);

            if (value.length <= limit) {
                return value;
            }

            if (limit <= 3) {
                return ".".repeat(limit);
            }

            return value.substring(0, limit - 3).trimEnd() + "...";
        },

        /* ================================================
           USER INITIALS
        ================================================ */

        getInitials(name = "") {

            return String(name)
                .trim()
                .split(/\s+/)
                .filter(Boolean)
                .slice(0, 2)
                .map(word => word.charAt(0).toUpperCase())
                .join("");
        },

        /* ================================================
           DEBOUNCE
        ================================================ */

        debounce(callback, delay = 300) {

            if (typeof callback !== "function") {
                throw new TypeError(
                    "Debounce callback must be a function."
                );
            }

            let timer;

            return function (...args) {

                clearTimeout(timer);

                const context = this;

                timer = setTimeout(() => {
                    callback.apply(context, args);
                }, Math.max(0, Number(delay) || 0));
            };
        },

        /* ================================================
           SAFE LOCAL STORAGE
        ================================================ */

        setStorage(key, value) {

            try {

                if (!key) return false;

                const serialized = JSON.stringify(value);

                localStorage.setItem(
                    String(key),
                    serialized
                );

                return true;

            } catch (error) {

                console.error(
                    "ScamShield Storage Error:",
                    error
                );

                return false;
            }
        },

        getStorage(key, defaultValue = null) {

            try {

                if (!key) return defaultValue;

                const value = localStorage.getItem(String(key));

                if (value === null) {
                    return defaultValue;
                }

                return JSON.parse(value);

            } catch (error) {

                console.error(
                    "ScamShield Storage Read Error:",
                    error
                );

                return defaultValue;
            }
        },

        removeStorage(key) {

            try {

                if (!key) return false;

                localStorage.removeItem(String(key));

                return true;

            } catch (error) {

                console.error(
                    "ScamShield Storage Remove Error:",
                    error
                );

                return false;
            }
        },

        /* ================================================
           TOAST CONTAINER
        ================================================ */

        getToastContainer() {

            let container = document.getElementById(
                "toast-container"
            );

            if (container) {
                return container;
            }

            container = document.createElement("div");

            container.id = "toast-container";

            container.setAttribute("aria-live", "polite");
            container.setAttribute("aria-relevant", "additions");
            container.setAttribute("aria-atomic", "false");

            Object.assign(container.style, {

                position: "fixed",
                top: "20px",
                right: "20px",
                zIndex: "99999",

                display: "flex",
                flexDirection: "column",
                gap: "10px",

                width: "min(360px, calc(100vw - 40px))",
                pointerEvents: "none"

            });

            document.body.appendChild(container);

            return container;
        },

        /* ================================================
           SHOW TOAST NOTIFICATION
        ================================================ */

        showToast(message, type = "info", duration = 3000) {

            const colors = {

                success: "#16a34a",
                error: "#dc2626",
                warning: "#d97706",
                info: "#2563eb"

            };

            const safeType = Object.hasOwn(colors, type)
                ? type
                : "info";

            const container = this.getToastContainer();

            const toast = document.createElement("div");

            toast.className = `scamshield-toast toast-${safeType}`;

            toast.textContent = String(message);

            toast.setAttribute("role", "status");

            Object.assign(toast.style, {

                padding: "13px 18px",
                color: "#ffffff",
                background: colors[safeType],

                borderRadius: "8px",
                fontSize: "14px",
                fontFamily: "inherit",

                boxShadow: "0 4px 15px rgba(0,0,0,0.15)",

                maxWidth: "100%",
                overflowWrap: "anywhere",

                opacity: "0",
                transform: "translateY(-8px)",

                transition: "opacity 0.25s ease, transform 0.25s ease",

                pointerEvents: "auto"

            });

            container.appendChild(toast);

            const prefersReducedMotion =
                window.matchMedia &&
                window.matchMedia("(prefers-reduced-motion: reduce)").matches;

            requestAnimationFrame(() => {

                toast.style.opacity = "1";

                toast.style.transform = "translateY(0)";

                if (prefersReducedMotion) {
                    toast.style.transition = "none";
                }

            });

            const safeDuration = Math.max(
                0,
                Number(duration) || 0
            );

            const removeToast = () => {

                toast.style.opacity = "0";
                toast.style.transform = "translateY(-8px)";

                const cleanup = () => {

                    toast.remove();

                    if (
                        container.children.length === 0 &&
                        container.isConnected
                    ) {
                        container.remove();
                    }

                };

                if (prefersReducedMotion) {
                    cleanup();
                } else {
                    setTimeout(cleanup, 250);
                }
            };

            const timer = setTimeout(
                removeToast,
                safeDuration
            );

            // Allow users to dismiss a toast by clicking it.
            toast.addEventListener("click", () => {

                clearTimeout(timer);

                removeToast();

            });

            return toast;
        },

        /* ================================================
           EMAIL VALIDATION
        ================================================ */

        isValidEmail(email = "") {

            const value = String(email).trim();

            if (value.length > 254) {
                return false;
            }

            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
        },

        /* ================================================
           URL VALIDATION
        ================================================ */

        isValidURL(value = "") {

            try {

                const url = new URL(
                    String(value).trim()
                );

                return (
                    url.protocol === "http:" ||
                    url.protocol === "https:"
                );

            } catch {

                return false;
            }
        },

        /* ================================================
           RISK LEVEL
        ================================================ */

        getRiskLevel(score) {

            const value = Number(score);

            if (
                !Number.isFinite(value) ||
                value < 0 ||
                value > 100
            ) {
                return "Unknown";
            }

            if (value <= 24) return "Low";

            if (value <= 49) return "Medium";

            if (value <= 74) return "High";

            return "Critical";
        },

        /* ================================================
           FORMAT RISK SCORE
        ================================================ */

        formatRiskScore(score) {

            const value = Number(score);

            if (
                !Number.isFinite(value) ||
                value < 0 ||
                value > 100
            ) {
                return "N/A";
            }

            return `${Number(value.toFixed(2))}/100`;
        }

    };

    /* ================================================
       GLOBAL ACCESS
    ================================================ */

    window.ScamShieldHelpers = ScamShieldHelpers;

})(window, document);
