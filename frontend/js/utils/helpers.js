"use strict";

/* =====================================================
   SCAMSHIELD AI - HELPER UTILITIES

   Version: 2.1.0

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

   SECURITY:
   - Never store passwords, OTPs or authentication secrets
     using these generic storage helpers.
   - Toast content is rendered as plain text.
===================================================== */

(function (window, document) {
    "use strict";

    if (window.ScamShieldHelpers) {
        return;
    }

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
                (character) => entities[character]
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

            try {
                return parsedDate.toLocaleDateString("en-IN", {
                    day: "2-digit",
                    month: "short",
                    year: "numeric",
                    ...options
                });
            } catch {
                return "Invalid date";
            }
        },

        /* ================================================
           DATE AND TIME FORMATTING
        ================================================ */

        formatDateTime(date, options = {}) {
            const parsedDate = new Date(date);

            if (Number.isNaN(parsedDate.getTime())) {
                return "Invalid date";
            }

            try {
                return parsedDate.toLocaleString("en-IN", {
                    day: "2-digit",
                    month: "short",
                    year: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                    ...options
                });
            } catch {
                return "Invalid date";
            }
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

            if (seconds < 0) {
                return "In the future";
            }

            if (seconds < 60) {
                return "Just now";
            }

            if (seconds < 3600) {
                const minutes = Math.floor(seconds / 60);

                return `${minutes} min ago`;
            }

            if (seconds < 86400) {
                const hours = Math.floor(seconds / 3600);

                return `${hours} hours ago`;
            }

            if (seconds < 604800) {
                const days = Math.floor(seconds / 86400);

                return `${days} days ago`;
            }

            return this.formatDate(parsedDate);
        },

        /* ================================================
           TEXT TRUNCATION
        ================================================ */

        truncateText(text = "", maxLength = 100) {
            const value = String(text);

            const numericLimit = Number(maxLength);

            const limit = Number.isFinite(numericLimit)
                ? Math.max(0, Math.floor(numericLimit))
                : 100;

            if (value.length <= limit) {
                return value;
            }

            if (limit <= 3) {
                return ".".repeat(limit);
            }

            return (
                value.substring(0, limit - 3).trimEnd() + "..."
            );
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
                .map((word) => word.charAt(0).toUpperCase())
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

            let timer = null;

            const numericDelay = Number(delay);

            const safeDelay = Number.isFinite(numericDelay)
                ? Math.max(0, numericDelay)
                : 300;

            return function (...args) {
                if (timer !== null) {
                    clearTimeout(timer);
                }

                const context = this;

                timer = setTimeout(() => {
                    timer = null;

                    callback.apply(context, args);
                }, safeDelay);
            };
        },

        /* ================================================
           SAFE LOCAL STORAGE
        ================================================ */

        setStorage(key, value) {
            try {
                if (
                    typeof key !== "string" ||
                    !key.trim()
                ) {
                    return false;
                }

                const serialized = JSON.stringify(value);

                if (serialized === undefined) {
                    return false;
                }

                window.localStorage.setItem(
                    key,
                    serialized
                );

                return true;

            } catch {
                return false;
            }
        },

        getStorage(key, defaultValue = null) {
            try {
                if (
                    typeof key !== "string" ||
                    !key.trim()
                ) {
                    return defaultValue;
                }

                const value = window.localStorage.getItem(key);

                if (value === null) {
                    return defaultValue;
                }

                return JSON.parse(value);

            } catch {
                return defaultValue;
            }
        },

        removeStorage(key) {
            try {
                if (
                    typeof key !== "string" ||
                    !key.trim()
                ) {
                    return false;
                }

                window.localStorage.removeItem(key);

                return true;

            } catch {
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

            const safeType = Object.prototype.hasOwnProperty.call(
                colors,
                type
            )
                ? type
                : "info";

            const container = this.getToastContainer();

            const toast = document.createElement("div");

            toast.className = `scamshield-toast toast-${safeType}`;

            // Never interpret notification content as HTML.
            toast.textContent = String(message);

            toast.setAttribute(
                "role",
                safeType === "error" ? "alert" : "status"
            );

            toast.setAttribute("aria-atomic", "true");

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

                pointerEvents: "auto",
                cursor: "pointer"
            });

            container.appendChild(toast);

            const prefersReducedMotion =
                typeof window.matchMedia === "function" &&
                window.matchMedia(
                    "(prefers-reduced-motion: reduce)"
                ).matches;

            if (prefersReducedMotion) {
                toast.style.transition = "none";
            }

            requestAnimationFrame(() => {
                toast.style.opacity = "1";
                toast.style.transform = "translateY(0)";
            });

            const numericDuration = Number(duration);

            const safeDuration = Number.isFinite(numericDuration)
                ? Math.max(0, numericDuration)
                : 3000;

            let removed = false;

            let timer = null;

            const removeToast = () => {
                if (removed) {
                    return;
                }

                removed = true;

                if (timer !== null) {
                    clearTimeout(timer);
                    timer = null;
                }

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
                    window.setTimeout(cleanup, 250);
                }
            };

            timer = window.setTimeout(
                removeToast,
                safeDuration
            );

            toast.addEventListener(
                "click",
                removeToast
            );

            toast.addEventListener(
                "keydown",
                (event) => {
                    if (
                        event.key === "Enter" ||
                        event.key === " "
                    ) {
                        event.preventDefault();
                        removeToast();
                    }
                }
            );

            toast.setAttribute("tabindex", "0");

            toast.setAttribute(
                "aria-label",
                `${safeType} notification. Activate to dismiss.`
            );

            return toast;
        },

        /* ================================================
           EMAIL VALIDATION
        ================================================ */

        isValidEmail(email = "") {
            const value = String(email).trim();

            if (
                !value ||
                value.length > 254
            ) {
                return false;
            }

            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
        },

        /* ================================================
           URL VALIDATION
        ================================================ */

        isValidURL(value = "") {
            try {
                const input = String(value).trim();

                if (!input) {
                    return false;
                }

                const url = new URL(input);

                return (
                    url.protocol === "http:" ||
                    url.protocol === "https:"
                ) && Boolean(url.hostname);

            } catch {
                return false;
            }
        },

        /* ================================================
           RISK LEVEL
        ================================================ */

        getRiskLevel(score) {
            if (
                score === null ||
                score === undefined ||
                score === ""
            ) {
                return "Unknown";
            }

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
            if (
                score === null ||
                score === undefined ||
                score === ""
            ) {
                return "N/A";
            }

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

    window.ScamShieldHelpers = Object.freeze(
        ScamShieldHelpers
    );

})(window, document);