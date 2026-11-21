
"use strict";

/* =====================================================
   SCAMSHIELD AI - NAVIGATION MANAGER
   Version: 2.0.0

   Responsibilities:
   1. Active navigation link management.
   2. Dropdown menu management.
   3. SPA and multi-page navigation support.

   Mobile navigation: main.js
   Logout handling: app.js
===================================================== */

(function (window, document) {
    const Navigation = {
        initialized: false,

        init() {
            if (this.initialized) return;

            this.initialized = true;

            this.setActiveLink();
            this.initMobileMenu();
            this.initLogout();
            this.initDropdowns();

            window.addEventListener("hashchange", () => {
                this.setActiveLink();
            });

            window.addEventListener("popstate", () => {
                this.setActiveLink();
            });

            document.addEventListener("scamshield:screenchange", () => {
                this.setActiveLink();
            });
        },

        /* ================================================
           ROUTE NORMALIZATION
        ================================================ */

        normalizeRoute(value) {
            if (!value) return "";

            return String(value)
                .replace(/^#\/?/, "")
                .replace(/^\/+|\/+$/g, "")
                .split("?")[0]
                .replace(/\.html$/i, "")
                .toLowerCase();
        },

        /* ================================================
           GET CURRENT PAGE
        ================================================ */

        getCurrentPage() {
            const hashRoute = this.normalizeRoute(
                window.location.hash
            );

            if (hashRoute) {
                return hashRoute;
            }

            const currentPath = window.location.pathname
                .split("/")
                .pop()
                .replace(/\.html$/i, "")
                .toLowerCase();

            return currentPath || "dashboard";
        },

        /* ================================================
           ACTIVE NAVIGATION LINK
        ================================================ */

        setActiveLink() {
            const currentPage = this.getCurrentPage();

            document.querySelectorAll(
                ".nav-links a, [data-nav-link]"
            ).forEach((link) => {
                const route =
                    link.getAttribute("data-route") ||
                    link.getAttribute("data-screen") ||
                    link.getAttribute("href");

                if (!route) return;

                const linkPage = this.normalizeRoute(route);

                const isActive =
                    linkPage === currentPage ||
                    (
                        currentPage &&
                        linkPage &&
                        currentPage.startsWith(linkPage + "/")
                    );

                link.classList.toggle("active", isActive);

                if (isActive) {
                    link.setAttribute("aria-current", "page");
                } else {
                    link.removeAttribute("aria-current");
                }
            });
        },

        /* ================================================
           MOBILE NAVIGATION

           Managed by main.js.
           No duplicate event listeners here.
        ================================================ */

        initMobileMenu() {
            // Mobile navigation is managed by main.js.
        },

        /* ================================================
           LOGOUT

           Managed by app.js.
           No duplicate logout listeners here.
        ================================================ */

        initLogout() {
            // Authentication and logout are managed by app.js.
        },

        /* ================================================
           DROPDOWN MENUS
        ================================================ */

        initDropdowns() {
            const dropdownButtons = document.querySelectorAll(
                "[data-dropdown-toggle]"
            );

            dropdownButtons.forEach((button) => {
                if (button.dataset.dropdownInitialized === "true") {
                    return;
                }

                button.dataset.dropdownInitialized = "true";

                const targetId = button.getAttribute(
                    "data-dropdown-toggle"
                );

                const dropdown = document.getElementById(targetId);

                if (!dropdown) return;

                button.setAttribute(
                    "aria-expanded",
                    String(dropdown.classList.contains("show"))
                );

                button.addEventListener("click", (event) => {
                    event.preventDefault();
                    event.stopPropagation();

                    const isCurrentlyOpen =
                        dropdown.classList.contains("show");

                    this.closeAllDropdowns();

                    if (!isCurrentlyOpen) {
                        dropdown.classList.add("show");
                        button.setAttribute("aria-expanded", "true");
                    }
                });
            });

            if (!this.dropdownGlobalListenersInitialized) {
                this.dropdownGlobalListenersInitialized = true;

                document.addEventListener("click", (event) => {
                    const clickedInsideDropdown =
                        event.target.closest("[data-dropdown-toggle]") ||
                        event.target.closest(".dropdown");

                    if (!clickedInsideDropdown) {
                        this.closeAllDropdowns();
                    }
                });

                document.addEventListener("keydown", (event) => {
                    if (event.key === "Escape") {
                        this.closeAllDropdowns();
                    }
                });
            }
        },

        /* ================================================
           CLOSE ALL DROPDOWNS
        ================================================ */

        closeAllDropdowns() {
            document.querySelectorAll(
                "[data-dropdown-toggle]"
            ).forEach((button) => {
                const targetId = button.getAttribute(
                    "data-dropdown-toggle"
                );

                const dropdown = document.getElementById(targetId);

                if (!dropdown) return;

                dropdown.classList.remove("show");

                button.setAttribute("aria-expanded", "false");
            });
        }
    };

    window.ScamShieldNavigation = Navigation;

    /* ================================================
       INITIALIZATION
    ================================================ */

    if (document.readyState === "loading") {
        document.addEventListener(
            "DOMContentLoaded",
            () => Navigation.init(),
            { once: true }
        );
    } else {
        Navigation.init();
    }

})(window, document);
