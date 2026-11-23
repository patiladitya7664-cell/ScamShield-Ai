"use strict";

/* =====================================================
   SCAMSHIELD AI - NAVIGATION MANAGER
   Version: 2.1.0

   Responsibilities:
   1. Active navigation link management.
   2. Dropdown menu management.
   3. SPA and multi-page navigation support.
   4. Dynamic navigation refresh.
   5. Keyboard accessibility.

   Mobile navigation: main.js
   Logout handling: app.js
===================================================== */

(function (window, document) {
    const Navigation = {
        initialized: false,
        dropdownGlobalListenersInitialized: false,

        init() {
            if (this.initialized) {
                this.refresh();
                return;
            }

            this.initialized = true;

            this.refresh();

            window.addEventListener("hashchange", () => {
                this.setActiveLink();
            });

            window.addEventListener("popstate", () => {
                this.setActiveLink();
            });

            window.addEventListener("pageshow", () => {
                this.setActiveLink();
            });

            document.addEventListener(
                "scamshield:screenchange",
                () => {
                    this.refresh();
                }
            );
        },

        /* ================================================
           ROUTE NORMALIZATION
        ================================================ */

        normalizeRoute(value) {
            if (!value) return "";

            let route = String(value).trim();

            if (!route || route === "#") {
                return "";
            }

            // Handle SPA hash routes.
            if (route.startsWith("#")) {
                route = route.replace(/^#\/?/, "");
            }

            // Remove query parameters.
            route = route.split("?")[0];

            // Ignore external URLs.
            if (/^[a-z][a-z0-9+.-]*:\/\//i.test(route)) {
                try {
                    const url = new URL(route);

                    if (url.origin !== window.location.origin) {
                        return "";
                    }

                    route = url.pathname;
                } catch {
                    return "";
                }
            }

            // Normalize relative and absolute paths.
            route = route.replace(/\\/g, "/");

            // Remove trailing slash.
            route = route.replace(/\/+$/, "");

            // Get the final path segment.
            route = route.split("/").pop() || "";

            // Remove HTML extension.
            route = route.replace(/\.html$/i, "");

            return route.toLowerCase();
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

            const currentPath = window.location.pathname;

            const page = this.normalizeRoute(currentPath);

            return page || "dashboard";
        },

        /* ================================================
           ACTIVE NAVIGATION LINK
        ================================================ */

        setActiveLink() {
            const currentPage = this.getCurrentPage();

            if (!currentPage) return;

            document.querySelectorAll(
                ".nav-links a, [data-nav-link]"
            ).forEach((link) => {
                const route =
                    link.getAttribute("data-route") ||
                    link.getAttribute("data-screen") ||
                    link.getAttribute("href");

                if (!route) return;

                const linkPage = this.normalizeRoute(route);

                if (!linkPage) {
                    link.classList.remove("active");
                    link.removeAttribute("aria-current");
                    return;
                }

                const isActive =
                    linkPage === currentPage ||
                    currentPage.startsWith(linkPage + "/");

                link.classList.toggle("active", isActive);

                if (isActive) {
                    link.setAttribute("aria-current", "page");
                } else {
                    link.removeAttribute("aria-current");
                }
            });
        },

        /* ================================================
           REFRESH NAVIGATION
        ================================================ */

        refresh() {
            this.setActiveLink();
            this.initDropdowns();
        },

        /* ================================================
           MOBILE NAVIGATION
           
           Managed by main.js.
           No duplicate event listeners.
        ================================================ */

        initMobileMenu() {
            // Mobile navigation is managed by main.js.
        },

        /* ================================================
           LOGOUT

           Managed by app.js.
           No duplicate event listeners.
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
                if (
                    button.dataset.dropdownInitialized === "true"
                ) {
                    return;
                }

                const targetId = button.getAttribute(
                    "data-dropdown-toggle"
                );

                if (!targetId) return;

                const dropdown = document.getElementById(targetId);

                // Do not mark initialized until target exists.
                if (!dropdown) return;

                button.dataset.dropdownInitialized = "true";

                button.setAttribute(
                    "aria-expanded",
                    String(dropdown.classList.contains("show"))
                );

                button.setAttribute("aria-controls", targetId);

                button.addEventListener("click", (event) => {
                    event.preventDefault();
                    event.stopPropagation();

                    const isCurrentlyOpen =
                        dropdown.classList.contains("show");

                    this.closeAllDropdowns();

                    if (!isCurrentlyOpen) {
                        dropdown.classList.add("show");

                        button.setAttribute(
                            "aria-expanded",
                            "true"
                        );
                    }
                });
            });

            this.initDropdownGlobalListeners();
        },

        /* ================================================
           GLOBAL DROPDOWN LISTENERS
        ================================================ */

        initDropdownGlobalListeners() {
            if (this.dropdownGlobalListenersInitialized) {
                return;
            }

            this.dropdownGlobalListenersInitialized = true;

            document.addEventListener("click", (event) => {
                const target = event.target;

                if (!(target instanceof Element)) {
                    return;
                }

                const clickedInsideDropdown =
                    target.closest("[data-dropdown-toggle]") ||
                    target.closest(".dropdown");

                if (!clickedInsideDropdown) {
                    this.closeAllDropdowns();
                }
            });

            document.addEventListener("keydown", (event) => {
                if (event.key !== "Escape") return;

                const openButton = document.querySelector(
                    '[data-dropdown-toggle][aria-expanded="true"]'
                );

                if (openButton) {
                    this.closeAllDropdowns();
                    openButton.focus();
                }
            });
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

                if (!targetId) return;

                const dropdown = document.getElementById(targetId);

                button.setAttribute("aria-expanded", "false");

                if (dropdown) {
                    dropdown.classList.remove("show");
                }
            });
        }
    };

    /* ================================================
       GLOBAL API
    ================================================ */

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