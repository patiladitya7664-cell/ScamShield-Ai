"use strict";

/* =====================================================
   SCAMSHIELD AI
   MAIN APPLICATION JAVASCRIPT

   Version: 2.0.0

   Responsibilities:
   1. Mobile navigation
   2. Navbar scroll effects
   3. Internal smooth navigation
   4. Current year management
   5. Keyboard accessibility
   6. Responsive navigation behavior
   7. Application initialization
===================================================== */

(() => {
  /* ================================================
     INITIALIZATION GUARD
  ================================================ */

  if (window.ScamShieldMainInitialized) {
    return;
  }

  window.ScamShieldMainInitialized = true;

  /* ================================================
     DOM INITIALIZATION
  ================================================ */

  function initializeMain() {
    /* ================================================
       DOM ELEMENTS
    ================================================ */

    const menuToggle = document.getElementById("menuToggle");

    const navLinks = document.getElementById("navLinks");

    const navbar = document.querySelector(".navbar");

    const mobileBreakpoint = 768;

    /* ================================================
       ACCESSIBILITY
    ================================================ */

    const prefersReducedMotion = window.matchMedia(
      "(prefers-reduced-motion: reduce)",
    );

    /* ================================================
       MOBILE NAVIGATION
    ================================================ */

    function closeMobileMenu() {
      if (!menuToggle || !navLinks) {
        return;
      }

      navLinks.classList.remove("active", "open");

      menuToggle.setAttribute("aria-expanded", "false");

      menuToggle.innerHTML =
        '<i class="fa-solid fa-bars" aria-hidden="true"></i>';
    }

    function openMobileMenu() {
      if (!menuToggle || !navLinks) {
        return;
      }

      navLinks.classList.add("active");

      menuToggle.setAttribute("aria-expanded", "true");

      menuToggle.innerHTML =
        '<i class="fa-solid fa-xmark" aria-hidden="true"></i>';
    }

    function toggleMobileMenu() {
      if (!menuToggle || !navLinks) {
        return;
      }

      const isOpen = navLinks.classList.contains("active");

      if (isOpen) {
        closeMobileMenu();
      } else {
        openMobileMenu();
      }
    }

    /* ================================================
       MENU BUTTON
    ================================================ */

    if (menuToggle && navLinks) {
      menuToggle.addEventListener("click", (event) => {
        event.stopPropagation();

        toggleMobileMenu();
      });
    }

    /* ================================================
       NAVIGATION EVENTS
    ================================================ */

    document.addEventListener("click", (event) => {
      const routeLink = event.target.closest("[data-route]");

      const navigationLink = event.target.closest("#navLinks a");

      if (routeLink || navigationLink) {
        closeMobileMenu();
      }
    });

    /* ================================================
       CLOSE MENU OUTSIDE CLICK
    ================================================ */

    document.addEventListener("click", (event) => {
      if (!menuToggle || !navLinks) {
        return;
      }

      const clickedInsideMenu = navLinks.contains(event.target);

      const clickedToggle = menuToggle.contains(event.target);

      if (!clickedInsideMenu && !clickedToggle) {
        closeMobileMenu();
      }
    });

    /* ================================================
       ESCAPE KEY
    ================================================ */

    document.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") {
        return;
      }

      if (navLinks && navLinks.classList.contains("active")) {
        closeMobileMenu();

        menuToggle?.focus();
      }
    });

    /* ================================================
       RESPONSIVE SCREEN SIZE
    ================================================ */

    function handleResponsiveNavigation() {
      if (window.innerWidth > mobileBreakpoint) {
        closeMobileMenu();
      }
    }

    window.addEventListener("resize", handleResponsiveNavigation, {
      passive: true,
    });

    /* ================================================
       NAVBAR SCROLL EFFECT
    ================================================ */

    let previousScrollState = null;

    function handleNavbarScroll() {
      if (!navbar) {
        return;
      }

      const isScrolled = window.scrollY > 30;

      if (previousScrollState === isScrolled) {
        return;
      }

      previousScrollState = isScrolled;

      navbar.classList.toggle("scrolled", isScrolled);
    }

    window.addEventListener("scroll", handleNavbarScroll, { passive: true });

    handleNavbarScroll();

    /* ================================================
       INTERNAL SMOOTH NAVIGATION
    ================================================ */

    document.addEventListener("click", (event) => {
      const link = event.target.closest('a[href^="#"]:not([data-route])');

      if (!link) {
        return;
      }

      const targetId = link.getAttribute("href");

      if (!targetId || targetId === "#" || targetId.startsWith("#screen-")) {
        return;
      }

      let targetElement;

      try {
        targetElement = document.querySelector(targetId);
      } catch (error) {
        console.warn("ScamShield AI: Invalid navigation selector.", targetId);

        return;
      }

      if (!targetElement) {
        return;
      }

      event.preventDefault();

      targetElement.scrollIntoView({
        behavior: prefersReducedMotion.matches ? "auto" : "smooth",

        block: "start",
      });
    });

    /* ================================================
       CURRENT YEAR
    ================================================ */

    function updateCurrentYear() {
      const currentYear = new Date().getFullYear();

      document.querySelectorAll(".current-year").forEach((element) => {
        element.textContent = currentYear;
      });
    }

    updateCurrentYear();

    /* ================================================
       ROUTER INTEGRATION
    ================================================ */

    window.addEventListener("scamshield:screenchange", () => {
      closeMobileMenu();
    });

    /* ================================================
       INITIAL STATE
    ================================================ */

    closeMobileMenu();

    /* ================================================
       APPLICATION READY
    ================================================ */

    console.log(
      "%c SCAMSHIELD AI ",
      "background:#25d9bd;color:#06131c;font-size:16px;font-weight:bold;padding:8px;",
    );

    console.log("Main application initialized successfully.");
  }

  /* ================================================
     DOCUMENT READY
  ================================================ */

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initializeMain, {
      once: true,
    });
  } else {
    initializeMain();
  }
})();
