/* =====================================================
SCAMSHIELD AI
MAIN JAVASCRIPT
===================================================== */

"use strict";

(() => {
  // Prevent duplicate initialization
  if (window.ScamShieldMainInitialized) {
    return;
  }

  window.ScamShieldMainInitialized = true;

  document.addEventListener("DOMContentLoaded", () => {
    /* ================= DOM ELEMENTS ================= */

    const menuToggle = document.getElementById("menuToggle");
    const navLinks = document.getElementById("navLinks");
    const navItems = document.querySelectorAll(".nav-links a");
    const navbar = document.querySelector(".navbar");

    /* ================= MOBILE NAVIGATION ================= */

    function closeMobileMenu() {
      if (!menuToggle || !navLinks) return;

      navLinks.classList.remove("active");

      menuToggle.setAttribute("aria-expanded", "false");

      menuToggle.innerHTML = '<i class="fa-solid fa-bars"></i>';
    }

    function toggleMobileMenu() {
      if (!menuToggle || !navLinks) return;

      const isOpen = navLinks.classList.toggle("active");

      menuToggle.setAttribute("aria-expanded", String(isOpen));

      menuToggle.innerHTML = isOpen
        ? '<i class="fa-solid fa-xmark"></i>'
        : '<i class="fa-solid fa-bars"></i>';
    }

    /* ================= MENU BUTTON ================= */

    if (menuToggle && navLinks) {
      menuToggle.addEventListener("click", toggleMobileMenu);
    }

    /* ================= NAVIGATION LINKS ================= */

    navItems.forEach((link) => {
      link.addEventListener("click", closeMobileMenu);
    });

    /* ================= CLOSE MENU OUTSIDE CLICK ================= */

    document.addEventListener("click", (event) => {
      if (!menuToggle || !navLinks) return;

      const clickedInsideMenu = navLinks.contains(event.target);

      const clickedToggle = menuToggle.contains(event.target);

      if (!clickedInsideMenu && !clickedToggle) {
        closeMobileMenu();
      }
    });

    /* ================= ESCAPE KEY ================= */

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeMobileMenu();
      }
    });

    /* ================= SCREEN RESIZE ================= */

    window.addEventListener("resize", () => {
      if (window.innerWidth > 768) {
        closeMobileMenu();
      }
    });

    /* ================= NAVBAR SCROLL EFFECT ================= */

    window.addEventListener(
      "scroll",
      () => {
        if (!navbar) return;

        navbar.classList.toggle("scrolled", window.scrollY > 30);
      },
      { passive: true },
    );

    /* ================= SMOOTH INTERNAL NAVIGATION ================= */

    document.querySelectorAll('a[href^="#"]:not([data-route])').forEach((link) => {
      link.addEventListener("click", (event) => {
        const targetId = link.getAttribute("href");

        if (!targetId || targetId === "#") return;

        const targetElement = document.querySelector(targetId);

        if (!targetElement) return;

        event.preventDefault();

        targetElement.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      });
    });

    /* ================= CURRENT YEAR ================= */

    document.querySelectorAll(".current-year").forEach((element) => {
      element.textContent = new Date().getFullYear();
    });

    /* ================= INITIALIZATION ================= */

    closeMobileMenu();

    console.log(
      "%c SCAMSHIELD AI ",
      "background:#25d9bd;color:#06131c;font-size:16px;font-weight:bold;padding:8px;",
    );

    console.log("Frontend initialized successfully.");
  });
})();
