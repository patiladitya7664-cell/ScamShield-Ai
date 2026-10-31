"use strict";

/* =====================================================
SCAMSHIELD AI - NAVIGATION MANAGER
Horizontal Navbar + Mobile Navigation
===================================================== */

(function (window, document) {
  const Navigation = {
    init() {
      this.setActiveLink();
      this.initMobileMenu();
      this.initLogout();
      this.initDropdowns();
    },

    /* ================================================
   ACTIVE NAVIGATION LINK
================================================ */

    setActiveLink() {
      const currentPage =
        window.location.pathname.split("/").pop().replace(".html", "") ||
        "dashboard";

      document.querySelectorAll(".nav-links a").forEach((link) => {
        const href = link.getAttribute("href");

        if (!href) return;

        const linkPage = href
          .split("/")
          .pop()
          .split("?")[0]
          .replace(".html", "");

        const isActive = linkPage === currentPage;

        link.classList.toggle("active", isActive);

        if (isActive) {
          link.setAttribute("aria-current", "page");
        } else {
          link.removeAttribute("aria-current");
        }
      });
    },

    /* ================================================
   MOBILE HORIZONTAL NAVBAR
================================================ */

    initMobileMenu() {
      const menuButton = document.querySelector(
        "#menuToggle, #menu-toggle, .menu-toggle, [data-menu-toggle]",
      );

      const navLinks = document.querySelector("#navLinks");

      if (!menuButton || !navLinks) return;

      const closeMenu = () => {
        navLinks.classList.remove("open", "active");

        menuButton.setAttribute("aria-expanded", "false");

        const icon = menuButton.querySelector("i");

        if (icon) {
          icon.classList.remove("fa-xmark");
          icon.classList.add("fa-bars");
        }
      };

      const toggleMenu = () => {
        const isOpen = !navLinks.classList.contains("open");

        navLinks.classList.toggle("open", isOpen);
        navLinks.classList.toggle("active", isOpen);

        menuButton.setAttribute("aria-expanded", String(isOpen));

        const icon = menuButton.querySelector("i");

        if (icon) {
          icon.classList.toggle("fa-bars", !isOpen);
          icon.classList.toggle("fa-xmark", isOpen);
        }
      };

      menuButton.addEventListener("click", toggleMenu);

      navLinks.querySelectorAll("a").forEach((link) => {
        link.addEventListener("click", closeMenu);
      });

      document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
          closeMenu();
        }
      });

      window.addEventListener("resize", () => {
        if (window.innerWidth > 768) {
          closeMenu();
        }
      });
    },

    /* ================================================
   LOGOUT
================================================ */

    initLogout() {
      document
        .querySelectorAll("#logout-btn, .logout-btn, [data-logout]")
        .forEach((button) => {
          button.addEventListener("click", (event) => {
            event.preventDefault();

            const confirmed = window.confirm(
              "Are you sure you want to logout?",
            );

            if (!confirmed) return;

            localStorage.removeItem("scamshieldToken");
            localStorage.removeItem("scamshieldUser");

            sessionStorage.removeItem("scamshieldToken");
            sessionStorage.removeItem("scamshieldUser");

            window.location.href = "login.html";
          });
        });
    },

    /* ================================================
   DROPDOWN MENUS
================================================ */

    initDropdowns() {
      document.querySelectorAll("[data-dropdown-toggle]").forEach((button) => {
        button.addEventListener("click", () => {
          const targetId = button.getAttribute("data-dropdown-toggle");

          const dropdown = document.getElementById(targetId);

          if (!dropdown) return;

          const isOpen = dropdown.classList.toggle("show");

          button.setAttribute("aria-expanded", String(isOpen));
        });
      });
    },
  };

  window.ScamShieldNavigation = Navigation;

  document.addEventListener("DOMContentLoaded", () => {
    Navigation.init();
  });
})(window, document);
