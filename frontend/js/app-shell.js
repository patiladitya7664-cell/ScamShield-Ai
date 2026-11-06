"use strict";

/* =====================================================
   SCAMSHIELD AI
   APPLICATION ROUTER + AUTHENTICATION GUARD
===================================================== */

(() => {
  if (window.ScamShieldAppInitialized) return;
  window.ScamShieldAppInitialized = true;

  const screens = new Set([
    "home",
    "dashboard",
    "detection",
    "analysis",
    "agents",
    "decoy-lab",
    "intelligence",
    "analytics",
    "reports",
    "settings",
    "login",
    "register",
  ]);

  const protectedScreens = new Set([
    "dashboard",
    "detection",
    "analysis",
    "agents",
    "decoy-lab",
    "intelligence",
    "analytics",
    "reports",
    "settings",
  ]);

  let bootstrapping = true;

  const refreshButtons = {
    dashboard: "refreshDashboard",
    analytics: "refreshAnalytics",
    reports: "refreshReports",
  };

  const styles = {
    dashboard: "dashboard",
    detection: "detection",
    analysis: "analysis",
    agents: "agents",
    "decoy-lab": "decoy-lab",
    intelligence: "intelligence",
    analytics: "analytics",
    reports: "reports",
    settings: "setting",
    login: "auth",
    register: "auth",
  };

  /* ================================================
     AUTHENTICATION
  ================================================ */

  function tokenExists() {
    return Boolean(
      localStorage.getItem("scamshieldToken") ||
      sessionStorage.getItem("scamshieldToken")
    );
  }

  function clearAuthentication() {
    localStorage.removeItem("scamshieldToken");
    localStorage.removeItem("scamshieldUser");

    sessionStorage.removeItem("scamshieldToken");
    sessionStorage.removeItem("scamshieldUser");
  }

  /* ================================================
     HEADER AUTHENTICATION ACTIONS
  ================================================ */

  function updateAuthActions(screen) {
    const signedIn = tokenExists();

    document.querySelectorAll("[data-auth-link]").forEach((link) => {
      link.hidden = signedIn;
    });

    document.querySelectorAll("[data-logout]").forEach((button) => {
      button.hidden = !signedIn;
    });

    document.body.classList.toggle(
      "auth-screen",
      screen === "login" || screen === "register"
    );

    document.body.classList.toggle(
      "guest-screen",
      !signedIn
    );
  }

  /* ================================================
     SCREEN NAVIGATION
  ================================================ */

  function showScreen(screen, updateUrl = true) {
    if (!screens.has(screen)) {
      screen = "home";
    }

    /* Protect private application screens */
    if (protectedScreens.has(screen) && !tokenExists()) {
      screen = "login";
    }

    /* Logged-in users should not revisit login/register */
    if (
      (screen === "login" || screen === "register") &&
      tokenExists()
    ) {
      screen = "dashboard";
    }

    const targetScreen = document.querySelector(
      `[data-screen="${screen}"]`
    );

    /* Do not silently display a blank screen */
    if (!targetScreen) {
      console.warn(`ScamShield AI: Screen "${screen}" was not found.`);
      screen = "home";
    }

    document.querySelectorAll("[data-screen]").forEach((element) => {
      const active = element.dataset.screen === screen;

      element.classList.toggle("active", active);
      element.setAttribute("aria-hidden", String(!active));
    });

    /* Load screen-specific CSS */
    const stylesheet = document.getElementById("screenStyles");
    const cssFile = styles[screen];

    if (stylesheet) {
      if (cssFile) {
        stylesheet.href = `css/${cssFile}.css`;
        stylesheet.disabled = false;
      } else {
        stylesheet.removeAttribute("href");
        stylesheet.disabled = true;
      }
    }

    updateAuthActions(screen);

    document.title =
      screen === "home"
        ? "ScamShield AI | Cyber Fraud Protection"
        : `${screen
            .replaceAll("-", " ")
            .replace(/\b\w/g, (char) => char.toUpperCase())} | ScamShield AI`;

    window.scrollTo({
      top: 0,
      behavior: "instant",
    });

    /* Update browser URL */
    if (updateUrl && location.hash !== `#screen-${screen}`) {
      history.pushState(
        { screen },
        "",
        `#screen-${screen}`
      );
    }

    /* Notify application modules */
    window.dispatchEvent(
      new CustomEvent("scamshield:screenchange", {
        detail: { screen },
      })
    );

    /* Refresh protected screen data */
    if (!bootstrapping && tokenExists() && refreshButtons[screen]) {
      document.getElementById(refreshButtons[screen])?.click();
    }

    return screen;
  }

  /* ================================================
     GLOBAL NAVIGATION
  ================================================ */

  document.addEventListener("click", (event) => {
    const route = event.target.closest("a[data-route]");

    if (route) {
      event.preventDefault();

      showScreen(route.dataset.route);

      document.getElementById("navLinks")?.classList.remove(
        "active",
        "open"
      );

      document.getElementById("menuToggle")?.setAttribute(
        "aria-expanded",
        "false"
      );

      return;
    }

    /* Logout */
    const logout = event.target.closest("[data-logout]");

    if (logout) {
      event.preventDefault();

      clearAuthentication();
      showScreen("home");

      return;
    }
  });

  /* ================================================
     URL / HISTORY GUARD
  ================================================ */

  function syncFromHash() {
    const match = location.hash.match(/^#screen-(.+)$/);

    const requestedScreen =
      match && screens.has(match[1])
        ? match[1]
        : "home";

    showScreen(requestedScreen, false);
  }

  window.addEventListener("hashchange", syncFromHash);

  window.addEventListener("popstate", syncFromHash);

  /* ================================================
     LOGIN SUCCESS HANDLER
  ================================================ */

  function loginSuccess() {
    if (!tokenExists()) {
      console.error("Login failed: authentication token not found.");
      return false;
    }

    showScreen("dashboard");
    return true;
  }

  /* ================================================
     GLOBAL APP API
  ================================================ */

  window.ScamShieldApp = {
    showScreen,
    tokenExists,
    clearAuthentication,
    loginSuccess,
  };

  /* ================================================
     INITIALIZATION
  ================================================ */

  function initialize() {
    syncFromHash();
    bootstrapping = false;

    console.log("ScamShield AI Router initialized.");
  }

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      initialize,
      { once: true }
    );
  } else {
    initialize();
  }
})();