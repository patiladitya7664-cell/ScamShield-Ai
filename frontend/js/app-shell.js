"use strict";

/* =====================================================
   SCAMSHIELD AI
   APPLICATION ROUTER + AUTHENTICATION GUARD

   Version: 2.1.0

   Responsibilities:
   1. Application screen routing
   2. Backend-verified authentication
   3. Protected screen access
   4. Login / Register navigation
   5. Browser history management
   6. Screen-specific stylesheet loading
   7. Authentication UI synchronization
   8. Cross-tab session synchronization
   9. Session expiry handling
===================================================== */

(() => {
  /* ================================================
     INITIALIZATION GUARD
  ================================================ */

  if (window.ScamShieldAppInitialized) {
    return;
  }

  window.ScamShieldAppInitialized = true;

  /* ================================================
     ROUTE CONFIGURATION
  ================================================ */

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

  const authScreens = new Set(["login", "register"]);

  /* ================================================
     SCREEN STYLESHEETS
  ================================================ */

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
     REFRESH ACTIONS
  ================================================ */

  const refreshButtons = {
    dashboard: "refreshDashboard",
    analytics: "refreshAnalytics",
    reports: "refreshReports",
  };

  /* ================================================
     APPLICATION STATE
  ================================================ */

  let bootstrapping = true;
  let currentScreen = null;
  let navigationLocked = false;

  // Only backend-verified sessions are authenticated.
  let authVerified = false;

  let currentUser = null;

  let verificationPromise = null;

  /* ================================================
     API SERVICE
  ================================================ */

  function getAPI() {
    return window.ScamShieldAPI || null;
  }

  /* ================================================
     TOKEN MANAGEMENT
  ================================================ */

  function getToken() {
    return getAPI()?.getToken?.() || null;
  }

  function tokenExists() {
    return Boolean(getToken());
  }

  function getStoredUser() {
    return currentUser || getAPI()?.getSavedUser?.() || null;
  }

  function isAuthenticated() {
    return authVerified && tokenExists();
  }

  /* ================================================
     AUTHENTICATION UI
  ================================================ */

  function updateAuthActions(screen = currentScreen) {
    const signedIn = isAuthenticated();

    document.querySelectorAll("[data-private-link]").forEach((element) => {
      element.hidden = !signedIn;
    });

    document
      .querySelectorAll("[data-auth-link], [data-public-link]")
      .forEach((element) => {
        element.hidden = signedIn;
      });

    document.querySelectorAll("[data-logout]").forEach((element) => {
      element.hidden = !signedIn;
    });

    document.body.classList.toggle("auth-screen", authScreens.has(screen));

    document.body.classList.toggle("guest-screen", !signedIn);

    document.body.classList.toggle("authenticated", signedIn);

    document.body.classList.toggle("is-authenticated", signedIn);

    document.body.classList.toggle("is-guest", !signedIn);

    window.dispatchEvent(
      new CustomEvent("scamshield:auth-ui-updated", {
        detail: {
          authenticated: signedIn,
          user: getStoredUser(),
        },
      }),
    );
  }

  /* ================================================
     AUTHENTICATION EVENTS
  ================================================ */

  function notifyAuthenticationChange() {
    const authenticated = isAuthenticated();

    window.dispatchEvent(
      new CustomEvent("scamshield:authchange", {
        detail: {
          authenticated,
          user: getStoredUser(),
        },
      }),
    );

    updateAuthActions();
  }

  /* ================================================
     CLEAR AUTHENTICATION
  ================================================ */

  function clearAuthentication() {
    authVerified = false;
    currentUser = null;

    const API = getAPI();

    if (API?.clearSession) {
      API.clearSession();
    } else {
      const keys = [
        "scamshield_token",
        "scamshieldToken",
        "scamshield_user",
        "scamshieldUser",
        "token",
        "authToken",
        "accessToken",
      ];

      keys.forEach((key) => {
        try {
          localStorage.removeItem(key);
          sessionStorage.removeItem(key);
        } catch (error) {
          console.warn("ScamShield AI: Storage cleanup failed.");
        }
      });
    }

    notifyAuthenticationChange();
  }

  /* ================================================
     BACKEND SESSION VERIFICATION
  ================================================ */

  async function verifySession() {
    const API = getAPI();

    if (!API || typeof API.getCurrentUser !== "function") {
      authVerified = false;
      currentUser = null;

      updateAuthActions();

      return false;
    }

    if (!tokenExists()) {
      authVerified = false;
      currentUser = null;

      updateAuthActions();

      return false;
    }

    if (verificationPromise) {
      return verificationPromise;
    }

    verificationPromise = (async () => {
      try {
        const user = await API.getCurrentUser();

        if (!user || !user.id) {
          throw new Error("Invalid user profile returned by server.");
        }

        authVerified = true;
        currentUser = user;

        notifyAuthenticationChange();

        return true;
      } catch (error) {
        console.warn(
          "ScamShield AI: Session verification failed.",
          error.message,
        );

        authVerified = false;
        currentUser = null;

        // API handles 401 cleanup itself.
        // Clear remaining local session data if necessary.
        if (tokenExists()) {
          clearAuthentication();
        } else {
          notifyAuthenticationChange();
        }

        return false;
      } finally {
        verificationPromise = null;
      }
    })();

    return verificationPromise;
  }

  /* ================================================
     MOBILE NAVIGATION
  ================================================ */

  function closeMobileNavigation() {
    const navLinks = document.getElementById("navLinks");
    const menuToggle = document.getElementById("menuToggle");

    navLinks?.classList.remove("active", "open");

    menuToggle?.setAttribute("aria-expanded", "false");

    if (menuToggle) {
      menuToggle.innerHTML =
        '<i class="fa-solid fa-bars" aria-hidden="true"></i>';
    }
  }

  /* ================================================
     SCREEN STYLESHEET MANAGEMENT
  ================================================ */

  function loadScreenStyles(screen) {
    const stylesheet = document.getElementById("screenStyles");

    if (!stylesheet) {
      return;
    }

    const cssFile = styles[screen];

    if (!cssFile) {
      stylesheet.removeAttribute("href");
      stylesheet.disabled = true;

      return;
    }

    const stylesheetPath = `css/${cssFile}.css`;

    if (stylesheet.getAttribute("href") !== stylesheetPath) {
      stylesheet.href = stylesheetPath;
    }

    stylesheet.disabled = false;
  }

  /* ================================================
     SCREEN VALIDATION
  ================================================ */

  function validateScreen(screen) {
    if (!screens.has(screen)) {
      return "home";
    }

    const target = document.querySelector(`[data-screen="${screen}"]`);

    if (!target) {
      console.warn(
        `ScamShield AI: Screen "${screen}" does not exist in the current document.`,
      );

      return "home";
    }

    return screen;
  }

  /* ================================================
     URL MANAGEMENT
  ================================================ */

  function updateBrowserUrl(screen, replace = false) {
    const newHash = `#screen-${screen}`;

    if (location.hash === newHash) {
      return;
    }

    const state = {
      screen,
    };

    if (replace) {
      history.replaceState(state, "", newHash);
    } else {
      history.pushState(state, "", newHash);
    }
  }

  /* ================================================
     SCREEN NAVIGATION
  ================================================ */

  function showScreen(screen, updateUrl = true) {
    if (navigationLocked) {
      return currentScreen;
    }

    navigationLocked = true;

    try {
      screen = validateScreen(screen);

      /* ==========================================
         PROTECTED ROUTES
      ========================================== */

      if (protectedScreens.has(screen) && !isAuthenticated()) {
        screen = "login";
      }

      /* ==========================================
         AUTHENTICATED USERS
      ========================================== */

      if (authScreens.has(screen) && isAuthenticated()) {
        screen = "dashboard";
      }

      /* ==========================================
         FINAL SCREEN VALIDATION
      ========================================== */

      screen = validateScreen(screen);

      const targetScreen = document.querySelector(`[data-screen="${screen}"]`);

      if (!targetScreen) {
        console.error("ScamShield AI: Target screen is unavailable.");

        return currentScreen;
      }

      /* ==========================================
         UPDATE ACTIVE SCREENS
      ========================================== */

      document.querySelectorAll("[data-screen]").forEach((element) => {
        const active = element.dataset.screen === screen;

        element.classList.toggle("active", active);

        element.setAttribute("aria-hidden", String(!active));

        if ("inert" in element) {
          element.inert = !active;
        }
      });

      /* ==========================================
         STYLESHEETS
      ========================================== */

      loadScreenStyles(screen);

      /* ==========================================
         AUTHENTICATION UI
      ========================================== */

      updateAuthActions(screen);

      /* ==========================================
         DOCUMENT TITLE
      ========================================== */

      const formattedScreen = screen
        .replace(/-/g, " ")
        .replace(/\b\w/g, (char) => char.toUpperCase());

      document.title =
        screen === "home"
          ? "ScamShield AI | Cyber Fraud Protection"
          : `${formattedScreen} | ScamShield AI`;

      /* ==========================================
         BROWSER HISTORY
      ========================================== */

      if (updateUrl) {
        updateBrowserUrl(screen);
      }

      /* ==========================================
         SCROLL
      ========================================== */

      window.scrollTo({
        top: 0,
        behavior: "instant",
      });

      /* ==========================================
         APPLICATION STATE
      ========================================== */

      const previousScreen = currentScreen;

      currentScreen = screen;

      closeMobileNavigation();

      /* ==========================================
         SCREEN CHANGE EVENT
      ========================================== */

      window.dispatchEvent(
        new CustomEvent("scamshield:screenchange", {
          detail: {
            screen,
            previousScreen,
          },
        }),
      );

      /* ==========================================
         REFRESH SCREEN DATA
      ========================================== */

      if (!bootstrapping && isAuthenticated() && refreshButtons[screen]) {
        const refreshButton = document.getElementById(refreshButtons[screen]);

        refreshButton?.click();
      }

      return screen;
    } finally {
      navigationLocked = false;
    }
  }

  /* ================================================
     HASH ROUTING
  ================================================ */

  function getScreenFromHash() {
    const match = location.hash.match(/^#screen-([a-z-]+)$/);

    if (!match) {
      return "home";
    }

    return screens.has(match[1]) ? match[1] : "home";
  }

  function syncFromHash() {
    const requestedScreen = getScreenFromHash();

    const actualScreen = showScreen(requestedScreen, false);

    if (actualScreen && actualScreen !== requestedScreen) {
      updateBrowserUrl(actualScreen, true);
    }

    if (!location.hash || !/^#screen-[a-z-]+$/.test(location.hash)) {
      if (actualScreen) {
        updateBrowserUrl(actualScreen, true);
      }
    }
  }

  /* ================================================
     LOGIN SUCCESS
  ================================================ */

  function loginSuccess(user) {
    if (!tokenExists()) {
      console.error("ScamShield AI: Login token is missing.");

      return false;
    }

    authVerified = true;

    currentUser = user || getStoredUser();

    notifyAuthenticationChange();

    showScreen("dashboard");

    return true;
  }

  /* ================================================
     REGISTER SUCCESS
  ================================================ */

  function registerSuccess() {
    /*
      Backend registration does not issue a JWT.
      Therefore registration must return to login.
    */

    authVerified = false;
    currentUser = null;

    showScreen("login");

    return true;
  }

  /* ================================================
     LOGOUT
  ================================================ */

  function logout() {
    const API = getAPI();

    if (API?.logout) {
      API.logout();
    } else {
      clearAuthentication();
    }

    authVerified = false;
    currentUser = null;

    notifyAuthenticationChange();

    closeMobileNavigation();

    showScreen("home");

    return true;
  }

  /* ================================================
     GLOBAL NAVIGATION EVENTS
  ================================================ */

  document.addEventListener("click", (event) => {
    const route = event.target.closest("[data-route]");

    if (route) {
      event.preventDefault();

      const requestedRoute = route.dataset.route;

      if (!requestedRoute) {
        return;
      }

      showScreen(requestedRoute);

      return;
    }

    const logoutButton = event.target.closest("[data-logout]");

    if (logoutButton) {
      event.preventDefault();

      logout();
    }
  });

  /* ================================================
     AUTHENTICATION EVENTS
  ================================================ */

  window.addEventListener("scamshield:login", (event) => {
    loginSuccess(event.detail?.user);
  });

  window.addEventListener("scamshield:logout", () => {
    authVerified = false;
    currentUser = null;

    notifyAuthenticationChange();

    if (protectedScreens.has(currentScreen)) {
      showScreen("home");
    }
  });

  window.addEventListener("scamshield:authchange", (event) => {
    if (event.detail?.authenticated === false) {
      authVerified = false;
      currentUser = null;

      notifyAuthenticationChange();

      if (protectedScreens.has(currentScreen)) {
        showScreen("login");
      }
    }
  });

  window.addEventListener("scamshield:session-expired", () => {
    authVerified = false;
    currentUser = null;

    notifyAuthenticationChange();

    if (protectedScreens.has(currentScreen)) {
      showScreen("login");
    }
  });

  /* ================================================
     BROWSER HISTORY EVENTS
  ================================================ */

  window.addEventListener("hashchange", syncFromHash);

  window.addEventListener("popstate", syncFromHash);

  /* ================================================
     CROSS-TAB AUTHENTICATION
  ================================================ */

  window.addEventListener("storage", async (event) => {
    const authKeys = [
      "scamshield_token",
      "scamshieldToken",
      "scamshield_user",
      "scamshieldUser",
    ];

    if (!authKeys.includes(event.key)) {
      return;
    }

    if (!tokenExists()) {
      authVerified = false;
      currentUser = null;

      notifyAuthenticationChange();

      if (protectedScreens.has(currentScreen)) {
        showScreen("login");
      }

      return;
    }

    const valid = await verifySession();

    if (!valid && protectedScreens.has(currentScreen)) {
      showScreen("login");
    }

    if (valid && authScreens.has(currentScreen)) {
      showScreen("dashboard");
    }
  });

  /* ================================================
     GLOBAL APPLICATION API
  ================================================ */

  window.ScamShieldApp = Object.freeze({
    showScreen,

    tokenExists,

    isAuthenticated,

    getToken,

    getStoredUser,

    clearAuthentication,

    verifySession,

    loginSuccess,

    registerSuccess,

    logout,

    closeMobileNavigation,

    getCurrentScreen() {
      return currentScreen;
    },
  });

  /* ================================================
     APPLICATION INITIALIZATION
  ================================================ */

  async function initialize() {
    const homeScreen = document.querySelector('[data-screen="home"]');

    if (!homeScreen) {
      console.error("ScamShield AI: Required home screen was not found.");

      bootstrapping = false;

      return;
    }

    /*
      Validate an existing token with the backend
      before allowing access to protected screens.
    */

    if (tokenExists()) {
      await verifySession();
    } else {
      authVerified = false;
      currentUser = null;
    }

    /*
      Now resolve the requested route.
    */

    syncFromHash();

    bootstrapping = false;

    notifyAuthenticationChange();

    console.info("ScamShield AI Router v2.1.0 initialized.");
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initialize, { once: true });
  } else {
    initialize();
  }
})();
