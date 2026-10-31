(() => {
  "use strict";

  const screens = new Set([
    "home", "dashboard", "detection", "agents", "decoy-lab",
    "intelligence", "analytics", "reports", "settings", "login", "register",
  ]);
  let bootstrapping = true;
  const refreshButtons = {
    dashboard: "refreshDashboard",
    analytics: "refreshAnalytics",
    reports: "refreshReports",
  };
  const styles = {
    dashboard: "dashboard", detection: "detection", agents: "agents",
    "decoy-lab": "decoy-lab", intelligence: "intelligence",
    analytics: "analytics", reports: "reports", settings: "setting",
    login: "auth", register: "auth",
  };

  function tokenExists() {
    return Boolean(localStorage.getItem("scamshieldToken") || sessionStorage.getItem("scamshieldToken"));
  }

  function updateAuthActions(screen) {
    const signedIn = tokenExists();
    document.querySelectorAll("[data-auth-link]").forEach((link) => { link.hidden = signedIn; });
    document.querySelectorAll("[data-logout]").forEach((button) => { button.hidden = !signedIn; });
    document.body.classList.toggle("auth-screen", screen === "login" || screen === "register");
  }

  function showScreen(screen, updateUrl = true) {
    if (!screens.has(screen)) screen = "home";
    document.querySelectorAll("[data-screen]").forEach((element) => {
      const active = element.dataset.screen === screen;
      element.classList.toggle("active", active);
      element.setAttribute("aria-hidden", String(!active));
    });

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
    document.title = `${screen === "home" ? "ScamShield AI" : screen.replaceAll("-", " ").replace(/\b\w/g, (c) => c.toUpperCase()) + " | ScamShield AI"}`;
    window.scrollTo({ top: 0, behavior: "instant" });
    if (updateUrl && location.hash !== `#screen-${screen}`) history.pushState({ screen }, "", `#screen-${screen}`);
    window.dispatchEvent(new CustomEvent("scamshield:screenchange", { detail: { screen } }));
    if (!bootstrapping && tokenExists() && refreshButtons[screen]) {
      document.getElementById(refreshButtons[screen])?.click();
    }
  }

  document.addEventListener("click", (event) => {
    const route = event.target.closest("a[data-route]");
    if (route) {
      event.preventDefault();
      showScreen(route.dataset.route);
      document.getElementById("navLinks")?.classList.remove("active");
      document.getElementById("menuToggle")?.setAttribute("aria-expanded", "false");
      return;
    }
    const logout = event.target.closest("[data-logout]");
    if (logout) {
      localStorage.removeItem("scamshieldToken");
      localStorage.removeItem("scamshieldUser");
      sessionStorage.removeItem("scamshieldToken");
      sessionStorage.removeItem("scamshieldUser");
      showScreen("home");
    }
  });

  function syncFromHash() {
    const match = location.hash.match(/^#screen-(.+)$/);
    showScreen(match && screens.has(match[1]) ? match[1] : "home", false);
  }
  window.addEventListener("hashchange", syncFromHash);
  window.ScamShieldApp = { showScreen, tokenExists };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      syncFromHash();
      bootstrapping = false;
    }, { once: true });
  } else {
    syncFromHash();
    bootstrapping = false;
  }
})();
