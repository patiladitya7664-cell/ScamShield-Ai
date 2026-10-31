"use strict";

/* =========================================================
SCAMSHIELD AI — SETTINGS
File: frontend/js/setting.js

Handles:

1. Account preferences
2. Notification preferences
3. Security preferences
4. Privacy preferences
5. Appearance preferences
6. Local storage
7. Settings reset
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {
  initializeSettings();
});

/* =========================================================
CONFIGURATION
========================================================= */

const SETTINGS_STORAGE_KEY = "scamshieldSettingsV1";

const DEFAULT_SETTINGS = {
  account: {
    displayName: "",
    email: "",
  },

  notifications: {
    securityAlerts: true,
    threatAlerts: true,
    reportNotifications: true,
    productUpdates: false,
  },

  security: {
    loginVerification: true,
    loginMonitoring: true,
  },

  privacy: {
    saveAnalysisHistory: true,
    usageAnalytics: false,
  },

  appearance: {
    themePreference: "dark",
    languagePreference: "en",
    reduceAnimations: false,
  },
};

let settings = structuredClone(DEFAULT_SETTINGS);

/* =========================================================
INITIALIZATION
========================================================= */

function initializeSettings() {
  loadSettings();
  initializeAccountSettings();
  initializePreferenceControls();
  initializeAppearanceSettings();
  initializeNavigation();
  initializeButtons();
  updateCurrentYear();
}

/* =========================================================
STORAGE
========================================================= */

function loadSettings() {
  try {
    const savedSettings = localStorage.getItem(SETTINGS_STORAGE_KEY);

    if (!savedSettings) {
      settings = structuredClone(DEFAULT_SETTINGS);
      return;
    }

    const parsedSettings = JSON.parse(savedSettings);

    settings = {
      account: {
        ...DEFAULT_SETTINGS.account,
        ...parsedSettings.account,
      },

      notifications: {
        ...DEFAULT_SETTINGS.notifications,
        ...parsedSettings.notifications,
      },

      security: {
        ...DEFAULT_SETTINGS.security,
        ...parsedSettings.security,
      },

      privacy: {
        ...DEFAULT_SETTINGS.privacy,
        ...parsedSettings.privacy,
      },

      appearance: {
        ...DEFAULT_SETTINGS.appearance,
        ...parsedSettings.appearance,
      },
    };
  } catch (error) {
    console.error("Unable to load settings:", error);
    settings = structuredClone(DEFAULT_SETTINGS);
  }
}

function saveSettings() {
  try {
    localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));

    return true;
  } catch (error) {
    console.error("Unable to save settings:", error);
    showMessage(
      "settingsSaveMessage",
      "Unable to save settings in this browser.",
      "error",
    );

    return false;
  }
}

/* =========================================================
ACCOUNT SETTINGS
========================================================= */

function initializeAccountSettings() {
  const displayNameInput = document.getElementById("displayName");
  const emailInput = document.getElementById("accountEmail");

  if (displayNameInput) {
    displayNameInput.value = settings.account.displayName;
  }

  if (emailInput) {
    emailInput.value = settings.account.email;
  }

  updateAccountLabels();

  const editProfileBtn = document.getElementById("editProfileBtn");

  editProfileBtn?.addEventListener("click", () => {
    displayNameInput?.focus();
  });

  const saveAccountBtn = document.getElementById("saveAccountBtn");

  saveAccountBtn?.addEventListener("click", saveAccountSettings);
}

function saveAccountSettings() {
  const displayNameInput = document.getElementById("displayName");
  const emailInput = document.getElementById("accountEmail");

  const displayName = displayNameInput?.value.trim() || "";
  const email = emailInput?.value.trim() || "";

  if (!displayName) {
    showMessage(
      "accountSaveMessage",
      "Please enter your display name.",
      "error",
    );

    displayNameInput?.focus();
    return;
  }

  if (email && !isValidEmail(email)) {
    showMessage(
      "accountSaveMessage",
      "Please enter a valid email address.",
      "error",
    );

    emailInput?.focus();
    return;
  }

  settings.account.displayName = displayName;
  settings.account.email = email;

  if (saveSettings()) {
    updateAccountLabels();

    showMessage(
      "accountSaveMessage",
      "Account preferences saved in this browser.",
      "success",
    );
  }
}

function updateAccountLabels() {
  const nameElement = document.getElementById("settingsUserName");
  const emailElement = document.getElementById("settingsUserEmail");

  if (nameElement) {
    nameElement.textContent = settings.account.displayName || "ScamShield User";
  }

  if (emailElement) {
    emailElement.textContent = settings.account.email || "No email added";
  }
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+.[^\s@]+$/.test(email);
}

/* =========================================================
PREFERENCE CONTROLS
========================================================= */

function initializePreferenceControls() {
  const preferenceElements = {
    notifications: [
      "securityAlerts",
      "threatAlerts",
      "reportNotifications",
      "productUpdates",
    ],

    security: ["loginVerification", "loginMonitoring"],

    privacy: ["saveAnalysisHistory", "usageAnalytics"],
  };

  Object.entries(preferenceElements).forEach(([section, elementIds]) => {
    elementIds.forEach((id) => {
      const element = document.getElementById(id);

      if (!element) return;

      element.checked = Boolean(settings[section][id]);

      element.addEventListener("change", () => {
        settings[section][id] = element.checked;

        saveSettings();
      });
    });
  });
}

/* =========================================================
APPEARANCE SETTINGS
========================================================= */

function initializeAppearanceSettings() {
  const themeSelect = document.getElementById("themePreference");
  const languageSelect = document.getElementById("languagePreference");
  const reduceAnimations = document.getElementById("reduceAnimations");

  if (themeSelect) {
    themeSelect.value = settings.appearance.themePreference;

    themeSelect.addEventListener("change", () => {
      settings.appearance.themePreference = themeSelect.value;

      applyTheme(themeSelect.value);
      saveSettings();
    });
  }

  if (languageSelect) {
    languageSelect.value = settings.appearance.languagePreference;

    languageSelect.addEventListener("change", () => {
      settings.appearance.languagePreference = languageSelect.value;

      saveSettings();

      showMessage(
        "settingsSaveMessage",
        languageSelect.value === "hi"
          ? "Hindi preference saved. Translation support is not connected yet."
          : "English preference saved.",
        "success",
      );
    });
  }

  if (reduceAnimations) {
    reduceAnimations.checked = settings.appearance.reduceAnimations;

    reduceAnimations.addEventListener("change", () => {
      settings.appearance.reduceAnimations = reduceAnimations.checked;

      applyReducedMotion(reduceAnimations.checked);
      saveSettings();
    });
  }

  applyTheme(settings.appearance.themePreference);

  applyReducedMotion(settings.appearance.reduceAnimations);
}

function applyTheme(theme) {
  const root = document.documentElement;

  root.setAttribute("data-theme", theme);

  if (theme === "system") {
    const prefersDark = window.matchMedia(
      "(prefers-color-scheme: dark)",
    ).matches;

    root.setAttribute("data-active-theme", prefersDark ? "dark" : "light");
  } else {
    root.setAttribute("data-active-theme", theme);
  }
}

function applyReducedMotion(enabled) {
  document.documentElement.classList.toggle("reduce-motion", enabled);
}

/* =========================================================
NAVIGATION
========================================================= */

function initializeNavigation() {
  const navLinks = document.querySelectorAll(".settings-nav-link");

  navLinks.forEach((link) => {
    link.addEventListener("click", () => {
      navLinks.forEach((item) => {
        item.classList.remove("active");
      });

      link.classList.add("active");
    });
  });

  const sections = document.querySelectorAll(".settings-card[id]");

  if (!("IntersectionObserver" in window)) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;

        const sectionId = entry.target.id;

        navLinks.forEach((link) => {
          const target = link.getAttribute("href");

          link.classList.toggle("active", target === `#${sectionId}`);
        });
      });
    },
    {
      rootMargin: "-20% 0px -65% 0px",
    },
  );

  sections.forEach((section) => {
    observer.observe(section);
  });
}

/* =========================================================
BUTTON ACTIONS
========================================================= */

function initializeButtons() {
  const saveAllBtn = document.getElementById("saveAllSettings");
  const resetBtn = document.getElementById("resetSettingsBtn");
  const changePasswordBtn = document.getElementById("changePasswordBtn");

  saveAllBtn?.addEventListener("click", () => {
    if (saveSettings()) {
      showMessage(
        "settingsSaveMessage",
        "All preferences saved successfully.",
        "success",
      );
    }
  });

  resetBtn?.addEventListener("click", resetSettings);

  changePasswordBtn?.addEventListener("click", () => {
    alert(
      "Password management is not connected yet. " +
        "Please use the official account authentication system.",
    );
  });
}

/* =========================================================
RESET SETTINGS
========================================================= */

function resetSettings() {
  const confirmed = window.confirm(
    "Are you sure you want to reset all preferences?\n\n" +
      "This will reset browser-stored settings only.",
  );

  if (!confirmed) return;

  settings = structuredClone(DEFAULT_SETTINGS);

  try {
    localStorage.removeItem(SETTINGS_STORAGE_KEY);
  } catch (error) {
    console.error("Unable to reset settings:", error);
  }

  loadSettings();
  initializeAccountSettings();
  initializePreferenceControls();
  initializeAppearanceSettings();

  showMessage(
    "settingsSaveMessage",
    "Preferences have been reset successfully.",
    "success",
  );
}

/* =========================================================
MESSAGE HELPER
========================================================= */

function showMessage(elementId, message, type = "success") {
  const element = document.getElementById(elementId);

  if (!element) return;

  element.textContent = message;
  element.className = `settings-message ${type}`;
  element.style.display = "block";

  clearTimeout(element._messageTimer);

  element._messageTimer = setTimeout(() => {
    element.style.display = "none";
  }, 4000);
}

/* =========================================================
CURRENT YEAR
========================================================= */

function updateCurrentYear() {
  const yearElement = document.getElementById("currentYear");

  if (yearElement) {
    yearElement.textContent = new Date().getFullYear();
  }
}
