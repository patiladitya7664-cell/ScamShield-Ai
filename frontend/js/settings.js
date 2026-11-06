"use strict";

/* =========================================================
   SCAMSHIELD AI — SETTINGS
   File: frontend/js/setting.js

   Features:
   1. Account preferences
   2. Notification preferences
   3. Security preferences
   4. Privacy preferences
   5. Appearance preferences
   6. Local storage persistence
   7. Settings reset
========================================================= */

document.addEventListener("DOMContentLoaded", initializeSettings);

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

let settings = cloneDefaults();

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
   UTILITIES
========================================================= */

function cloneDefaults() {
  return JSON.parse(JSON.stringify(DEFAULT_SETTINGS));
}

function isObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* =========================================================
   STORAGE
========================================================= */

function loadSettings() {
  try {
    const savedSettings = localStorage.getItem(
      SETTINGS_STORAGE_KEY,
    );

    if (!savedSettings) {
      settings = cloneDefaults();
      return;
    }

    const parsedSettings = JSON.parse(savedSettings);

    if (!isObject(parsedSettings)) {
      throw new Error("Invalid settings format.");
    }

    settings = {
      account: {
        ...DEFAULT_SETTINGS.account,
        ...(isObject(parsedSettings.account)
          ? parsedSettings.account
          : {}),
      },

      notifications: {
        ...DEFAULT_SETTINGS.notifications,
        ...(isObject(parsedSettings.notifications)
          ? parsedSettings.notifications
          : {}),
      },

      security: {
        ...DEFAULT_SETTINGS.security,
        ...(isObject(parsedSettings.security)
          ? parsedSettings.security
          : {}),
      },

      privacy: {
        ...DEFAULT_SETTINGS.privacy,
        ...(isObject(parsedSettings.privacy)
          ? parsedSettings.privacy
          : {}),
      },

      appearance: {
        ...DEFAULT_SETTINGS.appearance,
        ...(isObject(parsedSettings.appearance)
          ? parsedSettings.appearance
          : {}),
      },
    };
  } catch (error) {
    console.error("Unable to load settings:", error);

    settings = cloneDefaults();
  }
}

function saveSettings() {
  try {
    localStorage.setItem(
      SETTINGS_STORAGE_KEY,
      JSON.stringify(settings),
    );

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

  document
    .getElementById("editProfileBtn")
    ?.addEventListener("click", () => {
      displayNameInput?.focus();
    });

  document
    .getElementById("saveAccountBtn")
    ?.addEventListener("click", saveAccountSettings);
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

  if (!saveSettings()) return;

  updateAccountLabels();

  showMessage(
    "accountSaveMessage",
    "Account preferences saved in this browser.",
    "success",
  );
}

function updateAccountLabels() {
  const nameElement = document.getElementById("settingsUserName");
  const emailElement = document.getElementById("settingsUserEmail");

  if (nameElement) {
    nameElement.textContent =
      settings.account.displayName || "ScamShield User";
  }

  if (emailElement) {
    emailElement.textContent =
      settings.account.email || "No email added";
  }
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

    security: [
      "loginVerification",
      "loginMonitoring",
    ],

    privacy: [
      "saveAnalysisHistory",
      "usageAnalytics",
    ],
  };

  Object.entries(preferenceElements).forEach(
    ([section, elementIds]) => {
      elementIds.forEach((id) => {
        const element = document.getElementById(id);

        if (!element) return;

        element.checked = Boolean(settings[section][id]);

        element.addEventListener("change", () => {
          settings[section][id] = element.checked;

          saveSettings();
        });
      });
    },
  );
}

/* =========================================================
   APPEARANCE SETTINGS
========================================================= */

function initializeAppearanceSettings() {
  const themeSelect = document.getElementById("themePreference");

  const languageSelect = document.getElementById(
    "languagePreference",
  );

  const reduceAnimations = document.getElementById(
    "reduceAnimations",
  );

  if (themeSelect) {
    themeSelect.value = settings.appearance.themePreference;

    themeSelect.addEventListener("change", () => {
      const selectedTheme = themeSelect.value;

      if (!["dark", "light", "system"].includes(selectedTheme)) {
        return;
      }

      settings.appearance.themePreference = selectedTheme;

      applyTheme(selectedTheme);
      saveSettings();
    });
  }

  if (languageSelect) {
    languageSelect.value =
      settings.appearance.languagePreference;

    languageSelect.addEventListener("change", () => {
      const selectedLanguage = languageSelect.value;

      if (!["en", "hi"].includes(selectedLanguage)) {
        return;
      }

      settings.appearance.languagePreference = selectedLanguage;

      saveSettings();

      showMessage(
        "settingsSaveMessage",
        selectedLanguage === "hi"
          ? "Hindi preference saved. Translation support is not connected yet."
          : "English preference saved.",
        "success",
      );
    });
  }

  if (reduceAnimations) {
    reduceAnimations.checked =
      settings.appearance.reduceAnimations;

    reduceAnimations.addEventListener("change", () => {
      settings.appearance.reduceAnimations =
        reduceAnimations.checked;

      applyReducedMotion(reduceAnimations.checked);
      saveSettings();
    });
  }

  applyTheme(settings.appearance.themePreference);

  applyReducedMotion(settings.appearance.reduceAnimations);
}

/* =========================================================
   THEME MANAGEMENT
========================================================= */

function applyTheme(theme) {
  const root = document.documentElement;

  if (!["dark", "light", "system"].includes(theme)) {
    theme = "dark";
  }

  root.setAttribute("data-theme", theme);

  if (theme === "system") {
    updateSystemTheme();
    return;
  }

  root.setAttribute("data-active-theme", theme);
}

function updateSystemTheme() {
  const prefersDark = window.matchMedia(
    "(prefers-color-scheme: dark)",
  ).matches;

  document.documentElement.setAttribute(
    "data-active-theme",
    prefersDark ? "dark" : "light",
  );
}

function initializeSystemThemeListener() {
  if (!window.matchMedia) return;

  const mediaQuery = window.matchMedia(
    "(prefers-color-scheme: dark)",
  );

  const handleThemeChange = () => {
    if (settings.appearance.themePreference === "system") {
      updateSystemTheme();
    }
  };

  if (mediaQuery.addEventListener) {
    mediaQuery.addEventListener("change", handleThemeChange);
  } else {
    mediaQuery.addListener(handleThemeChange);
  }
}

function applyReducedMotion(enabled) {
  document.documentElement.classList.toggle(
    "reduce-motion",
    Boolean(enabled),
  );
}

/* =========================================================
   NAVIGATION
========================================================= */

function initializeNavigation() {
  const navLinks = document.querySelectorAll(
    ".settings-nav-link",
  );

  const sections = document.querySelectorAll(
    ".settings-card[id]",
  );

  navLinks.forEach((link) => {
    link.addEventListener("click", () => {
      navLinks.forEach((item) => {
        item.classList.remove("active");
      });

      link.classList.add("active");
    });
  });

  if (!("IntersectionObserver" in window)) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;

        const sectionId = entry.target.id;

        navLinks.forEach((link) => {
          const target = link.getAttribute("href");

          link.classList.toggle(
            "active",
            target === `#${sectionId}`,
          );
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
  document
    .getElementById("saveAllSettings")
    ?.addEventListener("click", () => {
      if (!saveSettings()) return;

      showMessage(
        "settingsSaveMessage",
        "All preferences saved successfully.",
        "success",
      );
    });

  document
    .getElementById("resetSettingsBtn")
    ?.addEventListener("click", resetSettings);

  document
    .getElementById("changePasswordBtn")
    ?.addEventListener("click", () => {
      showMessage(
        "settingsSaveMessage",
        "Password management is not connected yet.",
        "error",
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

  try {
    localStorage.removeItem(SETTINGS_STORAGE_KEY);
  } catch (error) {
    console.error("Unable to reset settings:", error);

    showMessage(
      "settingsSaveMessage",
      "Unable to reset settings in this browser.",
      "error",
    );

    return;
  }

  settings = cloneDefaults();

  initializeAccountSettings();
  refreshPreferenceControls();
  refreshAppearanceControls();

  showMessage(
    "settingsSaveMessage",
    "Preferences have been reset successfully.",
    "success",
  );
}

/* =========================================================
   REFRESH CONTROLS AFTER RESET
========================================================= */

function refreshPreferenceControls() {
  const preferenceIds = [
    "securityAlerts",
    "threatAlerts",
    "reportNotifications",
    "productUpdates",
    "loginVerification",
    "loginMonitoring",
    "saveAnalysisHistory",
    "usageAnalytics",
  ];

  preferenceIds.forEach((id) => {
    const element = document.getElementById(id);

    if (!element) return;

    const section = Object.keys(settings).find(
      (key) =>
        key !== "account" &&
        key !== "appearance" &&
        Object.prototype.hasOwnProperty.call(settings[key], id),
    );

    if (section) {
      element.checked = Boolean(settings[section][id]);
    }
  });
}

function refreshAppearanceControls() {
  const themeSelect = document.getElementById("themePreference");

  const languageSelect = document.getElementById(
    "languagePreference",
  );

  const reduceAnimations = document.getElementById(
    "reduceAnimations",
  );

  if (themeSelect) {
    themeSelect.value = settings.appearance.themePreference;
  }

  if (languageSelect) {
    languageSelect.value =
      settings.appearance.languagePreference;
  }

  if (reduceAnimations) {
    reduceAnimations.checked =
      settings.appearance.reduceAnimations;
  }

  applyTheme(settings.appearance.themePreference);

  applyReducedMotion(settings.appearance.reduceAnimations);
}

/* =========================================================
   MESSAGE HELPER
========================================================= */

function showMessage(
  elementId,
  message,
  type = "success",
) {
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

/* =========================================================
   SYSTEM THEME LISTENER
========================================================= */

initializeSystemThemeListener();