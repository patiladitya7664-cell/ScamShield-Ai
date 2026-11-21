"use strict";

/* =====================================================
   SCAMSHIELD AI
   AUTHENTICATION HANDLER

   Version: 3.0.0

   Responsibilities:
   1. Login form handling
   2. Client-side validation
   3. Centralized API integration
   4. Remember Me support
   5. Password visibility
   6. Authentication feedback
   7. Dashboard redirection
===================================================== */

(() => {
  if (window.ScamShieldAuthInitialized) {
    return;
  }

  window.ScamShieldAuthInitialized = true;

  /* ================================================
     CONFIGURATION
  ================================================ */

  const REDIRECT_DELAY = 700;

  /* ================================================
     DOM ELEMENTS
  ================================================ */

  const form = document.getElementById("loginForm");

  // This script may be loaded on other pages.
  if (!form) {
    return;
  }

  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const rememberInput = document.getElementById("rememberMe");

  const submitButton = document.getElementById("loginButton");
  const messageElement = document.getElementById("authMessage");

  const passwordToggle = document.getElementById("togglePassword");
  const forgotPassword = document.getElementById("forgotPassword");

  /* ================================================
     STATE
  ================================================ */

  let isSubmitting = false;

  /* ================================================
     MESSAGE HANDLER
  ================================================ */

  function showMessage(message, type = "error") {
    if (!messageElement) {
      return;
    }

    messageElement.textContent = message;

    messageElement.classList.remove(
      "success",
      "error",
      "warning"
    );

    messageElement.classList.add(type);
    messageElement.hidden = false;
  }

  function clearMessage() {
    if (!messageElement) {
      return;
    }

    messageElement.textContent = "";
    messageElement.classList.remove(
      "success",
      "error",
      "warning"
    );

    messageElement.hidden = true;
  }

  /* ================================================
     BUTTON LOADING STATE
  ================================================ */

  const originalButtonContent = submitButton?.innerHTML;

  function setLoading(loading) {
    if (!submitButton) {
      return;
    }

    submitButton.disabled = loading;

    submitButton.setAttribute(
      "aria-busy",
      String(loading)
    );

    if (loading) {
      submitButton.innerHTML = `
        <span>Signing in...</span>
        <i class="fa-solid fa-spinner fa-spin"
           aria-hidden="true"></i>
      `;
    } else {
      submitButton.innerHTML = originalButtonContent;
    }
  }

  /* ================================================
     PASSWORD VISIBILITY
  ================================================ */

  function togglePasswordVisibility() {
    if (!passwordInput || !passwordToggle) {
      return;
    }

    const isPassword =
      passwordInput.type === "password";

    passwordInput.type = isPassword
      ? "text"
      : "password";

    passwordToggle.setAttribute(
      "aria-label",
      isPassword ? "Hide password" : "Show password"
    );

    const icon = passwordToggle.querySelector("i");

    if (icon) {
      icon.classList.toggle("fa-eye", !isPassword);
      icon.classList.toggle("fa-eye-slash", isPassword);
    }
  }

  passwordToggle?.addEventListener(
    "click",
    togglePasswordVisibility
  );

  /* ================================================
     INPUT VALIDATION
  ================================================ */

  function validateCredentials(email, password) {
    const emailPattern =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!email) {
      return "Please enter your email address.";
    }

    if (!emailPattern.test(email)) {
      return "Please enter a valid email address.";
    }

    if (!password) {
      return "Please enter your password.";
    }

    if (password.length < 8) {
      return "Password must contain at least 8 characters.";
    }

    return null;
  }

  /* ================================================
     REDIRECT AFTER LOGIN
  ================================================ */

  function redirectToDashboard() {
    if (
      window.ScamShieldApp &&
      typeof window.ScamShieldApp.showScreen === "function"
    ) {
      window.ScamShieldApp.showScreen("dashboard");
      return;
    }

    window.location.replace("../index.html#dashboard");
  }

  /* ================================================
     FORGOT PASSWORD
  ================================================ */

  forgotPassword?.addEventListener("click", (event) => {
    event.preventDefault();

    showMessage(
      "Password recovery is not available yet. Please contact your administrator.",
      "warning"
    );
  });

  /* ================================================
     CLEAR MESSAGE ON INPUT
  ================================================ */

  [emailInput, passwordInput].forEach((input) => {
    input?.addEventListener("input", clearMessage);
  });

  /* ================================================
     LOGIN SUBMISSION
  ================================================ */

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (isSubmitting) {
      return;
    }

    clearMessage();

    const email = emailInput?.value.trim().toLowerCase() || "";
    const password = passwordInput?.value || "";

    const validationError = validateCredentials(
      email,
      password
    );

    if (validationError) {
      showMessage(validationError, "error");
      return;
    }

    const API = window.ScamShieldAPI;

    if (!API || typeof API.login !== "function") {
      showMessage(
        "Authentication service is unavailable. Please refresh the page.",
        "error"
      );

      console.error(
        "ScamShield AI: ScamShieldAPI is not initialized."
      );

      return;
    }

    isSubmitting = true;
    setLoading(true);

    try {
      const remember = Boolean(
        rememberInput?.checked
      );

      const response = await API.login(
        {
          email,
          password
        },
        {
          remember
        }
      );

      if (
        !response ||
        response.success !== true ||
        !response.token ||
        !response.user
      ) {
        throw new Error(
          response?.message || "Login failed."
        );
      }

      showMessage(
        "Login successful! Redirecting to your dashboard...",
        "success"
      );

      form.reset();

      window.setTimeout(
        redirectToDashboard,
        REDIRECT_DELAY
      );

    } catch (error) {
      console.error(
        "ScamShield AI Login Error:",
        error.message
      );

      showMessage(
        error.message ||
        "Unable to sign in. Please try again.",
        "error"
      );

    } finally {
      isSubmitting = false;
      setLoading(false);
    }
  });

  /* ================================================
     INITIALIZATION
  ================================================ */

  clearMessage();

  console.info(
    "ScamShield AI Authentication Handler v3.0.0 initialized."
  );

})();