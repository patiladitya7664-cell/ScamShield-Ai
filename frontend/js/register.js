"use strict";

/* =====================================================
   SCAMSHIELD AI
   REGISTRATION HANDLER

   Version: 3.0.0

   Responsibilities:
   1. Registration form handling
   2. Client-side validation
   3. Centralized API integration
   4. Password confirmation
   5. Password visibility
   6. Terms acceptance
   7. Registration feedback
   8. Login page redirection
===================================================== */

(() => {
  if (window.ScamShieldRegisterInitialized) {
    return;
  }

  window.ScamShieldRegisterInitialized = true;

  /* ================================================
     CONFIGURATION
  ================================================ */

  const REDIRECT_DELAY = 1000;

  /* ================================================
     DOM ELEMENTS
  ================================================ */

  const form = document.getElementById("registerForm");

  if (!form) {
    return;
  }

  const nameInput = document.getElementById("name");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const confirmPasswordInput =
    document.getElementById("confirmPassword");

  const termsInput = document.getElementById("terms");

  const submitButton =
    document.getElementById("registerButton");

  const messageElement =
    document.getElementById("authMessage");

  const termsLink = document.getElementById("termsLink");
  const privacyLink = document.getElementById("privacyLink");

  /* ================================================
     STATE
  ================================================ */

  let isSubmitting = false;

  const originalButtonContent =
    submitButton?.innerHTML || "";

  /* ================================================
     MESSAGE HANDLING
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
     BUTTON LOADING
  ================================================ */

  function setLoading(loading) {
    if (!submitButton) {
      return;
    }

    submitButton.disabled = loading;

    submitButton.setAttribute(
      "aria-busy",
      String(loading)
    );

    submitButton.innerHTML = loading
      ? `
        <span>Creating account...</span>
        <i class="fa-solid fa-spinner fa-spin"
           aria-hidden="true"></i>
      `
      : originalButtonContent;
  }

  /* ================================================
     PASSWORD VISIBILITY
  ================================================ */

  function initializePasswordToggles() {
    const toggles = document.querySelectorAll(
      "[data-password-target]"
    );

    toggles.forEach((button) => {
      button.addEventListener("click", () => {
        const targetId =
          button.getAttribute("data-password-target");

        const input = document.getElementById(targetId);

        if (!input) {
          return;
        }

        const isPassword =
          input.type === "password";

        input.type = isPassword
          ? "text"
          : "password";

        button.setAttribute(
          "aria-label",
          isPassword ? "Hide password" : "Show password"
        );

        const icon = button.querySelector("i");

        if (icon) {
          icon.classList.toggle("fa-eye", !isPassword);
          icon.classList.toggle("fa-eye-slash", isPassword);
        }
      });
    });
  }

  /* ================================================
     VALIDATION
  ================================================ */

  function validateForm(data) {
    const emailPattern =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    const strongPassword =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

    if (!data.name) {
      return "Please enter your full name.";
    }

    if (data.name.length < 2 || data.name.length > 60) {
      return "Name must contain 2 to 60 characters.";
    }

    if (!data.email) {
      return "Please enter your email address.";
    }

    if (!emailPattern.test(data.email)) {
      return "Please enter a valid email address.";
    }

    if (!data.password) {
      return "Please create a password.";
    }

    if (!strongPassword.test(data.password)) {
      return "Password must contain at least 8 characters, including uppercase, lowercase and a number.";
    }

    if (data.password !== data.confirmPassword) {
      return "Passwords do not match.";
    }

    if (!data.termsAccepted) {
      return "Please accept the Terms of Service and Privacy Policy.";
    }

    return null;
  }

  /* ================================================
     REDIRECT TO LOGIN
  ================================================ */

  function redirectToLogin() {
    window.location.replace("login.html");
  }

  /* ================================================
     PLACEHOLDER LEGAL LINKS
  ================================================ */

  [termsLink, privacyLink].forEach((link) => {
    link?.addEventListener("click", (event) => {
      if (link.getAttribute("href") === "#") {
        event.preventDefault();

        showMessage(
          "This document is not available yet.",
          "warning"
        );
      }
    });
  });

  /* ================================================
     CLEAR MESSAGE ON INPUT
  ================================================ */

  [
    nameInput,
    emailInput,
    passwordInput,
    confirmPasswordInput,
    termsInput
  ].forEach((input) => {
    input?.addEventListener("input", clearMessage);
    input?.addEventListener("change", clearMessage);
  });

  /* ================================================
     FORM SUBMISSION
  ================================================ */

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (isSubmitting) {
      return;
    }

    clearMessage();

    const formData = {
      name: nameInput?.value.trim() || "",
      email: emailInput?.value.trim().toLowerCase() || "",
      password: passwordInput?.value || "",
      confirmPassword: confirmPasswordInput?.value || "",
      termsAccepted: Boolean(termsInput?.checked)
    };

    const validationError = validateForm(formData);

    if (validationError) {
      showMessage(validationError, "error");
      return;
    }

    const API = window.ScamShieldAPI;

    if (!API || typeof API.register !== "function") {
      showMessage(
        "Registration service is unavailable. Please refresh the page.",
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
      const response = await API.register({
        name: formData.name,
        email: formData.email,
        password: formData.password
      });

      if (!response || response.success !== true) {
        throw new Error(
          response?.message || "Registration failed."
        );
      }

      showMessage(
        response.message ||
        "Account created successfully! Redirecting to sign in...",
        "success"
      );

      form.reset();

      window.setTimeout(
        redirectToLogin,
        REDIRECT_DELAY
      );

    } catch (error) {
      console.error(
        "ScamShield AI Registration Error:",
        error.message
      );

      showMessage(
        error.message ||
        "Unable to create your account. Please try again.",
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

  initializePasswordToggles();
  clearMessage();

  console.info(
    "ScamShield AI Registration Handler v3.0.0 initialized."
  );

})();