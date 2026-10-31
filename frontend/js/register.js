(() => {
  "use strict";

  /* =========================================
   SCAMSHIELD AI - REGISTRATION
========================================= */

  const API_BASE_URL = "http://localhost:5000/api";

  const registerForm = document.getElementById("registerForm");

  const nameInput = document.getElementById("name");
  const emailInput = document.getElementById("registerEmail");
  const passwordInput = document.getElementById("registerPassword");
  const confirmPasswordInput = document.getElementById("confirmPassword");
  const termsInput = document.getElementById("terms");

  const registerButton = document.getElementById("registerButton");
  const authMessage = document.getElementById("registerAuthMessage");

  /* =========================================
   MESSAGE HANDLER
========================================= */

  function showMessage(message, type = "error") {
    if (!authMessage) return;

    authMessage.textContent = message;
    authMessage.className = `auth-message show ${type}`;
  }

  function clearMessage() {
    if (!authMessage) return;

    authMessage.textContent = "";
    authMessage.className = "auth-message";
  }

  /* =========================================
   PASSWORD VISIBILITY
========================================= */

  document.querySelectorAll("[data-password-target]").forEach((button) => {
    button.addEventListener("click", () => {
      const targetId = button.dataset.passwordTarget;
      const input = document.getElementById(targetId);

      if (!input) return;

      const isPassword = input.type === "password";

      input.type = isPassword ? "text" : "password";

      button.innerHTML = isPassword
        ? '<i class="fa-regular fa-eye-slash"></i>'
        : '<i class="fa-regular fa-eye"></i>';

      button.setAttribute(
        "aria-label",
        isPassword ? "Hide password" : "Show password",
      );
    });
  });

  /* =========================================
   VALIDATION HELPERS
========================================= */

  function isValidEmail(email) {
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    return emailPattern.test(email);
  }

  function isStrongPassword(password) {
    return (
      password.length >= 8 &&
      /[A-Z]/.test(password) &&
      /[a-z]/.test(password) &&
      /[0-9]/.test(password)
    );
  }

  /* =========================================
   BUTTON LOADING STATE
========================================= */

  function setLoading(isLoading) {
    if (!registerButton) return;

    registerButton.disabled = isLoading;

    registerButton.innerHTML = isLoading
      ? '<span>Creating account...</span><i class="fa-solid fa-spinner fa-spin"></i>'
      : '<span>Create Account</span><i class="fa-solid fa-arrow-right"></i>';
  }

  /* =========================================
   REGISTRATION SUBMISSION
========================================= */

  if (registerForm) {
    registerForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      clearMessage();

      const name = nameInput.value.trim();
      const email = emailInput.value.trim().toLowerCase();
      const password = passwordInput.value;
      const confirmPassword = confirmPasswordInput.value;

      // Name validation
      if (name.length < 2 || name.length > 60) {
        showMessage("Name must contain between 2 and 60 characters.");

        nameInput.focus();

        return;
      }

      // Email validation
      if (!isValidEmail(email)) {
        showMessage("Please enter a valid email address.");

        emailInput.focus();

        return;
      }

      // Password validation
      if (!isStrongPassword(password)) {
        showMessage(
          "Password must contain at least 8 characters, one uppercase letter, one lowercase letter and one number.",
        );

        passwordInput.focus();

        return;
      }

      // Confirm password validation
      if (password !== confirmPassword) {
        showMessage("Passwords do not match.");

        confirmPasswordInput.focus();

        return;
      }

      // Terms validation
      if (!termsInput.checked) {
        showMessage("Please accept the Terms of Service and Privacy Policy.");

        termsInput.focus();

        return;
      }

      setLoading(true);

      try {
        const response = await fetch(`${API_BASE_URL}/auth/register`, {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          body: JSON.stringify({
            name,
            email,
            password,
          }),
        });

        const result = await response.json();

        if (!response.ok || !result.success) {
          throw new Error(
            result.message || "Registration failed. Please try again.",
          );
        }

        showMessage(
          "Account created successfully! Redirecting to login...",
          "success",
        );

        registerForm.reset();

        setTimeout(() => {
          window.ScamShieldApp?.showScreen("login");
        }, 1500);
      } catch (error) {
        console.error("Registration Error:", error);

        showMessage(
          error.message || "Unable to create account. Please try again.",
        );
      } finally {
        setLoading(false);
      }
    });
  }

  /* =========================================
   CLEAR MESSAGE ON INPUT
========================================= */

  [nameInput, emailInput, passwordInput, confirmPasswordInput].forEach(
    (input) => {
      if (!input) return;

      input.addEventListener("input", clearMessage);
    },
  );

  /* =========================================
   INITIALIZATION
========================================= */

  document.addEventListener("DOMContentLoaded", () => {
    console.log("ScamShield AI Registration initialized.");
  });
})();
