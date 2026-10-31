"use strict";

/* =====================================================
SCAMSHIELD AI - LOGIN
Backend Authentication + JWT Token Management
===================================================== */

document.addEventListener("DOMContentLoaded", () => {
  // ================================================
  // CONFIGURATION
  // ================================================

  const API_BASE_URL = window.SCAMSHIELD_API_URL || "http://localhost:5000/api";

  const LOGIN_ENDPOINT = `${API_BASE_URL}/auth/login`;

  const TOKEN_KEY = "scamshieldToken";
  const USER_KEY = "scamshieldUser";

  // ================================================
  // DOM ELEMENTS
  // ================================================

  const loginForm = document.getElementById("loginForm");
  const emailInput = document.getElementById("email");
  const passwordInput = document.getElementById("password");
  const loginButton = document.getElementById("loginButton");
  const loginMessage = document.getElementById("loginMessage");

  // ================================================
  // CHECK REQUIRED ELEMENTS
  // ================================================

  if (!loginForm || !emailInput || !passwordInput) {
    console.error("Login form elements not found.");
    return;
  }

  // ================================================
  // DISPLAY MESSAGE
  // ================================================

  function showMessage(message, type = "error") {
    if (!loginMessage) {
      alert(message);
      return;
    }

    loginMessage.textContent = message;
    loginMessage.className = `login-message ${type}`;
    loginMessage.style.display = "block";
  }

  function clearMessage() {
    if (!loginMessage) return;

    loginMessage.textContent = "";
    loginMessage.style.display = "none";
  }

  // ================================================
  // BUTTON LOADING STATE
  // ================================================

  function setLoading(isLoading) {
    if (!loginButton) return;

    loginButton.disabled = isLoading;

    loginButton.innerHTML = isLoading
      ? '<i class="fa-solid fa-spinner fa-spin"></i> Signing in...'
      : "Sign In";
  }

  // ================================================
  // EMAIL VALIDATION
  // ================================================

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  // ================================================
  // LOGIN REQUEST
  // ================================================

  async function handleLogin(event) {
    event.preventDefault();

    clearMessage();

    const email = emailInput.value.trim().toLowerCase();
    const password = passwordInput.value;

    if (!email || !password) {
      showMessage("Please enter your email and password.");
      return;
    }

    if (!isValidEmail(email)) {
      showMessage("Please enter a valid email address.");
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(LOGIN_ENDPOINT, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },

        body: JSON.stringify({
          email,
          password,
        }),
      });

      const data = await response.json().catch(() => ({}));

      if (!response.ok || !data.success) {
        throw new Error(data.message || "Login failed. Please try again.");
      }

      if (!data.token || !data.user) {
        throw new Error("Invalid response received from server.");
      }

      // ========================================
      // SAVE JWT TOKEN AND USER
      // ========================================

      localStorage.setItem(TOKEN_KEY, data.token);

      localStorage.setItem(USER_KEY, JSON.stringify(data.user));

      showMessage("Login successful. Redirecting...", "success");

      // ========================================
      // REDIRECT TO DASHBOARD
      // ========================================

      setTimeout(() => {
        window.location.href = "dashboard.html";
      }, 700);
    } catch (error) {
      console.error("Login Error:", error);

      showMessage(error.message || "Unable to connect to the server.");
    } finally {
      setLoading(false);
    }
  }

  // ================================================
  // FORM SUBMISSION
  // ================================================

  loginForm.addEventListener("submit", handleLogin);

  // ================================================
  // CLEAR MESSAGE ON INPUT
  // ================================================

  emailInput.addEventListener("input", clearMessage);
  passwordInput.addEventListener("input", clearMessage);

  console.log("ScamShield AI Login Initialized.");
});
