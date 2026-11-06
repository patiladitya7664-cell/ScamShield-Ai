
"use strict";

(() => {

    /* =========================================
       SCAMSHIELD AI - AUTHENTICATION
       Centralized API Authentication
    ========================================= */

    const API = window.ScamShieldAPI;

    const loginForm = document.getElementById("loginForm");
    const emailInput = document.getElementById("email");
    const passwordInput = document.getElementById("password");
    const rememberMe = document.getElementById("rememberMe");

    const loginButton = document.getElementById("loginButton");
    const togglePassword = document.getElementById("togglePassword");
    const authMessage = document.getElementById("authMessage");
    const forgotPassword = document.getElementById("forgotPassword");


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

    if (togglePassword && passwordInput) {

        togglePassword.addEventListener("click", () => {

            const isPassword = passwordInput.type === "password";

            passwordInput.type = isPassword ? "text" : "password";

            togglePassword.innerHTML = isPassword
                ? '<i class="fa-regular fa-eye-slash"></i>'
                : '<i class="fa-regular fa-eye"></i>';

            togglePassword.setAttribute(
                "aria-label",
                isPassword ? "Hide password" : "Show password"
            );

        });

    }


    /* =========================================
       EMAIL VALIDATION
    ========================================= */

    function isValidEmail(email) {

        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

    }


    /* =========================================
       BUTTON LOADING STATE
    ========================================= */

    function setLoading(isLoading) {

        if (!loginButton) return;

        loginButton.disabled = isLoading;

        loginButton.innerHTML = isLoading
            ? '<span>Signing in...</span><i class="fa-solid fa-spinner fa-spin"></i>'
            : '<span>Sign In</span><i class="fa-solid fa-arrow-right"></i>';

    }


    /* =========================================
       LOGIN FORM
    ========================================= */

    if (loginForm) {

        loginForm.addEventListener("submit", async (event) => {

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
                emailInput.focus();
                return;

            }

            if (password.length < 8) {

                showMessage("Password must contain at least 8 characters.");
                passwordInput.focus();
                return;

            }

            if (!API || typeof API.login !== "function") {

                showMessage("Authentication service is unavailable. Please refresh the page.");
                console.error("ScamShieldAPI is not loaded.");

                return;

            }

            setLoading(true);

            try {

                // Clear any previous session first.
                API.logout();

                // Centralized API login.
                const result = await API.login({
                    email,
                    password
                });

                if (!result?.token || !result?.user) {

                    throw new Error("Invalid authentication response.");

                }

                /*
                 * API module uses localStorage.
                 * Remember Me preference is retained separately.
                 */
                localStorage.setItem(
                    "scamshield_remember",
                    rememberMe?.checked ? "true" : "false"
                );

                showMessage(
                    "Login successful! Redirecting...",
                    "success"
                );

                setTimeout(() => {

                    if (window.ScamShieldApp?.showScreen) {

                        window.ScamShieldApp.showScreen("dashboard");

                    } else {

                        window.location.href = "dashboard.html";

                    }

                }, 1000);

            } catch (error) {

                console.error("Login Error:", error);

                showMessage(
                    error.message || "Unable to sign in. Please try again."
                );

            } finally {

                setLoading(false);

            }

        });

    }


    /* =========================================
       FORGOT PASSWORD
    ========================================= */

    if (forgotPassword) {

        forgotPassword.addEventListener("click", (event) => {

            event.preventDefault();

            showMessage(
                "Password recovery is not available yet. Please contact the administrator."
            );

        });

    }


    /* =========================================
       CLEAR ERRORS WHILE TYPING
    ========================================= */

    [emailInput, passwordInput].forEach((input) => {

        if (!input) return;

        input.addEventListener("input", clearMessage);

    });


    /* =========================================
       INITIALIZATION
    ========================================= */

    console.log("ScamShield AI Authentication initialized.");

})();
