(() => {
"use strict";

/* =========================================
   SCAMSHIELD AI - AUTHENTICATION
========================================= */

const API_BASE_URL = "http://localhost:5000/api";

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
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    return emailPattern.test(email);
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
   LOGIN FORM SUBMISSION
========================================= */

if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
        event.preventDefault();

        clearMessage();

        const email = emailInput.value.trim().toLowerCase();
        const password = passwordInput.value;

        // Empty field validation
        if (!email || !password) {
            showMessage("Please enter your email and password.");
            return;
        }

        // Email validation
        if (!isValidEmail(email)) {
            showMessage("Please enter a valid email address.");
            emailInput.focus();
            return;
        }

        // Password validation
        if (password.length < 8) {
            showMessage("Password must contain at least 8 characters.");
            passwordInput.focus();
            return;
        }

        setLoading(true);

        try {
            const response = await fetch(`${API_BASE_URL}/auth/login`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    email,
                    password
                })
            });

            const result = await response.json();

            if (!response.ok || !result.success) {
                throw new Error(
                    result.message || "Unable to sign in. Please try again."
                );
            }

            // Validate token response
            if (!result.token) {
                throw new Error("Login response did not contain an authentication token.");
            }

            // Save authentication token
            const storage = rememberMe.checked
                ? localStorage
                : sessionStorage;

            storage.setItem("scamshieldToken", result.token);

            // Save safe user information only
            if (result.user) {
                const safeUser = {
                    name: result.user.name,
                    email: result.user.email,
                    role: result.user.role
                };

                storage.setItem(
                    "scamshieldUser",
                    JSON.stringify(safeUser)
                );
            }

            showMessage("Login successful! Redirecting...", "success");

            setTimeout(() => {
                window.ScamShieldApp?.showScreen("dashboard");
            }, 1000);

        } catch (error) {
            console.error("Login Error:", error);

            showMessage(
                error.message || "Something went wrong. Please try again."
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

document.addEventListener("DOMContentLoaded", () => {
    console.log("ScamShield AI Authentication initialized.");
});

})();
