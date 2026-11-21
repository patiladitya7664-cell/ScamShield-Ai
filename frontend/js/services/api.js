"use strict";

/* =====================================================
   SCAMSHIELD AI
   CENTRALIZED API SERVICE

   Version: 3.0.0

   Responsibilities:
   1. Centralized backend communication
   2. JWT authentication
   3. Login and registration
   4. Remember Me support
   5. Session management
   6. API error handling
   7. Request timeout and cancellation
   8. Current user management
===================================================== */

(() => {
  if (window.ScamShieldAPI) {
    return;
  }

  /* ================================================
     CONFIGURATION
  ================================================ */

  const API_BASE_URL = (
    window.SCAMSHIELD_API_URL ||
    "http://localhost:5000/api"
  ).replace(/\/+$/, "");

  const DEFAULT_TIMEOUT = 30000;

  const TOKEN_KEYS = [
    "scamshield_token",
    "scamshieldToken",
    "token",
    "authToken",
    "accessToken"
  ];

  const USER_KEYS = [
    "scamshield_user",
    "scamshieldUser"
  ];

  const REMEMBER_KEY = "scamshield_remember";

  /* ================================================
     CUSTOM API ERROR
  ================================================ */

  class ApiError extends Error {
    constructor(message, status = 0, data = null) {
      super(message);

      this.name = "ApiError";
      this.status = status;
      this.data = data;
    }
  }

  /* ================================================
     STORAGE HELPERS
  ================================================ */

  function getStorage(type) {
    try {
      return type === "session"
        ? window.sessionStorage
        : window.localStorage;
    } catch {
      return null;
    }
  }

  function safeGet(storage, key) {
    try {
      return storage?.getItem(key) || null;
    } catch {
      return null;
    }
  }

  function safeSet(storage, key, value) {
    try {
      storage?.setItem(key, value);
      return true;
    } catch {
      return false;
    }
  }

  function safeRemove(storage, key) {
    try {
      storage?.removeItem(key);
    } catch {
      // Ignore storage cleanup failures.
    }
  }

  function removeKeys(keys) {
    ["local", "session"].forEach((type) => {
      const storage = getStorage(type);

      keys.forEach((key) => {
        safeRemove(storage, key);
      });
    });
  }

  /* ================================================
     TOKEN MANAGEMENT
  ================================================ */

  function getToken() {
    for (const type of ["local", "session"]) {
      const storage = getStorage(type);

      for (const key of TOKEN_KEYS) {
        const token = safeGet(storage, key);

        if (token) {
          return token;
        }
      }
    }

    return null;
  }

  function getActiveStorage() {
    for (const type of ["local", "session"]) {
      const storage = getStorage(type);

      for (const key of TOKEN_KEYS) {
        if (safeGet(storage, key)) {
          return storage;
        }
      }
    }

    return getStorage("local");
  }

  function saveToken(token, remember = true) {
    if (!token || typeof token !== "string") {
      throw new ApiError("Invalid authentication token.");
    }

    const targetStorage = getStorage(
      remember ? "local" : "session"
    );

    if (!targetStorage) {
      throw new ApiError("Browser storage is unavailable.");
    }

    removeKeys(TOKEN_KEYS);

    const saved = safeSet(
      targetStorage,
      "scamshield_token",
      token
    );

    if (!saved) {
      throw new ApiError("Unable to save your login session.");
    }

    safeSet(
      getStorage("local"),
      REMEMBER_KEY,
      remember ? "true" : "false"
    );
  }

  /* ================================================
     USER MANAGEMENT
  ================================================ */

  function getSavedUser() {
    for (const type of ["local", "session"]) {
      const storage = getStorage(type);

      for (const key of USER_KEYS) {
        const rawUser = safeGet(storage, key);

        if (!rawUser) {
          continue;
        }

        try {
          return JSON.parse(rawUser);
        } catch {
          safeRemove(storage, key);
        }
      }
    }

    return null;
  }

  function saveUser(user) {
    if (!user || typeof user !== "object") {
      return;
    }

    const storage = getActiveStorage();

    if (!storage) {
      return;
    }

    removeKeys(USER_KEYS);

    safeSet(
      storage,
      "scamshield_user",
      JSON.stringify(user)
    );
  }

  /* ================================================
     SESSION MANAGEMENT
  ================================================ */

  function saveSession(token, user, remember = true) {
    if (!token || !user) {
      throw new ApiError(
        "Invalid login response from the server."
      );
    }

    saveToken(token, remember);
    saveUser(user);

    window.dispatchEvent(
      new CustomEvent("scamshield:authchange", {
        detail: {
          authenticated: true,
          user
        }
      })
    );
  }

  function clearSession() {
    const hadToken = Boolean(getToken());

    removeKeys([
      ...TOKEN_KEYS,
      ...USER_KEYS
    ]);

    const rememberStorage = getStorage("local");

    safeRemove(rememberStorage, REMEMBER_KEY);

    window.dispatchEvent(
      new CustomEvent("scamshield:authchange", {
        detail: {
          authenticated: false,
          user: null
        }
      })
    );

    if (hadToken) {
      window.dispatchEvent(
        new CustomEvent("scamshield:session-expired")
      );
    }
  }

  /* ================================================
     RESPONSE PARSER
  ================================================ */

  async function parseResponse(response) {
    const contentType =
      response.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
      try {
        return await response.json();
      } catch {
        throw new ApiError(
          "The server returned an invalid response.",
          response.status
        );
      }
    }

    const text = await response.text();

    return {
      message: text || "Unexpected server response."
    };
  }

  /* ================================================
     ERROR MESSAGE
  ================================================ */

  function getErrorMessage(data, status) {
    if (data && typeof data === "object") {
      if (typeof data.message === "string") {
        return data.message;
      }

      if (typeof data.error === "string") {
        return data.error;
      }
    }

    const messages = {
      400: "Invalid request.",
      401: "Your session is invalid or has expired.",
      403: "You do not have permission to perform this action.",
      404: "Requested resource was not found.",
      409: "This resource already exists.",
      422: "Unable to process your request.",
      429: "Too many requests. Please try again later.",
      500: "Internal server error.",
      502: "Server is temporarily unavailable.",
      503: "Service is currently unavailable."
    };

    return (
      messages[status] ||
      "Something went wrong. Please try again."
    );
  }

  /* ================================================
     CENTRAL REQUEST HANDLER
  ================================================ */

  async function request(path, options = {}) {
    if (
      typeof path !== "string" ||
      !path.trim() ||
      !path.startsWith("/")
    ) {
      throw new ApiError("Invalid API endpoint.");
    }

    const {
      method = "GET",
      headers = {},
      body,
      signal: externalSignal,
      timeout = DEFAULT_TIMEOUT,
      authenticated = true
    } = options;

    const controller = new AbortController();

    let timedOut = false;

    const timeoutId = window.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeout);

    const handleExternalAbort = () => {
      controller.abort();
    };

    if (externalSignal) {
      if (externalSignal.aborted) {
        controller.abort();
      } else {
        externalSignal.addEventListener(
          "abort",
          handleExternalAbort,
          { once: true }
        );
      }
    }

    try {
      const requestHeaders = new Headers(headers);

      requestHeaders.set("Accept", "application/json");

      const isFormData =
        typeof FormData !== "undefined" &&
        body instanceof FormData;

      if (body !== undefined && !isFormData) {
        requestHeaders.set(
          "Content-Type",
          "application/json"
        );
      }

      if (authenticated) {
        const token = getToken();

        if (token) {
          requestHeaders.set(
            "Authorization",
            `Bearer ${token}`
          );
        }
      }

      const response = await fetch(
        `${API_BASE_URL}${path}`,
        {
          method: method.toUpperCase(),
          headers: requestHeaders,
          body:
            body === undefined
              ? undefined
              : isFormData
                ? body
                : typeof body === "string"
                  ? body
                  : JSON.stringify(body),
          signal: controller.signal
        }
      );

      const data = await parseResponse(response);

      if (!response.ok) {
        if (response.status === 401 && authenticated) {
          clearSession();
        }

        throw new ApiError(
          getErrorMessage(data, response.status),
          response.status,
          data
        );
      }

      return data;

    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }

      if (timedOut) {
        throw new ApiError(
          "Request timed out. Please try again."
        );
      }

      if (
        externalSignal?.aborted ||
        error.name === "AbortError"
      ) {
        throw new ApiError(
          "Request was cancelled."
        );
      }

      throw new ApiError(
        "Unable to connect to ScamShield AI server. Please check your connection."
      );

    } finally {
      window.clearTimeout(timeoutId);

      externalSignal?.removeEventListener(
        "abort",
        handleExternalAbort
      );
    }
  }

  /* ================================================
     HTTP METHODS
  ================================================ */

  function get(path, options = {}) {
    return request(path, {
      ...options,
      method: "GET"
    });
  }

  function post(path, body, options = {}) {
    return request(path, {
      ...options,
      method: "POST",
      body
    });
  }

  function put(path, body, options = {}) {
    return request(path, {
      ...options,
      method: "PUT",
      body
    });
  }

  function patch(path, body, options = {}) {
    return request(path, {
      ...options,
      method: "PATCH",
      body
    });
  }

  function deleteRequest(path, options = {}) {
    return request(path, {
      ...options,
      method: "DELETE"
    });
  }

  /* ================================================
     AUTHENTICATION API
  ================================================ */

  async function register(userData) {
    const response = await post(
      "/auth/register",
      userData,
      {
        authenticated: false
      }
    );

    // Registration does not automatically create a session.
    return response;
  }

  async function login(credentials, options = {}) {
    const {
      remember = true
    } = options;

    const response = await post(
      "/auth/login",
      credentials,
      {
        authenticated: false
      }
    );

    if (
      !response ||
      response.success !== true ||
      !response.token ||
      !response.user
    ) {
      throw new ApiError(
        response?.message ||
        "Invalid login response from the server."
      );
    }

    saveSession(
      response.token,
      response.user,
      remember
    );

    window.dispatchEvent(
      new CustomEvent("scamshield:login", {
        detail: {
          user: response.user
        }
      })
    );

    return response;
  }

  async function getCurrentUser() {
    const token = getToken();

    if (!token) {
      throw new ApiError(
        "You are not authenticated.",
        401
      );
    }

    const response = await get("/auth/me");

    if (!response?.success || !response.user) {
      throw new ApiError(
        response?.message ||
        "Unable to retrieve your account."
      );
    }

    saveUser(response.user);

    return response.user;
  }

  function logout() {
    clearSession();

    window.dispatchEvent(
      new CustomEvent("scamshield:logout")
    );
  }

  /* ================================================
     PUBLIC API
  ================================================ */

  const ScamShieldAPI = {
    version: "3.0.0",

    baseURL: API_BASE_URL,

    ApiError,

    request,

    get,
    post,
    put,
    patch,
    delete: deleteRequest,

    auth: {
      register,
      login,
      getCurrentUser,
      logout
    },

    register,
    login,
    getCurrentUser,
    logout,

    getToken,
    getSavedUser,

    saveSession,
    clearSession,

    isAuthenticated() {
      return Boolean(getToken());
    }
  };

  window.ScamShieldAPI = Object.freeze(
    ScamShieldAPI
  );

  console.info(
    "ScamShield AI API Service v3.0.0 initialized."
  );

})();