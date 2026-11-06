"use strict";

(function () {
  const API_BASE_URL =
    window.SCAMSHIELD_API_URL || "http://localhost:5000/api";

  const TOKEN_KEY = "scamshield_token";
  const USER_KEY = "scamshield_user";

  class ApiError extends Error {
    constructor(message, status, data) {
      super(message);
      this.name = "ApiError";
      this.status = status;
      this.data = data;
    }
  }

  function getToken() {
    const keys = [
        "scamshield_token",
        "scamshieldToken"
    ];

    for (const key of keys) {
        const token =
            localStorage.getItem(key) ||
            sessionStorage.getItem(key);

        if (token) {
            return token;
        }
    }

    return null;
}

  function getSavedUser() {
    const savedUser = localStorage.getItem(USER_KEY);

    if (!savedUser) return null;

    try {
      return JSON.parse(savedUser);
    } catch {
      localStorage.removeItem(USER_KEY);
      return null;
    }
  }

  function saveSession(token, user) {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    }

    if (user) {
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    }
  }

  function clearSession() {
    const keys = [
        "scamshield_token",
        "scamshieldToken",
        "scamshield_user",
        "scamshieldUser"
    ];

    keys.forEach((key) => {
        localStorage.removeItem(key);
        sessionStorage.removeItem(key);
    });
}

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    const token = getToken();

    if (options.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    if (token && !headers.has("Authorization")) {
      headers.set("Authorization", `Bearer ${token}`);
    }

    let response;

    try {
      response = await fetch(`${API_BASE_URL}${path}`, {
        ...options,
        headers
      });
    } catch {
      throw new ApiError(
        "Backend se connect nahi ho pa raha. Check karein ki server chal raha hai.",
        0,
        null
      );
    }

    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json")
      ? await response.json()
      : null;

    if (!response.ok) {
      if (response.status === 401) {
        clearSession();
      }

      throw new ApiError(
        data?.message || `Request fail hua (${response.status}).`,
        response.status,
        data
      );
    }

    return data;
  }

  // ================================================
  // HTTP METHODS
  // ================================================

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
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  }

  function put(path, body, options = {}) {
    return request(path, {
      ...options,
      method: "PUT",
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  }

  function patch(path, body, options = {}) {
    return request(path, {
      ...options,
      method: "PATCH",
      body: body === undefined ? undefined : JSON.stringify(body)
    });
  }

  function deleteRequest(path, options = {}) {
    return request(path, {
      ...options,
      method: "DELETE"
    });
  }

  // ================================================
  // AUTHENTICATION
  // ================================================

  async function register({ name, email, password }) {
    const data = await post("/auth/register", {
      name,
      email,
      password
    });

    if (data?.user) {
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    }

    return data;
  }

  async function login({ email, password }) {
    const data = await post("/auth/login", {
      email,
      password
    });

    if (!data?.token || !data?.user) {
      throw new ApiError(
        "Login response mein token ya user details nahi mile.",
        500,
        data
      );
    }

    saveSession(data.token, data.user);
    return data;
  }

  async function getCurrentUser() {
    const data = await get("/auth/me");

    if (data?.user) {
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
    }

    return data?.user || null;
  }

  function logout() {
    clearSession();
  }

  // ================================================
  // PUBLIC API
  // ================================================

  window.ScamShieldAPI = Object.freeze({
    ApiError,

    request,
    get,
    post,
    put,
    patch,
    delete: deleteRequest,

    register,
    login,
    getCurrentUser,
    getToken,
    getSavedUser,
    logout
  });
})();