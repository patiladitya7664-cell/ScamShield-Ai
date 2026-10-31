"use strict";

/* ==========================================
   SCAMSHIELD AI - API SERVICE
   Backend API Communication
========================================== */

(function (window) {
  const API_BASE_URL = window.SCAMSHIELD_API_URL || "http://localhost:5000/api";

  const getToken = () => {
    return (
      localStorage.getItem("scamshieldToken") ||
      sessionStorage.getItem("scamshieldToken")
    );
  };

  const request = async (endpoint, options = {}) => {
    try {
      const token = getToken();

      const headers = {
        ...(options.headers || {}),
      };

      // Don't override Content-Type for FormData
      if (!(options.body instanceof FormData)) {
        headers["Content-Type"] = "application/json";
      }

      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }

      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers,
      });

      const contentType = response.headers.get("content-type") || "";

      const result = contentType.includes("application/json")
        ? await response.json()
        : await response.text();

      if (!response.ok) {
        const message =
          typeof result === "object" && result !== null
            ? result.message || "Something went wrong."
            : result || "Something went wrong.";

        throw new Error(message);
      }

      return result;
    } catch (error) {
      console.error(`API Error [${endpoint}]:`, error.message);
      throw error;
    }
  };

  const API = {
    // GET Request
    get(endpoint) {
      return request(endpoint, {
        method: "GET",
      });
    },

    // POST Request
    post(endpoint, data = {}) {
      return request(endpoint, {
        method: "POST",
        body: data instanceof FormData ? data : JSON.stringify(data),
      });
    },

    // PUT Request
    put(endpoint, data = {}) {
      return request(endpoint, {
        method: "PUT",
        body: data instanceof FormData ? data : JSON.stringify(data),
      });
    },

    // PATCH Request
    patch(endpoint, data = {}) {
      return request(endpoint, {
        method: "PATCH",
        body: data instanceof FormData ? data : JSON.stringify(data),
      });
    },

    // DELETE Request
    delete(endpoint) {
      return request(endpoint, {
        method: "DELETE",
      });
    },

    // Authentication APIs
    auth: {
      register(data) {
        return API.post("/auth/register", data);
      },

      login(data) {
        return API.post("/auth/login", data);
      },

      getProfile() {
        return API.get("/auth/me");
      },

      logout() {
        localStorage.removeItem("scamshieldToken");
        localStorage.removeItem("scamshieldUser");
        sessionStorage.removeItem("scamshieldToken");
        sessionStorage.removeItem("scamshieldUser");
      },
    },

    // Dashboard APIs
    dashboard: {
      getOverview() {
        return API.get("/dashboard/overview");
      },
    },

    // Health Check
    healthCheck() {
      return API.get("/health");
    },
  };

  window.ScamShieldAPI = API;
})(window);
