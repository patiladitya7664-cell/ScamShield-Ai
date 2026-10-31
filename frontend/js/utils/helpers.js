"use strict";

/* ==========================================
   SCAMSHIELD AI - HELPER UTILITIES
========================================== */

(function (window) {
  const ScamShieldHelpers = {
    // Safely escape HTML
    escapeHTML(value = "") {
      return String(value).replace(/[&<>"']/g, (character) => {
        const entities = {
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#039;",
        };

        return entities[character];
      });
    },

    // Format date
    formatDate(date, options = {}) {
      const parsedDate = new Date(date);

      if (Number.isNaN(parsedDate.getTime())) {
        return "Invalid date";
      }

      return parsedDate.toLocaleDateString("en-IN", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        ...options,
      });
    },

    // Format date and time
    formatDateTime(date) {
      const parsedDate = new Date(date);

      if (Number.isNaN(parsedDate.getTime())) {
        return "Invalid date";
      }

      return parsedDate.toLocaleString("en-IN", {
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    },

    // Relative time
    timeAgo(date) {
      const parsedDate = new Date(date);

      if (Number.isNaN(parsedDate.getTime())) {
        return "Unknown";
      }

      const seconds = Math.floor((Date.now() - parsedDate.getTime()) / 1000);

      if (seconds < 60) return "Just now";
      if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
      if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
      if (seconds < 604800) return `${Math.floor(seconds / 86400)} days ago`;

      return this.formatDate(parsedDate);
    },

    // Truncate long text
    truncateText(text = "", maxLength = 100) {
      const value = String(text);

      if (value.length <= maxLength) {
        return value;
      }

      return value.substring(0, maxLength).trimEnd() + "...";
    },

    // Get user initials
    getInitials(name = "") {
      return String(name)
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .slice(0, 2)
        .map((word) => word.charAt(0).toUpperCase())
        .join("");
    },

    // Debounce function
    debounce(callback, delay = 300) {
      let timer;

      return function (...args) {
        clearTimeout(timer);

        timer = setTimeout(() => {
          callback.apply(this, args);
        }, delay);
      };
    },

    // Safe localStorage access
    setStorage(key, value) {
      try {
        localStorage.setItem(key, JSON.stringify(value));
        return true;
      } catch (error) {
        console.error("Storage Error:", error);
        return false;
      }
    },

    getStorage(key, defaultValue = null) {
      try {
        const value = localStorage.getItem(key);

        return value === null ? defaultValue : JSON.parse(value);
      } catch (error) {
        console.error("Storage Read Error:", error);
        return defaultValue;
      }
    },

    removeStorage(key) {
      try {
        localStorage.removeItem(key);
        return true;
      } catch (error) {
        console.error("Storage Remove Error:", error);
        return false;
      }
    },

    // Show toast notification
    showToast(message, type = "info", duration = 3000) {
      let container = document.getElementById("toast-container");

      if (!container) {
        container = document.createElement("div");
        container.id = "toast-container";

        Object.assign(container.style, {
          position: "fixed",
          top: "20px",
          right: "20px",
          zIndex: "99999",
          display: "flex",
          flexDirection: "column",
          gap: "10px",
        });

        document.body.appendChild(container);
      }

      const toast = document.createElement("div");

      const colors = {
        success: "#16a34a",
        error: "#dc2626",
        warning: "#d97706",
        info: "#2563eb",
      };

      toast.textContent = String(message);

      Object.assign(toast.style, {
        padding: "13px 18px",
        color: "#ffffff",
        background: colors[type] || colors.info,
        borderRadius: "8px",
        fontSize: "14px",
        fontFamily: "Arial, sans-serif",
        boxShadow: "0 4px 15px rgba(0,0,0,0.15)",
        maxWidth: "320px",
        opacity: "0",
        transition: "opacity 0.3s ease",
      });

      container.appendChild(toast);

      requestAnimationFrame(() => {
        toast.style.opacity = "1";
      });

      setTimeout(() => {
        toast.style.opacity = "0";

        setTimeout(() => {
          toast.remove();

          if (!container.children.length) {
            container.remove();
          }
        }, 300);
      }, duration);
    },

    // Validate email
    isValidEmail(email = "") {
      return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email).trim());
    },

    // Validate URL
    isValidURL(value = "") {
      try {
        const url = new URL(value);
        return ["http:", "https:"].includes(url.protocol);
      } catch {
        return false;
      }
    },

    // Risk level from score
    getRiskLevel(score) {
      const value = Number(score);

      if (!Number.isFinite(value) || value < 0 || value > 100) {
        return "Unknown";
      }

      if (value <= 24) return "Low";
      if (value <= 49) return "Medium";
      if (value <= 74) return "High";

      return "Critical";
    },

    // Format risk score
    formatRiskScore(score) {
      const value = Number(score);

      if (!Number.isFinite(value)) {
        return "N/A";
      }

      return `${Math.max(0, Math.min(100, value))}/100`;
    },
  };

  // Make helpers globally accessible
  window.ScamShieldHelpers = ScamShieldHelpers;
})(window);
