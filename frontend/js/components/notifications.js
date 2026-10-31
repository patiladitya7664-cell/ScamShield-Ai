"use strict";

/* ==========================================
   SCAMSHIELD AI - NOTIFICATION MANAGER
========================================== */

(function (window, document) {
  const STORAGE_KEY = "scamshield_notifications";

  const Notifications = {
    items: [],

    init() {
      this.load();
      this.bindEvents();
      this.render();
    },

    // Load saved notifications
    load() {
      try {
        const saved = localStorage.getItem(STORAGE_KEY);
        const parsed = saved ? JSON.parse(saved) : [];

        this.items = Array.isArray(parsed) ? parsed : [];
      } catch (error) {
        console.error("Notification Load Error:", error);
        this.items = [];
      }
    },

    // Save notifications
    save() {
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(this.items));
      } catch (error) {
        console.error("Notification Save Error:", error);
      }
    },

    // Add notification
    add(notification = {}) {
      const item = {
        id:
          notification.id ||
          window.crypto?.randomUUID?.() ||
          `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        title: String(notification.title || "New Notification"),
        message: String(notification.message || ""),
        type: notification.type || "info",
        read: false,
        createdAt: new Date().toISOString(),
      };

      this.items.unshift(item);
      this.save();
      this.render();

      return item;
    },

    // Count unread notifications
    getUnreadCount() {
      return this.items.filter((item) => !item.read).length;
    },

    // Mark one notification as read
    markAsRead(id) {
      this.items = this.items.map((item) =>
        item.id === id ? { ...item, read: true } : item,
      );

      this.save();
      this.render();
    },

    // Mark all notifications as read
    markAllAsRead() {
      this.items = this.items.map((item) => ({
        ...item,
        read: true,
      }));

      this.save();
      this.render();
    },

    // Delete one notification
    remove(id) {
      this.items = this.items.filter((item) => item.id !== id);

      this.save();
      this.render();
    },

    // Clear all notifications
    clearAll() {
      this.items = [];
      this.save();
      this.render();
    },

    // Format notification time
    formatTime(date) {
      const parsed = new Date(date);

      if (Number.isNaN(parsed.getTime())) {
        return "";
      }

      if (window.ScamShieldHelpers) {
        return window.ScamShieldHelpers.timeAgo(parsed);
      }

      return parsed.toLocaleString("en-IN");
    },

    // Render notifications
    render() {
      const container = document.querySelector(
        "#notification-list, [data-notification-list]",
      );

      const badge = document.querySelector(
        "#notification-count, .notification-count, [data-notification-count]",
      );

      const emptyState = document.querySelector(
        "#notification-empty, [data-notification-empty]",
      );

      const unreadCount = this.getUnreadCount();

      if (badge) {
        badge.textContent = unreadCount > 99 ? "99+" : String(unreadCount);

        badge.hidden = unreadCount === 0;
      }

      if (emptyState) {
        emptyState.hidden = this.items.length > 0;
      }

      if (!container) return;

      if (this.items.length === 0) {
        container.innerHTML = "";
        return;
      }

      container.innerHTML = this.items
        .map(
          (item) => `
        <article class="notification-item ${item.read ? "read" : "unread"}"
                 data-notification-id="${this.escapeHTML(item.id)}">

          <div class="notification-content">
            <h4>${this.escapeHTML(item.title)}</h4>
            <p>${this.escapeHTML(item.message)}</p>
            <small>${this.escapeHTML(this.formatTime(item.createdAt))}</small>
          </div>

          <div class="notification-actions">
            ${
              !item.read
                ? `<button type="button" data-action="read"
                     data-id="${this.escapeHTML(item.id)}">
                     Mark read
                   </button>`
                : ""
            }

            <button type="button" data-action="delete"
                    data-id="${this.escapeHTML(item.id)}"
                    aria-label="Delete notification">
              Delete
            </button>
          </div>

        </article>
      `,
        )
        .join("");
    },

    // Escape HTML to prevent injection
    escapeHTML(value) {
      return String(value).replace(
        /[&<>"']/g,
        (character) =>
          ({
            "&": "&amp;",
            "<": "&lt;",
            ">": "&gt;",
            '"': "&quot;",
            "'": "&#039;",
          })[character],
      );
    },

    // Bind click events
    bindEvents() {
      const container = document.querySelector(
        "#notification-list, [data-notification-list]",
      );

      container?.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-action]");

        if (!button) return;

        const id = button.dataset.id;
        const action = button.dataset.action;

        if (action === "read") {
          this.markAsRead(id);
        }

        if (action === "delete") {
          this.remove(id);
        }
      });

      document
        .querySelector("#mark-all-read, [data-mark-all-read]")
        ?.addEventListener("click", () => {
          this.markAllAsRead();
        });

      document
        .querySelector("#clear-notifications, [data-clear-notifications]")
        ?.addEventListener("click", () => {
          if (window.confirm("Clear all notifications?")) {
            this.clearAll();
          }
        });
    },
  };

  window.ScamShieldNotifications = Notifications;

  document.addEventListener("DOMContentLoaded", () => {
    Notifications.init();
  });
})(window, document);
