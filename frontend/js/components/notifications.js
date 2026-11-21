
"use strict";

/* =====================================================
   SCAMSHIELD AI - NOTIFICATION MANAGER
   Version: 2.0.0

   Features:
   1. Local notification storage.
   2. Unread notification tracking.
   3. Mark as read / Mark all as read.
   4. Delete individual notifications.
   5. Clear all notifications.
   6. Secure HTML rendering.
   7. Cross-tab synchronization.
===================================================== */

(function (window, document) {

    const STORAGE_KEY = "scamshield_notifications";
    const MAX_NOTIFICATIONS = 100;
    const MAX_TITLE_LENGTH = 120;
    const MAX_MESSAGE_LENGTH = 1000;

    const ALLOWED_TYPES = [
        "info",
        "success",
        "warning",
        "error",
        "security",
        "danger"
    ];

    const Notifications = {

        items: [],
        initialized: false,
        eventsBound: false,

        /* ================================================
           INITIALIZATION
        ================================================ */

        init() {

            if (this.initialized) return;

            this.initialized = true;

            this.load();
            this.bindEvents();
            this.render();
            this.bindStorageSync();

            console.info("ScamShield Notifications initialized.");
        },

        /* ================================================
           VALIDATE NOTIFICATION
        ================================================ */

        validateNotification(notification = {}) {

            const type = ALLOWED_TYPES.includes(notification.type)
                ? notification.type
                : "info";

            return {

                id: String(
                    notification.id ||
                    window.crypto?.randomUUID?.() ||
                    `${Date.now()}-${Math.random().toString(16).slice(2)}`
                ),

                title: String(
                    notification.title || "New Notification"
                ).slice(0, MAX_TITLE_LENGTH),

                message: String(
                    notification.message || ""
                ).slice(0, MAX_MESSAGE_LENGTH),

                type,

                read: Boolean(notification.read),

                createdAt: notification.createdAt &&
                    !Number.isNaN(
                        new Date(notification.createdAt).getTime()
                    )
                    ? new Date(notification.createdAt).toISOString()
                    : new Date().toISOString()
            };
        },

        /* ================================================
           LOAD NOTIFICATIONS
        ================================================ */

        load() {

            try {

                const saved = localStorage.getItem(STORAGE_KEY);

                const parsed = saved
                    ? JSON.parse(saved)
                    : [];

                if (!Array.isArray(parsed)) {
                    this.items = [];
                    return;
                }

                this.items = parsed
                    .filter(item =>
                        item &&
                        typeof item === "object" &&
                        !Array.isArray(item)
                    )
                    .map(item => this.validateNotification(item))
                    .slice(0, MAX_NOTIFICATIONS);

            } catch (error) {

                console.error(
                    "ScamShield Notification Load Error:",
                    error
                );

                this.items = [];
            }
        },

        /* ================================================
           SAVE NOTIFICATIONS
        ================================================ */

        save() {

            try {

                localStorage.setItem(
                    STORAGE_KEY,
                    JSON.stringify(
                        this.items.slice(0, MAX_NOTIFICATIONS)
                    )
                );

                return true;

            } catch (error) {

                console.error(
                    "ScamShield Notification Save Error:",
                    error
                );

                return false;
            }
        },

        /* ================================================
           ADD NOTIFICATION
        ================================================ */

        add(notification = {}) {

            const item = this.validateNotification(notification);

            // Prevent duplicate notification IDs.
            this.items = this.items.filter(
                existing => existing.id !== item.id
            );

            this.items.unshift(item);

            // Keep the latest notifications.
            this.items = this.items.slice(0, MAX_NOTIFICATIONS);

            this.save();
            this.render();

            return item;
        },

        /* ================================================
           GET NOTIFICATIONS
        ================================================ */

        getAll() {

            return this.items.map(item => ({ ...item }));
        },

        /* ================================================
           GET UNREAD COUNT
        ================================================ */

        getUnreadCount() {

            return this.items.filter(
                item => !item.read
            ).length;
        },

        /* ================================================
           MARK ONE AS READ
        ================================================ */

        markAsRead(id) {

            const item = this.items.find(
                notification => notification.id === String(id)
            );

            if (!item || item.read) return;

            item.read = true;

            this.save();
            this.render();
        },

        /* ================================================
           MARK ALL AS READ
        ================================================ */

        markAllAsRead() {

            this.items = this.items.map(item => ({
                ...item,
                read: true
            }));

            this.save();
            this.render();
        },

        /* ================================================
           DELETE NOTIFICATION
        ================================================ */

        remove(id) {

            this.items = this.items.filter(
                item => item.id !== String(id)
            );

            this.save();
            this.render();
        },

        /* ================================================
           CLEAR ALL NOTIFICATIONS
        ================================================ */

        clearAll() {

            this.items = [];

            this.save();
            this.render();
        },

        /* ================================================
           FORMAT TIME
        ================================================ */

        formatTime(date) {

            const parsed = new Date(date);

            if (Number.isNaN(parsed.getTime())) {
                return "";
            }

            if (
                window.ScamShieldHelpers &&
                typeof window.ScamShieldHelpers.timeAgo === "function"
            ) {
                return window.ScamShieldHelpers.timeAgo(parsed);
            }

            return parsed.toLocaleString("en-IN");
        },

        /* ================================================
           ESCAPE HTML
        ================================================ */

        escapeHTML(value) {

            return String(value).replace(
                /[&<>"']/g,
                character => ({
                    "&": "&amp;",
                    "<": "&lt;",
                    ">": "&gt;",
                    '"': "&quot;",
                    "'": "&#039;"
                })[character]
            );
        },

        /* ================================================
           RENDER NOTIFICATIONS
        ================================================ */

        render() {

            const container = document.querySelector(
                "#notification-list, [data-notification-list]"
            );

            const badge = document.querySelector(
                "#notification-count, .notification-count, [data-notification-count]"
            );

            const emptyState = document.querySelector(
                "#notification-empty, [data-notification-empty]"
            );

            const unreadCount = this.getUnreadCount();

            // Update unread badge.
            if (badge) {

                badge.textContent =
                    unreadCount > 99
                        ? "99+"
                        : String(unreadCount);

                badge.hidden = unreadCount === 0;

                badge.setAttribute(
                    "aria-label",
                    `${unreadCount} unread notifications`
                );
            }

            // Update empty state.
            if (emptyState) {
                emptyState.hidden = this.items.length > 0;
            }

            if (!container) return;

            if (this.items.length === 0) {

                container.innerHTML = "";
                return;
            }

            container.innerHTML = this.items.map(item => {

                const safeId = this.escapeHTML(item.id);
                const safeTitle = this.escapeHTML(item.title);
                const safeMessage = this.escapeHTML(item.message);
                const safeTime = this.escapeHTML(
                    this.formatTime(item.createdAt)
                );

                const safeType = ALLOWED_TYPES.includes(item.type)
                    ? item.type
                    : "info";

                return `

                    <article
                        class="notification-item ${item.read ? "read" : "unread"} notification-${safeType}"
                        data-notification-id="${safeId}"
                    >

                        <div class="notification-content">

                            <h4>${safeTitle}</h4>

                            <p>${safeMessage}</p>

                            <small>${safeTime}</small>

                        </div>

                        <div class="notification-actions">

                            ${
                                !item.read
                                    ? `
                                        <button
                                            type="button"
                                            data-action="read"
                                            data-id="${safeId}"
                                            aria-label="Mark ${safeTitle} as read"
                                        >
                                            Mark read
                                        </button>
                                    `
                                    : ""
                            }

                            <button
                                type="button"
                                data-action="delete"
                                data-id="${safeId}"
                                aria-label="Delete ${safeTitle}"
                            >
                                Delete
                            </button>

                        </div>

                    </article>

                `;

            }).join("");
        },

        /* ================================================
           BIND EVENTS
        ================================================ */

        bindEvents() {

            if (this.eventsBound) return;

            this.eventsBound = true;

            // Notification actions.
            const container = document.querySelector(
                "#notification-list, [data-notification-list]"
            );

            container?.addEventListener("click", event => {

                const button = event.target.closest(
                    "button[data-action]"
                );

                if (!button || !container.contains(button)) return;

                const id = button.dataset.id;
                const action = button.dataset.action;

                if (action === "read") {
                    this.markAsRead(id);
                }

                if (action === "delete") {
                    this.remove(id);
                }
            });

            // Mark all as read.
            document.querySelectorAll(
                "#mark-all-read, [data-mark-all-read]"
            ).forEach(button => {

                button.addEventListener("click", () => {
                    this.markAllAsRead();
                });

            });

            // Clear all notifications.
            document.querySelectorAll(
                "#clear-notifications, [data-clear-notifications]"
            ).forEach(button => {

                button.addEventListener("click", () => {

                    if (
                        window.confirm(
                            "Are you sure you want to clear all notifications?"
                        )
                    ) {
                        this.clearAll();
                    }

                });

            });
        },

        /* ================================================
           CROSS-TAB SYNCHRONIZATION
        ================================================ */

        bindStorageSync() {

            window.addEventListener("storage", event => {

                if (event.key !== STORAGE_KEY) return;

                this.load();
                this.render();

            });
        }

    };

    /* ================================================
       GLOBAL ACCESS
    ================================================ */

    window.ScamShieldNotifications = Notifications;

    /* ================================================
       INITIALIZATION
    ================================================ */

    if (document.readyState === "loading") {

        document.addEventListener(
            "DOMContentLoaded",
            () => Notifications.init(),
            { once: true }
        );

    } else {

        Notifications.init();
    }

})(window, document);
