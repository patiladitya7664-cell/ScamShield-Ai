"use strict";

/* =====================================================
   SCAMSHIELD AI - NOTIFICATION MANAGER
   Version: 2.1.0

   Features:
   1. Local notification storage.
   2. Unread notification tracking.
   3. Mark as read / Mark all as read.
   4. Delete individual notifications.
   5. Clear all notifications.
   6. Safe DOM rendering.
   7. Cross-tab synchronization.
   8. Dynamic SPA container support.

   IMPORTANT:
   This version uses browser localStorage.
   It does NOT provide MongoDB/backend synchronization.
===================================================== */

(function (window, document) {
    const STORAGE_KEY = "scamshield_notifications";

    const MAX_NOTIFICATIONS = 100;
    const MAX_ID_LENGTH = 120;
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
            if (this.initialized) {
                this.render();
                return;
            }

            this.initialized = true;

            this.load();
            this.bindEvents();
            this.bindStorageSync();
            this.bindScreenChanges();

            this.render();

            console.info(
                "ScamShield Notifications initialized."
            );
        },

        /* ================================================
           GENERATE UNIQUE ID
        ================================================ */

        generateId() {
            if (
                window.crypto &&
                typeof window.crypto.randomUUID === "function"
            ) {
                return window.crypto.randomUUID();
            }

            return (
                Date.now().toString(36) +
                "-" +
                Math.random().toString(36).slice(2)
            );
        },

        /* ================================================
           VALIDATE NOTIFICATION
        ================================================ */

        validateNotification(notification = {}) {
            if (
                !notification ||
                typeof notification !== "object" ||
                Array.isArray(notification)
            ) {
                notification = {};
            }

            const rawId =
                typeof notification.id === "string" ||
                typeof notification.id === "number"
                    ? String(notification.id)
                    : "";

            const id = (
                rawId.trim().slice(0, MAX_ID_LENGTH) ||
                this.generateId()
            );

            const rawTitle =
                typeof notification.title === "string"
                    ? notification.title
                    : "New Notification";

            const rawMessage =
                typeof notification.message === "string"
                    ? notification.message
                    : "";

            const type = ALLOWED_TYPES.includes(
                notification.type
            )
                ? notification.type
                : "info";

            const timestamp = new Date(
                notification.createdAt
            );

            const createdAt =
                notification.createdAt &&
                !Number.isNaN(timestamp.getTime())
                    ? timestamp.toISOString()
                    : new Date().toISOString();

            return {
                id,
                title: rawTitle
                    .trim()
                    .slice(0, MAX_TITLE_LENGTH),

                message: rawMessage
                    .trim()
                    .slice(0, MAX_MESSAGE_LENGTH),

                type,
                read: notification.read === true,
                createdAt
            };
        },

        /* ================================================
           LOAD NOTIFICATIONS
        ================================================ */

        load() {
            try {
                const saved = window.localStorage.getItem(
                    STORAGE_KEY
                );

                if (!saved) {
                    this.items = [];
                    return;
                }

                const parsed = JSON.parse(saved);

                if (!Array.isArray(parsed)) {
                    this.items = [];
                    return;
                }

                this.items = parsed
                    .slice(0, MAX_NOTIFICATIONS)
                    .filter(item =>
                        item &&
                        typeof item === "object" &&
                        !Array.isArray(item)
                    )
                    .map(item =>
                        this.validateNotification(item)
                    );

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
                window.localStorage.setItem(
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
            const item = this.validateNotification(
                notification
            );

            this.items = this.items.filter(
                existing => existing.id !== item.id
            );

            this.items.unshift(item);

            this.items = this.items.slice(
                0,
                MAX_NOTIFICATIONS
            );

            this.save();
            this.render();

            return { ...item };
        },

        /* ================================================
           GET ALL NOTIFICATIONS
        ================================================ */

        getAll() {
            return this.items.map(item => ({
                ...item
            }));
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
                notification =>
                    notification.id === String(id)
            );

            if (!item || item.read) return false;

            item.read = true;

            this.save();
            this.render();

            return true;
        },

        /* ================================================
           MARK ALL AS READ
        ================================================ */

        markAllAsRead() {
            let changed = false;

            this.items.forEach(item => {
                if (!item.read) {
                    item.read = true;
                    changed = true;
                }
            });

            if (changed) {
                this.save();
                this.render();
            }
        },

        /* ================================================
           DELETE NOTIFICATION
        ================================================ */

        remove(id) {
            const previousLength = this.items.length;

            this.items = this.items.filter(
                item => item.id !== String(id)
            );

            if (this.items.length === previousLength) {
                return false;
            }

            this.save();
            this.render();

            return true;
        },

        /* ================================================
           CLEAR ALL NOTIFICATIONS
        ================================================ */

        clearAll() {
            if (this.items.length === 0) return;

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
                typeof window.ScamShieldHelpers.timeAgo ===
                    "function"
            ) {
                return window.ScamShieldHelpers.timeAgo(
                    parsed
                );
            }

            return parsed.toLocaleString("en-IN");
        },

        /* ================================================
           CREATE ELEMENT
        ================================================ */

        createElement(tag, className, text) {
            const element = document.createElement(tag);

            if (className) {
                element.className = className;
            }

            if (text !== undefined) {
                element.textContent = String(text);
            }

            return element;
        },

        /* ================================================
           GET NOTIFICATION CONTAINER
        ================================================ */

        getContainer() {
            return document.querySelector(
                "#notification-list, [data-notification-list]"
            );
        },

        /* ================================================
           UPDATE BADGE
        ================================================ */

        updateBadge() {
            const badge = document.querySelector(
                "#notification-count, .notification-count, [data-notification-count]"
            );

            if (!badge) return;

            const count = this.getUnreadCount();

            badge.textContent =
                count > 99 ? "99+" : String(count);

            badge.hidden = count === 0;

            badge.setAttribute(
                "aria-label",
                `${count} unread notifications`
            );
        },

        /* ================================================
           UPDATE EMPTY STATE
        ================================================ */

        updateEmptyState() {
            const emptyState = document.querySelector(
                "#notification-empty, [data-notification-empty]"
            );

            if (emptyState) {
                emptyState.hidden = this.items.length > 0;
            }
        },

        /* ================================================
           RENDER ONE NOTIFICATION
        ================================================ */

        createNotificationCard(item) {
            const article = this.createElement(
                "article",
                [
                    "notification-item",
                    item.read ? "read" : "unread",
                    `notification-${item.type}`
                ].join(" ")
            );

            article.dataset.notificationId = item.id;

            const content = this.createElement(
                "div",
                "notification-content"
            );

            const title = this.createElement(
                "h4",
                "",
                item.title
            );

            const message = this.createElement(
                "p",
                "",
                item.message
            );

            const time = this.createElement(
                "small",
                "",
                this.formatTime(item.createdAt)
            );

            content.append(title, message, time);

            const actions = this.createElement(
                "div",
                "notification-actions"
            );

            if (!item.read) {
                const readButton = this.createElement(
                    "button",
                    "",
                    "Mark read"
                );

                readButton.type = "button";
                readButton.dataset.action = "read";
                readButton.dataset.id = item.id;

                readButton.setAttribute(
                    "aria-label",
                    `Mark ${item.title} as read`
                );

                actions.appendChild(readButton);
            }

            const deleteButton = this.createElement(
                "button",
                "",
                "Delete"
            );

            deleteButton.type = "button";
            deleteButton.dataset.action = "delete";
            deleteButton.dataset.id = item.id;

            deleteButton.setAttribute(
                "aria-label",
                `Delete ${item.title}`
            );

            actions.appendChild(deleteButton);

            article.append(content, actions);

            return article;
        },

        /* ================================================
           RENDER NOTIFICATIONS
        ================================================ */

        render() {
            this.updateBadge();
            this.updateEmptyState();

            const container = this.getContainer();

            if (!container) return;

            const fragment = document.createDocumentFragment();

            this.items.forEach(item => {
                fragment.appendChild(
                    this.createNotificationCard(item)
                );
            });

            container.replaceChildren(fragment);
        },

        /* ================================================
           HANDLE NOTIFICATION ACTIONS
        ================================================ */

        handleAction(event) {
            const target = event.target;

            if (!(target instanceof Element)) {
                return;
            }

            const button = target.closest(
                "button[data-action]"
            );

            if (!button) return;

            const action = button.dataset.action;
            const id = button.dataset.id;

            if (!id) return;

            if (action === "read") {
                this.markAsRead(id);
            }

            if (action === "delete") {
                this.remove(id);
            }
        },

        /* ================================================
           HANDLE GLOBAL ACTION BUTTONS
        ================================================ */

        handleGlobalAction(event) {
            const target = event.target;

            if (!(target instanceof Element)) {
                return;
            }

            const markAllButton = target.closest(
                "#mark-all-read, [data-mark-all-read]"
            );

            if (markAllButton) {
                this.markAllAsRead();
                return;
            }

            const clearButton = target.closest(
                "#clear-notifications, [data-clear-notifications]"
            );

            if (!clearButton) return;

            const confirmed = window.confirm(
                "Are you sure you want to clear all notifications?"
            );

            if (confirmed) {
                this.clearAll();
            }
        },

        /* ================================================
           BIND EVENTS
        ================================================ */

        bindEvents() {
            if (this.eventsBound) return;

            this.eventsBound = true;

            // Delegation supports dynamically loaded containers.
            document.addEventListener("click", event => {
                this.handleAction(event);
                this.handleGlobalAction(event);
            });
        },

        /* ================================================
           CROSS-TAB SYNCHRONIZATION
        ================================================ */

        bindStorageSync() {
            window.addEventListener("storage", event => {
                if (
                    event.key !== STORAGE_KEY &&
                    event.key !== null
                ) {
                    return;
                }

                this.load();
                this.render();
            });
        },

        /* ================================================
           SPA SCREEN CHANGE
        ================================================ */

        bindScreenChanges() {
            document.addEventListener(
                "scamshield:screenchange",
                () => {
                    this.render();
                }
            );
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