"use strict";

/* =====================================================
   SCAMSHIELD AI
   CENTRALIZED API SERVICE

   Version: 3.1.0

   Responsibilities:
   1. Centralized backend communication
   2. JWT authentication
   3. Login and registration
   4. Remember Me support
   5. Session management
   6. API error handling
   7. Request timeout and cancellation
   8. Current user management

   SECURITY:
   Bearer tokens are currently stored in browser storage.
   Production recommendation: HttpOnly Secure cookies.
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
        "http://127.0.0.1:5000/api"
    ).replace(/\/+$/, "");

    const DEFAULT_TIMEOUT = 30000;

    const MAX_TIMEOUT = 120000;

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
            return storage
                ? storage.getItem(key)
                : null;
        } catch {
            return null;
        }
    }

    function safeSet(storage, key, value) {
        try {
            if (!storage) {
                return false;
            }

            storage.setItem(key, value);

            return true;
        } catch {
            return false;
        }
    }

    function safeRemove(storage, key) {
        try {
            storage?.removeItem(key);
        } catch {
            // Storage cleanup failure is non-fatal.
        }
    }

    function removeKeys(keys) {
        for (const type of ["local", "session"]) {
            const storage = getStorage(type);

            for (const key of keys) {
                safeRemove(storage, key);
            }
        }
    }

    /* ================================================
       TOKEN MANAGEMENT
    ================================================ */

    function getToken() {
        // Session storage takes priority over persistent storage.
        for (const type of ["session", "local"]) {
            const storage = getStorage(type);

            for (const key of TOKEN_KEYS) {
                const token = safeGet(storage, key);

                if (
                    typeof token === "string" &&
                    token.trim()
                ) {
                    return token.trim();
                }
            }
        }

        return null;
    }

    function getActiveStorage() {
        for (const type of ["session", "local"]) {
            const storage = getStorage(type);

            for (const key of TOKEN_KEYS) {
                if (safeGet(storage, key)) {
                    return storage;
                }
            }
        }

        return null;
    }

    function saveToken(token, remember = true) {
        if (
            typeof token !== "string" ||
            !token.trim()
        ) {
            throw new ApiError(
                "Invalid authentication token."
            );
        }

        const targetStorage = getStorage(
            remember ? "local" : "session"
        );

        if (!targetStorage) {
            throw new ApiError(
                "Browser storage is unavailable."
            );
        }

        removeKeys(TOKEN_KEYS);

        const saved = safeSet(
            targetStorage,
            "scamshield_token",
            token.trim()
        );

        if (!saved) {
            throw new ApiError(
                "Unable to save your login session."
            );
        }

        safeSet(
            getStorage("local"),
            REMEMBER_KEY,
            remember ? "true" : "false"
        );
    }

    /* ================================================
       SAFE USER PROFILE CACHE
    ================================================ */

    function sanitizeUser(user) {
        if (
            !user ||
            typeof user !== "object" ||
            Array.isArray(user)
        ) {
            return null;
        }

        const safeUser = {};

        const allowedFields = [
            "_id",
            "id",
            "name",
            "email",
            "role",
            "createdAt",
            "updatedAt"
        ];

        for (const field of allowedFields) {
            const value = user[field];

            if (
                typeof value === "string" ||
                typeof value === "number"
            ) {
                safeUser[field] = value;
            }
        }

        return Object.keys(safeUser).length
            ? safeUser
            : null;
    }

    function getSavedUser() {
        for (const type of ["session", "local"]) {
            const storage = getStorage(type);

            for (const key of USER_KEYS) {
                const rawUser = safeGet(storage, key);

                if (!rawUser) {
                    continue;
                }

                try {
                    const parsed = JSON.parse(rawUser);
                    const user = sanitizeUser(parsed);

                    if (user) {
                        return user;
                    }

                    safeRemove(storage, key);
                } catch {
                    safeRemove(storage, key);
                }
            }
        }

        return null;
    }

    function saveUser(user) {
        const safeUser = sanitizeUser(user);

        if (!safeUser) {
            throw new ApiError(
                "Invalid user information received from server."
            );
        }

        const storage = getActiveStorage();

        if (!storage) {
            throw new ApiError(
                "No active authentication session found."
            );
        }

        removeKeys(USER_KEYS);

        const saved = safeSet(
            storage,
            "scamshield_user",
            JSON.stringify(safeUser)
        );

        if (!saved) {
            throw new ApiError(
                "Unable to save account information."
            );
        }

        return safeUser;
    }

    /* ================================================
       AUTH EVENTS
    ================================================ */

    function dispatchAuthChange(authenticated, user = null) {
        window.dispatchEvent(
            new CustomEvent("scamshield:authchange", {
                detail: {
                    authenticated,
                    user
                }
            })
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

        const safeUser = sanitizeUser(user);

        if (!safeUser) {
            throw new ApiError(
                "Invalid account information received from server."
            );
        }

        saveToken(token, remember);

        try {
            saveUser(safeUser);
        } catch (error) {
            removeKeys([
                ...TOKEN_KEYS,
                ...USER_KEYS
            ]);

            safeRemove(
                getStorage("local"),
                REMEMBER_KEY
            );

            throw error;
        }

        dispatchAuthChange(true, safeUser);
    }

    function clearSession(options = {}) {
        const {
            expired = false,
            dispatch = true
        } = options;

        removeKeys([
            ...TOKEN_KEYS,
            ...USER_KEYS
        ]);

        safeRemove(
            getStorage("local"),
            REMEMBER_KEY
        );

        if (dispatch) {
            dispatchAuthChange(false, null);
        }

        if (expired) {
            window.dispatchEvent(
                new CustomEvent("scamshield:session-expired")
            );
        }
    }

    /* ================================================
       RESPONSE PARSER
    ================================================ */

    async function parseResponse(response) {
        if (response.status === 204) {
            return null;
        }

        const contentType =
            response.headers.get("content-type") || "";

        if (
            contentType.includes("application/json") ||
            contentType.includes("+json")
        ) {
            try {
                return await response.json();
            } catch {
                throw new ApiError(
                    "The server returned an invalid JSON response.",
                    response.status
                );
            }
        }

        const text = await response.text();

        if (!text) {
            return null;
        }

        return {
            message: text
        };
    }

    /* ================================================
       ERROR MESSAGE
    ================================================ */

    function getErrorMessage(data, status) {
        if (data && typeof data === "object") {
            if (
                typeof data.message === "string" &&
                data.message.trim()
            ) {
                return data.message;
            }

            if (
                typeof data.error === "string" &&
                data.error.trim()
            ) {
                return data.error;
            }

            if (
                typeof data.data?.message === "string"
            ) {
                return data.data.message;
            }
        }

        const messages = {
            400: "Invalid request.",
            401: "Your session is invalid or has expired.",
            403: "You do not have permission to perform this action.",
            404: "Requested resource was not found.",
            409: "This resource already exists.",
            413: "The submitted data is too large.",
            415: "Unsupported file or request format.",
            422: "Unable to process your request.",
            429: "Too many requests. Please try again later.",
            500: "Internal server error.",
            502: "Server is temporarily unavailable.",
            503: "Service is currently unavailable.",
            504: "The server took too long to respond."
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
            !path.startsWith("/") ||
            path.startsWith("//")
        ) {
            throw new ApiError(
                "Invalid API endpoint."
            );
        }

        const {
            method = "GET",
            headers = {},
            body,
            signal: externalSignal,
            timeout = DEFAULT_TIMEOUT,
            authenticated = true
        } = options;

        const normalizedMethod = String(method).toUpperCase();

        const validMethods = [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE"
        ];

        if (!validMethods.includes(normalizedMethod)) {
            throw new ApiError(
                "Unsupported HTTP method."
            );
        }

        if (
            !Number.isFinite(timeout) ||
            timeout < 0 ||
            timeout > MAX_TIMEOUT
        ) {
            throw new ApiError(
                "Invalid request timeout."
            );
        }

        if (
            externalSignal &&
            typeof externalSignal.addEventListener !== "function"
        ) {
            throw new ApiError(
                "Invalid request cancellation signal."
            );
        }

        if (
            body !== undefined &&
            ["GET", "DELETE"].includes(normalizedMethod)
        ) {
            throw new ApiError(
                `${normalizedMethod} requests cannot contain a request body.`
            );
        }

        const controller = new AbortController();

        let timedOut = false;
        let externallyCancelled = false;

        let timeoutId = null;

        const handleExternalAbort = () => {
            externallyCancelled = true;
            controller.abort();
        };

        if (externalSignal?.aborted) {
            throw new ApiError(
                "Request was cancelled."
            );
        }

        if (externalSignal) {
            externalSignal.addEventListener(
                "abort",
                handleExternalAbort,
                { once: true }
            );
        }

        if (timeout > 0) {
            timeoutId = window.setTimeout(() => {
                timedOut = true;
                controller.abort();
            }, timeout);
        }

        try {
            const requestHeaders = new Headers(headers);

            requestHeaders.set(
                "Accept",
                "application/json"
            );

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
                    method: normalizedMethod,
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
                if (
                    response.status === 401 &&
                    authenticated
                ) {
                    clearSession({
                        expired: true
                    });
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
                externallyCancelled ||
                externalSignal?.aborted ||
                error?.name === "AbortError"
            ) {
                throw new ApiError(
                    "Request was cancelled."
                );
            }

            throw new ApiError(
                "Unable to connect to ScamShield AI server. Please check your connection."
            );

        } finally {
            if (timeoutId !== null) {
                window.clearTimeout(timeoutId);
            }

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
       AUTH RESPONSE NORMALIZATION
    ================================================ */

    function extractAuthData(response) {
        if (!response || typeof response !== "object") {
            return null;
        }

        const data =
            response.data &&
            typeof response.data === "object"
                ? response.data
                : response;

        return {
            success: response.success === true,
            message: response.message || data.message || "",
            token: data.token || response.token || null,
            user: data.user || response.user || null,
            raw: response
        };
    }

    /* ================================================
       AUTHENTICATION API
    ================================================ */

    async function register(userData) {
        if (
            !userData ||
            typeof userData !== "object" ||
            Array.isArray(userData)
        ) {
            throw new ApiError(
                "Invalid registration information."
            );
        }

        return post(
            "/auth/register",
            userData,
            {
                authenticated: false
            }
        );
    }

    async function login(credentials, options = {}) {
        const {
            remember = true
        } = options;

        if (
            !credentials ||
            typeof credentials !== "object" ||
            Array.isArray(credentials)
        ) {
            throw new ApiError(
                "Invalid login information."
            );
        }

        const response = await post(
            "/auth/login",
            credentials,
            {
                authenticated: false
            }
        );

        const authData = extractAuthData(response);

        if (
            !authData ||
            !authData.success ||
            !authData.token ||
            !authData.user
        ) {
            throw new ApiError(
                authData?.message ||
                "Invalid login response from the server.",
                0,
                response
            );
        }

        saveSession(
            authData.token,
            authData.user,
            remember
        );

        window.dispatchEvent(
            new CustomEvent("scamshield:login", {
                detail: {
                    user: sanitizeUser(authData.user)
                }
            })
        );

        return response;
    }

    async function getCurrentUser() {
        if (!getToken()) {
            throw new ApiError(
                "You are not authenticated.",
                401
            );
        }

        const response = await get("/auth/me");

        const user =
            response?.user ||
            response?.data?.user ||
            response?.data ||
            null;

        if (
            response?.success !== true ||
            !user ||
            typeof user !== "object"
        ) {
            throw new ApiError(
                response?.message ||
                "Unable to retrieve your account.",
                0,
                response
            );
        }

        return saveUser(user);
    }

    function logout() {
        clearSession({
            expired: false
        });

        window.dispatchEvent(
            new CustomEvent("scamshield:logout")
        );
    }

    /* ================================================
       PUBLIC API
    ================================================ */

    const ScamShieldAPI = {
        version: "3.1.0",

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
        "ScamShield AI API Service v3.1.0 initialized."
    );

})();