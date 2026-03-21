/**
 * OAuth2 Client Library with PKCE Support
 *
 * Drop-in client for OAuth2 authorization code flow with PKCE (S256).
 * Handles token storage, automatic refresh, and authenticated API requests.
 *
 * @example
 * const client = new OAuthClient({
 *   authUrl: 'https://auth.example.com',
 *   clientId: 'your-client-id',
 *   redirectUri: 'https://app.example.com/callback',
 *   scope: 'openid',
 *   onSessionExpired: () => window.location.href = '/login'
 * });
 *
 * // Start authorization flow
 * await client.authorize();
 *
 * // In callback page
 * const tokens = await client.handleCallback();
 *
 * // Resume session on page load (starts auto-refresh timer)
 * client.startAutoRefresh();
 *
 * // Make authenticated requests (auto-refreshes if needed)
 * const response = await client.fetchWithToken('/api/resource');
 */
class OAuthClient {
    /**
     * @param {Object} config - Configuration options
     * @param {string} config.authUrl - Base URL of OAuth2 server
     * @param {string} config.clientId - OAuth2 client ID
     * @param {string} config.redirectUri - Redirect URI for callbacks
     * @param {string} [config.scope='openid'] - OAuth2 scope
     * @param {number} [config.refreshBufferSeconds=60] - Seconds before expiry to trigger proactive refresh
     * @param {Function} [config.onSessionExpired] - Called when session cannot be recovered (refresh token expired/revoked)
     * @param {Function} [config.onTokenRefresh] - Called after successful token refresh with new token data
     */
    constructor(config) {
        this.authUrl = config.authUrl;
        this.clientId = config.clientId;
        this.redirectUri = config.redirectUri;
        this.scope = config.scope || 'openid';
        this.refreshBufferSeconds = config.refreshBufferSeconds || 60;
        this.onSessionExpired = config.onSessionExpired || null;
        this.onTokenRefresh = config.onTokenRefresh || null;

        this.tokenKey = `tokens_${this.clientId}`;
        this.pkceKey = `pkce_${this.clientId}`;
        this._lockKey = `refresh_lock_${this.clientId}`;

        this._refreshTimer = null;
        this._refreshPromise = null;
        this._tabId = Math.random().toString(36).slice(2) + Date.now().toString(36);

        // Listen for token updates from other tabs
        this._onStorage = this._onStorage.bind(this);
        window.addEventListener('storage', this._onStorage);
    }

    /* ======================================================================
     * PKCE Helpers
     * ====================================================================== */

    /**
     * Generate PKCE code_verifier (random base64url string)
     * @private
     */
    _generateCodeVerifier() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode.apply(null, array))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /**
     * Compute PKCE code_challenge from code_verifier using S256
     * @private
     */
    async _generateCodeChallenge(verifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const hash = await crypto.subtle.digest('SHA-256', data);
        const base64 = btoa(String.fromCharCode.apply(null, new Uint8Array(hash)));
        return base64
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    /* ======================================================================
     * Authorization Flow
     * ====================================================================== */

    /**
     * Start OAuth2 authorization flow with PKCE
     * Redirects browser to authorization endpoint
     */
    async authorize() {
        const codeVerifier = this._generateCodeVerifier();
        const codeChallenge = await this._generateCodeChallenge(codeVerifier);

        // Generate state: client_id + random value for CSRF protection
        // Format: "clientId.randomValue" (defense in depth: validates both)
        const randomValue = this._generateCodeVerifier();
        const state = `${this.clientId}.${randomValue}`;

        // Store random portion for validation in callback
        sessionStorage.setItem(`state_${this.clientId}`, randomValue);
        sessionStorage.setItem(this.pkceKey, codeVerifier);

        const authUrl = `${this.authUrl}/authorize?` +
            `client_id=${encodeURIComponent(this.clientId)}` +
            `&redirect_uri=${encodeURIComponent(this.redirectUri)}` +
            `&response_type=code` +
            `&state=${encodeURIComponent(state)}` +
            `&scope=${encodeURIComponent(this.scope)}` +
            `&code_challenge=${encodeURIComponent(codeChallenge)}` +
            `&code_challenge_method=S256`;

        window.location.href = authUrl;
    }

    /**
     * Handle OAuth2 callback and exchange code for tokens
     * Call this from your callback page
     * @returns {Promise<Object>} Token data {access_token, refresh_token, expires_at}
     * @throws {Error} If authorization failed or parameters invalid
     */
    async handleCallback() {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');
        const error = params.get('error');

        // Check for OAuth errors
        if (error) {
            const errorDesc = params.get('error_description') || 'Authorization failed';
            throw new Error(`OAuth error: ${error} - ${errorDesc}`);
        }

        if (!code || !state) {
            throw new Error('Missing code or state parameter');
        }

        // Validate state format: "clientId.randomValue"
        const stateParts = state.split('.');
        if (stateParts.length !== 2) {
            throw new Error('Invalid state format');
        }

        const [stateClientId, stateRandom] = stateParts;

        // Validate client_id matches
        if (stateClientId !== this.clientId) {
            throw new Error('State client_id mismatch - possible CSRF attack');
        }

        // Validate random value matches stored value
        const storedRandom = sessionStorage.getItem(`state_${this.clientId}`);
        if (!storedRandom || stateRandom !== storedRandom) {
            throw new Error('State validation failed - possible CSRF attack');
        }

        // Clean up stored state
        sessionStorage.removeItem(`state_${this.clientId}`);

        // Retrieve PKCE code_verifier
        const codeVerifier = sessionStorage.getItem(this.pkceKey);
        if (!codeVerifier) {
            throw new Error(`PKCE verifier not found for client ${this.clientId}`);
        }

        // Exchange authorization code for tokens
        const response = await fetch(`${this.authUrl}/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: this.redirectUri,
                client_id: this.clientId,
                code_verifier: codeVerifier
            })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP ${response.status}`);
        }

        const tokens = await response.json();

        // Calculate expiration timestamp
        const tokenData = {
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: Date.now() + (tokens.expires_in * 1000)
        };

        // Store tokens, clean up PKCE verifier, schedule refresh
        this.storeTokens(tokenData);
        sessionStorage.removeItem(this.pkceKey);
        this._scheduleRefresh(tokenData);

        return tokenData;
    }

    /* ======================================================================
     * Token Storage
     * ====================================================================== */

    /**
     * Store tokens in localStorage
     * @param {Object} tokens - Token data to store
     */
    storeTokens(tokens) {
        localStorage.setItem(this.tokenKey, JSON.stringify(tokens));
    }

    /**
     * Retrieve stored tokens from localStorage
     * @returns {Object|null} Token data or null if not found
     */
    getTokens() {
        const stored = localStorage.getItem(this.tokenKey);
        return stored ? JSON.parse(stored) : null;
    }

    /**
     * Check if stored tokens are expired
     * @param {Object} [tokens] - Token data (if not provided, retrieves from storage)
     * @returns {boolean} True if tokens are expired or missing
     */
    tokensExpired(tokens = null) {
        const tokenData = tokens || this.getTokens();
        if (!tokenData || !tokenData.expires_at) return true;
        return Date.now() >= tokenData.expires_at;
    }

    /**
     * Clear stored tokens, PKCE data, and cancel any scheduled refresh
     */
    clearTokens() {
        localStorage.removeItem(this.tokenKey);
        sessionStorage.removeItem(this.pkceKey);
        this._cancelRefresh();
    }

    /* ======================================================================
     * Cross-Tab Coordination
     * ====================================================================== */

    /**
     * Handle localStorage changes from other tabs
     *
     * The 'storage' event fires in all OTHER tabs when localStorage changes.
     * When another tab refreshes tokens, this tab picks up the new tokens
     * and reschedules its refresh timer — preventing redundant refresh
     * requests that would trigger replay detection and revoke the chain.
     *
     * @private
     */
    _onStorage(event) {
        if (event.key !== this.tokenKey) return;

        if (event.newValue) {
            const tokens = JSON.parse(event.newValue);
            this._scheduleRefresh(tokens);
            if (this.onTokenRefresh) this.onTokenRefresh(tokens);
        } else {
            // Tokens cleared (logout from another tab)
            this._cancelRefresh();
            this._handleSessionExpired();
        }
    }

    /**
     * Acquire a cross-tab refresh lock using write-then-verify pattern
     *
     * Two tabs may attempt to refresh simultaneously. Both write their tab ID
     * to the same localStorage key. After a 50ms settle window, whichever
     * tab ID remains in storage is the winner (last-writer-wins). The loser
     * backs off and waits for the winner to complete the refresh.
     *
     * Stale locks (from crashed/closed tabs) expire after 10 seconds.
     *
     * @private
     * @returns {Promise<boolean>} True if this tab acquired the lock
     */
    async _acquireRefreshLock() {
        const now = Date.now();

        // Check for existing fresh lock held by another tab
        const existing = localStorage.getItem(this._lockKey);
        if (existing) {
            const lock = JSON.parse(existing);
            if (now - lock.ts < 10000) {
                return false;
            }
        }

        // Write our claim
        localStorage.setItem(this._lockKey,
            JSON.stringify({ tabId: this._tabId, ts: now }));

        // Settle window — let any concurrent writer finish
        await new Promise(r => setTimeout(r, 50));

        // Verify we still hold the lock
        const check = localStorage.getItem(this._lockKey);
        if (!check) return false;
        return JSON.parse(check).tabId === this._tabId;
    }

    /**
     * Release the refresh lock (only if we own it)
     * @private
     */
    _releaseRefreshLock() {
        const raw = localStorage.getItem(this._lockKey);
        if (raw) {
            const lock = JSON.parse(raw);
            if (lock.tabId === this._tabId) {
                localStorage.removeItem(this._lockKey);
            }
        }
    }

    /**
     * Wait for another tab to complete its token refresh
     *
     * Polls localStorage every 200ms for up to 5 seconds. Resolves as soon
     * as the stored tokens change (the other tab finished refreshing).
     *
     * @private
     * @param {number} originalExpiresAt - expires_at before refresh, used to detect change
     * @returns {Promise<Object>} Updated token data
     * @throws {Error} If tokens are cleared or timeout reached
     */
    async _waitForRefreshedTokens(originalExpiresAt) {
        for (let i = 0; i < 25; i++) {
            await new Promise(r => setTimeout(r, 200));
            const tokens = this.getTokens();
            if (!tokens) {
                this._handleSessionExpired();
                throw new Error('Session expired (cleared by another tab)');
            }
            if (tokens.expires_at !== originalExpiresAt) {
                this._scheduleRefresh(tokens);
                return tokens;
            }
        }
        this._handleSessionExpired();
        throw new Error('Token refresh timed out waiting for another tab');
    }

    /* ======================================================================
     * Token Refresh
     * ====================================================================== */

    /**
     * Initialize auto-refresh from stored tokens
     *
     * Call this on page load when resuming an existing session.
     * Schedules a proactive refresh before the access token expires.
     * If the access token is already expired, attempts an immediate refresh.
     *
     * @returns {Promise<Object|null>} Fresh token data if immediate refresh occurred, null if timer was scheduled
     */
    async startAutoRefresh() {
        const tokens = this.getTokens();
        if (!tokens || !tokens.refresh_token) return null;

        if (this.tokensExpired(tokens)) {
            return this.refreshAccessToken();
        }

        this._scheduleRefresh(tokens);
        return null;
    }

    /**
     * Exchange refresh token for new access token
     *
     * Handles token rotation: if the server issues a new refresh token,
     * it replaces the stored one. Concurrent calls are deduplicated
     * (only one network request in flight at a time).
     *
     * @returns {Promise<Object>} New token data {access_token, refresh_token, expires_at}
     * @throws {Error} If refresh fails (triggers onSessionExpired callback)
     */
    async refreshAccessToken() {
        // Deduplicate concurrent refresh attempts within this tab
        if (this._refreshPromise) return this._refreshPromise;

        const tokens = this.getTokens();
        if (!tokens || !tokens.refresh_token) {
            this._handleSessionExpired();
            throw new Error('No refresh token available');
        }

        // Acquire cross-tab lock (prevents multiple tabs from refreshing)
        const acquired = await this._acquireRefreshLock();
        if (!acquired) {
            return this._waitForRefreshedTokens(tokens.expires_at);
        }

        this._refreshPromise = this._executeRefresh(tokens.refresh_token);
        try {
            return await this._refreshPromise;
        } finally {
            this._refreshPromise = null;
            this._releaseRefreshLock();
        }
    }

    /**
     * @private
     */
    async _executeRefresh(refreshToken) {
        const response = await fetch(`${this.authUrl}/token`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
                client_id: this.clientId
            })
        });

        if (!response.ok) {
            this.clearTokens();
            this._handleSessionExpired();
            throw new Error('Token refresh failed');
        }

        const data = await response.json();
        const tokenData = {
            access_token: data.access_token,
            refresh_token: data.refresh_token || refreshToken,
            expires_at: Date.now() + (data.expires_in * 1000)
        };

        this.storeTokens(tokenData);
        this._scheduleRefresh(tokenData);
        if (this.onTokenRefresh) this.onTokenRefresh(tokenData);
        return tokenData;
    }

    /**
     * Schedule a proactive refresh before the access token expires
     * @private
     */
    _scheduleRefresh(tokens) {
        this._cancelRefresh();
        if (!tokens || !tokens.refresh_token || !tokens.expires_at) return;

        const msUntilExpiry = tokens.expires_at - Date.now();
        const refreshIn = msUntilExpiry - (this.refreshBufferSeconds * 1000);

        if (refreshIn <= 0) return;

        this._refreshTimer = setTimeout(() => {
            this.refreshAccessToken().catch(() => {});
        }, refreshIn);
    }

    /**
     * @private
     */
    _cancelRefresh() {
        if (this._refreshTimer) {
            clearTimeout(this._refreshTimer);
            this._refreshTimer = null;
        }
    }

    /**
     * @private
     */
    _handleSessionExpired() {
        this._cancelRefresh();
        if (this.onSessionExpired) this.onSessionExpired();
    }

    /* ======================================================================
     * Authenticated Requests
     * ====================================================================== */

    /**
     * Make an authenticated fetch request using stored access token
     *
     * Automatically refreshes the access token if expired (when a refresh
     * token is available). Retries once on 401 responses in case the token
     * was revoked server-side between the expiry check and the request.
     *
     * @param {string} url - URL to fetch
     * @param {Object} [options={}] - Fetch options (same as window.fetch)
     * @returns {Promise<Response>} Fetch response
     * @throws {Error} If not authenticated and cannot refresh
     */
    async fetchWithToken(url, options = {}) {
        let tokens = await this._ensureFreshTokens();

        const response = await fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                'Authorization': `Bearer ${tokens.access_token}`
            }
        });

        // Retry once on 401 — token may have been revoked server-side
        if (response.status === 401 && tokens.refresh_token) {
            tokens = await this.refreshAccessToken();
            return fetch(url, {
                ...options,
                headers: {
                    ...options.headers,
                    'Authorization': `Bearer ${tokens.access_token}`
                }
            });
        }

        return response;
    }

    /**
     * Ensure we have a valid access token, refreshing if necessary
     * @private
     */
    async _ensureFreshTokens() {
        const tokens = this.getTokens();
        if (!tokens) {
            this._handleSessionExpired();
            throw new Error('Not authenticated');
        }

        if (this.tokensExpired(tokens)) {
            if (tokens.refresh_token) {
                return this.refreshAccessToken();
            }
            this._handleSessionExpired();
            throw new Error('Access token expired, no refresh token available');
        }

        return tokens;
    }

    /* ======================================================================
     * Cleanup
     * ====================================================================== */

    /**
     * Cancel scheduled refresh timer
     *
     * Call this when the client instance is no longer needed
     * (e.g., on page unload or when switching accounts).
     */
    destroy() {
        this._cancelRefresh();
        window.removeEventListener('storage', this._onStorage);
    }
}
