# OAuth2 Client Library

Drop-in JavaScript library for OAuth2 authorization code flow with PKCE (S256).

## Features

- Full PKCE (Proof Key for Code Exchange) support with S256
- Automatic token storage in localStorage
- Automatic token refresh with proactive scheduling
- Transparent 401 retry with fresh tokens
- Concurrent refresh de-duplication
- Session expiry callbacks
- Helper methods for authenticated API requests
- Zero dependencies, pure vanilla JS

## Quick Start

### 1. Include the library

```html
<script src="/js/oauth-client.js"></script>
```

### 2. Initialize client

```javascript
const client = new OAuthClient({
    authUrl: 'https://auth.example.com',      // Your auth server
    clientId: 'your-client-id',               // OAuth2 client ID
    redirectUri: 'https://app.example.com/callback',  // Your callback URL
    scope: 'openid',                          // Requested scopes
    onSessionExpired: () => {                 // Called when refresh token is exhausted
        window.location.href = '/login';
    }
});
```

### 3. Start authorization flow

In your main application page:

```javascript
// Resume existing session (refreshes if access token expired)
try {
    await client.startAutoRefresh();
} catch (e) {
    // No valid session — start fresh
    await client.authorize();
    return;
}

if (client.tokensExpired()) {
    await client.authorize();
} else {
    showDashboard();
}
```

### 4. Handle callback

In your callback page (e.g., `/callback`):

```javascript
try {
    const tokens = await client.handleCallback();
    // Tokens stored, auto-refresh timer started, redirect to app
    window.location.href = '/dashboard';
} catch (error) {
    console.error('Authorization failed:', error);
}
```

### 5. Make authenticated requests

```javascript
// fetchWithToken auto-refreshes expired tokens and retries on 401
const response = await client.fetchWithToken('/api/user/profile');
const profile = await response.json();

// Manual token usage (no auto-refresh)
const tokens = client.getTokens();
const response = await fetch('/api/resource', {
    headers: {
        'Authorization': `Bearer ${tokens.access_token}`
    }
});
```

## API Reference

### Constructor

```javascript
new OAuthClient(config)
```

**Parameters:**
- `config.authUrl` (string, required) - Base URL of OAuth2 server
- `config.clientId` (string, required) - OAuth2 client ID
- `config.redirectUri` (string, required) - Redirect URI for callbacks
- `config.scope` (string, optional) - OAuth2 scope (default: `'openid'`)
- `config.refreshBufferSeconds` (number, optional) - Seconds before expiry to trigger proactive refresh (default: `60`)
- `config.onSessionExpired` (function, optional) - Called when session cannot be recovered (refresh token expired or revoked)
- `config.onTokenRefresh` (function, optional) - Called after successful token refresh with new token data

### Methods

#### `authorize()`

Starts the OAuth2 authorization flow. Generates PKCE parameters, stores verifier, and redirects browser to authorization endpoint.

```javascript
await client.authorize();
```

**Returns:** Promise that resolves before redirect

---

#### `handleCallback()`

Handles OAuth2 callback and exchanges authorization code for tokens. Call this from your callback page. Automatically starts the refresh timer.

```javascript
const tokens = await client.handleCallback();
```

**Returns:** Promise resolving to token object:
```javascript
{
    access_token: string,
    refresh_token: string,
    expires_at: number  // Millisecond timestamp (Date.now()-based)
}
```

**Throws:** Error if authorization failed or parameters invalid

---

#### `startAutoRefresh()`

Initialize auto-refresh from stored tokens. Call on page load to resume an existing session. If the access token is already expired but a refresh token is available, performs an immediate refresh.

```javascript
const freshTokens = await client.startAutoRefresh();
```

**Returns:** Promise resolving to fresh token data (if immediate refresh occurred) or `null` (if timer was scheduled)

**Throws:** Error if refresh fails (also triggers `onSessionExpired`)

---

#### `refreshAccessToken()`

Manually trigger a token refresh. Concurrent calls are de-duplicated — only one network request will be in flight at a time.

```javascript
const tokens = await client.refreshAccessToken();
```

**Returns:** Promise resolving to new token data

**Throws:** Error if refresh fails (also triggers `onSessionExpired`)

---

#### `fetchWithToken(url, options)`

Makes an authenticated fetch request. Automatically refreshes the access token if expired (when a refresh token is available). Retries once on 401 responses in case the token was revoked server-side.

```javascript
const response = await client.fetchWithToken('/api/resource', {
    method: 'POST',
    body: JSON.stringify(data)
});
```

**Parameters:**
- `url` (string) - URL to fetch
- `options` (object, optional) - Standard fetch options

**Returns:** Promise resolving to Response object

**Throws:** Error if not authenticated and cannot refresh (also triggers `onSessionExpired`)

---

#### `getTokens()`

Retrieves stored tokens from localStorage.

```javascript
const tokens = client.getTokens();
```

**Returns:** Token object or `null` if not found

---

#### `storeTokens(tokens)`

Stores tokens in localStorage.

```javascript
client.storeTokens({
    access_token: '...',
    refresh_token: '...',
    expires_at: Date.now() + 3600000
});
```

---

#### `tokensExpired(tokens)`

Checks if tokens are expired.

```javascript
const expired = client.tokensExpired();  // Uses stored tokens
// or
const expired = client.tokensExpired(tokens);  // Check specific tokens
```

**Returns:** `true` if expired or missing, `false` otherwise

---

#### `clearTokens()`

Removes tokens and PKCE data from storage and cancels any scheduled refresh.

```javascript
client.clearTokens();
```

---

#### `destroy()`

Cancels the scheduled refresh timer. Call when the client instance is no longer needed (e.g., on page unload or when switching accounts).

```javascript
client.destroy();
```

## Auto-Refresh Behavior

The library automatically manages token lifecycle:

1. **After `handleCallback()`** — a proactive refresh timer is scheduled for `refreshBufferSeconds` before the access token expires
2. **On `startAutoRefresh()`** — resumes the timer from stored tokens (call on page load)
3. **In `fetchWithToken()`** — if the access token is already expired, transparently refreshes before making the request
4. **On 401 response** — retries the request once with a freshly refreshed token (handles server-side revocation)
5. **On refresh failure** — calls `onSessionExpired` so your app can redirect to login
6. **Concurrent safety** — multiple simultaneous `fetchWithToken()` calls that trigger a refresh share a single refresh request

### Token Rotation

The auth server issues a new refresh token with each refresh response (token rotation). The library automatically stores the rotated token, ensuring the old one cannot be reused.

## Storage Keys

The library stores data in browser storage using these keys:

**localStorage:**
- `tokens_{clientId}` - Access and refresh tokens with expiration

**sessionStorage:**
- `pkce_{clientId}` - PKCE code verifier (temporary, cleared after token exchange)
- `state_{clientId}` - Random CSRF token (temporary, cleared after callback validation)

## Example: Complete Integration

See `admin.html` and `callback.html` in this repository for a complete working example.

## Security Notes

- **HTTPS Required:** Always use HTTPS in production to prevent token interception
- **PKCE Protection:** Implements PKCE S256 (RFC 7636) required for public clients - prevents authorization code interception attacks
- **CSRF Protection:** Uses cryptographic random state parameter combined with client_id binding - prevents cross-site request forgery attacks on the callback endpoint
- **Token Storage:** Tokens stored in localStorage (vulnerable to XSS - ensure your app sanitizes all user input)
- **Token Rotation:** Auth server issues new refresh tokens on each use, preventing replay of stolen refresh tokens
- **Session Cookies:** Auth server enforces `HttpOnly` session cookies which JavaScript cannot access (prevents XSS token theft)

## Browser Support

Requires browsers with:
- ES6+ support (classes, async/await, arrow functions)
- Web Crypto API (`crypto.subtle.digest`)
- localStorage
- TextEncoder
