# API Documentation

HTTP endpoints for the OAuth2 authentication server.

## Table of Contents

1. [Admin API (Localhost-Only)](#admin-api-localhost-only)
2. [Organization Management API (Session Auth)](#organization-management-api-session-auth)
3. [Organization Management API (Org-Key Auth)](#organization-management-api-org-key-auth)
4. [OAuth2 Endpoints (Public)](#oauth2-endpoints-public)
5. [User Account Endpoints (Session Auth)](#account-endpoints-session-auth)
6. [MFA Endpoints (Session Auth)](#mfa-endpoints-session-auth)

---

## Admin API (Localhost-Only)

Administrative endpoints for initial setup and tenant management. 
**Only accessible from localhost** (127.0.0.1 / ::1).

All endpoints reject connections from non-localhost IPs with `403 Forbidden`.

### Security Model

- **Access Control**: IP-based (localhost only)
- **Use Case**: Shell access to server host = trusted admin
- **Transport**: HTTP acceptable (localhost loopback)
- **Audience**: Server administrators via curl/scripts

---

### POST /api/admin/bootstrap

Bootstrap the authentication system with initial organization and management UI.

**Purpose**: One-time setup to create system organization, 
   management API resource server, management UI client, and first admin user.

**Note**: NOT idempotent - fails if requested organization code_name or username already exists.

**Request Body**:
```json
{
  "org_code_name": "system",
  "org_display_name": "System Organization",
  "username": "admin",
  "password": "SecurePassword123!"
}
```

| Field            | Type   | Required  | Description                                                |
|------------------|--------|-----------|------------------------------------------------------------|
| org_code_name    | string | No        | Organization code name (default: "system")                 |
| org_display_name | string | No        | Organization display name (default: "System Organization") |
| username         | string | Yes       | Admin username                                             |
| password         | string | Yes       | Admin password (plaintext, will be hashed)                 |

**Success Response** (200 OK):
```json
{
  "message": "Bootstrap successful",
  "organization_code_name": "system"
}
```

**Error Responses**:

- **403 Forbidden** (not from localhost):
```json
{
  "error": "forbidden",
  "message": "Admin endpoints only accessible from localhost"
}
```

- **409 Conflict** (organization exists):
```json
{
  "error": "conflict",
  "message": "Organization 'system' already exists"
}
```

- **400 Bad Request** (validation error):
```json
{
  "error": "invalid_request",
  "message": "Username is required"
}
```

**Creates**:
1. Organization (with provided/default code_name)
2. Resource Server (code_name: "management_api", address: "http://localhost:PORT/api")
3. Client (code_name: "management_ui", type: "public", grant: "authorization_code", universal: true)
4. Redirect URI ("http://localhost:PORT/callback")
5. Client-Resource-Server link (management_ui can access management_api)
6. User account with hashed password
7. Organization admin privilege for user

**Example**:
```bash
curl -X POST http://localhost:8080/api/admin/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "MySecurePassword123!"
  }'
```

---

### POST /api/admin/organizations

Create a new organization (tenant).

**Purpose**: Add new tenant organization. 
    Org admin will configure resources/clients via management UI.

**Idempotency**: NOT idempotent - fails if code_name already exists.

**Request Body**:
```json
{
  "code_name": "aaacorp",
  "display_name": "Triple A Corporation",
  "note": "Production tenant for AAA"
}
```

| Field        | Type   | Required  | Description                      |
|--------------|--------|-----------|----------------------------------|
| code_name    | string | Yes       | Unique organization identifier   |
| display_name | string | Yes       | Human-readable organization name |
| note         | string | No        | Optional description             |

**Success Response** (200 OK):
```json
{
  "organization_id": "aaace122-333b-4444-8cd8-999999999001",
  "code_name": "aaacorp",
  "display_name": "Triple A Corporation"
}
```

**Error Responses**:

- **403 Forbidden** (not from localhost)
- **409 Conflict** (code_name exists):
```json
{
  "error": "conflict",
  "message": "Organization code_name 'aaacorp' already exists"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/admin/organizations \
  -H "Content-Type: application/json" \
  -d '{
    "code_name": "aaacorp",
    "display_name": "Triple A Corporation"
  }'
```

---

### POST /api/admin/users

Create a user account (not attached to any organization or client).

**Purpose**: Create user who can later be granted org admin privileges or added to clients.

**Idempotency**: NOT idempotent - fails if username or email already exists.

**Request Body**:
```json
{
  "username": "tiger",
  "email": "tiger@example.com",
  "password": "T1g3rzP4$$w0rd"
}
```

| Field    | Type   | Required  | Description                          |
|----------|--------|-----------|--------------------------------------|
| username | string | No*       | Unique username                      |
| email    | string | No*       | Email address                        |
| password | string | Yes       | Password (plaintext, will be hashed) |

*At least one of username or email must be provided.

**Success Response** (200 OK):
```json
{
  "user_id": "a1b2c3d4-0000-4aaa-944b-a1b2c3d4e5f6",
  "username": "tiger",
  "email": "tiger@example.com"
}
```

**Error Responses**:

- **403 Forbidden** (not from localhost)
- **409 Conflict** (username exists):
```json
{
  "error": "conflict",
  "message": "Username 'tiger' already exists"
}
```
- **409 Conflict** (email exists):
```json
{
  "error": "conflict",
  "message": "Email 'tiger@example.com' already exists"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/admin/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "tiger",
    "email": "tiger@example.com",
    "password": "T1g3rzP4$$w0rd"
  }'
```

---

### POST /api/admin/org-admins

Grant organization admin privileges to a user.

**Purpose**: Make user an admin of an organization (can manage org resources via UI).

**Idempotency**: Idempotent - succeeds if user is already an admin.

**Request Body**:
```json
{
  "username": "tiger",
  "org_code_name": "aaacorp"
}
```

| Field         | Type   | Required  | Description                          |
|---------------|--------|-----------|--------------------------------------|
| username      | string | Yes       | Username of user to grant privileges |
| org_code_name | string | Yes       | Organization code name               |

**Success Response** (200 OK):
```json
{
  "user_id": "a1b2c3d4-0000-4aaa-944b-a1b2c3d4e5f6",
  "organization_id": "7777777a-333b-4444-8cd8-999999999001",
  "message": "User 'tiger' is now an admin of organization 'aaacorp'"
}
```

**Error Responses**:

- **403 Forbidden** (not from localhost)
- **404 Not Found** (user doesn't exist):
```json
{
  "error": "not_found",
  "message": "User 'tiger' does not exist"
}
```
- **404 Not Found** (organization doesn't exist):
```json
{
  "error": "not_found",
  "message": "Organization 'aaacorp' does not exist"
}
```

**Example**:
```bash
curl -X POST http://localhost:8080/api/admin/org-admins \
  -H "Content-Type: application/json" \
  -d '{
    "username": "tiger",
    "org_code_name": "aaacorp"
  }'
```

---

### Complete Bootstrap Workflow

```bash
# 1. Bootstrap system organization + management UI
curl -X POST http://localhost:8080/api/admin/bootstrap \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "email": "admin@example.com",
    "password": "MySecurePassword123!"
  }'

# System is now ready - admin can log into management UI at http://localhost:8080/

# 2. Create tenant organization
curl -X POST http://localhost:8080/api/admin/organizations \
  -H "Content-Type: application/json" \
  -d '{
    "code_name": "aaacorp",
    "display_name": "Triple A Corporation"
  }'

# 3. Create user for tenant
curl -X POST http://localhost:8080/api/admin/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "tiger",
    "email": "tiger@example.com",
    "password": "T1g3rzP4$$w0rd"
  }'

# 4. Make user admin of organization
curl -X POST http://localhost:8080/api/admin/org-admins \
  -H "Content-Type: application/json" \
  -d '{
    "username": "tiger",
    "org_code_name": "aaacorp"
  }'

# "tiger" can now log into management UI and configure "aaacorp" resources/clients
```

---

## Organization Management API (Session Auth)

Authenticated endpoints for organization administrators 
    to manage resources, clients, and configurations. 
    Requires valid session cookie from `/login`.

**Authentication**: Session cookie (user must be org admin)
**Use Case**: Management UI operations
**Access Control**: User must have org-admin role for the organization being managed

### Organizations

**GET /api/admin/organizations**
List organizations where user is admin, or get single organization.

Query params:
- `id` (optional) - Organization UUID for single get
- `limit` (default 20, max 100) - List mode
- `offset` (default 0) - List mode
- `is_active` (optional boolean) - Filter by status

**PUT /api/admin/organizations**
Update organization properties.

Query: `id` (required) - Organization UUID
Body: `display_name`, `note`, `is_active` (all optional)

### Resource Servers

**GET /api/admin/resource-servers**
List resource servers in org, or get single server.

Query params:
- `id` (optional) - Server UUID for single get
- `organization_id` (required for list) - Org UUID
- `limit`, `offset`, `is_active` - List mode filters

**POST /api/admin/resource-servers**
Create new resource server.

Body: `organization_id`, `code_name`, `display_name`, `address`, `note` (required except note)

**PUT /api/admin/resource-servers**
Update resource server.

Query: `id` (required)
Body: `display_name`, `address`, `note`, `is_active` (all optional)

### Clients

**GET /api/admin/clients**
List clients in org, or get single client.

Query params:
- `id` (optional) - Client UUID for single get
- `organization_id` (required for list)
- `limit`, `offset`, `is_active` - List mode filters

**POST /api/admin/clients**
Create new client.

Body: `organization_id`, `code_name`, `display_name`, `client_type`, `grant_type`,
    `access_token_ttl_seconds`, plus optional `note`, `require_mfa`,
    `issue_refresh_tokens`, `refresh_token_ttl_seconds`,
    `maximum_session_seconds` (enforced at `/authorize` — sessions older than this are rejected),
    `secret_rotation_seconds` (enforced at authentication — client keys older than this are rejected)

**PUT /api/admin/clients**
Update client configuration.

Query: `id` (required)
Body: `display_name`, `note`, TTL/MFA settings, `is_active` (all optional)

### Client Redirect URIs

**GET /api/admin/client-redirect-uris**
List redirect URIs for client.

Query: `client_id` (required), `limit`, `offset`

**POST /api/admin/client-redirect-uris**
Add redirect URI to client.

Body: `client_id`, `redirect_uri`, `note` (required except note)

**DELETE /api/admin/client-redirect-uris**
Remove redirect URI from client.

Query: `client_id`, `redirect_uri` (both required)

### Client-Resource-Server Links

**GET /api/admin/client-resource-servers**
List resource servers linked to a client.

Query: `client_id` (required), `limit`, `offset`

Response: Returns `links` array with resource server attributes: 
    (resource_server_id, resource_server_code_name, resource_server_display_name, resource_server_address)

**GET /api/admin/resource-server-clients**
List clients linked to a resource server.

Query: `resource_server_id` (required), `limit`, `offset`

Response: Returns `links` array with client attributes: (client_id, client_code_name, client_display_name)

**POST /api/admin/client-resource-servers**
Link client to resource server (grant access).

Body: `client_id`, `resource_server_id` (both required)

**DELETE /api/admin/client-resource-servers**
Unlink client from resource server.

Query: `client_id`, `resource_server_id` (both required)

### Resource Server Keys

API key management for resource server introspection authentication.

**POST /api/admin/resource-server-keys**
Create new resource server API key.

Body:
- `resource_server_id` (required) - Resource server UUID
- `secret` (optional) - User-provided secret (if omitted, generates secure 32-byte token)
- `note` (optional) - Description

Response (generated secret):
```json
{
  "id": "uuid",
  "key_id": "uuid",
  "secret": "generated-token",
  "message": "Save the secret now - it cannot be retrieved later!"
}
```

Response (user-provided secret):
```json
{
  "id": "uuid",
  "key_id": "uuid",
  "message": "Key created successfully"
}
```

**GET /api/admin/resource-server-keys**
List resource server API keys.

Query: `resource_server_id` (required), `limit` (default 100, max 1000), `offset` (default 0), 
    `is_active` (optional boolean filter)

Returns: `keys` array with `id`, `key_id`, `is_active`, `generated_at`, `note` (never returns secret/salt/hash)

**DELETE /api/admin/resource-server-keys**
Revoke (soft delete) resource server API key.

Query: `id` (required) - Key UUID

### Client Keys

API key management for confidential client authentication (client_credentials flow).

**POST /api/admin/client-keys**
Create new client API key (confidential clients only).

Body:
- `client_id` (required) - Client UUID (must be confidential type)
- `secret` (optional) - User-provided secret (if omitted, generates secure 32-byte token)
- `note` (optional) - Description

Response: Same format as resource server keys (with generated secret shown once, 
    or confirmation message for user-provided)

**GET /api/admin/client-keys**
List client API keys.

Query: `client_id` (required), `limit`, `offset`, `is_active`

Returns: Same format as resource server keys list

**DELETE /api/admin/client-keys**
Revoke (soft delete) client API key.

Query: `id` (required) - Key UUID

---

### Organization Keys

High-privilege API keys granting full administrative access to an organization. 
Used for programmatic access to org-admin endpoints (alternative to session cookies).

**SECURITY**: Organization keys grant FULL admin access, same as being an admin-user of an org.
Not managed through the web UI — use the API directly.

**POST /api/admin/organization-keys** (Localhost-only)
Create new organization API key.

Body:
- `organization_code_name` (required) - Organization code name (e.g., "system")
- `secret` (optional) - User-provided secret (if omitted, generates secure 32-byte token)
- `note` (optional) - Description

Response (generated secret):
```json
{
  "key_id": "555e5478-e10b-41c4-a554-098765432100",
  "secret": "xK9mN2pQ7rS4tV6wY8zA1bC3dE5fG7hJ9kL0mN2pQ4rS",
  "warning": "Save the secret now - it cannot be retrieved later!"
}
```

Response (user-provided secret):
```json
{
  "key_id": "555e5478-e10b-41c4-a554-098765432100"
}
```

**GET /api/admin/organization-keys** (Dual-auth)
List organization API keys.

Query: `organization_code_name` (required), `limit`, `offset`, `is_active`

Response:
```json
{
  "keys": [
    {
      "key_id": "555e5478-e10b-41c4-a554-098765432100",
      "is_active": true,
      "generated_at": "2026-02-04T10:30:00Z",
      "note": "CI/CD pipeline key"
    }
  ],
  "pagination": {"limit": 20, "offset": 0, "count": 1}
}
```

**DELETE /api/admin/organization-keys** (Dual-auth)
Revoke (soft delete) organization API key.

Query: `id` (required) - Key UUID

Note: Self-revocation allowed (key can revoke itself).

---

**GET /api/admin/list-all-organizations** (Localhost-only)
List all organizations (unscoped - no user authorization filter).

Auth: Localhost-only

Query: `limit`, `offset`, `is_active`

Response: Same format as GET /api/admin/organizations

---

## Organization Management API (Org-Key Auth)

The same organization management endpoints accept organization key authentication as an alternative to session cookies. 
Intended for programmatic access, CI/CD pipelines, and scripts.

**Authentication**: `X-Org-Key-Id` + `X-Org-Key-Secret` request headers
**Scope**: Full admin access to the organization that owns the key

**Headers**:
```
X-Org-Key-Id: <key_uuid_hex>
X-Org-Key-Secret: <plaintext_secret>
```

**Example**:
```bash
# List resource servers using org key auth
curl "http://localhost:8080/api/admin/resource-servers?organization_id=555e5478-e10b-41c4-a554-098765432100" \
  -H "X-Org-Key-Id: 555e5478-e10b-41c4-a554-098765432101" \
  -H "X-Org-Key-Secret: xK9mN2pQ7rS4tV6wY8zA1bC3dE5fG7hJ9kL0mN2pQ4rS"
```

Organization keys can be managed via:
- **API**: The endpoints documented above (for scripts, CLI, programmatic access)
- **Web UI**: Organization detail page in the management console includes a key management section 
    (for browser-based admin workflows)

---

## OAuth2 Endpoints (Public)

Standard OAuth2 endpoints for authentication and token management.

### POST /login

User authentication endpoint. Creates browser session on successful login.

**Request Body**:
```json
{
  "username": "alice",
  "password": "secret123"
}
```

**Success Response — no MFA** (200 OK):
```http
HTTP/1.1 200 OK
Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800
Content-Type: application/json

{"message": "Login successful"}
```

**Success Response — user has MFA** (200 OK):
```http
HTTP/1.1 200 OK
Set-Cookie: session=<token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=604800
Content-Type: application/json

{
  "message": "Login successful",
  "mfa_required": true,
  "mfa_methods": [
    {"id": "a1b2c3...", "type": "TOTP", "display_name": "My Phone"}
  ]
}
```

When `mfa_required` is true, the session cookie is set but the session's `mfa_completed` flag is false. The client must call `POST /api/user/mfa/verify` (or `POST /api/user/mfa/recover`) to complete authentication before `/authorize` will succeed.

**Error Response** (401 Unauthorized):
```json
{
  "error": "Invalid username or password"
}
```

**Session Cookie**:
- Name: `session`
- Attributes: `HttpOnly; Secure; SameSite=Strict`
- Lifetime: 7 days (604800 seconds)
- Used for subsequent OAuth2 authorization flow

**Example**:
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secret123"
  }'
```

---

### POST /token

OAuth2 token endpoint (RFC 6749 Section 3.2). Exchanges authorization codes or refresh tokens for access tokens.

**Supported Grant Types**:
- `authorization_code` - Exchange authorization code for tokens
- `refresh_token` - Refresh access token
- `client_credentials` - Machine-to-machine authentication

**Token Format**:
- **Access tokens**: ES256-signed JWTs (JSON Web Tokens) with cryptographic signatures
- **Refresh tokens**: Opaque random strings (32-byte base64url-encoded)
- Clients should treat both token types as opaque strings

#### Authorization Code Grant

**Request**:
```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=<authorization_code>&
redirect_uri=<redirect_uri>&
client_id=<client_id>&
code_verifier=<pkce_verifier>
```

**Parameters**:

| Parameter     | Required    | Description                                 |
|---------------|-------------|---------------------------------------------|
| grant_type    | Yes         | Must be `authorization_code`                |
| code          | Yes         | Authorization code from /authorize          |
| redirect_uri  | Yes         | Must match redirect_uri used in /authorize  |
| client_id     | Yes         | Client UUID (hex-encoded)                   |
| code_verifier | Conditional | PKCE verifier (required for public clients) |

**Success Response** (200 OK):
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0...",
  "scope": "read write"
}
```

**Error Responses**:
- **400 Bad Request** - Invalid or expired code:
```json
{
  "error": "Invalid authorization code"
}
```
- **400 Bad Request** - Replay attack detected:
```json
{
  "error": "Authorization code has already been used"
}
```

#### Refresh Token Grant

**Request**:
```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&
refresh_token=<refresh_token>&
client_id=<client_id>&
scope=<optional_scope>
```

**Parameters**:

| Parameter     | Required  | Description                                  |
|---------------|-----------|----------------------------------------------|
| grant_type    | Yes       | Must be `refresh_token`                      |
| refresh_token | Yes       | Valid refresh token                          |
| client_id     | Yes       | Client UUID (hex-encoded)                    |
| scope         | No        | Requested scope (must be subset of original) |

**Success Response** (200 OK):
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8...",
  "scope": "read write"
}
```

**Notes**:
- **Refresh Token Rotation**: Each refresh returns a new refresh token. Old token is invalidated.
- **Replay Detection**: Reusing an old refresh token indicates compromise and should trigger revocation of entire token chain.
- **Scope Downscoping**: Requested scope must be subset of original authorization.

**Example**:
```bash
# Exchange authorization code
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&code=abc123&redirect_uri=http://localhost:3000/callback&client_id=555e5478-e10b-41c4-a554-098765432100&code_verifier=xyz789"

# Refresh access token
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&refresh_token=8xLOxBtZp8&client_id=555e5478-e10b-41c4-a554-098765432100"
```

---

#### Client Credentials Grant

Machine-to-machine authentication (RFC 6749 Section 4.4). No user context.

**Request**:
```http
POST /token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=<client_id>&
client_key_id=<client_key_id>&
client_secret=<client_secret>&
scope=<scope>&
resource=<resource_address>
```

**Parameters**:

| Parameter     | Required   | Description                                            |
|---------------|------------|--------------------------------------------------------|
| grant_type    | Yes        | Must be `client_credentials`                           |
| client_id     | Yes        | Client UUID (hex-encoded)                              |
| client_key_id | Yes        | Client key UUID (hex-encoded, identifies which secret) |
| client_secret | Yes        | Client secret (plaintext)                              |
| scope         | No         | Requested scopes (space-separated)                     |
| resource      | No         | Resource server address (RFC 8707)                     |

**Success Response** (200 OK):
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**Notes**:
- No refresh token issued (machine clients re-authenticate when token expires)
- Only available for confidential clients with `grant_type=client_credentials`
- Requires client authentication with client_key_id + client_secret
- Successful authentications logged to `client_key_usage` table

**Example**:
```bash
# Client credentials grant
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=555e5478-e10b-41c4-a554-098765432100&client_key_id=555e5478-e10b-41c4-a554-098765432101&client_secret=MySecretKey123"
```

---

### GET /authorize

OAuth2 authorization endpoint (RFC 6749 Section 3.1). Initiates authorization code flow.

**Query Parameters**:

| Parameter             | Type          | Required  | Description                                            |
|-----------------------|---------------|-----------|--------------------------------------------------------|
| response_type         | string        | Yes       | Must be "code"                                         |
| client_id             | string (UUID) | Yes       | Client identifier                                      |
| redirect_uri          | string        | Yes       | Registered callback URL                                |
| scope                 | string        | No        | Space-separated scope list                             |
| state                 | string        | No        | CSRF protection token                                  |
| code_challenge        | string        | No        | PKCE challenge (required for public clients)           |
| code_challenge_method | string        | No        | "plain" or "S256" (required if code_challenge present) |

**Prerequisites**:
- User must be authenticated (valid session cookie)
- Client must be registered and active
- redirect_uri must be registered for the client
- MFA completed if required by client OR if user has any confirmed MFA methods

**Success Response** (302 Found):
```http
HTTP/1.1 302 Found
Location: https://app.example.com/callback?code=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...&state=abc123
```

**Error Responses**:

- **401 Unauthorized** (not authenticated):
```json
{
  "error": "Authentication required"
}
```

- **401 Unauthorized** (MFA required):
```json
{
  "error": "MFA required"
}
```

- **400 Bad Request** (invalid request):
```json
{
  "error": "Invalid authorization request"
}
```

**Authorization Code**:
- Format: Stateless JWT signed with HMAC-SHA256
- Lifetime: 60 seconds
- Single-use enforced via database replay detection
- JWT payload contains: client_id, user_account_id, redirect_uri, scope, PKCE challenge, nonce
- Database stores: id, client_pin, user_account_pin, code (JWT), code_challenge, code_challenge_method, timestamps
- Note: redirect_uri and scope are in the JWT and validated at endpoints, not duplicated in DB

**Example**:
```bash
# Redirect user to authorization endpoint (after login)
https://localhost:8080/authorize?response_type=code&client_id=555e5478-e10b-41c4-a554-098765432100&redirect_uri=https://app.example.com/callback&scope=read+write&state=xyz789&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

---

### GET /.well-known/jwks.json

JSON Web Key Set endpoint (RFC 7517). Returns public keys for verifying OAuth2 access tokens.

**Response** (200 OK):
```json
{
  "keys": [
    {
      "kty": "EC",
      "use": "sig",
      "crv": "P-256",
      "kid": "1706745600",
      "x": "WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis",
      "y": "y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE",
      "alg": "ES256"
    }
  ]
}
```

**Fields**:
- `kty`: Key type (always "EC" for ES256)
- `use`: Public key use (always "sig" for signature)
- `crv`: Curve name (always "P-256" for ES256)
- `kid`: Key ID (timestamp of key generation)
- `x`, `y`: EC public key coordinates (base64url-encoded)
- `alg`: Algorithm (always "ES256")

**Key Rotation**:
- Current and prior keys both present during rotation period
- Keys rotated every 60 days
- Prior key retained for grace period
- Use `kid` claim in JWT header to select verification key

**Caching**:
```http
Cache-Control: max-age=3600, public
```

**Example**:
```bash
curl http://localhost:8080/.well-known/jwks.json
```

---

### POST /revoke

OAuth2 token revocation endpoint (RFC 7009). Allows clients to revoke access or refresh tokens.

**Security**: Requires client authentication (client_id + client_key_id + client_secret). 
Clients can only revoke their own tokens.

**Request**:
```http
POST /revoke HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=<token>&
token_type_hint=<hint>&
client_id=<client_id>&
client_key_id=<client_key_id>&
client_secret=<client_secret>
```

**Parameters**:

| Parameter       | Required  | Description                                                             |
|-----------------|-----------|-------------------------------------------------------------------------|
| token           | Yes       | The token to revoke (access or refresh token)                           |
| token_type_hint | No        | Hint about token type: `access_token` or `refresh_token` (optimization) |
| client_id       | Yes       | Client UUID (hex-encoded)                                               |
| client_key_id   | Yes       | Client key UUID (hex-encoded)                                           |
| client_secret   | Yes       | Client secret for authentication                                        |

**Success Response** (200 OK):
```json
{}
```

**Notes**:
- Per RFC 7009, this endpoint **always returns 200 OK**, even if:
  - The token is invalid or already revoked
  - The token doesn't exist
  - Authentication fails
- This prevents information disclosure to unauthorized parties
- Only the token owner (authenticated client) can revoke tokens
- Revocation is idempotent (revoking an already-revoked token succeeds)
- This endpoint revokes **only the specified token**, not related tokens in the chain

**Example**:
```bash
curl -X POST http://localhost:8080/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJhbGc...&client_id=abc123&client_key_id=def456&client_secret=mysecret"
```

---

### POST /introspect

OAuth2 token introspection endpoint (RFC 7662). Allows resource servers to validate and obtain metadata about access tokens.

**Security**: Requires resource server authentication (resource_server_id + resource_server_key_id + resource_server_secret). 
Resource servers can only introspect tokens issued for their own resource.

**Request**:
```http
POST /introspect HTTP/1.1
Content-Type: application/x-www-form-urlencoded

token=<token>&
token_type_hint=<hint>&
resource_server_id=<resource_server_id>&
resource_server_key_id=<resource_server_key_id>&
resource_server_secret=<resource_server_secret>
```

**Parameters**:

| Parameter              | Required  | Description                                          |
|------------------------|-----------|------------------------------------------------------|
| token                  | Yes       | The token to introspect (typically an access token)  |
| token_type_hint        | No        | Hint about token type: `access_token` (optimization) |
| resource_server_id     | Yes       | Resource server UUID (hex-encoded)                   |
| resource_server_key_id | Yes       | Resource server key UUID (hex-encoded)               |
| resource_server_secret | Yes       | Resource server secret for authentication            |

**Success Response - Active Token** (200 OK):
```json
{
  "active": true,
  "token_type": "Bearer",
  "scope": "read write",
  "client_id": "ab12cd34-8765-4321-1234-5678abcdef92",
  "sub": "ab12cd34-8765-4321-1234-5678abcdef91",
  "aud": "ab12cd34-8765-4321-1234-5678abcdef90",
  "exp": 1735689600,
  "iat": 1735686000
}
```

**Response Fields** (when active=true):

| Field      | Type    | Description                                                    |
|------------|---------|----------------------------------------------------------------|
| active     | boolean | Always `true` for valid tokens                                 |
| token_type | string  | Always `"Bearer"`                                              |
| scope      | string  | Space-separated scopes (optional)                              |
| client_id  | string  | Client UUID (hex) that owns the token                          |
| sub        | string  | User account UUID (hex), omitted for client_credentials tokens |
| aud        | string  | Resource server UUID (hex, audience)                           |
| exp        | number  | Expiration time (Unix timestamp)                               |
| iat        | number  | Issued-at time (Unix timestamp)                                |

**Success Response - Inactive Token** (200 OK):
```json
{
  "active": false
}
```

**Notes**:
- Returns `active: false` for:
  - Invalid tokens
  - Expired tokens
  - Revoked tokens
  - Tokens not belonging to the authenticated resource server
  - Authentication failures
- This prevents information disclosure per RFC 7662
- Primarily used by resource servers to validate access tokens before granting access to protected resources
- The `sub` field is omitted for machine-to-machine (client_credentials) tokens

**Example**:
```bash
curl -X POST http://localhost:8080/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=eyJhbGc...&resource_server_id=xyz123&resource_server_key_id=abc456&resource_server_secret=mysecret"
```

---

### GET /userinfo

OpenID Connect UserInfo endpoint (OIDC Core Section 5.3). Returns claims about the authenticated user.

**Security**: Bearer token authentication. The access token (ES256 JWT) must be provided in the Authorization header. The token is verified against the server's current (and prior) signing keys.

**Request**:
```http
GET /userinfo HTTP/1.1
Authorization: Bearer eyJhbGciOiJFUzI1NiIs...
```

**Success Response** (200 OK):
```json
{
  "sub": "a1b2c3d4e5f6000044aa944ba1b2c3d4",
  "preferred_username": "alice",
  "email": "alice@example.com",
  "email_verified": true,
  "server_time": 1739800000
}
```

| Field              | Type    | Description                                                            |
|--------------------|---------|------------------------------------------------------------------------|
| sub                | string  | User UUID (32-character hex, always present)                           |
| preferred_username | string  | Username (omitted if not set)                                          |
| email              | string  | Primary email address (omitted if no email on account)                 |
| email_verified     | boolean | Whether primary email is verified (present only when email is present) |
| server_time        | integer | Server Unix timestamp (custom extension)                               |

**Error Responses**:
- `401 Unauthorized` — Missing, invalid, or expired Bearer token; or user not found

**Example**:
```bash
curl http://localhost:8080/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJFUzI1NiIs..."
```

---

## User Account Endpoints (Session Auth)

User profile and settings endpoints. Require valid browser session cookie from POST /login.

### Security Model

- **Access Control**: Session cookie authentication
- **Use Case**: Logged-in users managing their own account
- **Transport**: HTTPS required in production
- **Audience**: End users via browser
- **Privacy**: Never exposes internal database PINs (user_account_pin, etc.) - only UUIDs

---

### GET /api/user/profile

Get current user's profile information.

**Authentication**: Session cookie required

**Success Response** (200 OK):
```json
{
  "user_id": "a1b2c3d4-0000-4aaa-944b-a1b2c3d4e5f6",
  "username": "alice",
  "has_mfa": true,
  "require_mfa": false
}
```

**Response Fields**:

| Field       | Type    | Description                                        |
|-------------|---------|----------------------------------------------------|
| user_id     | string  | User UUID (never exposes internal PIN)             |
| username    | string  | Username (empty string for email-only accounts)    |
| has_mfa     | boolean | True if user has at least one confirmed MFA method |
| require_mfa | boolean | True if user opted in to enforce MFA on themselves |

**Error Response** (401 Unauthorized):
```json
{
  "error": "Authentication required"
}
```

**Example**:
```bash
curl http://localhost:8080/api/user/profile \
  -H "Cookie: session=<session_token>"
```

---

### GET /api/user/emails

Get current user's email addresses with pagination support.

**Authentication**: Session cookie required

**Query Parameters**:

| Parameter  | Type    | Required  | Default  | Description                      |
|------------|---------|-----------|----------|----------------------------------|
| limit      | integer | No        | 50       | Maximum emails to return (1-100) |
| offset     | integer | No        | 0        | Number of emails to skip         |

**Success Response** (200 OK):
```json
{
  "emails": [
    {
      "email_address": "alice@example.com",
      "is_primary": true,
      "is_verified": true
    },
    {
      "email_address": "alice.work@company.com",
      "is_primary": false,
      "is_verified": false
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "count": 2,
    "total": 2
  }
}
```

**Pagination Metadata**:
- `limit`: Requested page size
- `offset`: Starting position
- `count`: Number of emails in this response
- `total`: Total emails across all pages

**Notes**:
- Returns empty array for username-only accounts (users who signed up without email)
- `is_primary`: Only one email can be primary
- `is_verified`: Email ownership verified via verification link
- Emails ordered by: primary first, then by creation time (oldest first)

**Error Responses**:

- **400 Bad Request** (invalid pagination):
```json
{
  "error": "Invalid limit: maximum is 100"
}
```

- **401 Unauthorized** (not authenticated):
```json
{
  "error": "Authentication required"
}
```

**Examples**:
```bash
# Get first 50 emails (default)
curl http://localhost:8080/api/user/emails \
  -H "Cookie: session=<session_token>"

# Get first 10 emails
curl "http://localhost:8080/api/user/emails?limit=10" \
  -H "Cookie: session=<session_token>"

# Get next page (emails 10-19)
curl "http://localhost:8080/api/user/emails?limit=10&offset=10" \
  -H "Cookie: session=<session_token>"
```

---

### POST /api/user/password

Change current user's password.

**Authentication**: Session cookie required

**Request Body**:
```json
{
  "current_password": "OldPassword123!",
  "new_password": "NewPassword456!"
}
```

**Success Response** (200 OK):
```json
{
  "message": "Password changed successfully"
}
```

**Error Responses**:

- **401 Unauthorized** (not authenticated):
```json
{
  "error": "Authentication required"
}
```

- **401 Unauthorized** (wrong current password):
```json
{
  "error": "Current password is incorrect"
}
```

- **400 Bad Request** (missing fields):
```json
{
  "error": "current_password and new_password required"
}
```

**Security**:
- Current password must be verified before change
- New password hashed with Argon2id (or PBKDF2-SHA256 if configured)
- Session remains valid after password change (no forced logout)

**Example**:
```bash
curl -X POST http://localhost:8080/api/user/password \
  -H "Cookie: session=<session_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "OldPassword123!",
    "new_password": "NewPassword456!"
  }'
```

---

### POST /api/user/username

Change current user's username.

**Authentication**: Session cookie required

**Request Body**:
```json
{
  "new_username": "newname"
}
```

**Success Response** (200 OK):
```json
{
  "message": "Username changed successfully"
}
```

**Error Responses**:

- **401 Unauthorized** (not authenticated):
```json
{
  "error": "Authentication required"
}
```

- **409 Conflict** (username taken):
```json
{
  "error": "Username already taken"
}
```

- **400 Bad Request** (invalid username — empty, contains spaces, or contains @):
```json
{
  "error": "Invalid username"
}
```

**Validation Rules**:
- Cannot be empty
- Cannot contain spaces
- Cannot contain `@` symbol
- Must be unique (case-insensitive)

**Example**:
```bash
curl -X POST http://localhost:8080/api/user/username \
  -H "Cookie: session=<session_token>" \
  -H "Content-Type: application/json" \
  -d '{"new_username": "alice_new"}'
```

---

### POST /logout

Log out current user (close browser session).

**Authentication**: Session cookie required

**Request Body**: None

**Success Response** (200 OK):
```json
{
  "message": "Logged out successfully"
}
```

**Response Headers**:
```
Set-Cookie: session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0
```

**Error Response** (401 Unauthorized):
```json
{
  "error": "No session to logout"
}
```

**Security**:
- Marks session as closed in database (`is_closed = TRUE`, `closed_at = now()`)
- Clears session cookie via `Set-Cookie` header with `Max-Age=0`
- Even if cookie persists client-side, closed sessions are rejected server-side
- Client should also clear OAuth tokens from localStorage

**Example**:
```bash
curl -X POST http://localhost:8080/logout \
  -H "Cookie: session=<session_token>"
```

---

### GET /api/user/management-setups

Get management UI client setups available to current user.

**Authentication**: Session cookie required

**Query Parameters**:

| Parameter    | Type                 | Required  | Description           |
|--------------|----------------------|-----------|-----------------------|
| callback_url | string (URL-encoded) | Yes       | Expected callback URL |
| api_url      | string (URL-encoded) | Yes       | Expected API URL      |

**Success Response** (200 OK):
```json
{
  "setups": [
    {
      "org_code_name": "system",
      "org_display_name": "System Organization",
      "client_id": "dcf3cb56d5c2158ec556b66affa1d6b7",
      "client_code_name": "management_ui",
      "client_display_name": "Management UI",
      "resource_server_address": "http://localhost:8080/api"
    }
  ]
}
```

**Notes**:
- Returns organizations where user is admin
- Filters by matching callback_url and api_url (exact match, case-insensitive)
- Used by management UI to show organization picker
- Empty array if user is not admin of any organizations with matching URLs

**Example**:
```bash
curl "http://localhost:8080/api/user/management-setups?callback_url=http%3A%2F%2Flocalhost%3A8080%2Fcallback&api_url=http%3A%2F%2Flocalhost%3A8080%2Fapi" \
  -H "Cookie: session=<session_token>"
```

---

## JavaScript Client Library

A drop-in OAuth2 client library is available at `/js/oauth-client.js` for easy integration with web applications.

### Features

- Full PKCE (S256) support
- Automatic token storage and expiration checking
- Helper methods for authenticated requests
- Zero dependencies, vanilla JavaScript
- Comprehensive error handling

### Quick Start

```html
<script src="https://auth.example.com/js/oauth-client.js"></script>
<script>
  const client = new OAuthClient({
    authUrl: 'https://auth.example.com',
    clientId: 'your-client-id',
    redirectUri: 'https://app.example.com/callback',
    scope: 'openid'
  });

  // Check authentication
  if (client.tokensExpired()) {
    await client.authorize();  // Redirect to auth server
  }

  // In callback page
  await client.handleCallback();  // Exchange code for tokens

  // Make authenticated requests
  const response = await client.fetchWithToken('/api/user/profile');
</script>
```

### Documentation

Full API documentation available at [static/js/README.md](static/js/README.md) 
or see the management console (`admin.html`) for a complete working example.

### Reference Implementation

The management console at `/admin` dogfoods this library and serves as the reference implementation. 
See `static/admin.html` and `static/callback.html` for integration examples.

---

## MFA Endpoints (Session Auth)

TOTP-based multi-factor authentication enrollment, verification, and recovery. 
All endpoints require a valid session cookie.

**Authentication**: Session cookie required
**Method IDs**: 32-character lowercase hex strings (16-byte UUID without hyphens)

---

### POST /api/user/mfa/totp/setup

Begin TOTP enrollment (step 1 of 2). Generates a secret and returns a QR code URL for scanning with an authenticator app. 
The method is unconfirmed until `POST /api/user/mfa/totp/confirm` succeeds.

**Request Body**:
```json
{
  "display_name": "My Phone"
}
```

| Field        | Type   | Required  | Description                                             |
|--------------|--------|-----------|---------------------------------------------------------|
| display_name | string | Yes       | User-chosen label (e.g., "J-Phone 131", "Work Phone")   |

**Success Response** (200 OK):
```json
{
  "method_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_url": "otpauth://totp/auth:alice?secret=JBSWY3DPEHPK3PXP&issuer=auth"
}
```

| Field     | Description                                                      |
|-----------|------------------------------------------------------------------|
| method_id | UUID of the pending (unconfirmed) method                         |
| secret    | Base32-encoded TOTP secret for manual entry in authenticator app |
| qr_url    | `otpauth://` URL — encode as QR code for scanning                |

**Example**:
```bash
curl -X POST http://localhost:8080/api/user/mfa/totp/setup \
  -H "Cookie: session=<token>" \
  -H "Content-Type: application/json" \
  -d '{"display_name": "My Phone"}'
```

---

### POST /api/user/mfa/totp/confirm

Confirm TOTP enrollment (step 2 of 2). Verifies the first code from the authenticator app. 
On success the method becomes active. 
If this is the user's **first** confirmed method, 
recovery codes are generated and returned (shown once — user must save them).

**Request Body**:
```json
{
  "method_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "code": "123456"
}
```

**Success Response — first method** (200 OK):
```json
{
  "message": "MFA method confirmed",
  "recovery_codes": [
    "a1b2c3d4e5f6a7b8c9d0",
    "..."
  ]
}
```

**Success Response — additional method** (200 OK):
```json
{
  "message": "MFA method confirmed"
}
```

**Error Response — invalid code** (400 Bad Request):
```json
{
  "error": "Invalid TOTP code"
}
```

**Notes**:
- Recovery codes (10 × 20-char hex) are only returned on first confirmed method. Subsequent enrollments reuse the existing set.
- Caller must free/discard recovery codes after displaying — they cannot be retrieved again (only masked versions available).

---

### POST /api/user/mfa/verify

Verify a TOTP code during authentication (e.g., after password login to complete MFA step).

**Request Body**:
```json
{
  "method_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
  "code": "123456"
}
```

**Success Response** (200 OK):
```json
{"valid": true}
```
or
```json
{"valid": false}
```

**Notes**:
- Every call (valid or invalid) is logged to the MFA usage audit table.
- Method must be confirmed (`is_confirmed = 1`) and owned by the authenticated user.
- On success (`valid: true`), sets `mfa_completed = true` on the session, unblocking `/authorize`.

---

### POST /api/user/mfa/recover

Verify a one-time recovery code. Marks the code as used if valid.

**Request Body**:
```json
{
  "recovery_code": "a1b2c3d4e5f6a7b8c9d0"
}
```

**Success Response** (200 OK):
```json
{"valid": true}
```
or
```json
{"valid": false}
```

**Notes**:
- Each recovery code is single-use. Once used it cannot be reused.
- 10 codes per set. Regenerate with `POST /api/user/mfa/recovery-codes/regenerate` when running low.
- On success (`valid: true`), sets `mfa_completed = true` on the session, unblocking `/authorize`.

---

### GET /api/user/mfa/methods

List all MFA methods (confirmed and pending) for the authenticated user.

**Success Response** (200 OK):
```json
{
  "methods": [
    {
      "id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
      "type": "TOTP",
      "display_name": "My Phone",
      "is_confirmed": true,
      "confirmed_at": "2026-02-07T10:30:00"
    }
  ]
}
```

**Notes**:
- `secret` and internal PINs are never returned.
- `confirmed_at` is empty string for unconfirmed (pending) methods.

**Example**:
```bash
curl http://localhost:8080/api/user/mfa/methods \
  -H "Cookie: session=<token>"
```

---

### DELETE /api/user/mfa/methods?id=<method_id>

Delete an MFA method. The `id` query parameter is the 32-char hex method UUID.

**Success Response** (200 OK):
```json
{
  "message": "MFA method deleted"
}
```

**Example**:
```bash
curl -X DELETE "http://localhost:8080/api/user/mfa/methods?id=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" \
  -H "Cookie: session=<token>"
```

---

### POST /api/user/mfa/recovery-codes/regenerate

Regenerate recovery codes. Atomically revokes the existing set and creates a new one. 
Requires at least one confirmed MFA method.

**Request Body**: None required.

**Success Response** (200 OK):
```json
{
  "recovery_codes": [
    "a1b2c3d4e5f6a7b8c9d0",
    "..."
  ]
}
```

**Notes**:
- Returns all 10 plaintext codes. Save them immediately — they cannot be retrieved again.
- Old recovery codes are immediately invalidated.

**Example**:
```bash
curl -X POST http://localhost:8080/api/user/mfa/recovery-codes/regenerate \
  -H "Cookie: session=<token>"
```

---

### POST /api/user/mfa/require

Set user MFA enforcement preference. 
Allows users to toggle whether MFA is required for themselves (independent of `client.require_mfa`).

**Request Body**:
```json
{"enabled": true}
```
or
```json
{"enabled": false}
```

**Success Response** (200 OK):
```json
{"message": "MFA requirement updated"}
```

**Notes**:
- When `enabled: true`, MFA will be enforced at `/authorize` even if the client doesn't require it.
- When `enabled: false`, MFA is only enforced if the client requires it.
- Users can only enable this if they have at least one confirmed MFA method (`has_mfa = true`).
- The toggle is immediately effective for all subsequent `/authorize` requests.

**Example**:
```bash
# Enable MFA requirement
curl -X POST http://localhost:8080/api/user/mfa/require \
  -H "Cookie: session=<token>" \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'

# Disable MFA requirement
curl -X POST http://localhost:8080/api/user/mfa/require \
  -H "Cookie: session=<token>" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```
