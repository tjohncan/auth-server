# Auth Server

High-performance, high-security OAuth2 authentication server written in C. 
Designed for deployment on Linux servers behind a reverse proxy or load balancer 
to cover TLS termination and rate limiting.

The database component is configurable as either SQLite or PostgreSQL. 
Static front-end html and js documents 
provide the "login" interface, session flow coordination, 
and multi-tenant setup/administration wizards.

## Documentation

- **[API Reference](api/README.md)** — All HTTP endpoints (admin, OAuth2, user, MFA)
- **[Database Schema](sql/README.md)** — Tables, relationships, design principles
- **[OAuth2 Client Library](static/js/README.md)** — Drop-in JavaScript client with PKCE
- **[Deployment Guide](deployment/README.md)** — Docker, nginx, cloud load balancer setup

## Deployment

The server speaks HTTP/1.0 on a configurable port. TLS termination and rate limiting 
are expected to be handled by the infrastructure layer in front of it 
(for example, nginx in single-server deployments, 
or a load balancer and WAF in a horizontally-scaled cloud setup). 
This server focuses on authentication logic.

## Core Design

**Multi-threaded event loop architecture**
- N worker threads (auto-detected from CPU cores or explicitly configured)
- Each worker runs independent epoll instance (non-blocking I/O; edge-triggered)
- Kernel-level load balancing via SO_REUSEPORT
- No shared state between workers: no locks required
- One database connection per worker (1:1 mapping)
- Thread-safe logging with per-thread timestamp buffers

**Network layer**
- Dual-stack IPv4/IPv6 support (single socket handles both)
- Connection timeout enforcement with efficient linked-list tracking
- Request smuggling protection (detects conflicting Content-Length headers, rejects Transfer-Encoding)
- Per-worker connection limit (default 1024) prevents resource exhaustion

**Security hardening**
- Stack buffer overflow protection (`-fstack-protector-strong`)
- Buffer overflow detection in libc (`-D_FORTIFY_SOURCE=2`)
- Position-independent executable for ASLR (`-fPIE -pie`)
- Format string vulnerability warnings
- JSON injection protection in error responses
- SHA-256 hashed token storage (sessions, auth codes, refresh/access tokens)
- AES-256-GCM encryption of sensitive information at rest (usernames, emails, MFA secrets) 
    with HMAC-SHA256 blind indexes for lookups

**System Dependencies**
- POSIX + pthreads
- libargon2 (Argon2id is the default algorithm for password hashing)
- OpenSSL (PBKDF2, HMAC, JWT)
- Database backend (choose at compile time):
  - SQLite (default)
  - PostgreSQL (libpq)

**Installation Examples:**

`sudo apt-get install libargon2-dev libssl-dev` (add `libpq-dev` for PostgreSQL)

... or: `sudo dnf install libargon2-devel openssl-devel` (add `libpq-devel`)

... or: `sudo pacman -S argon2 openssl` (add `postgresql-libs`)

## System Components

### Server Layer (`src/server/`)
Core HTTP server infrastructure.

- **Event Loop** (`event_loop.c`, `include/server/event_loop.h`) - Multi-threaded epoll network layer. 
    Each worker runs independent epoll instance with kernel-level load balancing via SO_REUSEPORT.
- **HTTP** (`http.c`, `include/server/http.h`) - Zero-copy parser and response builder. HTTP/1.0 implementation.
- **Router** (`router.c`, `include/server/router.h`) - Hash table-based routing (FNV-1a, O(1) lookup). 
    Path parameters disabled by default.

### Database Layer (`src/db/`)
Database abstraction supporting SQLite and PostgreSQL.

- **Core** (`db.c`, `include/db/db.h`) - Connection abstraction with prepared statement API. 
    Validates all parameters are bound before execution.
- **SQL Portability** (`db_sql.h`) - Compile-time macros for portable SQL across backends
- **Initialization** (`init/db_init.c`, `include/db/init/db_init.h`) - Schema setup: auto-create database on first run
- **History Tables** (`init/db_history.c`, `include/db/init/db_history.h`) - Auto-generate "history tables" 
    via system catalog queries and dynamic SQL construction
- **Connection Pool** (`db_pool.c`) - One connection per worker thread (1:1 mapping). 
    Thread-local storage for lock-free access.
- **Cleaner** (`cleaner.c`, `include/db/cleaner.h`) - Background thread for purging old sessions, tokens, 
    usage logs, and history records. Prevents unbounded database growth with configurable retention periods. 
    Uses dedicated connection (not from pool). Randomized table rotation prevents thundering herd in horizontal deployments.

### Utilities (`src/util/`)
Common helper functions.

- **String** (`str.c`, `include/util/str.h`) - Safe string operations
- **Logging** (`log.c`, `include/util/log.h`) - Thread-safe timestamped logging
- **Config** (`config.c`, `include/util/config.h`) - Configuration file + environment variable parsing
- **Data** (`data.c`, `include/util/data.h`) - Hex encoding/decoding utilities used by crypto modules
- **Validation** (`validation.c`, `include/util/validation.h`) - Input validation for usernames, emails, and code names
- **JSON** (`json.c`, `include/util/json.h`) - JSON parsing utilities (unescape, get_string, get_int, get_bool)

### Crypto Layer (`src/crypto/`)
Cryptographic primitives for OAuth2 security.

- **Random** (`random.c`, `include/crypto/random.h`) - CSPRNG using getrandom() syscall. Base64url encoding/decoding. 
    Random integer generation for password hashing iterations.
- **Argon2** (`argon2.c`, `include/crypto/argon2.h`) - Argon2id password hashing (memory-hard, GPU-resistant)
- **PBKDF2** (`pbkdf2.c`, `include/crypto/pbkdf2.h`) - PBKDF2-SHA256 password hashing (alternative to Argon2)
- **Password** (`password.c`, `include/crypto/password.h`) - Config-driven wrapper with random iteration selection
- **HMAC** (`hmac.c`, `include/crypto/hmac.h`) - HMAC-SHA256 for JWT signatures and token validation. Timing-safe comparison.
- **JWT** (`jwt.c`, `include/crypto/jwt.h`) - HS256/ES256 JWT encoding/decoding for OAuth2 tokens with expiration checking
- **Signing Keys** (`signing_keys.c`, `include/crypto/signing_keys.h`) - Automatic key rotation management for JWTs. 
    HMAC secrets for auth requests, ES256 keypairs for access tokens.
- **Encrypt** (`encrypt.c`, `include/crypto/encrypt.h`) - AES-256-GCM field encryption and HMAC-SHA256 blind indexing 
    for PII and security info at rest. HKDF-derived keys from config passphrase.
- **TOTP** (`totp.c`, `include/crypto/totp.h`) - RFC 6238 TOTP implementation for multi-factor authentication

### Handlers (`src/handlers/`)
HTTP endpoint implementations.

- `common.c` - JSON response helpers with injection protection
- `health.c` - GET /health endpoint
- `admin.c` - Business logic for administrative operations
- `admin_http.c` - HTTP endpoints for localhost-only bootstrap admin API
- `admin_org_http.c` - HTTP endpoints for authenticated organization management API
- `session.c` - Business logic for user authentication and session management
- `session_http.c` - HTTP endpoints for login, logout, and user profile
- `oauth.c` - Business logic for OAuth2 token operations
- `oauth_http.c` - HTTP endpoints for OAuth2 flows (authorize, token, introspect, revoke)
- `mfa.c` - Business logic for MFA enrollment, verification, and recovery
- `mfa_http.c` - HTTP endpoints for MFA operations (TOTP setup/confirm, verify, recover)
- `static.c` - Static file serving for management console

## Handler Architecture

The application uses a three-layer handler architecture for separation of concerns:

### 1. Database Query Layer (`src/db/queries/`)
Entity-based query functions for direct database operations.

- **Files**: `org.c`, `user.c`, `client.c`, `resource_server.c`, `mfa.c`
- **Responsibility**: Prepared statements, parameter binding, result extraction
- **Used by**: Admin handlers, OAuth2 handlers
- **Design**: Natural keys (code_name, username) instead of internal PINs
- **Thread-safety**: Each caller must use their own db_handle_t from pool

Examples:
- `org_exists(db, code_name)` - Check if organization exists
- `user_create(db, username, email, password, out_id)` - Create user with hashed password
- `client_link_resource_server(db, org_code_name, client_id, address)` - Link client to API
- `oauth_session_create(db, user_pin, token, auth_method, ttl, out_id)` - Create browser session
- `oauth_auth_code_consume(db, code, out_data)` - Atomically consume auth code with replay detection
- `oauth_token_rotate_refresh(db, old_token, new_token, ttl, out_data, out_id)` - Refresh token rotation

### 2. Admin Handler Layer (`src/handlers/admin.c`)
Business logic for administrative operations.

- **Files**: `admin.c`, `admin.h`
- **Responsibility**: Input validation, existence checks, calling query functions
- **Used by**: HTTP endpoints, CLI tools, test fixtures
- **Design**: Wraps queries with pre-checks (e.g., check org exists before creating user)

Examples:
- `admin_bootstrap(db, config, ...)` - Complete system initialization
- `admin_create_user(db, username, email, password, out_id)` - Validate then create
- `admin_make_org_admin(db, user_id, org_code_name)` - Grant admin privileges

### 3. HTTP Handler Layer (`src/handlers/admin_http.c`, `admin_org_http.c`)
HTTP endpoint implementations for admin API.

- **Files**: `admin_http.c` (localhost-only bootstrap), `admin_org_http.c` (authenticated org management)
- **Responsibility**: JSON parsing, HTTP responses, authentication, input validation
- **Used by**: Router (called when endpoint matches)
- **Design**: Parses request, validates input, gets DB connection from pool, calls admin handler, builds JSON response
- **Thread-safety**: Each handler gets dedicated connection from pool via `db_pool_get_connection()`

**Dual-auth architecture** (`admin_org_http.c`):
- Organization management endpoints support session cookie OR organization key headers
- `get_auth_context(req, &ctx)` extracts credentials, sets one PIN, sentinels other to -1
- Both PINs passed through all layers (handler → admin → query)
- Query layer uses sentinel discrimination and SQL JOINs for authorization
- TOCTOU protection: specific key re-verified active at query execution time

Examples:
- `admin_bootstrap_handler(req, params)` - POST /api/admin/bootstrap (localhost-only)
- `admin_get_organizations_handler(req, params)` - GET /api/admin/organizations (dual-auth)
- `admin_create_client_handler(req, params)` - POST /api/admin/clients (dual-auth)

**Benefits of layered approach:**
- Query functions reusable across handlers
- Admin handlers reusable across HTTP/CLI/tests
- Easy to test each layer independently
- Clear separation of concerns (DB/logic/HTTP)
- Thread-safe connection management at HTTP layer
- Dual-auth at SQL level provides defense-in-depth security

### 4. Session Handler Layer (`src/handlers/session.c`)
Business logic for user authentication and session management.

- **Files**: `session.c`, `session.h`
- **Responsibility**: Credential validation, session token generation, session lifecycle
- **Used by**: Login endpoint, session validation middleware
- **Design**: Coordinates password verification with session creation in single operation

Examples:
- `session_authenticate_and_create(db, username, password, ip, ua, ttl, out_token, out_pin)` - Verify credentials and create session

### 5. Session HTTP Handler Layer (`src/handlers/session_http.c`)
HTTP endpoints for user authentication and management.

- **Files**: `session_http.c`
- **Responsibility**: JSON parsing, secure cookie setting, session validation, HTTP responses
- **Used by**: Router (called for session-authenticated endpoints)
- **Design**: Sets HttpOnly, Secure, SameSite=Strict session cookie with 7-day default TTL
- **Security**: Never exposes internal database PINs to browser, only UUIDs

Examples:
- `login_handler(req, params)` - POST /login
- `logout_handler(req, params)` - POST /logout
- `management_setups_handler(req, params)` - GET /api/user/management-setups
- `profile_handler(req, params)` - GET /api/user/profile
- `emails_handler(req, params)` - GET /api/user/emails
- `change_password_handler(req, params)` - POST /api/user/password
- `change_username_handler(req, params)` - POST /api/user/username

### 6. OAuth2 Handler Layer (`src/handlers/oauth.c`)
Business logic for OAuth2 token operations.

- **Files**: `oauth.c`, `oauth.h`
- **Responsibility**: PKCE validation, token generation, transaction-wrapped token exchanges
- **Used by**: Token endpoint, introspection/revocation endpoints
- **Design**: All token operations wrapped in transactions for atomicity
- **Security**: Replay attack detection via return codes (0=success, 1=replay, -1=error)

Examples:
- `oauth_exchange_authorization_code(db, client_id, code, redirect_uri, verifier, resource, out_response)` - Exchange auth code for tokens
- `oauth_refresh_access_token(db, client_id, refresh_token, scope, resource, out_response)` - Rotate refresh token and issue new access token

### 7. OAuth2 HTTP Handler Layer (`src/handlers/oauth_http.c`)
HTTP endpoint for OAuth2 token operations.

- **Files**: `oauth_http.c`
- **Responsibility**: Form-urlencoded parsing, RFC 6749 compliant JSON responses
- **Used by**: Router (called for POST /token)
- **Design**: Supports grant_type: authorization_code, refresh_token, client_credentials

Examples:
- `token_handler(req, params)` - POST /token

## Cryptographic Infrastructure

### Signing Keys (`crypto/signing_keys.c`)
Manages cryptographic signing keys for JWTs with automatic rotation.

**Key Types:**
- **Auth Request**: HMAC-SHA256 secrets for stateless authorization code JWTs
- **Access Token**: ES256 (ECDSA P-256) keypairs for OAuth2 access token JWTs

**Storage:**
- Database tables: `auth_request_signing`, `access_token_signing` (SQLite) or `keys.*` (PostgreSQL)
- Single-row tables enforced via `singleton` column (CHECK + UNIQUE constraint)
- Current + prior keys retained for graceful rotation

**Rotation:**
- **Passive mechanism**: Keys checked on every use, rotated if stale
- **Intervals**: 24 hours (HMAC), 60 days (ES256)
- **Auto-initialization**: Keys generated automatically on first use
- **Grace period**: Prior keys retained to validate tokens issued before rotation

### JWT Implementation (`crypto/jwt.c`)
Generates and verifies JWTs for OAuth2 access tokens.

**Algorithms:**
- **HS256** (HMAC-SHA256): For internal auth request JWTs
- **ES256** (ECDSA P-256): For OAuth2 access tokens

**Configuration:**
- `jwt_clock_skew_seconds`: Clock skew tolerance for token expiration (default: 0 for strict validation)

**Access Token Claims:**
```json
{
  "alg": "ES256",
  "typ": "JWT",
  "sub": "7777777a-333b-4444-8cd8-999999999000",  // user_account_id (UUID)
  "aud": "7777777a-333b-4444-8cd8-999999999001",  // resource_server_id (UUID)
  "client_id": "7777777a-333b-4444-8cd8-999999999002",  // client_id (UUID)
  "scope": "read write",
  "iat": 1766770496,
  "exp": 1766774096
}
```

**Authorization Code Claims (Stateless JWT):**
```json
{
  "alg": "HS256",
  "typ": "JWT",
  "client_id": "7777777a-333b-4444-8cd8-999999999000",  // Client UUID
  "user_account_id": "7777777a-333b-4444-8cd8-999999999001",  // User UUID
  "redirect_uri": "https://app.example.com/callback",
  "scope": "read write",
  "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method": "S256",
  "iat": 1766770490,
  "exp": 1766770550,  // 60 second TTL
  "nonce": "a1b2c3d4e5f6..."
}
```

**Benefits:**
- **Self-contained**: Resource servers validate locally without database calls
- **Cryptographic integrity**: ES256 signature prevents tampering
- **Standard**: RFC 7519 (JWT), RFC 7518 (JWA)
- **Efficient**: ~0.05ms to generate, ~0.15ms to verify

**OpenSSL Integration:**
- EVP API for ECDSA operations
- PEM format for key storage

## File Structure

```
auth.conf.example  # copy to auth.conf with no .example suffix, and review/change default settings
Makefile  # compilation instructions

sql/  # schema definitions for security and session entities/concepts
api/  # endpoint documentation and usage examples

src/
├── server/             # HTTP server
│   ├── event_loop.c
│   ├── http.c
│   └── router.c
├── db/                 # Database layer
│   ├── db.c
│   ├── db_pool.c
│   ├── cleaner.c
│   ├── init/
│   │   ├── db_init.c
│   │   └── db_history.c
│   └── queries/
│       ├── org.c
│       ├── user.c
│       ├── client.c
│       ├── resource_server.c
│       ├── oauth.c
│       └── mfa.c
├── crypto/             # Cryptographic primitives
│   ├── random.c
│   ├── argon2.c
│   ├── pbkdf2.c
│   ├── password.c
│   ├── hmac.c
│   ├── jwt.c
│   ├── signing_keys.c
│   ├── sha256.c
│   ├── encrypt.c
│   └── totp.c
├── util/               # Utilities
│   ├── str.c
│   ├── log.c
│   ├── config.c
│   ├── data.c
│   ├── validation.c
│   └── json.c
├── handlers/           # Endpoints
│   ├── common.c
│   ├── health.c
│   ├── admin.c
│   ├── admin_http.c
│   ├── admin_org_http.c
│   ├── session.c
│   ├── session_http.c
│   ├── oauth.c
│   ├── oauth_http.c
│   ├── mfa.c
│   ├── mfa_http.c
│   └── static.c
└── main.c              # Server entry point

include/
├── server/
│   ├── event_loop.h
│   ├── http.h
│   └── router.h
├── db/
│   ├── db.h
│   ├── db_pool.h
│   ├── db_sql.h
│   ├── cleaner.h
│   ├── init/
│   │   ├── db_init.h
│   │   └── db_history.h
│   └── queries/
│       ├── org.h
│       ├── user.h
│       ├── client.h
│       ├── resource_server.h
│       ├── oauth.h
│       └── mfa.h
├── crypto/
│   ├── random.h
│   ├── argon2.h
│   ├── pbkdf2.h
│   ├── password.h
│   ├── hmac.h
│   ├── jwt.h
│   ├── signing_keys.h
│   ├── sha256.h
│   ├── encrypt.h
│   └── totp.h
├── util/
│   ├── str.h
│   ├── log.h
│   ├── config.h
│   ├── data.h
│   ├── validation.h
│   └── json.h
├── handlers/
│   ├── admin.h
│   ├── session.h
│   ├── oauth.h
│   └── mfa.h
└── handlers.h

test/
├── test_http.c         # HTTP parser unit tests
├── test_router.c       # Router unit tests
├── test_str.c          # String utilities unit tests
├── test_db.c           # Database integration test
└── test_crypto.c       # Crypto test (random, password hashing, hmac, jwt)

data/  # Git-ignored default home for SQLite database

static/  # website files (HTML, JS, images) for login and admin pages
templates/  # email composition

vendor/
├── setup_notes.txt     # Commands to fetch SQLite amalgamation
└── sqlite/
    ├── sqlite3.c       # SQLite amalgamation (not tracked in repo)
    └── sqlite3.h
```

## Performance Characteristics

**Concurrency:**
- Designed to handle high-concurrency load
- Linear scaling with CPU cores
- No context switching within event loop

**Memory:**
- ~4KB per connection (initial buffer)
- Dynamic growth up to 1MB max request size
- Zero-copy parsing minimizes allocations

## Build System

**Database Backend Selection:**
- `make` or `make DB_BACKEND=sqlite` - Build with SQLite (default)
- `make DB_BACKEND=postgresql` - Build with PostgreSQL
- Conditional compilation ensures only selected backend is compiled
- Smaller binaries, reduced attack surface
- **SQLite setup:** The amalgamation (`sqlite3.c`) is not included in the repository — see `vendor/setup_notes.txt`

**Test Targets:**
- `make test-str` - String utilities tests
- `make test-http` - HTTP parser tests
- `make test-router` - Router tests
- `make test-db` - Database integration test
- `make test-crypto` - Crypto tests (random generation, password hashing, hmac, jwt)
- `make test` - All of the above!

## Linux-Specific Features

**SO_REUSEPORT:** Allows multiple threads to bind to same port. Kernel distributes incoming connections. 
    Requires Linux 3.9+.

**epoll:** Scalable I/O event notification with O(1) performance. 
    Linux-only (BSD uses kqueue, Windows uses IOCP).

**Edge-triggered mode (EPOLLET):** Notification only on state change. 
    Requires non-blocking I/O and complete buffer draining.

## Data Model

See **[sql/README.md](sql/README.md)** for full schema documentation. Key design points:

**Multi-tenant Organizations**
- Organizations own resource servers (APIs) and clients (applications)
- Cross-tenant mix-ups prevented via composite foreign keys

**Stateless Authorization Codes**
- Authorization codes are signed JWTs containing all required state
- Minimal database footprint: one row per code for replay detection only
- JWT provides cryptographic integrity, DB provides single-use enforcement
- Horizontally scalable (any server instance can verify JWT signature)

**Token Security**
- All tokens (session, auth code, refresh, access) stored as SHA-256 hashes — database compromise yields no usable credentials. 
    Tokens are 256-bit CSPRNG output; reversing the hash is 2^256 work, identical to guessing the token blind. 
    Collision probability at 1 billion active tokens: p ~ 10^-59
- Partial unique indexes enforce single-use semantics
- Refresh token rotation with chain tracking for replay detection
- Registered redirect URI validation (exact match, no wildcards)

## Design Philosophy

- We love speed and hate waste
- Correctness over convenience: never settle for less than our achievable best!
- Accept dependencies only when DIY feels dumb or dangerous
- Vibe: ace-tight, military-grade, production-ready (for low-impact 0-user systems)
