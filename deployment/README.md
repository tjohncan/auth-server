# Deployment

## Architecture

```
            Internet
               |
          HTTPS / 443
               |
    ┌──────────▼──────────┐
    │   TLS Termination   │
    │   ex: nginx / ALB   │
    └──────────┬──────────┘
               |
          HTTP / 8080
               |
    ┌──────────▼──────────┐
    │    auth-server      │
    │    (C, HTTP/1.0)    │
    └──────────┬──────────┘
               |
    ┌──────────▼──────────┐
    │     Database        │
    │ SQLite / PostgreSQL │
    └─────────────────────┘
```

The auth server speaks HTTP/1.0 on port 8080. It does not handle TLS or rate limiting —
those responsibilities belong to the infrastructure layer in front of it.

**TLS termination** is handled by nginx (self-hosted) or a load balancer like AWS ALB.
Internal traffic between the proxy and auth-server is unencrypted within the trusted network.

**Rate limiting** is handled by nginx (`limit_req_zone`, configured at 10 req/s per IP with
burst of 20) or a cloud WAF. This is a deliberate architectural choice: rate limiting at
the infrastructure edge is simpler, more efficient, and easier to tune than application-level
throttling. The server's job is authentication logic, not traffic policing.

## Quick Start (Local Development)

```bash
# From project root
mkdir -p data && chown 1000:1000 data    # Container runs as uid 1000
docker build -f deployment/Dockerfile -t auth-server .
docker run -d --name auth-server -p 8080:8080 -v ./data:/app/data auth-server
curl http://localhost:8080/health

# Bootstrap admin account: the admin API listens on a Unix socket in the data
# directory (admin_socket), so it's reached with docker exec, as the container's user,
# and never published. The body goes on standard input, out of the process list.
docker exec -i auth-server /app/auth-server --admin POST /api/admin/bootstrap - <<'EOF'
{"username":"admin","password":"changeme"}
EOF
```

## Single-Server Production (Docker Compose)

This runs auth-server + nginx + certbot with automatic TLS via Let's Encrypt.
For multi-server deployments, use a load balancer with managed certificates instead.

### 1. Configure

```bash
cd deployment
cp .env.example .env
# Edit .env with your domain, database settings, etc.

# The server's own settings, at the project root. The compose file mounts ../auth.conf and
# ../data; a mount whose source is missing comes up as an empty directory, which the server
# refuses to start on. Set encryption_key in auth.conf before the first start.
cp ../auth.conf.example ../auth.conf
mkdir -p ../data && sudo chown 1000:1000 ../data    # the container runs as uid 1000
# The compose file mounts an email script too: the no-op one unless the server sends mail
# (Email Delivery, below)
cp email/send-email.sh.example-noop email/send-email.sh && chmod +x email/send-email.sh
```

### 2. Generate nginx config

```bash
export DOMAIN=auth.yourdomain.com
envsubst '${DOMAIN}' < nginx/conf.d/default.conf.template > nginx/conf.d/default.conf
```

### 3. Obtain TLS certificate

Get the initial certificate before starting nginx 
(standalone mode runs a temporary server on port 80):

```bash
docker run --rm -p 80:80 -v /etc/letsencrypt:/etc/letsencrypt certbot/certbot certonly \
  --standalone -d auth.yourdomain.com \
  --email you@example.com \
  --agree-tos --non-interactive
```

### 4. Start

```bash
docker compose up -d
docker compose ps
curl https://auth.yourdomain.com/health
```

### Maintenance

```bash
# View logs
docker compose logs -f auth-server --tail 10

# View logs (filtered — hide health checks, static assets, routine 200s)
docker logs auth-server 2>&1 | grep -v -E \
  "GET /health|Sending 200 response|Accepted connection|GET /(css|js|favicon|images)/"

# Restart
docker compose restart

# Update (rebuild and restart)
docker compose up -d --build

# Certificate renewal is automatic (certbot checks every 12h, nginx reloads to pick up new certs).
# To force a manual renewal:
docker compose run --rm certbot renew
docker compose exec nginx nginx -s reload

# A maintenance run (--drophistory, --rekey; sql/README.md) needs every instance stopped;
# it refuses to run otherwise, and an instance won't start while it runs
docker compose stop auth-server
docker compose run --rm auth-server --drophistory
docker compose start auth-server

# Changing the encryption key: export the key in use now as AUTH_ENCRYPTION_KEY_PREVIOUS
# and the new one as AUTH_ENCRYPTION_KEY in this shell; after the run, put the new one in
# auth.conf, then start
docker compose stop auth-server
docker compose run --rm -e AUTH_ENCRYPTION_KEY_PREVIOUS -e AUTH_ENCRYPTION_KEY auth-server --rekey
docker compose start auth-server
```

## Cloud Deployment (ALB / Load Balancer)

If deploying behind a cloud load balancer (e.g., AWS ALB), we don't need nginx or certbot.
The load balancer handles TLS termination (using ACM certificates on AWS) and can optionally
attach a WAF for rate limiting and bot protection.

In this setup, the auth-server runs directly — either as a Docker container or a bare binary
with a systemd unit. The load balancer forwards HTTP traffic to port 8080.

```
Internet → ALB (TLS + WAF) → EC2:8080 (auth-server)
```

The server itself sends only three security headers: `X-Content-Type-Options: nosniff`,
`X-Frame-Options: SAMEORIGIN` and `Content-Security-Policy: frame-ancestors 'self'`.
Everything else the shipped nginx config adds (HSTS, Referrer-Policy,
Permissions-Policy, and the full CSP as a header rather than the pages' `<meta>` tag)
has to come from whatever sits in front of the server. With an ALB, that means
configuring the load balancer's header settings or the WAF to add them.

Set `client_ip_header = x-forwarded-for` in auth.conf. The client address the server
records (`source_ip` on sessions, key-usage logs, MFA attempts and emailed links) comes from
the header that setting names, `X-Real-IP` by default, which the shipped nginx overwrites
with the real peer. An ALB doesn't touch `X-Real-IP`, so a client could put anything there.
It appends the real address to the end of `X-Forwarded-For`, and `x-forwarded-for` reads that
last entry. (Putting nginx between the ALB and the server, with `real_ip` configured as
`deployment/nginx/nginx.conf` describes, works with the default instead.)

### Bare Binary with systemd

1. Install dependencies and build the binary (see [main top-level README](../README.md) for packages)
2. Create a service user: `useradd -r -s /bin/false authserver`
3. Place the project in `/opt/auth-server` and configure `auth.conf`
4. Set ownership: `chown -R authserver:authserver /opt/auth-server/data`
5. Create the systemd unit file at `/etc/systemd/system/auth-server.service`:

```ini
[Unit]
Description=auth-server
After=network.target

[Service]
ExecStart=/opt/auth-server/auth-server
WorkingDirectory=/opt/auth-server
User=authserver
Restart=always

[Install]
WantedBy=multi-user.target
```

6. Enable and start:

```bash
systemctl daemon-reload
systemctl enable auth-server
systemctl start auth-server
systemctl status auth-server
```

## Configuration

The server loads `auth.conf` from its working directory. These settings can also be set by
environment variable, which wins over the file (useful for Docker and secrets management); the
rest go in `auth.conf`.

| Environment Variable  | auth.conf key    | Description              | Default        |
|-----------------------|------------------|--------------------------|----------------|
| `AUTH_SERVER_HOST`    | `server_host`    | Public hostname          | `localhost`    |
| `AUTH_SERVER_PORT`    | `server_port`    | Public port              | `8080`         |
| `AUTH_DB_TYPE`        | `db_type`        | `sqlite` or `postgresql` | `sqlite`       |
| `AUTH_DB_HOST`        | `db_host`        | PostgreSQL host          | —              |
| `AUTH_DB_PORT`        | `db_port`        | PostgreSQL port          | `5432`         |
| `AUTH_DB_NAME`        | `db_name`        | PostgreSQL database      | —              |
| `AUTH_DB_USER`        | `db_user`        | PostgreSQL user          | —              |
| `AUTH_DB_PASSWORD`    | `db_password`    | PostgreSQL password      | —              |
| `AUTH_DB_OWNER_ROLE`  | `db_owner_role`  | Schema owner role        | (db_user)      |
| `AUTH_ENCRYPTION_KEY` | `encryption_key` | Field encryption key     | `customize_me` |
| `AUTH_ENCRYPTION_KEY_PREVIOUS` | `encryption_key_previous` | The key data is sealed under now, for `--rekey` only | — |
| `AUTH_ADMIN_SOCKET`   | `admin_socket`   | The admin API's Unix socket (empty: none) | `./data/admin.sock` |
| `AUTH_ADMIN_PORT`     | `admin_port`     | The admin API on loopback TCP too (0: not) | `0` |
| `AUTH_LOG_LEVEL`      | `log_level`      | `debug/info/warn/error`  | `info`         |
| `AUTH_MOTHERSHIP_URL` | `mothership_url` | Parent/brand URL on the index page | —     |
| `AUTH_ENABLE_HISTORY_TABLES` | `enable_history_tables` | History of changed and deleted rows | `false` |
| `AUTH_CLEANER_ENABLED` | `cleaner_enabled` | Purge expired rows in the background | `true` |
| `AUTH_CLEANER_INTERVAL_SECONDS` | `cleaner_interval_seconds` | Pause between table checks | `10` |
| `AUTH_CLEANER_BATCH_SIZE` | `cleaner_batch_size` | Rows deleted per batch | `1000` |
| `AUTH_CLEANER_SQLITE_VACUUM_PAGES` | `cleaner_sqlite_vacuum_pages` | SQLite pages freed per pass | `100` |
| `AUTH_CLEANER_POSTGRES_VACUUM_ENABLED` | `cleaner_postgres_vacuum_enabled` | VACUUM after purging (PostgreSQL) | `true` |
| `AUTH_RETENTION_USAGE_LOGS_DAYS` | `retention_usage_logs_days` | Usage logs kept | `60` |
| `AUTH_RETENTION_HISTORY_DAYS` | `retention_history_days` | History kept | `90` |
| `AUTH_RETENTION_SESSIONS_GRACE_DAYS` | `retention_sessions_grace_days` | Ended sessions kept | `8` |
| `AUTH_RETENTION_TOKENS_GRACE_DAYS` | `retention_tokens_grace_days` | Expired tokens kept | `8` |
| `AUTH_EMAIL_COMMAND`  | `email_command`  | Email delivery script    | —              |
| `AUTH_EMAIL_FROM`     | `email_from`     | Sender address           | —              |
| `AUTH_EMAIL_FROM_NAME`| `email_from_name`| Sender display name      | —              |

Environment variable names can be customized in `auth.conf` (e.g., `db_password_env = MY_SECRET`)
to match your infrastructure's naming conventions. See `auth.conf.example` for the full list of
configuration options including password policy, session TTL, token limits, and cleaner settings.

## Email Delivery (Optional)

Email support is a compile-time feature. Build with `EMAIL_SUPPORT=1` to enable it:

```bash
make EMAIL_SUPPORT=1
# or with Docker:
docker build -f deployment/Dockerfile --build-arg EMAIL_SUPPORT=1 -t auth-server .
```

The server sends email by forking a process that pipes a JSON payload to a configured command.
Delivery is non-blocking (worker threads return immediately) with a 30-second timeout to prevent
runaway children. This keeps email delivery a deployment concern — the deployer chooses the transport
(CLI tool, SMTP relay, HTTP API, etc.).

### Setup

1. **Copy an example script** from `deployment/email/` and make it executable:

   ```bash
   cp deployment/email/send-email.sh.example-noop deployment/email/send-email.sh
   chmod +x deployment/email/send-email.sh
   ```

   Available examples:
   - `example-noop` — logs to `/tmp/auth-server-email.log` (testing)
   - `example-cli` — AWS SES via `aws ses send-email`
   - `example-curl` — generic HTTP API
   - `example-msmtp` — local SMTP via msmtp

2. **Configure `auth.conf`:**

   ```ini
   email_command = ./deployment/email/send-email.sh
   email_from = noreply@yourdomain.com
   email_from_name = Auth System
   ```

3. **Test** with the standalone test binary:

   ```bash
   make EMAIL_SUPPORT=1 test-email
   ./test-email you@example.com
   ```

### Docker

Set `EMAIL_SUPPORT=1` in `deployment/.env`. If your email script needs additional packages
(e.g., `aws-cli`), set `EXTRA_PACKAGES` in `.env` as well. The compose file volume-mounts
`deployment/email/send-email.sh` into the container automatically.

## Production Hardening

### Secrets

The default setup loads database credentials from `.env` into container environment variables.
This is standard for single-server deployments. For higher-security environments, be aware that
environment variables are visible via `docker inspect` and `/proc/1/environ` inside the container.
Alternatives include Docker Swarm secrets or mounting a credentials file as a read-only volume.

### Resource Limits

To set memory, CPU, or other resource constraints without modifying the committed
`docker-compose.yml`, create a `docker-compose.override.yml` (gitignored) in the same directory.
Docker Compose automatically merges it with the base file.

Example `docker-compose.override.yml`:

```yaml
services:
  auth-server:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '2.0'
  nginx:
    deploy:
      resources:
        limits:
          memory: 128M
          cpus: '0.5'
```

## Building the Image

```bash
# Default (SQLite)
docker build -f deployment/Dockerfile -t auth-server .

# PostgreSQL
docker build -f deployment/Dockerfile --build-arg DB_BACKEND=postgresql -t auth-server .
```

## Files

```
deployment/
├── Dockerfile                         # Multi-stage build
├── docker-compose.yml                 # auth-server + nginx + certbot
├── .env.example                       # Environment variable template
├── email/
│   ├── send-email.sh.example-noop     # No-op logger (testing)
│   ├── send-email.sh.example-cli      # AWS SES via CLI
│   ├── send-email.sh.example-curl     # Generic HTTP API
│   └── send-email.sh.example-msmtp    # Local SMTP via msmtp
├── nginx/
│   ├── nginx.conf                     # Main nginx config (rate limiting, security headers)
│   └── conf.d/
│       └── default.conf.template      # Server block template (envsubst with $DOMAIN)
└── README.md
```
