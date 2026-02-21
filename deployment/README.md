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

# Bootstrap admin account (localhost only)
docker exec auth-server wget -qO- \
  --header='Content-Type: application/json' \
  --post-data='{"username":"admin","password":"changeme"}' \
  http://localhost:8080/api/admin/bootstrap
```

## Self-Hosted Production (Docker Compose)

This runs auth-server + nginx + certbot with automatic TLS via Let's Encrypt.

### 1. Configure

```bash
cd deployment
cp .env.example .env
# Edit .env with your domain, database settings, etc.
```

### 2. Generate nginx config

```bash
export DOMAIN=auth.yourdomain.com
envsubst '${DOMAIN}' < nginx/conf.d/default.conf.template > nginx/conf.d/default.conf
```

### 3. Obtain TLS certificate

Get the initial certificate before starting nginx (standalone mode runs a temporary server on port 80):

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
docker compose logs -f auth-server

# Restart
docker compose restart

# Update (rebuild and restart)
docker compose up -d --build

# Manual certificate renewal
docker compose run --rm certbot renew
docker compose exec nginx nginx -s reload
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

The server loads `auth.conf` from its working directory. All settings can also be
overridden by environment variables (useful for Docker and secrets management).

| Environment Variable  | auth.conf key    | Description              | Default        |
|-----------------------|------------------|--------------------------|----------------|
| `AUTH_DB_TYPE`        | `db_type`        | `sqlite` or `postgresql` | `sqlite`       |
| `AUTH_DB_HOST`        | `db_host`        | PostgreSQL host          | —              |
| `AUTH_DB_PORT`        | `db_port`        | PostgreSQL port          | `5432`         |
| `AUTH_DB_NAME`        | `db_name`        | PostgreSQL database      | —              |
| `AUTH_DB_USER`        | `db_user`        | PostgreSQL user          | —              |
| `AUTH_DB_PASSWORD`    | `db_password`    | PostgreSQL password      | —              |
| `AUTH_DB_OWNER_ROLE`  | `db_owner_role`  | Schema owner role        | (db_user)      |
| `AUTH_ENCRYPTION_KEY` | `encryption_key` | Field encryption key     | `customize_me` |
| `AUTH_LOG_LEVEL`      | `log_level`      | `debug/info/warn/error`  | `info`         |

Environment variable names can be customized in `auth.conf` (e.g., `db_password_env = MY_SECRET`)
to match your infrastructure's naming conventions.

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
├── nginx/
│   ├── nginx.conf                     # Main nginx config (rate limiting, security headers)
│   └── conf.d/
│       └── default.conf.template      # Server block template (envsubst with $DOMAIN)
└── README.md
```
