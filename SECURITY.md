# Security

This document covers the threat model, security features, and deployment guidance for running ClewdR in a public-facing environment.

## Threat Model

ClewdR acts as a reverse proxy for Claude.ai, holding sensitive session cookies. The primary threats, in priority order:

| # | Threat | Impact | Mitigation |
|---|--------|--------|------------|
| 1 | Brute-force admin password | Full admin access | Argon2id hashing + progressive lockout |
| 2 | Cookie theft from disk/memory | Session hijack | ChaCha20-Poly1305 AEAD encryption at rest |
| 3 | Brute-force API password | Unauthorized API usage | Same lockout + argon2id verification |
| 4 | Unauthorized admin panel access | Config tampering | IP allowlist + password auth |
| 5 | Information leakage via errors | Reconnaissance | Sanitized 500 responses with correlation IDs |
| 6 | Missing security headers | XSS/clickjacking | CSP, HSTS, X-Frame-Options, etc. |

## Security Features

### Password Hashing (argon2id)

All passwords are hashed with argon2id before storage in `clewdr.toml`.

- Parameters: m=64MB, t=3, p=4 (OWASP 2024 recommendation)
- On first run, passwords are generated and printed to stdout once; only the hash is saved
- Existing plaintext passwords are auto-migrated on startup
- Verification results are cached in-memory to avoid repeated argon2 computation

### Cookie Encryption (ChaCha20-Poly1305)

Session cookies (`cookie_array`) are encrypted at rest using AEAD.

**Key management** (checked in order):

1. `CLEWDR_DATA_KEY` environment variable (64 hex chars = 32 bytes)
2. `clewdr.key` file next to `clewdr.toml`
3. Auto-generated key file on first save

Generate a key manually:
```bash
openssl rand -hex 32
```

If encrypted cookies exist but no key is available, ClewdR refuses to start.

### Brute-Force Protection

Failed authentication attempts trigger progressive lockout per IP:

| Failed Attempts | Lockout Duration |
|----------------|-----------------|
| 1-4 | None |
| 5-9 | 5 minutes |
| 10-19 | 1 hour |
| 20-49 | 24 hours |
| 50+ | Permanent (restart to clear) |

A successful login resets the failure counter for that IP.

### IP Allowlist

Restrict access by client IP using CIDR notation in `clewdr.toml`:

```toml
# Only allow admin panel from these IPs
admin_ip_allowlist = ["10.0.0.0/8", "192.168.1.0/24"]

# API endpoints open by default; restrict if needed
api_ip_allowlist = []
```

### Client IP behind a reverse proxy

`X-Real-IP` / `X-Forwarded-For` are attacker-controlled, so ClewdR only trusts
them when the request's TCP peer is itself a configured trusted proxy. Otherwise
the real TCP source address is used and the headers are ignored — a client
hitting ClewdR directly cannot spoof its IP to bypass the allowlist or
brute-force throttle.

```toml
# Networks whose forwarding headers are believed.
# Default: loopback + RFC1918 + ULA. Add your proxy's address if it sits
# outside these ranges (e.g. a Docker bridge subnet).
trusted_proxies = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
```

Configure your proxy to set `X-Real-IP $remote_addr` (and/or
`X-Forwarded-For`), restrict direct access to ClewdR's port, and verify
`audit.*.jsonl` shows real client IPs rather than the proxy address.

### Security Headers

All responses include:

- `Content-Security-Policy`: `default-src 'self'` with WASM support
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: same-origin`
- `Permissions-Policy`: no camera/mic/geo/payment
- `Strict-Transport-Security`: enabled in production mode (behind TLS)

### Audit Log

Security-relevant events are logged to `audit.YYYY-MM-DD.jsonl` in the log directory:

- Admin login attempts (success/failure)
- Configuration changes
- Cookie additions/deletions

Each entry is a JSON line with: timestamp, event type, actor IP, success flag, and optional details.

### Error Sanitization

Internal errors (HTTP 500) return a generic message with a correlation UUID. The full error details are logged server-side, referencing the same UUID for debugging without leaking internals to clients.

## Public Deployment Guide

### Prerequisites

- A TLS-terminating reverse proxy (nginx, Caddy)
- A generated data encryption key
- Firewall rules restricting direct access to ClewdR's port

### Step 1: Generate Secrets

```bash
# Data encryption key
export CLEWDR_DATA_KEY=$(openssl rand -hex 32)
echo $CLEWDR_DATA_KEY > /opt/clewdr/.env

# Passwords are auto-generated on first run
```

### Step 2: Docker Compose

```yaml
version: "3.9"
services:
  clewdr:
    image: ghcr.io/your-org/clewdr:latest
    build: .
    restart: unless-stopped
    environment:
      - CLEWDR_DATA_KEY=${CLEWDR_DATA_KEY}
    ports:
      - "127.0.0.1:8484:8484"
    volumes:
      - ./data:/etc/clewdr
```

### Step 3: nginx Reverse Proxy

```nginx
server {
    listen 443 ssl http2;
    server_name clewdr.example.com;

    ssl_certificate     /etc/letsencrypt/live/clewdr.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/clewdr.example.com/privkey.pem;

    # Rate limiting on API endpoints
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=admin:10m rate=5r/m;

    # Pass real client IP
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Host $host;

    # API endpoints (OpenAI-compatible dialect)
    location /openai/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:8484;
        proxy_buffering off;
    }

    # API endpoints (Anthropic-native dialect)
    location /anthropic/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://127.0.0.1:8484;
        proxy_buffering off;
    }

    # Admin panel - restrict access
    location / {
        limit_req zone=admin burst=5 nodelay;
        # Optional: additional IP restriction at nginx level
        # allow 1.2.3.4;
        # deny all;
        proxy_pass http://127.0.0.1:8484;
    }
}
```

### Step 4: Verify

```bash
# Check security headers
curl -I https://clewdr.example.com

# Verify API works (OpenAI dialect; or /anthropic/v1/models for Anthropic)
curl https://clewdr.example.com/openai/v1/models \
  -H "Authorization: Bearer YOUR_PASSWORD"

# Verify brute-force protection
for i in $(seq 1 6); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    https://clewdr.example.com/api/auth \
    -H "Authorization: Bearer wrong"
done
# Last request should return 429
```

### Backup Strategy

- **Config backup**: Back up `clewdr.toml` (contains hashed passwords, encrypted cookies)
- **Key backup**: Back up `clewdr.key` or record `CLEWDR_DATA_KEY` securely
- Without the encryption key, cookie data in `clewdr.toml` cannot be recovered
- Audit logs are in the log directory as dated JSONL files

## Configuration Reference

All security-related fields in `clewdr.toml`:

```toml
# Passwords (auto-generated and hashed on first run)
password = "$argon2id$..."
admin_password = "$argon2id$..."

# IP allowlists (empty = allow all)
admin_ip_allowlist = []
api_ip_allowlist = []

# Reverse proxies whose forwarding headers are trusted
# (default: loopback + RFC1918 + ULA)
trusted_proxies = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]

# Encrypted cookie storage (managed automatically)
# cookie_array_enc = "base64..."

# On-disk schema version (managed automatically)
config_version = 1
```

Environment variables:

| Variable | Description |
|----------|-------------|
| `CLEWDR_DATA_KEY` | 32-byte hex key for cookie encryption |
| `CLEWDR_PASSWORD` | Override API password |
| `CLEWDR_ADMIN_PASSWORD` | Override admin password |
| `CLEWDR_IP` | Bind address (e.g. `0.0.0.0` to listen on all interfaces) |
