# ClewdR

<p align="center">
  <img src="./assets/clewdr-logo.svg" alt="ClewdR" height="60">
</p>

ClewdR is a Rust proxy for Claude (Claude.ai, Claude Code).  
It keeps resource usage low, serves OpenAI-style endpoints, and ships with a Leptos/WASM admin UI for managing cookies and settings.

---

## Highlights

- Works with Claude web and Claude Code.
- Single static binary for Linux, macOS, Windows, and Android; Docker image available.
- Web dashboard shows live status and supports hot config reloads.
- Drops into existing OpenAI-compatible clients while keeping native Claude formats.
- Typical production footprint: `<10 MB` RAM, `<1 s` startup, `~15 MB` binary.

## Supported Endpoints

Endpoints are split by API dialect: **Anthropic-native** under `/anthropic/`
and **OpenAI-compatible** under `/openai/`.

| Service | Dialect | Endpoint |
|---------|---------|----------|
| Claude.ai | Anthropic-native | `http://127.0.0.1:8484/anthropic/v1/messages` |
| Claude.ai | OpenAI-compatible | `http://127.0.0.1:8484/openai/v1/chat/completions` |
| Claude Code | Anthropic-native | `http://127.0.0.1:8484/anthropic/code/v1/messages` |
| Claude Code | OpenAI-compatible | `http://127.0.0.1:8484/openai/code/v1/chat/completions` |
| Model list | Anthropic-native | `http://127.0.0.1:8484/anthropic/v1/models` |
| Model list | OpenAI-compatible | `http://127.0.0.1:8484/openai/v1/models` |

Streaming responses work on every endpoint. Authenticate with either
`Authorization: Bearer <password>` or `x-api-key: <password>`.

The advertised model list lives in `clewdr.toml` as `[[models]]` entries with
the full Anthropic model schema (id, display name, dates, token limits, and a
`capabilities` tree). It can be edited freely and powers both `/models`
endpoints — served verbatim by `/anthropic/v1/models` and projected to the
OpenAI shape by `/openai/v1/models`.

## Quick Start

1. Download the latest release for your platform from GitHub.  
   Linux/macOS example:
   ```bash
   curl -L -o clewdr.tar.gz https://github.com/Xerxes-2/clewdr/releases/latest/download/clewdr-linux-x64.tar.gz
   tar -xzf clewdr.tar.gz && cd clewdr-linux-x64
   chmod +x clewdr
   ```
2. Run the binary:
   ```bash
   ./clewdr
   ```
3. Open `http://127.0.0.1:8484` and enter the admin password shown in the console (or container logs if using Docker).

## Using the Web Admin

- `Dashboard` shows health, connected clients, and rate-limit status.
- `Claude` tab stores browser cookies; paste `cookie: value` pairs and save.
- `Settings` lets you rotate the admin password, set upstream proxies, and reload config without restarting.

If you forget the password, delete `clewdr.toml` and start the binary again. Docker users can mount a persistent folder for that file.

## Configure Upstreams

### Claude

1. Export your Claude.ai cookies (e.g., via browser devtools).  
2. Paste them into the Claude tab; ClewdR tracks their status automatically.  
3. Optionally set an outbound proxy or fingerprint overrides if Claude blocks your region.

## Client Examples

SillyTavern:

```json
{
  "api_url": "http://127.0.0.1:8484/openai/v1/chat/completions",
  "api_key": "password-from-console",
  "model": "claude-sonnet-4-6"
}
```

Continue (VS Code):

```json
{
  "models": [
    {
      "title": "Claude via ClewdR",
      "provider": "openai",
      "model": "claude-sonnet-4-6",
      "apiBase": "http://127.0.0.1:8484/openai/v1/",
      "apiKey": "password-from-console"
    }
  ]
}
```

Cursor:

```json
{
  "openaiApiBase": "http://127.0.0.1:8484/openai/v1/",
  "openaiApiKey": "password-from-console"
}
```

## Security / Public Deployment

ClewdR includes production-grade security features for public-facing deployments:

- **Password hashing**: argon2id (OWASP 2024 params) with auto-migration from plaintext
- **Cookie encryption**: ChaCha20-Poly1305 AEAD at rest, keyed via `CLEWDR_DATA_KEY` env var
- **Brute-force protection**: progressive lockout (5 fails → 5 min, escalating to permanent)
- **IP allowlist**: CIDR-based access control for admin and API endpoints
- **Security headers**: CSP, HSTS, X-Frame-Options, and more
- **Audit log**: JSON Lines log of all admin actions
- **Error sanitization**: no stack traces in responses, correlation IDs for debugging

For deployment behind a TLS reverse proxy (nginx/Caddy), see [SECURITY.md](./SECURITY.md).

Quick start for public deployment:
```bash
# Generate encryption key
export CLEWDR_DATA_KEY=$(openssl rand -hex 32)

# Run (passwords auto-generated on first start)
./clewdr

# Restrict admin access in clewdr.toml
# admin_ip_allowlist = ["your.ip.here/32"]
```

## Resources

- Wiki: <https://github.com/Xerxes-2/clewdr/wiki>  

## Thanks

- [wreq](https://github.com/0x676e67/wreq) for the fingerprinting library.  
- [Clewd](https://github.com/teralomaniac/clewd) for many upstream ideas.  
- [Clove](https://github.com/mirrorange/clove) for Claude Code helpers.
