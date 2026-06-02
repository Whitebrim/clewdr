# Release Notes

## Whitebrim fork — security & deployment hardening

### Breaking changes

API endpoints are now split by dialect: **Anthropic-native** under `/anthropic/*`
and **OpenAI-compatible** under `/openai/*`. The pre-0.12.29 `/v1/*` and
`/code/v1/*` paths still work as **deprecated aliases** and will be removed in a
future release — migrate clients when convenient.

| Old (deprecated alias) | New (canonical) |
|------------------------|-----------------|
| `/v1/messages` | `/anthropic/v1/messages` |
| `/v1/chat/completions` | `/openai/v1/chat/completions` |
| `/v1/models` | `/openai/v1/models` (OpenAI shape) · `/anthropic/v1/models` (Anthropic shape) |
| `/code/v1/messages` | `/anthropic/code/v1/messages` |
| `/code/v1/messages/count_tokens` | `/anthropic/code/v1/messages/count_tokens` |
| `/code/v1/chat/completions` | `/openai/code/v1/chat/completions` |
| `/code/v1/models` | `/openai/v1/models` |

All endpoints accept either `Authorization: Bearer <password>` or
`x-api-key: <password>`. Update Cursor / Continue / Cline / SillyTavern base
URLs to `/openai/v1` (legacy `/v1` keeps working for now).

### New security features

- **argon2id** password hashing at rest, with automatic migration from plaintext.
- **ChaCha20-Poly1305** encryption of stored cookies, keyed by `CLEWDR_DATA_KEY`
  or a generated `clewdr.key`. The proxy refuses to start if encrypted cookies
  exist but the key is missing.
- **Progressive brute-force lockout** per client IP (5 → 5 min, escalating).
- **CIDR IP allowlists**: `admin_ip_allowlist` and `api_ip_allowlist`.
- **Security headers**: CSP with a per-request nonce (so the WASM admin UI
  loads under a strict policy), HSTS, `X-Frame-Options`, and more.
- Append-only **JSON-Lines audit log** of admin actions.
- **Configurable model list** in `clewdr.toml` (`models = [...]`), served by both
  `/openai/v1/models` (OpenAI shape) and `/anthropic/v1/models` (Anthropic shape).

### Deployment fixes

- **Config is no longer rewritten on every startup.** A clean restart preserves
  `clewdr.toml` byte-for-byte; the file is only written on first run, when a
  password is generated/migrated, or when cookies are imported from `--file`. A
  config that fails to parse now **aborts startup** instead of being overwritten
  with defaults. (Bug A)
- **Encrypted cookies are preserved** if decryption fails — the blob is kept on
  disk and a clear error is logged instead of silently zeroing it. (Bug E)
- **Correct client IP behind a reverse proxy.** `X-Forwarded-For` / `X-Real-IP`
  are trusted only when the TCP peer is in the new `trusted_proxies` set
  (default: loopback + RFC1918 + ULA), so the brute-force throttle, IP allowlist
  and audit log all key off the real client — and a direct client cannot spoof
  its IP. (Bug C)
- Admin-UI config saves no longer reset the IP allowlists / `trusted_proxies` /
  model list.

### Migration guide for existing deployments

Once on this build you can drop the docker-compose workarounds:

- **Remove `network_mode: host`.** The bind address honors `ip` / `CLEWDR_IP`,
  so set `CLEWDR_IP=0.0.0.0` (or `ip = "0.0.0.0"`) and go back to normal bridge
  networking with a `127.0.0.1:8484:8484` port mapping.
- **Remove the read-only `clewdr.toml` mount** (`:ro`). Restarts no longer
  rewrite the file, so a writable mount is safe and lets first-run password
  generation and admin-UI edits persist.
- **Set `trusted_proxies`** to cover your nginx address if it isn't already in
  the loopback/RFC1918/ULA defaults (e.g. add your Docker bridge subnet). Verify
  `audit.*.jsonl` shows real client IPs, not the proxy address.
- **Back up `CLEWDR_DATA_KEY` / `clewdr.key`.** Without it the encrypted cookies
  in `clewdr.toml` cannot be decrypted and the proxy will refuse to start.

See [`SECURITY.md`](./SECURITY.md) for the full threat model and reverse-proxy
configuration.

---

## What's New
- Use native incognito mode (`is_temporary`) for non-preserved chats (PR #145 by @GottenHeave)
- Web usage endpoint for enterprise accounts
- Update TLS emulation to Chrome 145

## Bug Fixes
- Fix `clewdr.toml` file permissions on Unix: now created with `0600` instead of default umask (#122)
- Add fallback for unknown `ContentBlock` types to prevent 422 deserialization errors (#97)
- Fix OAI `ImageUrl` to Claude `Image` format conversion in Claude Code proxy (PR #121 by @DragonFSKY)
- Fix enterprise usage tracking (PR #144 by @GottenHeave)
- Work around a bug in `tower-serve-static` (#147)

## Improvements
- Unify HTTP client construction across codebase
- Always use mimalloc as default allocator
- Unpin `tracing-subscriber`, allow ANSI color output
- Update dependencies to latest versions
- Use distroless Docker image
