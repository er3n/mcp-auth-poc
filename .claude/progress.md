---
name: project-progress
description: "MCP Auth POC build progress — what's done, what's next"
metadata: 
  node_type: memory
  type: project
  originSessionId: 82f8b25c-a906-46c1-bf7a-25da988303dd
---

## Completed

### Project Setup
- Go 1.26.3, module: `mcp-auth-poc`
- Directory structure: `cmd/server/`, `internal/authserver/`, `internal/mcpserver/`
- Git initialized with `.gitignore`

### Authorization Server — implemented so far
1. **`GET /health`** — basic health check
2. **`GET /.well-known/oauth-authorization-server`** (RFC 8414) — AS metadata endpoint, returns issuer, endpoints, supported grant types, PKCE methods. Issuer read from `ISSUER` env var, defaults to `http://localhost:8080`.
3. **`GET /authorize`** — shows HTML consent form, validates `client_id`, `redirect_uri`, `code_challenge` (S256 required), `response_type=code`
4. **`POST /authorize`** — user approves, generates cryptographically random `code` (32 bytes, base64url), saves to in-memory store with `code_challenge` + 5min expiry, redirects to `redirect_uri?code=...&state=...`

### Key files
- `cmd/server/main.go` — wires up all handlers, creates single `Store` instance
- `internal/authserver/metadata.go` — RFC 8414 metadata handler
- `internal/authserver/authorize.go` — GET/POST /authorize, two private functions: `handleAuthorizeForm`, `handleAuthorizeConfirm`
- `internal/authserver/store.go` — in-memory `AuthCode` store with `sync.RWMutex`
- `requests/health.http` — HTTP test requests for all endpoints

## Next Steps (in order)
1. **`POST /token`** — exchange `code` + `code_verifier` for JWT access token (PKCE S256 verification, refresh token rotation)
2. **`POST /revoke`** (RFC 7009) — token revocation
3. **`GET /.well-known/jwks.json`** — public key endpoint for JWT verification
4. **`POST /register`** (RFC 7591) — Dynamic Client Registration (Claude Desktop uses this)
5. **MCP Resource Server** — `internal/mcpserver/`, protected resource metadata (RFC 9728), token validation, 2+ tools
6. **Claude Desktop integration** — `claude_desktop_config.json`

## Architecture decisions
- JWT access tokens (not opaque) — MCP server validates independently without calling AS
- In-memory store for now — no database
- Single `Store` instance created in `main.go`, passed to handlers (singleton pattern via dependency injection)
- Go 1.22+ method routing: `"GET /path"` syntax for method-specific handlers

**Why:** Teaching project for OAuth 2.1 + PKCE + MCP Auth spec. Student (Eren) is experienced engineer, new to Go.
