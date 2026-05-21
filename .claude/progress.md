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
- Directory structure: `cmd/server/`, `internal/authserver/`
- Git initialized, all changes committed

### Authorization Server (`:8080`) — DONE

1. `GET /health`
2. `GET /.well-known/oauth-authorization-server` — RFC 8414 AS Metadata
3. `GET /authorize` — PKCE S256 (RFC 7636), HTML consent form with username field
4. `POST /authorize` — user approves, auth code generated and saved to store
5. `POST /token` — authorization_code grant (PKCE verify, single-use code, exact-match redirect_uri) + refresh_token grant (rotation + replay detection)
6. `POST /revoke` — RFC 7009, only refresh tokens can be revoked (JWT access tokens are stateless)
7. `GET /.well-known/jwks.json` — RFC 7517, RSA public key (n, e fields)
8. `GET /userinfo` — JWT validation test endpoint, returns claims

### Token design
- Access token: JWT (RS256), `sub`=user, `client_id`=app, `scope`, `iss`, `iat`, `exp`
- Refresh token: opaque, kept in store (rotation/revocation requires server-side state)
- Key pair: RSA 2048-bit generated at startup, held in memory (POC)

### Key files
```
cmd/server/main.go
internal/authserver/
  authorize.go   — /authorize handler, includes username field for sub
  jwt.go         — ExtractBearer, ParseJWT helper (alg:none attack protection)
  jwks.go        — GenerateKeyPair, /.well-known/jwks.json handler
  metadata.go    — /.well-known/oauth-authorization-server
  revoke.go      — /revoke handler
  store.go       — in-memory store (AuthCode + Subject, RefreshTokenInfo + Subject)
  token.go       — /token handler, issueTokens (JWT via RS256)
  userinfo.go    — /userinfo handler
requests/
  health.http
  token.http     — full PKCE flow (Step 1-6 + error cases, real token values filled in)
  revoke.http
  jwks.http
  userinfo.http
```

### Last commit
`629f37a` — Add /userinfo endpoint and separate sub from client_id in JWT

## Next Steps: MCP Resource Server

Start fresh chat here. Will run on separate port (`:8081`).

### Todo (in order):
1. `GET /.well-known/oauth-protected-resource` — RFC 9728 Protected Resource Metadata
   - `resource` and `authorization_servers` fields
   - MCP client learns which auth server to use from here
2. `401 + WWW-Authenticate: Bearer` — redirect client when token is missing
3. JWT-protected MCP tool endpoints
   - `ParseJWT` helper already exists (`jwt.go`), add scope enforcement
   - At least 2 simple tools
4. Claude Desktop integration — `claude_desktop_config.json`

### Architecture decision:
- Resource server (`:8081`) treats auth server as an HTTP dependency
- Fetches JWKS from `http://localhost:8080/.well-known/jwks.json` at startup (cached)
- MCP spec via RFC 9728 supports different ports/domains

## Architecture decisions
- JWT access tokens — MCP server verifies locally without AS roundtrip
- Opaque refresh tokens — rotation/revocation requires server-side state
- In-memory store — POC only, production needs a DB
- Single Store instance, dependency injection via main.go
- Go 1.22+ method routing: `"GET /path"` syntax for method-specific handlers

**Why:** Teaching project for OAuth 2.1 + PKCE + MCP Auth spec. Student (Eren) is experienced engineer, new to Go.