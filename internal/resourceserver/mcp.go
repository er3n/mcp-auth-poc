package resourceserver

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// JSON-RPC 2.0 wire types (MCP uses this protocol for all messages).
// In Go, struct tags like `json:"jsonrpc"` control JSON serialization key names.

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`      // null for notifications
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"` // RawMessage = defer parsing to handler
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Standard JSON-RPC 2.0 error codes.
const (
	errCodeParse          = -32700 // invalid JSON
	errCodeInvalidRequest = -32600 // not a valid JSON-RPC request
	errCodeMethodNotFound = -32601 // method doesn't exist
	errCodeInvalidParams  = -32602 // invalid method parameters
	errCodeInternal       = -32603
	errCodeInsufficientScope = -32003 // MCP Auth: token lacks required scope
)

// tools is the static list of tools this server exposes.
// MCP clients call "tools/list" to discover these.
var mcpTools = []map[string]any{
	{
		"name":        "echo",
		"description": "Echoes the provided message back. Requires 'read' scope.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"message": map[string]any{
					"type":        "string",
					"description": "The message to echo back",
				},
			},
			"required": []string{"message"},
		},
	},
	{
		"name":        "current_time",
		"description": "Returns the current UTC time. Requires 'read' scope.",
		"inputSchema": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	},
}

// NewMCPHandler returns the POST /mcp handler.
//
// Every request is authenticated first — if there's no valid bearer token,
// the handler returns 401 with a WWW-Authenticate header that points to
// /.well-known/oauth-protected-resource (RFC 9728 §5).
// MCP clients that implement MCP Auth will follow this header to discover
// the authorization server and kick off the PKCE flow.
func NewMCPHandler(resourceURL string, pub *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ── 1. Token validation ────────────────────────────────────────────────
		tokenStr, err := ExtractBearer(r)
		if err != nil {
			// RFC 6750 §3 + RFC 9728 §5: include resource_metadata URI so MCP clients
			// know where to find the protected resource metadata (and therefore the AS).
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer realm="mcp-auth-poc", resource_metadata="%s/.well-known/oauth-protected-resource"`,
				resourceURL,
			))
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		claims, err := ParseJWT(tokenStr, pub)
		if err != nil {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer realm="mcp-auth-poc", error="invalid_token", resource_metadata="%s/.well-known/oauth-protected-resource"`,
				resourceURL,
			))
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}

		// ── 2. Parse JSON-RPC request ──────────────────────────────────────────
		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, nil, errCodeParse, "parse error")
			return
		}
		if req.JSONRPC != "2.0" {
			writeError(w, req.ID, errCodeInvalidRequest, "invalid request")
			return
		}

		// ── 3. Method routing ──────────────────────────────────────────────────
		switch req.Method {
		case "initialize":
			// Handshake: client declares its protocol version and capabilities,
			// server responds with its own. This must be the first call in a session.
			writeResult(w, req.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "mcp-auth-poc", "version": "1.0"},
			})

		case "notifications/initialized":
			// Notification (no "id") — client confirms handshake complete.
			// JSON-RPC notifications don't get a response body; 202 signals receipt.
			w.WriteHeader(http.StatusAccepted)

		case "tools/list":
			writeResult(w, req.ID, map[string]any{"tools": mcpTools})

		case "tools/call":
			handleToolCall(w, req, claims)

		default:
			writeError(w, req.ID, errCodeMethodNotFound, "method not found: "+req.Method)
		}
	}
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

func handleToolCall(w http.ResponseWriter, req rpcRequest, claims map[string]any) {
	// Scope enforcement: all tools require at least "read".
	// In a real server each tool would declare its own required scope.
	if !HasScope(claims, "read") {
		writeError(w, req.ID, errCodeInsufficientScope, "token missing required scope: read")
		return
	}

	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, errCodeInvalidParams, "invalid params")
		return
	}

	switch params.Name {
	case "echo":
		msg, _ := params.Arguments["message"].(string)
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": msg}},
		})

	case "current_time":
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": time.Now().UTC().Format(time.RFC3339),
			}},
		})

	default:
		writeError(w, req.ID, errCodeInvalidParams, "unknown tool: "+params.Name)
	}
}

func writeResult(w http.ResponseWriter, id any, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func writeError(w http.ResponseWriter, id any, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}
