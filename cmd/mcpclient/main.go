// cmd/mcpclient — MCP client using the official Go MCP SDK.
//
// Exercises the full MCP Auth flow automatically:
//   - Dynamic Client Registration (RFC 7591)
//   - OAuth 2.1 PKCE (RFC 7636)
//   - Protected Resource Metadata discovery (RFC 9728)
//
// Usage: go run ./cmd/mcpclient/ <mcp-server-url>
// Example: go run ./cmd/mcpclient/ https://mcp-auth-poc-rs.onrender.com/mcp
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: mcpclient <mcp-server-url>")
	}
	serverURL := os.Args[1]

	// Start a local HTTP server on a random port to receive the OAuth callback.
	// net.Listen(":0") asks the OS to pick a free port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURL := fmt.Sprintf("http://localhost:%d/callback", port)

	// codeCh receives the authorization code + state after the browser redirect.
	codeCh := make(chan *auth.AuthorizationResult, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		if code == "" {
			errCh <- fmt.Errorf("no code in callback: %s", r.URL.RawQuery)
			return
		}
		fmt.Fprint(w, "<h2>Authorization successful! You can close this tab.</h2>")
		codeCh <- &auth.AuthorizationResult{Code: code, State: state}
	})

	cbServer := &http.Server{Handler: mux}
	go func() {
		if err := cbServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	defer cbServer.Close()

	// Build the auth handler using dynamic client registration + PKCE.
	// The SDK handles RFC 9728 discovery, RFC 7591 registration, and RFC 7636 PKCE internally.
	authHandler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		RedirectURL: redirectURL,
		DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{
			Metadata: &oauthex.ClientRegistrationMetadata{
				ClientName:   "mcp-auth-poc-client",
				RedirectURIs: []string{redirectURL},
			},
		},
		// SDK calls this when it has built the authorization URL and needs us to
		// open the browser and return the code from the redirect.
		AuthorizationCodeFetcher: func(ctx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			fmt.Printf("\nOpening browser for authorization...\nURL: %s\n\n", args.URL)
			openBrowser(args.URL)
			fmt.Println("Waiting for authorization...")
			select {
			case res := <-codeCh:
				return res, nil
			case err := <-errCh:
				return nil, err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	})
	if err != nil {
		log.Fatalf("auth handler: %v", err)
	}

	// Connect to the MCP server. The SDK sends an unauthenticated request first,
	// handles the 401, runs the full OAuth flow via authHandler, then retries.
	transport := &mcp.StreamableClientTransport{
		Endpoint:     serverURL,
		OAuthHandler: authHandler,
	}

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "mcp-auth-poc-client",
		Version: "1.0.0",
	}, nil)

	fmt.Printf("Connecting to %s ...\n", serverURL)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer session.Close()

	fmt.Println("\n=== tools/list ===")
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		log.Fatalf("list tools: %v", err)
	}
	for _, t := range tools.Tools {
		fmt.Printf("  - %s: %s\n", t.Name, t.Description)
	}

	fmt.Println("\n=== tools/call echo ===")
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "Hello from Go MCP SDK client!"},
	})
	if err != nil {
		log.Fatalf("call echo: %v", err)
	}
	printContent(result.Content)

	fmt.Println("\n=== tools/call current_time ===")
	result, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "current_time",
		Arguments: map[string]any{},
	})
	if err != nil {
		log.Fatalf("call current_time: %v", err)
	}
	printContent(result.Content)
}

func printContent(contents []mcp.Content) {
	for _, c := range contents {
		if tc, ok := c.(*mcp.TextContent); ok {
			fmt.Printf("  → %s\n", tc.Text)
		}
	}
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "linux":
		cmd = exec.Command("xdg-open", u)
	default:
		return
	}
	_ = cmd.Start()
}
