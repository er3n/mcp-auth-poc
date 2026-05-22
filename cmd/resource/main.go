package main

import (
	"log"
	"net/http"
	"os"

	"mcp-auth-poc/internal/middleware"
	"mcp-auth-poc/internal/resourceserver"
)

func main() {
	resourceURL := os.Getenv("RESOURCE_URL")
	if resourceURL == "" {
		resourceURL = "http://localhost:8081"
	}

	authServerURL := os.Getenv("AUTH_SERVER_URL")
	if authServerURL == "" {
		authServerURL = "http://localhost:8080"
	}

	// Fetch the AS's public key at startup via JWKS (RFC 7517).
	// The resource server uses this to verify JWT signatures locally —
	// no need to call the AS on every request (stateless verification).
	jwksURL := authServerURL + "/.well-known/jwks.json"
	log.Printf("Fetching public key from %s ...", jwksURL)
	pub, err := resourceserver.FetchPublicKey(jwksURL)
	if err != nil {
		log.Fatalf("failed to load public key: %v\n(is the auth server running?)", err)
	}
	log.Printf("RSA public key loaded (n length: %d bits)", pub.N.BitLen())

	// Use a dedicated mux so this server's routes don't bleed into the
	// default mux if both servers ever run in the same process.
	mux := http.NewServeMux()

	// RFC 9728: MCP clients hit this to discover the auth server URL.
	mux.HandleFunc("GET /.well-known/oauth-protected-resource",
		resourceserver.NewMetadataHandler(resourceURL, authServerURL))

	// All MCP JSON-RPC traffic goes through POST /mcp.
	mux.HandleFunc("POST /mcp",
		resourceserver.NewMCPHandler(resourceURL, pub))

	log.Printf("Resource server starting on :8081 (resource: %s)", resourceURL)
	log.Fatal(http.ListenAndServe(":8081", middleware.Logging(mux)))
}
