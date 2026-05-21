package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"mcp-auth-poc/internal/authserver"
)

func main() {
	issuer := os.Getenv("ISSUER")
	if issuer == "" {
		issuer = "http://localhost:8080"
	}

	http.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "OK")
	})

	store := authserver.NewStore()

	http.HandleFunc("GET /.well-known/oauth-authorization-server", authserver.NewMetadataHandler(issuer))
	http.HandleFunc("/authorize", authserver.NewAuthorizeHandler(store))

	log.Printf("Server starting on :8080 (issuer: %s)", issuer)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
