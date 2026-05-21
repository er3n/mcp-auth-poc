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

	kp, err := authserver.GenerateKeyPair()
	if err != nil {
		log.Fatalf("failed to generate key pair: %v", err)
	}

	store := authserver.NewStore()

	http.HandleFunc("GET /.well-known/oauth-authorization-server", authserver.NewMetadataHandler(issuer))
	http.HandleFunc("GET /.well-known/jwks.json", authserver.NewJWKSHandler(kp))
	http.HandleFunc("/authorize", authserver.NewAuthorizeHandler(store))
	http.HandleFunc("POST /token", authserver.NewTokenHandler(store, kp, issuer))
	http.HandleFunc("POST /revoke", authserver.NewRevokeHandler(store))

	log.Printf("Server starting on :8080 (issuer: %s)", issuer)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
