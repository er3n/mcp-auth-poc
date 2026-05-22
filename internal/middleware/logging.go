package middleware

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// responseRecorder wraps http.ResponseWriter to capture status code and body.
type responseRecorder struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.status = code
	rr.ResponseWriter.WriteHeader(code)
}

func (rr *responseRecorder) Write(b []byte) (int, error) {
	rr.body.Write(b)
	return rr.ResponseWriter.Write(b)
}

// Logging wraps a handler and logs the full request and response.
// Useful for observing the OAuth flow step by step.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Read and restore the request body so the handler can still read it.
		var reqBody []byte
		if r.Body != nil {
			reqBody, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		log.Printf("\n──────────────────────────────────────────────\n"+
			"→ REQUEST  %s %s\n"+
			"  Headers: %s\n"+
			"  Body:    %s\n"+
			"──────────────────────────────────────────────",
			r.Method, r.RequestURI,
			formatHeaders(r.Header),
			formatBody(reqBody, r.Header.Get("Content-Type")),
		)

		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		log.Printf("\n──────────────────────────────────────────────\n"+
			"← RESPONSE %s %s → %d (%s)\n"+
			"  Headers: %s\n"+
			"  Body:    %s\n"+
			"──────────────────────────────────────────────",
			r.Method, r.RequestURI, rec.status, time.Since(start),
			formatHeaders(rec.Header()),
			formatBody(rec.body.Bytes(), rec.Header().Get("Content-Type")),
		)
	})
}

func formatHeaders(h http.Header) string {
	var parts []string
	for k, vs := range h {
		// Redact Authorization header value but keep the scheme visible.
		if strings.EqualFold(k, "Authorization") {
			for _, v := range vs {
				if idx := strings.Index(v, " "); idx > 0 {
					parts = append(parts, k+": "+v[:idx+1]+"[redacted]")
				} else {
					parts = append(parts, k+": [redacted]")
				}
			}
			continue
		}
		parts = append(parts, k+": "+strings.Join(vs, ", "))
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return "\n    " + strings.Join(parts, "\n    ")
}

func formatBody(body []byte, contentType string) string {
	if len(body) == 0 {
		return "(empty)"
	}
	s := strings.TrimSpace(string(body))
	// Indent multiline bodies for readability.
	s = strings.ReplaceAll(s, "\n", "\n    ")
	return "\n    " + s
}
