package rsserver

import (
	"net/http"
	"strings"
)

// CORSConfig allows customization of CORS settings
type CORSConfig struct {
	AllowOrigin      string
	AllowMethods     []string
	AllowHeaders     []string
	ExposeHeaders    []string
	AllowCredentials bool
}

// NewCORSMiddleware creates a CORS middleware with the given configuration
func NewCORSMiddleware(config CORSConfig) func(http.Handler) http.Handler {
	// Set defaults for RemoteStorage
	if config.AllowOrigin == "" {
		config.AllowOrigin = "*"
	}
	if len(config.AllowMethods) == 0 {
		config.AllowMethods = []string{"GET", "PUT", "DELETE", "HEAD", "OPTIONS"}
	}
	if len(config.AllowHeaders) == 0 {
		config.AllowHeaders = []string{"Authorization", "Content-Type", "If-Match", "If-None-Match"}
	}
	if len(config.ExposeHeaders) == 0 {
		config.ExposeHeaders = []string{"ETag", "Content-Type", "Content-Length"}
	}
	
	// Pre-join headers for performance
	allowMethods := strings.Join(config.AllowMethods, ", ")
	allowHeaders := strings.Join(config.AllowHeaders, ", ")
	exposeHeaders := strings.Join(config.ExposeHeaders, ", ")
	
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers
			w.Header().Set("Access-Control-Allow-Origin", config.AllowOrigin)
			w.Header().Set("Access-Control-Allow-Methods", allowMethods)
			w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
			w.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
			
			if config.AllowCredentials {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			
			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// DefaultCORSMiddleware creates a CORS middleware with default settings for RemoteStorage
func DefaultCORSMiddleware() func(http.Handler) http.Handler {
	return NewCORSMiddleware(CORSConfig{})
}

