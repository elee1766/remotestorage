package webfinger

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"anime.bike/remotestorage/pkg/nullable"
	"anime.bike/remotestorage/pkg/rs"
)

// UserStorageInfo contains the remoteStorage information for a user
type UserStorageInfo struct {
	// StorageRoot is the base URL for the user's storage (e.g., "https://storage.example.com/alice")
	StorageRoot string

	// AuthEndpoint is the OAuth authorization endpoint URL (can be nil for Kerberos-only)
	AuthEndpoint *string

	// Version is the remoteStorage protocol version (defaults to draft-dejong-remotestorage-25)
	Version string

	// QueryTokenSupport indicates if bearer tokens can be passed via query parameter
	// Set to nil to omit, true to enable, false to explicitly disable
	QueryTokenSupport *bool

	// RangeRequestSupport indicates support for HTTP Range requests (e.g., "GET")
	// Set to empty string to omit
	RangeRequestSupport string

	// WebAuthoringDomain for web authoring support
	// Set to empty string to omit
	WebAuthoringDomain string
}

// StorageResolver is a callback interface for looking up user storage information
type StorageResolver interface {
	// ResolveStorage returns storage information for the given user identifier
	// Returns nil if the user is not found
	// The userID is extracted from the WebFinger resource parameter (e.g., "alice" from "acct:alice@example.com")
	ResolveStorage(userID string) (*UserStorageInfo, error)
}

// StorageResolverFunc is a function adapter for StorageResolver
type StorageResolverFunc func(userID string) (*UserStorageInfo, error)

func (f StorageResolverFunc) ResolveStorage(userID string) (*UserStorageInfo, error) {
	return f(userID)
}

// Server handles WebFinger requests for remoteStorage discovery
type Server struct {
	resolver StorageResolver
	domain   string // Expected domain for resource queries
}

// NewServer creates a new WebFinger server
// domain is the expected domain in resource queries (e.g., "example.com" for "acct:alice@example.com")
func NewServer(domain string, resolver StorageResolver) *Server {
	return &Server{
		domain:   domain,
		resolver: resolver,
	}
}

// ServeHTTP implements http.Handler for the /.well-known/webfinger endpoint
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the resource parameter
	resource := r.URL.Query().Get("resource")
	if resource == "" {
		http.Error(w, "Missing 'resource' parameter", http.StatusBadRequest)
		return
	}

	// Parse the resource identifier
	userID, err := s.parseResource(resource)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Resolve storage information for this user
	storageInfo, err := s.resolver.ResolveStorage(userID)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if storageInfo == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Build WebFinger response
	wf := s.buildWebFingerResponse(resource, storageInfo)

	// Return JSON response
	w.Header().Set("Content-Type", "application/jrd+json")
	w.Header().Set("Access-Control-Allow-Origin", "*") // Required for CORS
	json.NewEncoder(w).Encode(wf)
}

// parseResource extracts the user ID from a WebFinger resource identifier
// Supports formats:
// - acct:user@domain
// - http://domain/
// - https://domain/
func (s *Server) parseResource(resource string) (string, error) {
	// Handle acct: URI format (most common)
	if strings.HasPrefix(resource, "acct:") {
		acctPart := strings.TrimPrefix(resource, "acct:")
		parts := strings.SplitN(acctPart, "@", 2)

		if len(parts) != 2 {
			return "", fmt.Errorf("invalid acct URI format: %s", resource)
		}

		userID := parts[0]
		domain := parts[1]

		// Verify domain matches (optional security check)
		if s.domain != "" && domain != s.domain {
			return "", fmt.Errorf("domain mismatch: expected %s, got %s", s.domain, domain)
		}

		return userID, nil
	}

	// Handle http:// or https:// format (for single-user domains)
	if strings.HasPrefix(resource, "http://") || strings.HasPrefix(resource, "https://") {
		parsedURL, err := url.Parse(resource)
		if err != nil {
			return "", fmt.Errorf("invalid URL format: %s", resource)
		}

		// For URL format, return the hostname as the user ID
		// This is typically used for single-user personal domains
		return parsedURL.Host, nil
	}

	return "", fmt.Errorf("unsupported resource format: %s (expected acct: or http(s):// URI)", resource)
}

// buildWebFingerResponse constructs a WebFinger response with remoteStorage link
func (s *Server) buildWebFingerResponse(subject string, info *UserStorageInfo) *WebFinger {
	wf := NewWebFinger(subject)

	// Set version (default to current spec version)
	version := info.Version
	if version == "" {
		version = string(rs.SupportedVersion)
	}

	// Build properties
	props := &rs.RemoteStorageProperties{
		Version: rs.VersionName(version),
	}

	// Add auth endpoint if provided
	if info.AuthEndpoint != nil {
		props.AuthEndpoint = nullable.NewString(*info.AuthEndpoint)
	}

	// Add query token support if specified
	if info.QueryTokenSupport != nil {
		props.QueryTokenSupport = nullable.NewBoolPtr(info.QueryTokenSupport)
	}

	// Add range request support if specified
	if info.RangeRequestSupport != "" {
		props.RangeRequestSupport = nullable.NewString(info.RangeRequestSupport)
	}

	// Add web authoring domain if specified
	if info.WebAuthoringDomain != "" {
		props.WebAuthoringDomain = nullable.NewString(info.WebAuthoringDomain)
	}

	// Add the remoteStorage link
	wf.AddRemoteStorageLink(info.StorageRoot, props)

	return wf
}

// Handler returns an http.Handler that can be mounted at /.well-known/webfinger
func (s *Server) Handler() http.Handler {
	return s
}
