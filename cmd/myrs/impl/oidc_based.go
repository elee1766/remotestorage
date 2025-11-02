package impl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rsstorage"
)

// WebfingerUser represents a user configured for webfinger discovery
type WebfingerUser struct {
	Username string
	Sub      string
}

// OidcBasedImplementation implements ServerImplementation with /{username}/{path} routing
type OidcBasedImplementation struct {
	mu                   sync.RWMutex
	storages             map[string]*rsstorage.BucketStorage
	authURL              string
	tokenInfoURL         string
	introspectionURL     string // Introspection endpoint URL
	clientID             string
	clientSecret         string // Client secret for introspection
	subClaim             string // Claim for storage bucket ID (default: "sub")
	usernameClaim        string // Claim for URL username (default: "preferred_username")
	httpClient           *http.Client
	webfingerUsers       []WebfingerUser // Optional list of users with sub validation
	useIntrospection     bool            // Whether to use introspection (when client secret is available)
	insecureIgnoreScopes bool            // INSECURE: Ignore scopes and grant full access
}

// NewOidcBasedImplementationWithOAuth creates a new OIDC-based server implementation with external OAuth
func NewOidcBasedImplementationWithOAuth(authURL, tokenInfoURL, introspectionURL, clientID, clientSecret, subClaim, usernameClaim string) *OidcBasedImplementation {
	return &OidcBasedImplementation{
		storages:         make(map[string]*rsstorage.BucketStorage),
		authURL:          authURL,
		tokenInfoURL:     tokenInfoURL,
		introspectionURL: introspectionURL,
		clientID:         clientID,
		clientSecret:     clientSecret,
		subClaim:         subClaim,
		usernameClaim:    usernameClaim,
		httpClient:       &http.Client{},
		useIntrospection: clientSecret != "" && introspectionURL != "",
	}
}

// SetWebfingerUsers sets the list of users for webfinger validation
func (p *OidcBasedImplementation) SetWebfingerUsers(users []WebfingerUser) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.webfingerUsers = users
}

// SetInsecureIgnoreScopes enables ignoring scopes (INSECURE - for development only)
func (p *OidcBasedImplementation) SetInsecureIgnoreScopes(ignore bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.insecureIgnoreScopes = ignore
	if ignore {
		log.Printf("WARNING: InsecureIgnoreScopes is enabled - all authenticated users have full access!")
	}
}

// GetAuth validates authentication and returns auth info
func (p *OidcBasedImplementation) GetAuth(r *http.Request) (*rsserver.AuthInfo, error) {
	// Extract username from path for validation
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, rsserver.NewHTTPError(http.StatusBadRequest, "Invalid path: must be /{username}/{module}/{file}")
	}

	nickname := parts[0]
	module := parts[1]

	// Get authentication info from the request
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, rsserver.NewHTTPError(http.StatusUnauthorized, "Missing or invalid authorization header")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate token and get auth info
	storageID, requestNickname, scopes, err := p.validateTokenForStorage(r.Context(), token)
	if err != nil {
		log.Printf("Error validating token: %v", err)
		return nil, rsserver.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	}

	// Verify that the requested username matches the user's username
	if requestNickname != nickname {
		return nil, rsserver.NewHTTPError(http.StatusForbidden, "Access denied: username mismatch")
	}

	// If webfinger users are configured, validate sub claim if specified
	if len(p.webfingerUsers) > 0 {
		var foundUser *WebfingerUser
		for _, user := range p.webfingerUsers {
			if user.Username == nickname {
				foundUser = &user
				break
			}
		}

		if foundUser != nil && foundUser.Sub != "" {
			// User has a configured sub that must match
			if storageID != foundUser.Sub {
				return nil, rsserver.NewHTTPError(http.StatusForbidden, "Access denied: sub mismatch")
			}
		}
	}

	// Check scopes for access to this module
	isRead := r.Method == "GET" || r.Method == "HEAD"
	if !rs.CheckScopeAccess(scopes, module, isRead) {
		return nil, rsserver.NewHTTPError(http.StatusForbidden, "Insufficient scope")
	}

	return &rsserver.AuthInfo{
		UserID:          storageID,
		Username:        requestNickname,
		Scopes:          scopes,
		IsAuthenticated: true,
	}, nil
}

// GetStorage returns storage backend and routing info for the request
func (p *OidcBasedImplementation) GetStorage(r *http.Request) (*rsserver.StorageResult, error) {
	// Extract username, module, and path from URL
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, rsserver.NewHTTPError(http.StatusBadRequest, "Invalid path: must be /{username}/{module}/{file}")
	}

	module := parts[1]
	var filePath string
	if len(parts) > 2 {
		filePath = "/" + parts[2]
	} else {
		filePath = "/"
	}

	// Get auth info from context (should have been set by GetAuth)
	authInfo, ok := rsserver.AuthInfoFromContext(r.Context())
	if !ok || !authInfo.IsAuthenticated {
		// For public paths, we might not have auth - that's okay
		// Use a default storage identifier
		storage := p.getStorageForUser("public", module)
		return &rsserver.StorageResult{
			Storage: storage,
			Module:  module,
			Path:    filePath,
		}, nil
	}

	// Get storage for this authenticated user and module
	storage := p.getStorageForUser(authInfo.UserID, module)

	return &rsserver.StorageResult{
		Storage: storage,
		Module:  module,
		Path:    filePath,
	}, nil
}

// getStorageForUser gets or creates storage for a user and module
func (p *OidcBasedImplementation) getStorageForUser(storageID, module string) rsserver.StorageBackend {
	bucketKey := storageID + ":" + module

	// Get or create storage for this storageID-module combination
	p.mu.Lock()
	defer p.mu.Unlock()

	storage, exists := p.storages[bucketKey]
	if !exists {
		storage = rsstorage.NewBucketStorage()
		p.storages[bucketKey] = storage
	}

	return storage
}

// TokenInfoResponse represents the response from the OAuth token info endpoint
type TokenInfoResponse struct {
	// Introspection fields
	Active bool `json:"active"`

	// Common OIDC userinfo fields
	Sub               string `json:"sub"`                // Subject (user ID)
	Name              string `json:"name"`               // Full name
	GivenName         string `json:"given_name"`         // First name
	FamilyName        string `json:"family_name"`        // Last name
	PreferredUsername string `json:"preferred_username"` // OIDC standard preferred username
	Email             string `json:"email"`              // Email address
	EmailVerified     bool   `json:"email_verified"`     // Email verification status

	// Alternative username fields
	UserID   string `json:"user_id"`  // Alternative field for user ID
	Username string `json:"username"` // Another alternative
	Nickname string `json:"nickname"` // Nickname field

	// Scope fields
	Scope  string   `json:"scope"`  // Space-separated scopes
	Scopes []string `json:"scopes"` // Array of scopes (alternative)

	// Other potential fields
	Aud any    `json:"aud"` // Audience
	Iss string `json:"iss"` // Issuer
	Iat int64  `json:"iat"` // Issued at
	Exp int64  `json:"exp"` // Expiration time
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Email             string   `json:"email"`
	Scope             string   `json:"scope"`
	Scopes            []string `json:"scopes"`
	// Add any other fields your JWT might contain
}

// decodeJWT decodes a JWT token without verifying the signature
// This is safe because we validate the token via introspection
func decodeJWT(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode the claims (second part)
	claimsData, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	// First log the raw claims to see everything
	var rawClaims map[string]interface{}
	if err := json.Unmarshal(claimsData, &rawClaims); err != nil {
		return nil, fmt.Errorf("failed to parse raw JWT claims: %w", err)
	}
	log.Printf("Raw JWT claims: %+v", rawClaims)

	// Pretty print the claims for better debugging
	prettyJSON, _ := json.MarshalIndent(rawClaims, "", "  ")
	log.Printf("JWT claims (formatted):\n%s", string(prettyJSON))

	var claims JWTClaims
	if err := json.Unmarshal(claimsData, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return &claims, nil
}

// validateTokenForStorage validates a token and returns storage ID, username, and scopes
func (p *OidcBasedImplementation) validateTokenForStorage(ctx context.Context, token string) (storageID, nickname string, scopes []rs.Scope, err error) {
	var req *http.Request

	if p.useIntrospection {
		// Use introspection endpoint with client credentials
		formData := url.Values{}
		formData.Set("token", token)

		req, err = http.NewRequestWithContext(ctx, "POST", p.introspectionURL, strings.NewReader(formData.Encode()))
		if err != nil {
			return "", "", nil, fmt.Errorf("failed to create introspection request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		// Use HTTP Basic Authentication for client credentials
		req.SetBasicAuth(p.clientID, p.clientSecret)
	} else {
		// Use userinfo endpoint with bearer token
		req, err = http.NewRequestWithContext(ctx, "GET", p.tokenInfoURL, nil)
		if err != nil {
			return "", "", nil, fmt.Errorf("failed to create userinfo request: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Log the validation request
	fmt.Printf("Token validation request:\n")
	if p.useIntrospection {
		fmt.Printf("  Method: Introspection\n")
		fmt.Printf("  URL: %s\n", p.introspectionURL)
		fmt.Printf("  Client ID: %s\n", p.clientID)
		fmt.Printf("  Has Client Secret: %v\n", p.clientSecret != "")
	} else {
		fmt.Printf("  Method: Userinfo\n")
		fmt.Printf("  URL: %s\n", p.tokenInfoURL)
	}
	tokenPreview := token
	if len(token) > 20 {
		tokenPreview = token[:20] + "..."
	}
	fmt.Printf("  Token (first 20 chars): %s\n", tokenPreview)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to call token info endpoint: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Debug print the raw response
	fmt.Printf("Token validation response:\n")
	fmt.Printf("  Status: %d\n", resp.StatusCode)
	fmt.Printf("  Headers: %v\n", resp.Header)
	fmt.Printf("  Body: %s\n", string(body))

	if resp.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("token validation failed with status %d", resp.StatusCode)
	}

	var tokenInfo TokenInfoResponse
	if err := json.Unmarshal(body, &tokenInfo); err != nil {
		return "", "", nil, fmt.Errorf("failed to decode token info response: %w", err)
	}
	log.Printf("Parsed token info: %+v\n", tokenInfo)

	// Check if token is active (for introspection)
	if p.useIntrospection && !tokenInfo.Active {
		return "", "", nil, fmt.Errorf("token is not active")
	}

	// Try to decode the JWT to get additional claims, especially scopes
	jwtClaims, err := decodeJWT(token)
	if err != nil {
		log.Printf("Failed to decode JWT (this is OK if not a JWT): %v", err)
	} else {
		log.Printf("Successfully decoded JWT claims: %+v", jwtClaims)

		// If we got scopes from the JWT, use them
		if jwtClaims.Scope != "" && tokenInfo.Scope == "" {
			tokenInfo.Scope = jwtClaims.Scope
			log.Printf("Using scope from JWT: %s", jwtClaims.Scope)
		}
		if len(jwtClaims.Scopes) > 0 && len(tokenInfo.Scopes) == 0 {
			tokenInfo.Scopes = jwtClaims.Scopes
			log.Printf("Using scopes array from JWT: %v", jwtClaims.Scopes)
		}

		// Also fill in any missing user info from JWT
		if tokenInfo.Sub == "" && jwtClaims.Sub != "" {
			tokenInfo.Sub = jwtClaims.Sub
		}
		if tokenInfo.PreferredUsername == "" && jwtClaims.PreferredUsername != "" {
			tokenInfo.PreferredUsername = jwtClaims.PreferredUsername
		}
		if tokenInfo.Email == "" && jwtClaims.Email != "" {
			tokenInfo.Email = jwtClaims.Email
		}
	}

	// Get storage claim (for storage bucket)
	switch p.subClaim {
	case "sub":
		storageID = tokenInfo.Sub
	case "user_id":
		storageID = tokenInfo.UserID
	case "username":
		storageID = tokenInfo.Username
	case "preferred_username":
		storageID = tokenInfo.PreferredUsername
	case "nickname":
		storageID = tokenInfo.Nickname
	case "email":
		storageID = tokenInfo.Email
	default:
		storageID = tokenInfo.Sub // default to sub
	}

	// Get username claim (for URL routing)
	switch p.usernameClaim {
	case "sub":
		nickname = tokenInfo.Sub
	case "user_id":
		nickname = tokenInfo.UserID
	case "username":
		nickname = tokenInfo.Username
	case "preferred_username":
		nickname = tokenInfo.PreferredUsername
	case "nickname":
		nickname = tokenInfo.Nickname
	case "email":
		nickname = tokenInfo.Email
	default:
		nickname = tokenInfo.PreferredUsername // default to preferred_username
	}

	// If nickname is still empty, try fallback fields
	if nickname == "" {
		if tokenInfo.Username != "" {
			nickname = tokenInfo.Username
		} else if tokenInfo.Nickname != "" {
			nickname = tokenInfo.Nickname
		} else if tokenInfo.Email != "" {
			// Extract username part from email
			if idx := strings.Index(tokenInfo.Email, "@"); idx > 0 {
				nickname = tokenInfo.Email[:idx]
			}
		}
	}

	if storageID == "" {
		return "", "", nil, fmt.Errorf("no storage identifier found in token info")
	}
	if nickname == "" {
		return "", "", nil, fmt.Errorf("no username found in token info")
	}

	// Parse scopes - handle both array and space-separated string formats
	var scopeStrings []string
	if len(tokenInfo.Scopes) > 0 {
		scopeStrings = tokenInfo.Scopes
	} else if tokenInfo.Scope != "" {
		scopeStrings = strings.Split(tokenInfo.Scope, " ")
	}

	log.Printf("Raw scopes from token info: %v", scopeStrings)

	// Convert to RemoteStorage scopes
	var rsScopes []rs.Scope
	for _, scopeStr := range scopeStrings {
		// Skip OIDC standard scopes
		if scopeStr == "openid" || scopeStr == "profile" || scopeStr == "email" {
			log.Printf("Skipping OIDC scope: %s", scopeStr)
			continue
		}

		// RemoteStorage scopes are in format "module:access" (e.g., "documents:rw")
		parts := strings.SplitN(scopeStr, ":", 2)
		if len(parts) != 2 {
			log.Printf("Skipping scope with invalid format: %s", scopeStr)
			continue // Skip invalid scope format
		}

		var access rs.AccessLevel
		switch parts[1] {
		case "r":
			access = rs.ReadAccess
		case "rw":
			access = rs.ReadWriteAccess
		default:
			continue // Skip invalid access level
		}

		rsScopes = append(rsScopes, rs.Scope{
			Module: parts[0],
			Access: access,
		})
		log.Printf("Added RemoteStorage scope: %s:%s", parts[0], parts[1])
	}

	// If no RemoteStorage scopes were found, check if we should ignore scopes
	if len(rsScopes) == 0 {
		if p.insecureIgnoreScopes {
			log.Printf("WARNING: No RemoteStorage scopes found, but InsecureIgnoreScopes is enabled - granting full access")
			rsScopes = []rs.Scope{
				{Module: "*", Access: rs.ReadWriteAccess},
			}
		} else {
			log.Printf("No RemoteStorage scopes found and InsecureIgnoreScopes is disabled")
			// Return empty scopes - the user won't have access to anything
		}
	}

	log.Printf("Final RemoteStorage scopes: %+v", rsScopes)
	return storageID, nickname, rsScopes, nil
}
