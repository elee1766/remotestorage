package oauth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"anime.bike/remotestorage/pkg/rs"
)

// User represents a configured user with credentials and allowed scopes
type User struct {
	Username      string
	Password      string
	AllowedScopes []rs.Scope // Pre-configured scopes this user can access
}

// Token represents an issued access token
type Token struct {
	AccessToken string
	Username    string
	Scopes      []rs.Scope
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// SimpleProvider is a minimal OAuth 2.0 provider for proof of concept
// It uses static user configuration and auto-approves all requests
type SimpleProvider struct {
	mu     sync.RWMutex
	users  map[string]*User  // username -> user
	tokens map[string]*Token // access_token -> token
}

// NewSimpleProvider creates a new simple OAuth provider
func NewSimpleProvider(users []*User) *SimpleProvider {
	userMap := make(map[string]*User)
	for _, user := range users {
		userMap[user.Username] = user
	}

	return &SimpleProvider{
		users:  userMap,
		tokens: make(map[string]*Token),
	}
}

// HandleAuthDialog handles the OAuth 2.0 implicit grant authorization endpoint
// For PoC: auto-approves if user exists and has valid credentials
func (p *SimpleProvider) HandleAuthDialog(w http.ResponseWriter, r *http.Request) {
	// Extract OAuth parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")

	// Validate required parameters
	if redirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}

	// For PoC: show simple login form
	if r.Method == "GET" {
		p.showLoginForm(w, r, clientID, redirectURI, scope, state)
		return
	}

	// Handle POST (login submission)
	if r.Method == "POST" {
		p.handleLogin(w, r, clientID, redirectURI, scope, state)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// showLoginForm displays a simple login form
func (p *SimpleProvider) showLoginForm(w http.ResponseWriter, r *http.Request, clientID, redirectURI, scope, state string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>remoteStorage Authorization</title></head>
<body>
<h2>Authorize Access</h2>
<p>Client: <strong>%s</strong></p>
<p>Requested scopes: <strong>%s</strong></p>
<form method="POST">
	<input type="hidden" name="client_id" value="%s">
	<input type="hidden" name="redirect_uri" value="%s">
	<input type="hidden" name="scope" value="%s">
	<input type="hidden" name="state" value="%s">
	<div>
		<label>Username: <input type="text" name="username" required></label>
	</div>
	<div>
		<label>Password: <input type="password" name="password" required></label>
	</div>
	<div>
		<button type="submit">Authorize</button>
	</div>
</form>
</body>
</html>`, clientID, scope, clientID, redirectURI, scope, state)

	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

// handleLogin processes login and issues token
func (p *SimpleProvider) handleLogin(w http.ResponseWriter, r *http.Request, clientID, redirectURI, scope, state string) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Validate user credentials
	p.mu.RLock()
	user, exists := p.users[username]
	p.mu.RUnlock()

	if !exists || user.Password != password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Parse requested scopes
	requestedScopes := parseScopesFromString(scope)

	// Filter scopes: only grant scopes the user is allowed to have
	grantedScopes := filterGrantedScopes(requestedScopes, user.AllowedScopes)

	// Generate access token
	accessToken := generateToken()

	// Store token
	p.mu.Lock()
	p.tokens[accessToken] = &Token{
		AccessToken: accessToken,
		Username:    username,
		Scopes:      grantedScopes,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(24 * time.Hour), // 24 hour expiry
	}
	p.mu.Unlock()

	// Build redirect URL with token (implicit grant flow)
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// Implicit grant: token in fragment
	fragment := url.Values{}
	fragment.Set("access_token", accessToken)
	fragment.Set("token_type", "bearer")
	fragment.Set("expires_in", "86400") // 24 hours in seconds
	if state != "" {
		fragment.Set("state", state)
	}

	redirectURL.Fragment = fragment.Encode()

	// Redirect user back to application
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// ValidateToken validates a bearer token and returns user info and scopes
func (p *SimpleProvider) ValidateToken(token string) (username string, scopes []rs.Scope, err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	t, exists := p.tokens[token]
	if !exists {
		return "", nil, fmt.Errorf("invalid token")
	}

	// Check if expired
	if time.Now().After(t.ExpiresAt) {
		return "", nil, fmt.Errorf("token expired")
	}

	return t.Username, t.Scopes, nil
}

// generateToken generates a random access token
func generateToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// parseScopesFromString parses space-separated scope string into rs.Scope objects
func parseScopesFromString(scopeStr string) []rs.Scope {
	if scopeStr == "" {
		return nil
	}

	var scopes []rs.Scope
	parts := strings.Split(scopeStr, " ")

	for _, part := range parts {
		// RemoteStorage scope format: "module:access" (e.g., "contacts:rw")
		scopeParts := strings.SplitN(part, ":", 2)
		if len(scopeParts) != 2 {
			continue // Skip invalid scopes
		}

		var access rs.AccessLevel
		switch scopeParts[1] {
		case "r":
			access = rs.ReadAccess
		case "rw":
			access = rs.ReadWriteAccess
		default:
			continue // Skip invalid access level
		}

		scopes = append(scopes, rs.Scope{
			Module: scopeParts[0],
			Access: access,
		})
	}

	return scopes
}

// filterGrantedScopes returns only scopes that are in the allowed list
func filterGrantedScopes(requested, allowed []rs.Scope) []rs.Scope {
	var granted []rs.Scope

	for _, req := range requested {
		for _, allow := range allowed {
			// Check if this requested scope is allowed
			if req.Module == allow.Module {
				// Grant the minimum of requested and allowed access
				if req.Access == allow.Access || allow.Access == rs.ReadWriteAccess {
					granted = append(granted, req)
				} else if req.Access == rs.ReadWriteAccess && allow.Access == rs.ReadAccess {
					// User requested rw but only has r
					granted = append(granted, rs.Scope{
						Module: req.Module,
						Access: rs.ReadAccess,
					})
				}
				break
			}

			// Handle wildcard scopes
			if allow.Module == "*" {
				grantedAccess := req.Access
				if allow.Access == rs.ReadAccess && req.Access == rs.ReadWriteAccess {
					grantedAccess = rs.ReadAccess
				}
				granted = append(granted, rs.Scope{
					Module: req.Module,
					Access: grantedAccess,
				})
				break
			}
		}
	}

	return granted
}
