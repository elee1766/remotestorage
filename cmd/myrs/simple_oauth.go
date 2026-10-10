package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"anime.bike/remotestorage/pkg/rs"
)

const (
	tokenTTL    = 24 * time.Hour
	authCodeTTL = 10 * time.Minute
)

// OAuthUser represents a configured user with credentials and allowed scopes
type OAuthUser struct {
	Username      string
	Password      string
	AllowedScopes []rs.Scope // Pre-configured scopes this user can access
}

// OAuthToken represents an issued access token
type OAuthToken struct {
	AccessToken string
	Username    string
	Scopes      []rs.Scope
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// authCode is a one-time code of the PKCE code flow (spec §10.1).
type authCode struct {
	Username      string
	ClientID      string
	RedirectURI   string
	Scopes        []rs.Scope
	CodeChallenge string
	ExpiresAt     time.Time
}

// SimpleOAuthProvider is a minimal OAuth 2.0 provider for proof of concept
// It uses static user configuration and auto-approves all requests
type SimpleOAuthProvider struct {
	mu     sync.RWMutex
	users  map[string]*OAuthUser  // username -> user
	tokens map[string]*OAuthToken // access_token -> token
	codes  map[string]*authCode   // sha256(code) -> code
}

// NewSimpleOAuthProvider creates a new simple OAuth provider
func NewSimpleOAuthProvider(users []*OAuthUser) *SimpleOAuthProvider {
	userMap := make(map[string]*OAuthUser)
	for _, user := range users {
		userMap[user.Username] = user
	}

	return &SimpleOAuthProvider{
		users:  userMap,
		tokens: make(map[string]*OAuthToken),
		codes:  make(map[string]*authCode),
	}
}

// authRequest holds the parameters of an authorization request, either the
// implicit grant (response_type=token) or the code grant with PKCE (response_type=code).
type authRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func (a *authRequest) isCodeFlow() bool { return a.ResponseType == "code" }

// errorRedirect returns redirect_uri carrying an OAuth error, in the query for
// the code flow (RFC 6749 §4.1.2.1) and in the fragment for implicit (§4.2.2.1).
func (a *authRequest) errorRedirect(redirectURL *url.URL, code string) string {
	v := url.Values{"error": {code}}
	if a.State != "" {
		v.Set("state", a.State)
	}
	u := *redirectURL
	if a.isCodeFlow() {
		q := u.Query()
		for k, vals := range v {
			q[k] = vals
		}
		u.RawQuery = q.Encode()
	} else {
		u.Fragment = v.Encode()
	}
	return u.String()
}

// HandleAuthDialog handles the OAuth 2.0 authorization endpoint for both the
// implicit grant and the authorization code grant with PKCE.
// For PoC: auto-approves if user exists and has valid credentials
func (p *SimpleOAuthProvider) HandleAuthDialog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	req := &authRequest{
		ResponseType:        r.Form.Get("response_type"),
		ClientID:            r.Form.Get("client_id"),
		RedirectURI:         r.Form.Get("redirect_uri"),
		Scope:               r.Form.Get("scope"),
		State:               r.Form.Get("state"),
		CodeChallenge:       r.Form.Get("code_challenge"),
		CodeChallengeMethod: r.Form.Get("code_challenge_method"),
	}
	if req.ResponseType == "" {
		req.ResponseType = "token"
	}

	// Never redirect until redirect_uri is known to be usable.
	if req.RedirectURI == "" {
		http.Error(w, "redirect_uri required", http.StatusBadRequest)
		return
	}
	redirectURL, err := url.Parse(req.RedirectURI)
	if err != nil || !redirectURL.IsAbs() || (redirectURL.Scheme != "http" && redirectURL.Scheme != "https") || redirectURL.Fragment != "" {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	switch req.ResponseType {
	case "token":
	case "code":
		// S256 only (spec §10.1): reject a missing challenge and "plain".
		if req.CodeChallengeMethod != rs.PKCEMethodS256 || !rs.ValidS256Challenge(req.CodeChallenge) {
			http.Redirect(w, r, req.errorRedirect(redirectURL, "invalid_request"), http.StatusFound)
			return
		}
		if req.ClientID == "" {
			http.Redirect(w, r, req.errorRedirect(redirectURL, "invalid_request"), http.StatusFound)
			return
		}
	default:
		http.Redirect(w, r, req.errorRedirect(redirectURL, "unsupported_response_type"), http.StatusFound)
		return
	}

	if r.Method == http.MethodGet {
		p.showLoginForm(w, req)
		return
	}
	p.handleLogin(w, r, req, redirectURL)
}

var loginForm = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head><title>remoteStorage Authorization</title></head>
<body>
<h2>Authorize Access</h2>
<p>Client: <strong>{{.ClientID}}</strong></p>
<p>Requested scopes: <strong>{{.Scope}}</strong></p>
<form method="POST">
	<input type="hidden" name="response_type" value="{{.ResponseType}}">
	<input type="hidden" name="client_id" value="{{.ClientID}}">
	<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
	<input type="hidden" name="scope" value="{{.Scope}}">
	<input type="hidden" name="state" value="{{.State}}">
	<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
	<input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
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
</html>`))

// showLoginForm displays a simple login form
func (p *SimpleOAuthProvider) showLoginForm(w http.ResponseWriter, req *authRequest) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginForm.Execute(w, req)
}

// handleLogin processes login and issues a token (implicit) or a one-time code (PKCE)
func (p *SimpleOAuthProvider) handleLogin(w http.ResponseWriter, r *http.Request, req *authRequest, redirectURL *url.URL) {
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

	// Only grant scopes the user is allowed to have
	grantedScopes := filterGrantedScopes(parseScopesFromString(req.Scope), user.AllowedScopes)

	u := *redirectURL
	if req.isCodeFlow() {
		code := generateOAuthToken()
		p.mu.Lock()
		p.codes[hashCode(code)] = &authCode{
			Username:      username,
			ClientID:      req.ClientID,
			RedirectURI:   req.RedirectURI,
			Scopes:        grantedScopes,
			CodeChallenge: req.CodeChallenge,
			ExpiresAt:     time.Now().Add(authCodeTTL),
		}
		p.mu.Unlock()

		// Code grant: code in the query (RFC 6749 §4.1.2)
		q := u.Query()
		q.Set("code", code)
		if req.State != "" {
			q.Set("state", req.State)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}

	accessToken := p.issueToken(username, grantedScopes)

	// Implicit grant: token in fragment
	fragment := url.Values{}
	fragment.Set("access_token", accessToken)
	fragment.Set("token_type", "bearer")
	fragment.Set("expires_in", fmt.Sprintf("%d", int(tokenTTL.Seconds())))
	if req.State != "" {
		fragment.Set("state", req.State)
	}
	u.Fragment = fragment.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}

// HandleToken is the token endpoint of the PKCE code flow (RFC 6749 §3.2, spec §10.1).
func (p *SimpleOAuthProvider) HandleToken(w http.ResponseWriter, r *http.Request) {
	setTokenCORS(w, r)

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parameters must come from a form body, never the query string.
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		writeOAuthError(w, "invalid_request")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, "invalid_request")
		return
	}
	form := r.PostForm

	grantType := form.Get("grant_type")
	if grantType == "" {
		writeOAuthError(w, "invalid_request")
		return
	}
	if grantType != "authorization_code" {
		writeOAuthError(w, "unsupported_grant_type")
		return
	}

	code := form.Get("code")
	clientID := form.Get("client_id")
	redirectURI := form.Get("redirect_uri")
	verifier := form.Get("code_verifier")
	if code == "" || clientID == "" || redirectURI == "" || verifier == "" {
		writeOAuthError(w, "invalid_request")
		return
	}

	ac := p.redeemCode(code)
	if ac == nil || time.Now().After(ac.ExpiresAt) ||
		ac.ClientID != clientID || ac.RedirectURI != redirectURI ||
		!rs.VerifyS256(verifier, ac.CodeChallenge) {
		writeOAuthError(w, "invalid_grant")
		return
	}

	accessToken := p.issueToken(ac.Username, ac.Scopes)

	// RFC 6749 §5.1: token responses must not be cached.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"token_type":   "bearer",
		"expires_in":   int(tokenTTL.Seconds()),
		"scope":        formatScopes(ac.Scopes),
	})
}

// redeemCode removes and returns the code. A code is consumed on first use,
// even if the rest of the exchange fails, so it cannot be retried.
func (p *SimpleOAuthProvider) redeemCode(code string) *authCode {
	h := hashCode(code)
	p.mu.Lock()
	defer p.mu.Unlock()
	ac := p.codes[h]
	delete(p.codes, h)
	return ac
}

func (p *SimpleOAuthProvider) issueToken(username string, scopes []rs.Scope) string {
	accessToken := generateOAuthToken()
	now := time.Now()
	p.mu.Lock()
	p.tokens[accessToken] = &OAuthToken{
		AccessToken: accessToken,
		Username:    username,
		Scopes:      scopes,
		IssuedAt:    now,
		ExpiresAt:   now.Add(tokenTTL),
	}
	p.mu.Unlock()
	return accessToken
}

func setTokenCORS(w http.ResponseWriter, r *http.Request) {
	// Echo the origin without credentials so browser apps can read the reply.
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")
	}
}

// writeOAuthError writes an RFC 6749 §5.2 error response.
func writeOAuthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	status := http.StatusBadRequest
	if code == "invalid_client" {
		status = http.StatusUnauthorized
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func formatScopes(scopes []rs.Scope) string {
	parts := make([]string, len(scopes))
	for i, s := range scopes {
		parts[i] = s.Module + ":" + string(s.Access)
	}
	return strings.Join(parts, " ")
}

// ValidateToken validates a bearer token and returns user info and scopes
func (p *SimpleOAuthProvider) ValidateToken(token string) (username string, scopes []rs.Scope, err error) {
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

// generateOAuthToken generates a random access token
func generateOAuthToken() string {
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
