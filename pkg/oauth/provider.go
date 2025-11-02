package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Provider implements an OAuth2 provider that delegates to an upstream OIDC provider
type Provider struct {
	publicURL       string
	jwtSecret       []byte
	upstreamClient  *UpstreamClient
	userMappings    map[string]string // sub -> username
	stateStore      *StateStore
	tokenStore      *TokenStore
}

// Config for the OAuth provider
type Config struct {
	PublicURL       string
	JWTSecret       string
	UpstreamClient  *UpstreamClient
	UserMappings    []UserMapping
}

type UserMapping struct {
	Username string
	Sub      string
}

type UpstreamClient struct {
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	discovery    *OIDCDiscovery
}

type OIDCDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

type AuthState struct {
	State        string
	ClientID     string
	RedirectURI  string
	Scope        string
	ResponseType string
	CreatedAt    time.Time
}

type TokenData struct {
	AccessToken  string
	Sub          string
	Username     string
	Scopes       []string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

type StateStore struct {
	mu     sync.RWMutex
	states map[string]AuthState
}

type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]TokenData
}

// NewProvider creates a new OAuth provider
func NewProvider(config Config) (*Provider, error) {
	// Fetch upstream discovery
	if err := config.UpstreamClient.fetchDiscovery(); err != nil {
		return nil, fmt.Errorf("failed to fetch upstream discovery: %w", err)
	}

	// Build user mappings
	mappings := make(map[string]string)
	for _, m := range config.UserMappings {
		mappings[m.Sub] = m.Username
	}

	return &Provider{
		publicURL:      config.PublicURL,
		jwtSecret:      []byte(config.JWTSecret),
		upstreamClient: config.UpstreamClient,
		userMappings:   mappings,
		stateStore: &StateStore{
			states: make(map[string]AuthState),
		},
		tokenStore: &TokenStore{
			tokens: make(map[string]TokenData),
		},
	}, nil
}

// RegisterHandlers registers the OAuth endpoints
func (p *Provider) RegisterHandlers(mux *http.ServeMux, basePath string) {
	mux.HandleFunc(basePath+"/authorize", p.handleAuthorize)
	mux.HandleFunc(basePath+"/callback", p.handleCallback)
	mux.HandleFunc(basePath+"/token", p.handleToken)
	mux.HandleFunc(basePath+"/introspect", p.handleIntrospect)
}

// GetDiscovery returns the OIDC discovery document
func (p *Provider) GetDiscovery(basePath string) map[string]interface{} {
	return map[string]interface{}{
		"issuer":                 p.publicURL,
		"authorization_endpoint": p.publicURL + basePath + "/authorize",
		"token_endpoint":         p.publicURL + basePath + "/token",
		"introspection_endpoint": p.publicURL + basePath + "/introspect",
		"response_types_supported": []string{"token", "code"},
		"grant_types_supported":    []string{"implicit", "authorization_code"},
		"scopes_supported": []string{
			"openid", "profile", "email",
			"*:r", "*:rw",
			"documents:r", "documents:rw",
			"contacts:r", "contacts:rw",
			"root:r", "root:rw",
		},
	}
}

func (p *Provider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Parse parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")

	// Validate parameters
	if clientID == "" || redirectURI == "" || responseType == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Generate our own state for the upstream request
	upstreamState := generateState()

	// Store the auth state
	p.stateStore.Store(upstreamState, AuthState{
		State:        state,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Scope:        scope,
		ResponseType: responseType,
		CreatedAt:    time.Now(),
	})

	// Build upstream authorization URL
	upstreamURL, _ := url.Parse(p.upstreamClient.discovery.AuthorizationEndpoint)
	q := upstreamURL.Query()
	q.Set("client_id", p.upstreamClient.ClientID)
	q.Set("redirect_uri", p.publicURL+"/oauth/callback")
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", upstreamState)
	upstreamURL.RawQuery = q.Encode()

	log.Printf("OAuth: Redirecting to upstream provider: %s", upstreamURL.String())

	// Redirect to upstream provider
	http.Redirect(w, r, upstreamURL.String(), http.StatusFound)
}

func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get authorization code and state
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	
	if code == "" || state == "" {
		http.Error(w, "Missing code or state", http.StatusBadRequest)
		return
	}

	// Retrieve auth state
	authState, ok := p.stateStore.Get(state)
	if !ok {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}
	p.stateStore.Delete(state)

	// Exchange code for token with upstream provider
	tokenResp, err := p.upstreamClient.exchangeCode(code, p.publicURL+"/oauth/callback")
	if err != nil {
		log.Printf("Failed to exchange code: %v", err)
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	// Get user info from upstream
	userInfo, err := p.upstreamClient.getUserInfo(tokenResp.AccessToken)
	if err != nil {
		log.Printf("Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	// Find user mapping
	username, ok := p.userMappings[userInfo.Sub]
	if !ok {
		log.Printf("No user mapping found for sub: %s", userInfo.Sub)
		http.Error(w, "User not authorized", http.StatusForbidden)
		return
	}

	log.Printf("OAuth: User authenticated - sub: %s, username: %s", userInfo.Sub, username)

	// Parse requested scopes
	scopes := parseScopes(authState.Scope)
	log.Printf("OAuth: Requested scopes: %v", scopes)

	// Generate our own access token
	accessToken, err := p.generateAccessToken(userInfo.Sub, username, scopes)
	if err != nil {
		log.Printf("Failed to generate access token: %v", err)
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Store token for introspection
	p.tokenStore.Store(accessToken, TokenData{
		AccessToken: accessToken,
		Sub:         userInfo.Sub,
		Username:    username,
		Scopes:      scopes,
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	// Build redirect URL based on response type
	redirectURL, _ := url.Parse(authState.RedirectURI)
	if authState.ResponseType == "token" {
		// Implicit flow - return token in fragment
		fragment := url.Values{}
		fragment.Set("access_token", accessToken)
		fragment.Set("token_type", "Bearer")
		fragment.Set("expires_in", "3600")
		if authState.State != "" {
			fragment.Set("state", authState.State)
		}
		redirectURL.Fragment = fragment.Encode()
	} else {
		// Code flow - not implemented yet
		http.Error(w, "Code flow not yet implemented", http.StatusNotImplemented)
		return
	}

	log.Printf("OAuth: Redirecting to client with token: %s", redirectURL.String())
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (p *Provider) handleToken(w http.ResponseWriter, r *http.Request) {
	// This would handle code exchange for authorization code flow
	// For now, we only support implicit flow
	http.Error(w, "Token endpoint not yet implemented", http.StatusNotImplemented)
}

func (p *Provider) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse token from request
	token := r.FormValue("token")
	if token == "" {
		http.Error(w, "Missing token", http.StatusBadRequest)
		return
	}

	// Check if token exists and is valid
	tokenData, ok := p.tokenStore.Get(token)
	if !ok {
		// Token not found or expired
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"active": false,
		})
		return
	}

	// Return token info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active":   true,
		"sub":      tokenData.Sub,
		"username": tokenData.Username,
		"scope":    strings.Join(tokenData.Scopes, " "),
		"exp":      tokenData.ExpiresAt.Unix(),
		"iat":      tokenData.IssuedAt.Unix(),
	})
}

func (p *Provider) generateAccessToken(sub, username string, scopes []string) (string, error) {
	claims := jwt.MapClaims{
		"sub":      sub,
		"username": username,
		"scope":    strings.Join(scopes, " "),
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iss":      p.publicURL,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(p.jwtSecret)
}

func (uc *UpstreamClient) fetchDiscovery() error {
	resp, err := http.Get(uc.DiscoveryURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return err
	}

	uc.discovery = &discovery
	return nil
}

func (uc *UpstreamClient) exchangeCode(code, redirectURI string) (*TokenResponse, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", uc.ClientID)
	data.Set("client_secret", uc.ClientSecret)

	resp, err := http.PostForm(uc.discovery.TokenEndpoint, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (uc *UpstreamClient) getUserInfo(accessToken string) (*UserInfo, error) {
	req, err := http.NewRequest("GET", uc.discovery.UserinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", resp.StatusCode)
	}

	var userInfo UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return &userInfo, nil
}

// StateStore methods
func (s *StateStore) Store(state string, authState AuthState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state] = authState

	// Clean up old states
	for k, v := range s.states {
		if time.Since(v.CreatedAt) > 10*time.Minute {
			delete(s.states, k)
		}
	}
}

func (s *StateStore) Get(state string) (AuthState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	authState, ok := s.states[state]
	return authState, ok
}

func (s *StateStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, state)
}

// TokenStore methods
func (t *TokenStore) Store(token string, data TokenData) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tokens[token] = data

	// Clean up expired tokens
	for k, v := range t.tokens {
		if time.Now().After(v.ExpiresAt) {
			delete(t.tokens, k)
		}
	}
}

func (t *TokenStore) Get(token string) (TokenData, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	data, ok := t.tokens[token]
	if !ok {
		return data, false
	}
	if time.Now().After(data.ExpiresAt) {
		return data, false
	}
	return data, true
}

// Helper functions
func generateState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func parseScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{"*:rw"} // Default to full access
	}
	return strings.Split(scopeStr, " ")
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type UserInfo struct {
	Sub               string `json:"sub"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Email             string `json:"email"`
}