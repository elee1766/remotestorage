package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"
	"sigs.k8s.io/yaml"

	"anime.bike/remotestorage/cmd/myrs/impl"
	"anime.bike/remotestorage/pkg/nullable"
	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/webfinger"
)

type OAuthConfig struct {
	DiscoveryURL       string `yaml:"discoveryURL"`
	ClientID           string `yaml:"clientID"`
	ClientSecret       string `yaml:"clientSecret"`       // Client secret for confidential client (introspection)
	SubClaim           string `yaml:"subClaim"`           // Claim for storage bucket ID (default: "sub")
	UsernameClaim      string `yaml:"usernameClaim"`      // Claim for URL username (default: "preferred_username")
	InsecureIgnoreScopes bool `yaml:"insecureIgnoreScopes"` // INSECURE: Ignore scopes and grant full access to authenticated users
}

type WebfingerUser struct {
	Username string `yaml:"username"`
	Sub      string `yaml:"sub"`
}

type Config struct {
	Addr           string          `yaml:"addr"`
	StorageHost    string          `yaml:"storageHost"`
	AuthHost       string          `yaml:"authHost"` // Host for OAuth endpoints (e.g., dev.put.plus)
	BaseRoute      string          `yaml:"baseRoute"`
	CorsOrigin     string          `yaml:"corsOrigin"`
	OAuth          *OAuthConfig    `yaml:"oauth"`
	WebfingerUsers []WebfingerUser `yaml:"webfingerUsers"`
}

type CLI struct {
	ConfigFile string `kong:"arg,required,help='Path to YAML config file'"`
}

// PKCEStore stores PKCE verifiers temporarily
type PKCEStore struct {
	mu    sync.RWMutex
	store map[string]PKCEData
}

type PKCEData struct {
	Verifier    string
	RedirectURI string
	Scope       string
	CreatedAt   time.Time
}

func NewPKCEStore() *PKCEStore {
	return &PKCEStore{
		store: make(map[string]PKCEData),
	}
}

func (s *PKCEStore) Store(state, verifier, redirectURI, scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[state] = PKCEData{
		Verifier:    verifier,
		RedirectURI: redirectURI,
		Scope:       scope,
		CreatedAt:   time.Now(),
	}
	// Clean up old entries
	for k, v := range s.store {
		if time.Since(v.CreatedAt) > 10*time.Minute {
			delete(s.store, k)
		}
	}
}

func (s *PKCEStore) Get(state string) (PKCEData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.store[state]
	return data, ok
}

func (s *PKCEStore) Delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, state)
}

// generateCodeVerifier creates a PKCE code verifier
func generateCodeVerifier() (string, error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(verifierBytes), nil
}

// generateCodeChallenge creates a PKCE code challenge from the verifier
func generateCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// OIDCDiscoveryResponse represents the OIDC discovery document
type OIDCDiscoveryResponse struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// fetchOIDCDiscovery fetches the OIDC discovery document
func fetchOIDCDiscovery(discoveryURL string) (*OIDCDiscoveryResponse, error) {
	resp, err := http.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery OIDCDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("failed to decode OIDC discovery response: %w", err)
	}

	return &discovery, nil
}

// setupWebfingerEndpoints adds webfinger endpoints for configured users
func setupWebfingerEndpoints(mux *http.ServeMux, authEndpoint string, config Config) {
	// Webfinger endpoint
	mux.HandleFunc("/.well-known/webfinger", func(w http.ResponseWriter, r *http.Request) {
		resource := r.URL.Query().Get("resource")
		if resource == "" {
			http.Error(w, "Missing resource parameter", http.StatusBadRequest)
			return
		}

		// Extract username from resource (support both acct: and bare username)
		var username string
		if strings.HasPrefix(resource, "acct:") {
			// Format: acct:username@domain
			parts := strings.SplitN(strings.TrimPrefix(resource, "acct:"), "@", 2)
			if len(parts) > 0 {
				username = parts[0]
			}
		} else {
			// Assume bare username
			username = resource
		}

		// Check if username is in our configured list
		var foundUser *WebfingerUser
		for _, user := range config.WebfingerUsers {
			if user.Username == username {
				foundUser = &user
				break
			}
		}

		if foundUser == nil {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}

		// Build storage href
		storageHref := "https://" + config.StorageHost
		if config.BaseRoute != "/" {
			storageHref += config.BaseRoute
		}
		storageHref += "/" + username + "/"

		// Create webfinger response
		response := webfinger.NewWebFinger("acct:" + username + "@" + config.StorageHost)

		// Create RemoteStorageProperties with OAuth endpoint
		// Point to our OAuth authorize endpoint on authHost
		oauthEndpoint := "https://" + config.AuthHost + "/oauth/authorize"

		version := rs.SupportedVersion
		props := &rs.RemoteStorageProperties{
			Version:             version,
			AuthEndpoint:        nullable.NewString(oauthEndpoint),
			RangeRequestSupport: nullable.NewString("GET"),
		}
		response.AddRemoteStorageLink(storageHref, props)

		w.Header().Set("Content-Type", "application/jrd+json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(response)
	})

	// Host-meta endpoint (optional but good practice)
	mux.HandleFunc("/.well-known/host-meta", func(w http.ResponseWriter, r *http.Request) {
		hostMeta := `<?xml version="1.0" encoding="UTF-8"?>
<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">
  <Link rel="lrdd" template="https://` + config.StorageHost + `/.well-known/webfinger?resource={uri}"/>
</XRD>`
		w.Header().Set("Content-Type", "application/xrd+xml")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		fmt.Fprint(w, hostMeta)
	})
}

// setupOAuthEndpoints adds OAuth endpoints for initiating authorization
func setupOAuthEndpoints(mux *http.ServeMux, authEndpoint string, config Config, pkceStore *PKCEStore) {
	// OAuth authorize endpoint pattern: /oauth/authorize
	authorizePath := "/oauth/authorize"
	if config.BaseRoute != "/" {
		authorizePath = config.BaseRoute + "/oauth/authorize"
	}

	mux.HandleFunc(authorizePath, func(w http.ResponseWriter, r *http.Request) {

		// Get redirect_uri from query parameters
		redirectURI := r.URL.Query().Get("redirect_uri")
		if redirectURI == "" {
			http.Error(w, "redirect_uri parameter required", http.StatusBadRequest)
			return
		}

		// Always use our configured client ID for the OAuth provider
		clientID := config.OAuth.ClientID

		// Client expects implicit flow, but we'll use code flow with PKCE internally
		clientResponseType := r.URL.Query().Get("response_type")
		if clientResponseType == "" {
			clientResponseType = "token"
		}

		// Get scope from query parameters (default to standard RemoteStorage scopes)
		scope := r.URL.Query().Get("scope")
		if scope == "" {
			scope = "*:rw"
		}
		
		// Add standard OIDC scopes to get user profile information
		// RemoteStorage scopes are for the RS protocol, but we need OIDC scopes for user info
		// Also add root:rw which some providers might recognize
		oidcScopes := "openid profile email"
		additionalScopes := "root:rw"
		if scope != "" {
			scope = oidcScopes + " " + additionalScopes + " " + scope
		} else {
			scope = oidcScopes + " " + additionalScopes
		}

		// Construct authorization URL with proper parameters
		authURL, err := url.Parse(authEndpoint)
		if err != nil {
			http.Error(w, "Invalid authorization endpoint", http.StatusInternalServerError)
			return
		}

		q := authURL.Query()
		// Generate PKCE parameters
		codeVerifier, err := generateCodeVerifier()
		if err != nil {
			http.Error(w, "Failed to generate PKCE verifier", http.StatusInternalServerError)
			return
		}
		codeChallenge := generateCodeChallenge(codeVerifier)

		// Generate state parameter if not provided
		state := r.URL.Query().Get("state")
		if state == "" {
			// Generate a random state
			stateBytes := make([]byte, 16)
			if _, err := rand.Read(stateBytes); err != nil {
				http.Error(w, "Failed to generate state", http.StatusInternalServerError)
				return
			}
			state = base64.RawURLEncoding.EncodeToString(stateBytes)
		}

		// Store PKCE verifier, redirect URI, and scope for later use
		pkceStore.Store(state, codeVerifier, redirectURI, scope)

		// Use authorization code flow with PKCE
		q.Set("response_type", "code")
		q.Set("client_id", clientID)

		// Build redirect URI with authHost and state
		callbackURL := fmt.Sprintf("https://%s/oauth/callback", config.AuthHost)

		q.Set("redirect_uri", callbackURL)
		q.Set("scope", scope)
		q.Set("state", state)
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")

		authURL.RawQuery = q.Encode()

		// Log the redirect URL for debugging
		log.Printf("OAuth redirect: %s", authURL.String())
		log.Printf("  response_type: code (converting from %s)", clientResponseType)
		log.Printf("  client_id: %s", clientID)
		log.Printf("  redirect_uri: %s", callbackURL)
		log.Printf("  client_redirect_uri: %s", redirectURI)
		log.Printf("  scope: %s", scope)
		log.Printf("  state: %s", state)
		log.Printf("  code_challenge: %s", codeChallenge)
		log.Printf("  code_challenge_method: S256")
		
		// Also log the full URL for debugging
		log.Printf("Full authorization URL: %s", authURL.String())

		// Redirect to authorization endpoint
		http.Redirect(w, r, authURL.String(), http.StatusFound)
	})

	// OAuth callback endpoint pattern: /oauth/callback
	callbackPath := "/oauth/callback"
	if config.BaseRoute != "/" {
		callbackPath = config.BaseRoute + "/oauth/callback"
	}

	mux.HandleFunc(callbackPath, func(w http.ResponseWriter, r *http.Request) {
		// Log the callback request
		log.Printf("OAuth callback received:")
		log.Printf("  Full URL: %s", r.URL.String())
		log.Printf("  Query params: %v", r.URL.Query())
		log.Printf("  Method: %s", r.Method)

		// Get state parameter
		state := r.URL.Query().Get("state")
		if state == "" {
			http.Error(w, "Missing state parameter", http.StatusBadRequest)
			return
		}

		// Retrieve PKCE data
		pkceData, ok := pkceStore.Get(state)
		if !ok {
			http.Error(w, "Invalid or expired state", http.StatusBadRequest)
			return
		}

		// Clean up the state
		pkceStore.Delete(state)

		clientRedirectURI := pkceData.RedirectURI

		// Check if we have an authorization code
		code := r.URL.Query().Get("code")
		if code != "" {
			// Authorization code flow - need to exchange code for token
			// For RemoteStorage, we typically want implicit flow, but since PocketID is returning a code,
			// we need to exchange it

			// Get token endpoint from discovery
			discovery, err := fetchOIDCDiscovery(config.OAuth.DiscoveryURL)
			if err != nil {
				http.Error(w, "Failed to fetch OIDC discovery", http.StatusInternalServerError)
				return
			}

			// Exchange code for token
			tokenReq := url.Values{}
			tokenReq.Set("grant_type", "authorization_code")
			tokenReq.Set("code", code)
			tokenReq.Set("redirect_uri", fmt.Sprintf("https://%s/oauth/callback", config.AuthHost))
			tokenReq.Set("code_verifier", pkceData.Verifier)
			
			// Include the scope that was requested during authorization
			if pkceData.Scope != "" {
				tokenReq.Set("scope", pkceData.Scope)
			}
			
			// Only include client_id in body if we're not using Basic Auth
			if config.OAuth.ClientSecret == "" {
				tokenReq.Set("client_id", config.OAuth.ClientID)
			}

			log.Printf("Exchanging code for token:")
			log.Printf("  Token endpoint: %s", discovery.TokenEndpoint)
			log.Printf("  Client ID: %s", config.OAuth.ClientID)
			log.Printf("  Redirect URI: %s", fmt.Sprintf("https://%s/oauth/callback", config.AuthHost))
			log.Printf("  Scope: %s", pkceData.Scope)
			if config.OAuth.ClientSecret != "" {
				log.Printf("  Authentication: HTTP Basic Auth (confidential client)")
			} else {
				log.Printf("  Authentication: client_id in body (public client)")
			}

			// Create the request
			req, err := http.NewRequest("POST", discovery.TokenEndpoint, strings.NewReader(tokenReq.Encode()))
			if err != nil {
				log.Printf("Failed to create token request: %v", err)
				http.Error(w, "Failed to create token request", http.StatusInternalServerError)
				return
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			
			// If we have a client secret, use HTTP Basic Authentication
			if config.OAuth.ClientSecret != "" {
				req.SetBasicAuth(config.OAuth.ClientID, config.OAuth.ClientSecret)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("Token exchange failed: %v", err)
				http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			var tokenResp struct {
				AccessToken string `json:"access_token"`
				TokenType   string `json:"token_type"`
				ExpiresIn   int    `json:"expires_in"`
				Error       string `json:"error"`
				ErrorDesc   string `json:"error_description"`
			}

			if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
				log.Printf("Failed to decode token response: %v", err)
				http.Error(w, "Failed to decode token response", http.StatusInternalServerError)
				return
			}

			if tokenResp.Error != "" {
				log.Printf("Token exchange error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
				// Redirect with error
				errorURL := fmt.Sprintf("%s?error=%s", clientRedirectURI, url.QueryEscape(tokenResp.Error))
				http.Redirect(w, r, errorURL, http.StatusFound)
				return
			}

			if tokenResp.AccessToken == "" {
				log.Printf("No access token in response")
				http.Error(w, "No access token received", http.StatusInternalServerError)
				return
			}

			// Log the token details
			log.Printf("Token exchange successful:")
			log.Printf("  Access Token: %s...", tokenResp.AccessToken[:min(20, len(tokenResp.AccessToken))])
			log.Printf("  Token Type: %s", tokenResp.TokenType)
			log.Printf("  Expires In: %d", tokenResp.ExpiresIn)

			// Redirect to client with token in fragment (as RemoteStorage expects)
			tokenURL := fmt.Sprintf("%s#access_token=%s&token_type=%s",
				clientRedirectURI,
				url.QueryEscape(tokenResp.AccessToken),
				url.QueryEscape(tokenResp.TokenType))
			http.Redirect(w, r, tokenURL, http.StatusFound)
			return
		}

		// For implicit flow, the token comes in the fragment
		// We need to use JavaScript to extract it and redirect
		html := `<!DOCTYPE html>
<html>
<head>
    <title>RemoteStorage OAuth Callback</title>
</head>
<body>
    <h1>Processing authentication...</h1>
    <div id="debug" style="background: #f0f0f0; padding: 10px; margin: 20px 0; font-family: monospace;">
        <h3>Debug Information:</h3>
        <p>Full URL: <span id="fullurl"></span></p>
        <p>Hash: <span id="hash"></span></p>
        <p>Query String: <span id="query"></span></p>
    </div>
    <script>
        // Debug information
        document.getElementById('fullurl').textContent = window.location.href;
        document.getElementById('hash').textContent = window.location.hash || '(none)';
        document.getElementById('query').textContent = window.location.search || '(none)';

        // Get the fragment from PocketID
        var hash = window.location.hash;
        var redirectUri = '` + clientRedirectURI + `';

        if (hash) {
            // Redirect to the client with the fragment
            document.body.innerHTML += '<p>Found token in fragment, redirecting to: ' + redirectUri + hash + '</p>';
            setTimeout(function() {
                window.location.href = redirectUri + hash;
            }, 2000); // Give 2 seconds to see the debug info
        } else {
            // Check for error in query string
            var params = new URLSearchParams(window.location.search);
            var error = params.get('error');
            var errorDescription = params.get('error_description');

            if (error) {
                // Redirect with error
                document.body.innerHTML += '<p>Found error: ' + error + ' - ' + (errorDescription || '') + '</p>';
                document.body.innerHTML += '<p>Redirecting to: ' + redirectUri + '?error=' + encodeURIComponent(error) + '</p>';
                setTimeout(function() {
                    window.location.href = redirectUri + '?error=' + encodeURIComponent(error);
                }, 2000);
            } else {
                document.body.innerHTML += '<p style="color: red;">No access token or error received from OAuth provider.</p>';
                document.body.innerHTML += '<p>Expected format: #access_token=... or ?error=...</p>';
            }
        }
    </script>
</body>
</html>`

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(html))
	})
}

func main() {
	var cli CLI
	ctx := kong.Parse(&cli,
		kong.Name("myrs"),
		kong.Description("a simple personal remotestorage server"),
	)
	_ = ctx

	// Load config from file
	data, err := os.ReadFile(cli.ConfigFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	// Set defaults if not specified in config
	if config.Addr == "" {
		config.Addr = ":8080"
	}
	if config.StorageHost == "" {
		config.StorageHost = "localhost:8080"
	}
	if config.BaseRoute == "" {
		config.BaseRoute = "/"
	}
	// Ensure base route starts with / and doesn't end with / unless it's just "/"
	if !strings.HasPrefix(config.BaseRoute, "/") {
		config.BaseRoute = "/" + config.BaseRoute
	}
	if config.BaseRoute != "/" && strings.HasSuffix(config.BaseRoute, "/") {
		config.BaseRoute = strings.TrimSuffix(config.BaseRoute, "/")
	}
	if config.CorsOrigin == "" {
		config.CorsOrigin = "*"
	}

	// Validate OAuth configuration
	if config.OAuth == nil {
		log.Fatal("OAuth configuration is required. Please provide OAuth settings in the config file.")
	}
	if config.OAuth.DiscoveryURL == "" || config.OAuth.ClientID == "" {
		log.Fatal("OAuth discovery URL and client ID are required.")
	}
	if config.AuthHost == "" {
		log.Fatal("authHost is required. Please specify the host for OAuth endpoints (e.g., dev.put.plus).")
	}

	// Set defaults for claims
	if config.OAuth.SubClaim == "" {
		config.OAuth.SubClaim = "sub"
	}
	if config.OAuth.UsernameClaim == "" {
		config.OAuth.UsernameClaim = "preferred_username"
	}

	// Fetch OIDC discovery document
	discovery, err := fetchOIDCDiscovery(config.OAuth.DiscoveryURL)
	if err != nil {
		log.Fatalf("Failed to fetch OIDC discovery: %v", err)
	}

	// Determine which endpoint to use based on client configuration
	var tokenInfoURL string
	var introspectionURL string
	
	if config.OAuth.ClientSecret != "" && discovery.IntrospectionEndpoint != "" {
		// Confidential client - use introspection
		introspectionURL = discovery.IntrospectionEndpoint
		tokenInfoURL = discovery.UserinfoEndpoint // Keep as fallback
		log.Printf("Using introspection endpoint: %s", introspectionURL)
	} else {
		// Public client - use userinfo only
		tokenInfoURL = discovery.UserinfoEndpoint
		log.Printf("Using userinfo endpoint: %s", tokenInfoURL)
	}

	// Use authorization endpoint from discovery
	authEndpoint := discovery.AuthorizationEndpoint

	// Create OIDC-based implementation with OAuth
	baseImpl := impl.NewOidcBasedImplementationWithOAuth(
		authEndpoint, 
		tokenInfoURL, 
		introspectionURL,
		config.OAuth.ClientID, 
		config.OAuth.ClientSecret,
		config.OAuth.SubClaim, 
		config.OAuth.UsernameClaim,
	)

	// Configure webfinger users for validation
	webfingerUsers := make([]impl.WebfingerUser, len(config.WebfingerUsers))
	for i, user := range config.WebfingerUsers {
		webfingerUsers[i] = impl.WebfingerUser{
			Username: user.Username,
			Sub:      user.Sub,
		}
	}
	baseImpl.SetWebfingerUsers(webfingerUsers)
	
	// Set insecure ignore scopes if configured
	if config.OAuth.InsecureIgnoreScopes {
		baseImpl.SetInsecureIgnoreScopes(true)
	}

	// Setup complete RemoteStorage server (no built-in OAuth portal needed)
	mux := http.NewServeMux()
	storageHandler := rsserver.NewStorageHandler(baseImpl)

	// Create middleware chain (auth is now handled in implementation)
	handler := rsserver.NewCORSMiddleware(rsserver.CORSConfig{AllowOrigin: config.CorsOrigin})(storageHandler)

	// Mount storage endpoint at base route
	if config.BaseRoute == "/" {
		mux.Handle("/", handler)
	} else {
		mux.Handle(config.BaseRoute+"/", handler)
	}

	// Add webfinger endpoints
	setupWebfingerEndpoints(mux, authEndpoint, config)

	// Create PKCE store
	pkceStore := NewPKCEStore()

	// Add OAuth endpoints
	setupOAuthEndpoints(mux, authEndpoint, config, pkceStore)

	// Add a simple status endpoint
	statusPath := "/status"
	if config.BaseRoute != "/" {
		statusPath = config.BaseRoute + "/status"
	}
	mux.HandleFunc(statusPath, func(w http.ResponseWriter, r *http.Request) {
		storagePattern := config.BaseRoute + "/{username}/{module}/{path}"
		if config.BaseRoute == "/" {
			storagePattern = "/{username}/{module}/{path}"
		}

		status := fmt.Sprintf(`MyRS: Personal RemoteStorage server is running

Base Route: %s

Endpoints:
- Storage: %s
- Webfinger: /.well-known/webfinger
- OAuth: https://%s/oauth/authorize

OAuth Configuration:
- Discovery URL: %s
- OIDC Authorization URL: %s
- Token Validation Method: %s
- Token Info URL: %s
- Insecure Ignore Scopes: %v

Configured Users: %d
Storage URL pattern: %s

OAuth flow:
1. Client discovers OAuth endpoint via webfinger
2. Client redirects to https://%s/oauth/authorize?redirect_uri=...&scope=...
3. MyRS redirects to OIDC provider with proper parameters
`, config.BaseRoute, storagePattern, config.AuthHost, config.OAuth.DiscoveryURL, authEndpoint, 
			func() string {
				if introspectionURL != "" {
					return "Introspection (confidential client)"
				}
				return "Userinfo (public client)"
			}(),
			func() string {
				if introspectionURL != "" {
					return introspectionURL
				}
				return tokenInfoURL
			}(),
			config.OAuth.InsecureIgnoreScopes,
			len(config.WebfingerUsers), storagePattern, config.AuthHost)

		fmt.Fprint(w, status)
	})

	// Start server
	storageEndpoint := "https://" + config.StorageHost + config.BaseRoute
	if config.BaseRoute != "/" {
		storageEndpoint += "/"
	}
	storageEndpoint += "{username}/{module}/{path}"

	exampleBase := "https://" + config.StorageHost + config.BaseRoute
	if config.BaseRoute != "/" {
		exampleBase += "/"
	}

	startupMsg := fmt.Sprintf(`Starting MyRS: Personal RemoteStorage server on %s

Configuration:
  Host: %s
  Base Route: %s
  Storage: in-memory with storage claim bucketing
  OAuth Discovery URL: %s
  OAuth Authorization URL: %s
  OAuth Token Validation: %s
  Sub Claim: %s
  Username Claim: %s
  Client Type: %s
  Configured Users: %d

Endpoints:
  Storage: %s
  Webfinger: https://%s/.well-known/webfinger
  OAuth: https://%s%s/oauth/callback

Example storage URLs:
  %salice/documents/notes.txt
  %salice/photos/vacation.jpg
  %sbob/contacts/friends.json

Example webfinger queries:
  https://%s/.well-known/webfinger?resource=alice
  https://%s/.well-known/webfinger?resource=acct:alice@%s

Example OAuth flow:
  1. App discovers: https://%s/.well-known/webfinger?resource=alice
  2. App redirects to: https://%s%s/oauth/alice?redirect_uri=...&scope=*:rw
  3. MyRS redirects to OIDC provider for authentication
`, config.Addr, config.StorageHost, config.BaseRoute, config.OAuth.DiscoveryURL, authEndpoint, 
		func() string {
			if introspectionURL != "" {
				return fmt.Sprintf("Introspection (%s)", introspectionURL)
			}
			return fmt.Sprintf("Userinfo (%s)", tokenInfoURL)
		}(),
		config.OAuth.SubClaim, config.OAuth.UsernameClaim,
		func() string {
			if config.OAuth.ClientSecret != "" {
				return "Confidential (has client secret)"
			}
			return "Public (no client secret)"
		}(),
		len(config.WebfingerUsers), storageEndpoint, config.StorageHost, config.StorageHost, config.BaseRoute, exampleBase, exampleBase, exampleBase, config.StorageHost, config.StorageHost, config.StorageHost, config.StorageHost, config.StorageHost, config.BaseRoute)

	log.Print(startupMsg)

	if err := http.ListenAndServe(config.Addr, mux); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
