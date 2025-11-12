package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver"
)

// Config represents the server configuration
type Config struct {
	Host        string       `json:"host"`          // e.g., "localhost:8080"
	MaxFileSize int64        `json:"max_file_size"` // Maximum file size in bytes (0 = no limit)
	Users       []UserConfig `json:"users"`         // List of users with credentials
}

// UserConfig represents a user in the config file
type UserConfig struct {
	Username string        `json:"username"`
	Password string        `json:"password"`
	Scopes   []ScopeConfig `json:"scopes"`
}

// ScopeConfig represents a scope in the config file
type ScopeConfig struct {
	Module string `json:"module"` // e.g., "contacts", "calendar", "*"
	Access string `json:"access"` // "r" or "rw"
}

func main() {
	// Load configuration
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Convert config users to OAuth users
	oauthUsers := make([]*OAuthUser, len(config.Users))
	for i, userCfg := range config.Users {
		scopes := make([]rs.Scope, len(userCfg.Scopes))
		for j, scopeCfg := range userCfg.Scopes {
			var access rs.AccessLevel
			switch scopeCfg.Access {
			case "r":
				access = rs.ReadAccess
			case "rw":
				access = rs.ReadWriteAccess
			default:
				log.Fatalf("Invalid access level for user %s: %s", userCfg.Username, scopeCfg.Access)
			}

			scopes[j] = rs.Scope{
				Module: scopeCfg.Module,
				Access: access,
			}
		}

		oauthUsers[i] = &OAuthUser{
			Username:      userCfg.Username,
			Password:      userCfg.Password,
			AllowedScopes: scopes,
		}
	}

	// Create OAuth provider
	oauthProvider := NewSimpleOAuthProvider(oauthUsers)

	// Build storage handler using builder pattern
	storageHandler := rsserver.NewBuilder().
		WithResourceResolver(NewSimpleResourceResolver()).
		WithAuthenticator(NewSimpleAuthenticator(oauthProvider)).
		WithAuthorizer(rsserver.NewScopeCheckingAuthorizer()).
		WithStorageProvider(NewSimpleStorageProvider()).
		WithHooks(rsserver.ServerHooks{
			BeforeWrite: fileSizeLimitHook(config.MaxFileSize),
		}).
		MustBuild()

	// Setup routes
	mux := http.NewServeMux()

	// WebFinger endpoint
	mux.HandleFunc("/.well-known/webfinger", func(w http.ResponseWriter, r *http.Request) {
		handleWebFinger(w, r, config.Host)
	})

	// OAuth authorization endpoint
	mux.HandleFunc("/oauth/authorize", oauthProvider.HandleAuthDialog)

	// Storage endpoints
	mux.Handle("/", storageHandler)

	// Start server
	log.Printf("Starting remoteStorage server on http://%s", config.Host)
	log.Printf("WebFinger: http://%s/.well-known/webfinger", config.Host)
	log.Printf("OAuth: http://%s/oauth/authorize", config.Host)
	log.Fatal(http.ListenAndServe(config.Host, mux))
}

// loadConfig loads configuration from a JSON file
func loadConfig(filename string) (*Config, error) {
	file, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(file, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// handleWebFinger handles WebFinger requests
func handleWebFinger(w http.ResponseWriter, r *http.Request, host string) {
	resource := r.URL.Query().Get("resource")
	if resource == "" {
		http.Error(w, "resource parameter required", http.StatusBadRequest)
		return
	}

	// Extract username from resource (e.g., "acct:alice@localhost:8080")
	// For simplicity, we just accept any resource and extract the username
	var username string
	if len(resource) > 5 && resource[:5] == "acct:" {
		// Format: acct:username@host
		parts := resource[5:] // Remove "acct:"
		atIndex := -1
		for i, c := range parts {
			if c == '@' {
				atIndex = i
				break
			}
		}
		if atIndex > 0 {
			username = parts[:atIndex]
		}
	}

	if username == "" {
		http.Error(w, "Invalid resource format", http.StatusBadRequest)
		return
	}

	// Build WebFinger response
	response := map[string]interface{}{
		"subject": resource,
		"links": []map[string]interface{}{
			{
				"rel":  "http://tools.ietf.org/id/draft-dejong-remotestorage",
				"href": fmt.Sprintf("http://%s/%s", host, username),
				"properties": map[string]interface{}{
					"http://remotestorage.io/spec/version":           "draft-dejong-remotestorage-25",
					"http://tools.ietf.org/html/rfc6749#section-4.2": fmt.Sprintf("http://%s/oauth/authorize", host),
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/jrd+json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(response)
}
