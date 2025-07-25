package rsserver

import (
	"fmt"
	"net/url"
	"strings"

	"anime.bike/remotestorage/pkg/rs"
)

// OAuthProvider validates tokens and provides the authorization URL
type OAuthProvider interface {
	// AuthorizationURL returns where clients should send users for authorization
	AuthorizationURL() string

	// ValidateToken checks if a token is valid and returns the user ID and scopes
	ValidateToken(token string) (userID string, scopes []rs.Scope, err error)
}

// GenericOAuthProvider implements a generic OAuth provider
type GenericOAuthProvider struct {
	AuthURL        string
	TokenValidator func(token string) (userID string, scopes []rs.Scope, err error)
}

// AuthorizationURL returns the OAuth authorization endpoint URL
func (p *GenericOAuthProvider) AuthorizationURL() string {
	return p.AuthURL
}

// ValidateToken validates an access token
func (p *GenericOAuthProvider) ValidateToken(token string) (string, []rs.Scope, error) {
	if p.TokenValidator == nil {
		return "", nil, fmt.Errorf("token validator not configured")
	}
	return p.TokenValidator(token)
}

// BuildAuthURL builds the full authorization URL with parameters
func (p *GenericOAuthProvider) BuildAuthURL(clientID, redirectURI, state string, scopes []rs.Scope) string {
	u, _ := url.Parse(p.AuthURL)
	q := u.Query()

	q.Set("response_type", "token") // RemoteStorage uses implicit flow
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)

	if state != "" {
		q.Set("state", state)
	}

	// Convert scopes to RemoteStorage format
	scopeStrings := make([]string, len(scopes))
	for i, scope := range scopes {
		scopeStrings[i] = fmt.Sprintf("%s:%s", scope.Module, scope.Access)
	}
	q.Set("scope", strings.Join(scopeStrings, " "))

	u.RawQuery = q.Encode()
	return u.String()
}
