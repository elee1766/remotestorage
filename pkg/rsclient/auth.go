package rsclient

import (
	"fmt"
	"strings"

	"anime.bike/remotestorage/pkg/rs"
	"golang.org/x/oauth2"
)

// GetOAuth2Config creates an OAuth2 config for RemoteStorage
func GetOAuth2Config(authEndpoint, clientID, redirectURI string, scopes []rs.Scope) *oauth2.Config {
	scopeStrings := make([]string, len(scopes))
	for i, scope := range scopes {
		scopeStrings[i] = fmt.Sprintf("%s:%s", scope.Module, scope.Access)
	}

	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: "", // RemoteStorage uses implicit flow, no secret needed
		Endpoint: oauth2.Endpoint{
			AuthURL:  authEndpoint,
			TokenURL: "", // Implicit flow doesn't use token endpoint
		},
		RedirectURL: redirectURI,
		Scopes:      scopeStrings,
	}
}

// GetAuthCodeURL generates the authorization URL for implicit flow
func GetAuthCodeURL(config *oauth2.Config, state string) string {
	// Force implicit flow by adding response_type=token
	return config.AuthCodeURL(state, oauth2.SetAuthURLParam("response_type", "token"))
}

// ParseScope parses a scope string into structured scopes
func ParseScope(scopeString string) ([]rs.Scope, error) {
	parts := strings.Split(scopeString, " ")
	scopes := make([]rs.Scope, 0, len(parts))

	for _, part := range parts {
		if part == "" {
			continue
		}

		colonIndex := strings.LastIndex(part, ":")
		if colonIndex == -1 {
			return nil, fmt.Errorf("invalid scope format: %s", part)
		}

		module := part[:colonIndex]
		access := rs.AccessLevel(part[colonIndex+1:])

		if access != rs.ReadAccess && access != rs.ReadWriteAccess {
			return nil, fmt.Errorf("invalid access level: %s", access)
		}

		scopes = append(scopes, rs.Scope{
			Module: module,
			Access: access,
		})
	}

	return scopes, nil
}
