package rsclient

import (
	"context"
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

// GetPKCEOAuth2Config creates an OAuth2 config for the spec §10.1 code flow.
func GetPKCEOAuth2Config(authorizationEndpoint, tokenEndpoint, clientID, redirectURI string, scopes []rs.Scope) *oauth2.Config {
	config := GetOAuth2Config(authorizationEndpoint, clientID, redirectURI, scopes)
	config.Endpoint.TokenURL = tokenEndpoint
	// Public client: send client_id in the form body, no secret.
	config.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	return config
}

// GetPKCEAuthURL generates the authorization URL for the code flow with an S256 challenge.
// Create verifier with oauth2.GenerateVerifier and keep it for ExchangePKCECode.
func GetPKCEAuthURL(config *oauth2.Config, state, verifier string) string {
	return config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

// ExchangePKCECode redeems an authorization code at the token endpoint.
func ExchangePKCECode(ctx context.Context, config *oauth2.Config, code, verifier string) (*oauth2.Token, error) {
	return config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
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
