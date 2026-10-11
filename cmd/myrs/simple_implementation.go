package main

import (
	"context"
	"net/http"
	"sync"

	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rstest"
)

// NewSimpleResourceResolver maps /{username}/{path} to a resource.
// Public documents live at /{username}/public/{module}/{path}.
func NewSimpleResourceResolver() rsserver.ResourceResolver {
	return rstest.PathResolver{}
}

// SimpleAuthenticator validates bearer tokens using an OAuth provider
type SimpleAuthenticator struct {
	oauthProvider *SimpleOAuthProvider
}

// NewSimpleAuthenticator creates a new authenticator
func NewSimpleAuthenticator(oauthProvider *SimpleOAuthProvider) *SimpleAuthenticator {
	return &SimpleAuthenticator{oauthProvider: oauthProvider}
}

// Authenticate validates the bearer token and returns user identity.
func (s *SimpleAuthenticator) Authenticate(r *http.Request, token string) (*rsserver.AuthInfo, error) {
	if token == "" {
		return nil, nil
	}
	username, scopes, err := s.oauthProvider.ValidateToken(token)
	if err != nil {
		return nil, rsserver.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	}
	return &rsserver.AuthInfo{UserID: username, Username: username, Scopes: scopes}, nil
}

// SimpleStorageProvider keeps one in-memory tree per user.
type SimpleStorageProvider struct {
	mu    sync.Mutex
	users map[string]*rstest.MemoryStorage
}

// NewSimpleStorageProvider creates a new storage provider
func NewSimpleStorageProvider() *SimpleStorageProvider {
	return &SimpleStorageProvider{users: map[string]*rstest.MemoryStorage{}}
}

// GetStorage returns the storage of the user named in the URL. Public reads
// have no AuthInfo, so the URL is the only reliable source of the user.
func (s *SimpleStorageProvider) GetStorage(_ context.Context, _ *rsserver.AuthInfo, req *rsserver.ResourceRequest) (rsserver.StorageBackend, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	user := req.Resource.RequestedUser
	st, ok := s.users[user]
	if !ok {
		st = rstest.NewMemoryStorage()
		s.users[user] = st
	}
	return st, nil
}
