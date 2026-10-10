package rsserver

import (
	"net/http"

	"anime.bike/remotestorage/pkg/rs"
)

// AuthorizerFunc is a function type that implements Authorizer
type AuthorizerFunc func(authInfo *AuthInfo, req *ResourceRequest) error

// Authorize implements the Authorizer interface
func (f AuthorizerFunc) Authorize(authInfo *AuthInfo, req *ResourceRequest) error {
	return f(authInfo, req)
}

// UserMatchAuthorizer applies the access rules of spec section 9:
//   - GET/HEAD of a document under /public/ is always allowed, without a token,
//   - everything else needs a token for the requested user,
//   - CheckAccess (usually scope checking) runs for authenticated requests.
type UserMatchAuthorizer struct {
	CheckAccess func(authInfo *AuthInfo, req *ResourceRequest) error
}

// NewUserMatchAuthorizer creates an authorizer that requires the authenticated user
// to match the requested user, with optional additional access checks
func NewUserMatchAuthorizer(checkAccess func(authInfo *AuthInfo, req *ResourceRequest) error) *UserMatchAuthorizer {
	return &UserMatchAuthorizer{CheckAccess: checkAccess}
}

// NewSimpleUserMatchAuthorizer creates an authorizer that only checks user matching
func NewSimpleUserMatchAuthorizer() *UserMatchAuthorizer {
	return &UserMatchAuthorizer{}
}

// Authorize checks if the user has permission to access the requested resource
func (a *UserMatchAuthorizer) Authorize(authInfo *AuthInfo, req *ResourceRequest) error {
	res := req.Resource
	if res.IsPublic && !req.IsWrite && !res.IsFolder() {
		return nil
	}
	if authInfo == nil {
		return NewHTTPError(http.StatusUnauthorized, "Missing or invalid bearer token")
	}
	if res.RequestedUser != "" && res.RequestedUser != authInfo.Username {
		return NewHTTPError(http.StatusForbidden, "Access denied: token belongs to another user")
	}
	if a.CheckAccess != nil {
		return a.CheckAccess(authInfo, req)
	}
	return nil
}

// NewScopeCheckingAuthorizer checks user matching and the token's scopes.
func NewScopeCheckingAuthorizer() *UserMatchAuthorizer {
	return NewUserMatchAuthorizer(func(authInfo *AuthInfo, req *ResourceRequest) error {
		if !rs.CheckScopeAccess(authInfo.Scopes, req.Resource.Module, !req.IsWrite) {
			return NewHTTPError(http.StatusForbidden, "Insufficient scope")
		}
		return nil
	})
}
