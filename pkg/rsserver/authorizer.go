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

// UserMatchAuthorizer checks that the authenticated user matches the requested user
// and delegates additional checks to a callback function
type UserMatchAuthorizer struct {
	// CheckAccess is called after verifying user match to perform additional checks
	// (e.g., scope validation). If nil, only user matching is performed.
	CheckAccess func(authInfo *AuthInfo, req *ResourceRequest) error
}

// NewUserMatchAuthorizer creates an authorizer that requires the authenticated user
// to match the requested user, with optional additional access checks
func NewUserMatchAuthorizer(checkAccess func(authInfo *AuthInfo, req *ResourceRequest) error) *UserMatchAuthorizer {
	return &UserMatchAuthorizer{
		CheckAccess: checkAccess,
	}
}

// NewSimpleUserMatchAuthorizer creates an authorizer that only checks user matching
// with no additional access control
func NewSimpleUserMatchAuthorizer() *UserMatchAuthorizer {
	return &UserMatchAuthorizer{
		CheckAccess: nil,
	}
}

// Authorize checks if the user has permission to access the requested resource
func (a *UserMatchAuthorizer) Authorize(authInfo *AuthInfo, req *ResourceRequest) error {
	resource := req.Resource
	isWrite := req.IsWrite

	// Per spec: public document reads (not folders, not writes) are allowed without auth
	if authInfo == nil {
		if !resource.IsPublic || isWrite {
			return NewHTTPError(http.StatusUnauthorized, "Missing authorization token")
		}
		// Public read without authentication - allowed
		return nil
	}

	// Verify username matches requested user
	if resource.RequestedUser != "" && resource.RequestedUser != authInfo.Username {
		return NewHTTPError(http.StatusForbidden, "Access denied: username mismatch")
	}

	// Call additional access check if provided
	if a.CheckAccess != nil {
		return a.CheckAccess(authInfo, req)
	}

	return nil
}

// NewScopeCheckingAuthorizer creates an authorizer that checks user matching and scope access
// This is a convenience constructor for the common pattern of checking both user and scopes
func NewScopeCheckingAuthorizer() *UserMatchAuthorizer {
	return NewUserMatchAuthorizer(func(authInfo *AuthInfo, req *ResourceRequest) error {
		// Check scopes for access to this module
		if !rs.CheckScopeAccess(authInfo.Scopes, req.Resource.Module, !req.IsWrite) {
			return NewHTTPError(http.StatusForbidden, "Insufficient scope")
		}
		return nil
	})
}
