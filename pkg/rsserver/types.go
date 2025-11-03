package rsserver

import (
	"anime.bike/remotestorage/pkg/rs"
)

// AuthInfo contains authentication and user information.
// If authentication succeeds, this struct is returned with user details.
// If authentication fails, an error should be returned instead.
// For public document reads without auth, implementations may return (nil, nil).
type AuthInfo struct {
	// UserID is the unique identifier for the user (e.g., sub claim)
	UserID string

	// Username is the human-readable username (e.g., preferred_username)
	Username string

	// Scopes are the access scopes granted to this request
	Scopes []rs.Scope
}

// ResourceRef identifies a specific resource location (parsed from the URL)
type ResourceRef struct {
	// RequestedUser is the user identifier from the URL (e.g., username in path or subdomain)
	// this could be empty if the request is not authenticated
	RequestedUser string

	// Module being accessed (e.g., "contacts", "calendar")
	Module string

	// Path within the module (e.g., "/friends.json", "/events/2025/")
	Path string

	// IsPublic indicates if this is accessing the public namespace (/public/<module>/...)
	IsPublic bool
}

// ResourceRequest combines resource location with the operation type
type ResourceRequest struct {
	// Resource is the location being accessed
	Resource *ResourceRef

	// IsWrite indicates if this is a write operation (PUT/DELETE vs GET/HEAD)
	IsWrite bool
}
