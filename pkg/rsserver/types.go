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

	// Username is the user name that appears in storage URLs
	Username string

	// Scopes are the access scopes granted to this request
	Scopes []rs.Scope
}

// ResourceRef identifies a specific resource location (parsed from the URL)
type ResourceRef struct {
	// RequestedUser is the user whose storage is addressed (path segment or subdomain).
	RequestedUser string

	// Path relative to the user's storage root, starting with "/".
	// Folders end in "/". Example: "/contacts/friends.json", "/public/blog/".
	Path string

	// Module is the scope module of Path (filled by the handler).
	Module string

	// IsPublic reports whether Path is in the /public/ subtree (filled by the handler).
	IsPublic bool
}

// IsFolder reports whether the resource is a folder.
func (r *ResourceRef) IsFolder() bool { return rs.IsFolderPath(r.Path) }

// ResourceRequest combines resource location with the operation type
type ResourceRequest struct {
	// Resource is the location being accessed
	Resource *ResourceRef

	// IsWrite indicates if this is a write operation (PUT/DELETE vs GET/HEAD)
	IsWrite bool
}
