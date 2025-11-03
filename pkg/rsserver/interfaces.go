package rsserver

import (
	"context"
	"io"
	"net/http"

	"anime.bike/remotestorage/pkg/rs"
)

// StorageBackend defines the interface for RemoteStorage backend implementations
type StorageBackend interface {
	// Get retrieves a document or folder listing
	Get(ctx context.Context, path string) (*rs.Document, *rs.FolderListing, error)

	// Create stores a new document (returns error if already exists)
	Create(ctx context.Context, path string, body io.Reader, contentType string) (etag string, err error)

	// Update modifies an existing document (returns error if doesn't exist or etag mismatch)
	Update(ctx context.Context, path string, body io.Reader, contentType string, etag string) (newETag string, err error)

	// Delete removes a document
	Delete(ctx context.Context, path string, etag string) error

	// Head retrieves document metadata
	Head(ctx context.Context, path string) (*rs.Metadata, error)
}

// StorageBackendRange is an optional interface for storage backends that support range requests
type StorageBackendRange interface {
	// GetRange retrieves a document with a specific byte range
	// If start is -1, it means "last N bytes" where end is the number of bytes
	// If end is -1, it means "from start to end of file"
	GetRange(ctx context.Context, path string, start, end int64) (*rs.Document, error)
}

// ResourceResolver extracts resource location information from HTTP request URLs
// This allows different implementations to support different URL structures:
// - Path-based: /{username}/{module}/{path}
// - Subdomain: https://{user}.example.com/{module}/{path}
// - Token-only (single tenant): /{module}/{path}
type ResourceResolver interface {
	// ResolveResource extracts the resource location from the HTTP request URL
	// Returns what resource is being accessed (user, module, path, public namespace)
	ResolveResource(r *http.Request) (*ResourceRef, error)
}

// Authenticator validates bearer tokens and returns user identity
// This is AUTHENTICATION only - it does NOT check resource access permissions
type Authenticator interface {
	// Authenticate validates a bearer token and returns user identity
	// The token parameter is the bearer token extracted from the Authorization header (empty string if no token)
	// Returns (nil, nil) if no token provided (may be acceptable for public reads)
	// Returns (*AuthInfo, nil) if token is valid
	// Returns (nil, error) if token is invalid or authentication fails
	Authenticate(r *http.Request, token string) (*AuthInfo, error)
}

// Authorizer checks if a user has permission to access a resource
// This is AUTHORIZATION only - it assumes authentication already happened
type Authorizer interface {
	// Authorize checks if the user has permission to access the requested resource
	// authInfo may be nil for unauthenticated requests (e.g., public document reads)
	// req contains the resource location and operation type
	// Returns nil if access is granted
	// Returns HTTPError with 403 Forbidden if access is denied
	// Returns HTTPError with 401 Unauthorized if auth is required but authInfo is nil
	Authorize(authInfo *AuthInfo, req *ResourceRequest) error
}

// StorageProvider returns storage backends for authenticated users
type StorageProvider interface {
	// GetStorage returns storage backend for the authenticated user and resource request
	// The request context should contain AuthInfo from Authenticate
	GetStorage(ctx context.Context, authInfo *AuthInfo, req *ResourceRequest) (StorageBackend, error)
}
