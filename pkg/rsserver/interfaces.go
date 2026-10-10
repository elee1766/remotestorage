package rsserver

import (
	"context"
	"io"
	"net/http"

	"anime.bike/remotestorage/pkg/rs"
)

// Condition is a precondition on a write, taken from If-Match / If-None-Match.
// ETags are unquoted.
type Condition struct {
	// IfMatch, if non-empty, requires the current document version to be one of these.
	IfMatch []string
	// IfNoneMatchAny requires that the document does not exist (If-None-Match: *).
	IfNoneMatchAny bool
}

// PutResult is returned by StorageBackend.Put.
type PutResult struct {
	ETag    string
	Created bool
}

// StorageBackend stores one user's tree of documents and folders.
//
// Paths start with "/" and are relative to the user's storage root; folder
// paths end in "/". The handler validates paths before calling the backend.
//
// Backends must implement the storage model of the spec:
//   - a folder exists iff its subtree contains at least one document,
//   - every write changes the ETag of the document and of all ancestor folders,
//   - a document and a folder with the same name cannot coexist (ErrConflict),
//   - conditions are checked atomically with the write.
type StorageBackend interface {
	// Get returns a document or a folder listing. For a folder that does not
	// exist, it returns an empty listing (not ErrNotFound). If the document
	// body implements io.Seeker, the server can serve Range requests.
	Get(ctx context.Context, path string) (*rs.Document, *rs.FolderListing, error)

	// Head returns metadata of a document or folder. For a missing document
	// it returns ErrNotFound; for a missing folder it returns metadata with
	// an empty ETag.
	Head(ctx context.Context, path string) (*rs.Metadata, error)

	// Put creates or replaces a document. size is -1 when unknown.
	// Errors: ErrPreconditionFailed, ErrConflict, ErrTooLarge, ErrQuotaExceeded.
	Put(ctx context.Context, path string, body io.Reader, size int64, contentType string, cond Condition) (*PutResult, error)

	// Delete removes a document and returns the ETag it had.
	// Errors: ErrNotFound, ErrPreconditionFailed.
	Delete(ctx context.Context, path string, cond Condition) (etag string, err error)
}

// ResourceResolver extracts resource location information from HTTP request URLs
// This allows different implementations to support different URL structures:
// - Path-based: /{username}/{path}
// - Subdomain: https://{user}.example.com/{path}
// - Token-only (single tenant): /{path}
type ResourceResolver interface {
	// ResolveResource returns the user and the storage path of the request.
	// Path must keep its trailing "/" for folders. Module and IsPublic may be
	// left empty; the handler fills them from Path.
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

// StorageProvider returns the storage of the user named in the request.
// For public reads authInfo is nil, so the provider must use
// req.Resource.RequestedUser, not authInfo, to pick the storage.
type StorageProvider interface {
	GetStorage(ctx context.Context, authInfo *AuthInfo, req *ResourceRequest) (StorageBackend, error)
}
