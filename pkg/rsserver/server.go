package rsserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

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

// HTTPError represents an HTTP error with status code and message
type HTTPError struct {
	StatusCode int
	Message    string
}

func (e *HTTPError) Error() string {
	return e.Message
}

// NewHTTPError creates a new HTTP error
func NewHTTPError(statusCode int, message string) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Message:    message,
	}
}

// AuthInfo contains authentication and user information
type AuthInfo struct {
	// UserID is the unique identifier for the user (e.g., sub claim)
	UserID string

	// Username is the human-readable username (e.g., preferred_username)
	Username string

	// Scopes are the access scopes granted to this request
	Scopes []rs.Scope

	// IsAuthenticated indicates if the request has valid authentication
	IsAuthenticated bool
}

// StorageResult contains the storage backend and routing information
type StorageResult struct {
	// Storage backend to use for this request
	Storage StorageBackend

	// Module name extracted from the path
	Module string

	// Path within the storage (after stripping username/module, for instance)
	Path string
}

// ServerImplementation handles authentication and storage routing
type ServerImplementation interface {
	// GetAuth validates authentication and returns auth info
	// For public paths, this may return unauthenticated AuthInfo
	// Returns 401 error if authentication is required but fails
	GetAuth(r *http.Request) (*AuthInfo, error)

	// GetStorage returns storage backend and routing info for the request
	// The request context should contain AuthInfo from GetAuth
	GetStorage(r *http.Request) (*StorageResult, error)
}

// StorageHandler implements the RemoteStorage server protocol
type StorageHandler struct {
	Implementation ServerImplementation
	mux            *http.ServeMux
}

// NewStorageHandler creates a new RemoteStorage storage handler
func NewStorageHandler(i ServerImplementation) *StorageHandler {
	s := &StorageHandler{
		Implementation: i,
		mux:            http.NewServeMux(),
	}

	// Register routes with method-based routing
	s.mux.HandleFunc("GET /", s.handleGet)
	s.mux.HandleFunc("PUT /", s.handlePut)
	s.mux.HandleFunc("DELETE /", s.handleDelete)
	s.mux.HandleFunc("HEAD /", s.handleHead)

	return s
}

// ServeHTTP implements http.Handler
func (s *StorageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *StorageHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	// Authenticate and get storage (handles public paths automatically)
	authInfo, storageResult, err := s.authenticateAndGetStorage(r)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok {
			http.Error(w, httpErr.Message, httpErr.StatusCode)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Store auth info in context for potential use by backend
	ctx := WithAuthInfo(r.Context(), authInfo)

	storage := storageResult.Storage
	path := storageResult.Path
	doc, listing, err := storage.Get(ctx, path)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if listing != nil {
		// Check If-None-Match for folder
		if checkIfNoneMatch(r, listing.Metadata.ETag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		// Return folder listing as JSON-LD
		w.Header().Set("Content-Type", "application/ld+json")
		w.Header().Set("Cache-Control", "no-cache")
		if listing.Metadata.ETag != "" {
			w.Header().Set("ETag", listing.Metadata.ETag)
		}

		// Ensure we have the JSON-LD context
		if listing.LDContext == nil {
			listing.LDContext = rs.GetFolderListingContext()
		}

		json.NewEncoder(w).Encode(listing)
		return
	}

	if doc != nil {
		// Check If-None-Match for document
		if checkIfNoneMatch(r, doc.Metadata.ETag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		// Return document
		w.Header().Set("Cache-Control", "no-cache")
		if doc.Metadata.ContentType != "" {
			w.Header().Set("Content-Type", doc.Metadata.ContentType)
		}
		if doc.Metadata.ETag != "" {
			w.Header().Set("ETag", doc.Metadata.ETag)
		}
		if !doc.Metadata.LastModified.IsZero() {
			w.Header().Set("Last-Modified", doc.Metadata.LastModified.UTC().Format(http.TimeFormat))
		}
		if doc.Metadata.Size > 0 {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", doc.Metadata.Size))
		}

		if doc.Body != nil {
			defer doc.Body.Close()
			io.Copy(w, doc.Body)
		}
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
}

func (s *StorageHandler) handlePut(w http.ResponseWriter, r *http.Request) {
	// Authenticate and get storage
	authInfo, storageResult, err := s.authenticateAndGetStorage(r)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok {
			http.Error(w, httpErr.Message, httpErr.StatusCode)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Store auth info in context
	ctx := WithAuthInfo(r.Context(), authInfo)

	storage := storageResult.Storage
	path := storageResult.Path
	contentType := r.Header.Get("Content-Type")
	ifMatch := r.Header.Get("If-Match")
	ifNoneMatch := r.Header.Get("If-None-Match")

	var etag string

	// If-None-Match: * means create only if doesn't exist
	if ifNoneMatch == "*" {
		etag, err = storage.Create(ctx, path, r.Body, contentType)
		if err != nil {
			if errors.Is(err, rs.ErrAlreadyExists) {
				http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
			} else {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusCreated)
		return
	}

	// If-Match header means update existing
	if ifMatch != "" {
		etag, err = storage.Update(ctx, path, r.Body, contentType, ifMatch)
		if err != nil {
			if errors.Is(err, rs.ErrNotFound) {
				http.Error(w, "Not found", http.StatusNotFound)
			} else if errors.Is(err, rs.ErrPreconditionFailed) {
				http.Error(w, "Precondition Failed", http.StatusPreconditionFailed)
			} else {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusOK)
		return
	}

	// No precondition - try create first, then update
	etag, err = storage.Create(ctx, path, r.Body, contentType)
	if err == nil {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusCreated)
		return
	}

	// Document exists, do update without etag check
	etag, err = storage.Update(ctx, path, r.Body, contentType, "")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
}

func (s *StorageHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	// Authenticate and get storage
	authInfo, storageResult, err := s.authenticateAndGetStorage(r)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok {
			http.Error(w, httpErr.Message, httpErr.StatusCode)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Store auth info in context
	ctx := WithAuthInfo(r.Context(), authInfo)

	storage := storageResult.Storage
	path := storageResult.Path
	ifMatch := r.Header.Get("If-Match")

	err = storage.Delete(ctx, path, ifMatch)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *StorageHandler) handleHead(w http.ResponseWriter, r *http.Request) {
	// Authenticate and get storage (handles public paths automatically)
	authInfo, storageResult, err := s.authenticateAndGetStorage(r)
	if err != nil {
		if httpErr, ok := err.(*HTTPError); ok {
			http.Error(w, httpErr.Message, httpErr.StatusCode)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// Store auth info in context
	ctx := WithAuthInfo(r.Context(), authInfo)

	storage := storageResult.Storage
	path := storageResult.Path
	metadata, err := storage.Head(ctx, path)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if metadata.ContentType != "" {
		w.Header().Set("Content-Type", metadata.ContentType)
	}
	if metadata.ETag != "" {
		w.Header().Set("ETag", metadata.ETag)
	}
	if !metadata.LastModified.IsZero() {
		w.Header().Set("Last-Modified", metadata.LastModified.UTC().Format(http.TimeFormat))
	}
	if metadata.Size > 0 {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", metadata.Size))
	}

	w.WriteHeader(http.StatusOK)
}

// Helper functions

// isPublicDocument checks if a path points to a public document (not a folder)
// Per spec section 9: "GET and HEAD requests to a document (but not a folder)
// whose path starts with '/public/' are always allowed"
func isPublicDocument(path string) bool {
	// Must start with "public/" after leading slash is trimmed
	if !strings.HasPrefix(path, "public/") {
		return false
	}

	// Must not end with "/" (which would indicate a folder)
	return !strings.HasSuffix(path, "/")
}

// checkIfNoneMatch checks if the If-None-Match header matches the given ETag
// Returns true if the header exists and matches, indicating a 304 should be returned
func checkIfNoneMatch(r *http.Request, currentETag string) bool {
	ifNoneMatch := r.Header.Get("If-None-Match")
	if ifNoneMatch == "" || currentETag == "" {
		return false
	}

	// Parse comma-separated list of ETags
	etags := strings.Split(ifNoneMatch, ",")
	for _, etag := range etags {
		if strings.TrimSpace(etag) == currentETag {
			return true
		}
	}

	return false
}

// authenticateAndGetStorage handles authentication and storage retrieval with context caching
// This implements spec-compliant public path handling and avoids duplicate token validation
func (s *StorageHandler) authenticateAndGetStorage(r *http.Request) (*AuthInfo, *StorageResult, error) {
	// Check if auth info is already in context (from a previous call in the same request)
	if authInfo, ok := AuthInfoFromContext(r.Context()); ok {
		// Get storage with the cached auth
		storageResult, err := s.Implementation.GetStorage(r)
		return authInfo, storageResult, err
	}

	// Check if this is a public document path that doesn't require auth
	path := strings.TrimPrefix(r.URL.Path, "/")
	isPublic := isPublicDocument(path)
	isReadOnly := r.Method == "GET" || r.Method == "HEAD"

	// Per spec: "GET and HEAD requests to a document whose path starts with '/public/'
	// are always allowed. They, as well as OPTIONS requests, can be made without a bearer token."
	if isPublic && isReadOnly {
		// Try to authenticate, but don't fail if there's no auth
		authInfo, err := s.Implementation.GetAuth(r)
		if err != nil {
			// No authentication provided - that's okay for public documents
			authInfo = &AuthInfo{
				IsAuthenticated: false,
				Scopes:         []rs.Scope{},
			}
		}

		// Store in context for future use
		ctx := WithAuthInfo(r.Context(), authInfo)
		r = r.WithContext(ctx)

		// Get storage
		storageResult, err := s.Implementation.GetStorage(r)
		return authInfo, storageResult, err
	}

	// All other requests require authentication
	authInfo, err := s.Implementation.GetAuth(r)
	if err != nil {
		return nil, nil, err
	}

	// Store in context for future use
	ctx := WithAuthInfo(r.Context(), authInfo)
	r = r.WithContext(ctx)

	// Get storage
	storageResult, err := s.Implementation.GetStorage(r)
	return authInfo, storageResult, err
}
