package main

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"anime.bike/remotestorage/pkg/oauth"
	"anime.bike/remotestorage/pkg/rsserver"
	"anime.bike/remotestorage/pkg/rsserver/rsstorage"
	"anime.bike/remotestorage/pkg/rsserver/rsstorage/rsstorage_inmemory"
)

// limitReadCloser wraps an io.Reader with a limit while preserving Close functionality
type limitReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (lrc *limitReadCloser) Read(p []byte) (n int, err error) {
	return lrc.reader.Read(p)
}

func (lrc *limitReadCloser) Close() error {
	return lrc.closer.Close()
}

// newLimitReadCloser creates a ReadCloser that limits reads but preserves Close
func newLimitReadCloser(rc io.ReadCloser, limit int64) io.ReadCloser {
	return &limitReadCloser{
		reader: io.LimitReader(rc, limit),
		closer: rc,
	}
}

// SimpleResourceResolver parses URLs with structure: /{username}/{module}/{path} or /{username}/public/{module}/{path}
type SimpleResourceResolver struct{}

// NewSimpleResourceResolver creates a new resource resolver
func NewSimpleResourceResolver() *SimpleResourceResolver {
	return &SimpleResourceResolver{}
}

// ResolveResource extracts resource location from URL: /{username}/{module}/{path}
func (s *SimpleResourceResolver) ResolveResource(r *http.Request) (*rsserver.ResourceRef, error) {
	path := strings.TrimPrefix(r.URL.Path, "/")

	if path == "" {
		return nil, rsserver.NewHTTPError(http.StatusBadRequest, "Invalid path: path cannot be empty")
	}

	// Split into segments
	parts := strings.SplitN(path, "/", 4)

	// Need at least /{username}/{module}
	if len(parts) < 2 {
		return nil, rsserver.NewHTTPError(http.StatusBadRequest, "Invalid path: must be /{username}/{module}/...")
	}

	username := parts[0]
	var module, filePath string
	var isPublic bool

	// Check if second segment is "public"
	if parts[1] == "public" {
		isPublic = true

		// Need at least /{username}/public/{module}
		if len(parts) < 3 {
			return nil, rsserver.NewHTTPError(http.StatusBadRequest, "Invalid path: must be /{username}/public/{module}/...")
		}

		module = parts[2]
		if len(parts) > 3 {
			filePath = "/" + parts[3]
		} else {
			filePath = "/"
		}
	} else {
		// Private path: /{username}/{module}/{path}
		module = parts[1]
		if len(parts) > 2 {
			filePath = "/" + strings.Join(parts[2:], "/")
		} else {
			filePath = "/"
		}
	}

	return &rsserver.ResourceRef{
		RequestedUser: username,
		Module:        module,
		Path:          filePath,
		IsPublic:      isPublic,
	}, nil
}

// SimpleAuthenticator validates bearer tokens using an OAuth provider
type SimpleAuthenticator struct {
	oauthProvider *oauth.SimpleProvider
}

// NewSimpleAuthenticator creates a new authenticator
func NewSimpleAuthenticator(oauthProvider *oauth.SimpleProvider) *SimpleAuthenticator {
	return &SimpleAuthenticator{
		oauthProvider: oauthProvider,
	}
}

// Authenticate validates the bearer token and returns user identity
// This only does AUTHENTICATION - authorization is handled separately
func (s *SimpleAuthenticator) Authenticate(r *http.Request, token string) (*rsserver.AuthInfo, error) {
	// No token provided - return nil (authorization will decide if this is acceptable)
	if token == "" {
		return nil, nil
	}

	// Validate token with OAuth provider
	username, scopes, err := s.oauthProvider.ValidateToken(token)
	if err != nil {
		return nil, rsserver.NewHTTPError(http.StatusUnauthorized, "Invalid token")
	}

	return &rsserver.AuthInfo{
		UserID:   username, // Use username as storage ID
		Username: username,
		Scopes:   scopes,
	}, nil
}


// fileSizeLimitHook creates a BeforeWrite hook that enforces file size limits
// Returns nil if maxFileSize is 0 (no limit)
func fileSizeLimitHook(maxFileSize int64) func(r *http.Request, authInfo *rsserver.AuthInfo, req *rsserver.ResourceRequest) error {
	if maxFileSize == 0 {
		return nil // No limit configured
	}

	return func(r *http.Request, authInfo *rsserver.AuthInfo, req *rsserver.ResourceRequest) error {
		// Parse Content-Length header
		contentLengthStr := r.Header.Get("Content-Length")
		if contentLengthStr == "" {
			// No Content-Length header - we can't validate, but we'll enforce limit during read
			// Wrap the body with a LimitReader while preserving Close functionality
			r.Body = newLimitReadCloser(r.Body, maxFileSize+1)
			return nil
		}

		contentLength, err := strconv.ParseInt(contentLengthStr, 10, 64)
		if err != nil {
			return rsserver.NewHTTPError(http.StatusBadRequest, "Invalid Content-Length")
		}

		// Check if content length exceeds max file size
		if contentLength > maxFileSize {
			return rsserver.NewHTTPError(http.StatusRequestEntityTooLarge, "Payload Too Large")
		}

		// Wrap body with LimitReader to enforce declared Content-Length
		// Add 1 to detect if client sends more than declared
		// Preserve Close functionality so the handler can properly close the body
		r.Body = newLimitReadCloser(r.Body, contentLength+1)

		return nil
	}
}

// SimpleStorageProvider manages per-user storage buckets using a shared in-memory backend
type SimpleStorageProvider struct {
	mu            sync.RWMutex
	sharedStorage *rsstorage_inmemory.InMemoryStorage
	storages      map[string]*rsstorage.BucketStorage // bucketKey -> storage
}

// NewSimpleStorageProvider creates a new storage provider
func NewSimpleStorageProvider() *SimpleStorageProvider {
	return &SimpleStorageProvider{
		sharedStorage: rsstorage_inmemory.NewInMemoryStorage(),
		storages:      make(map[string]*rsstorage.BucketStorage),
	}
}

// GetStorage returns storage backend for the authenticated user and resource request
func (s *SimpleStorageProvider) GetStorage(ctx context.Context, authInfo *rsserver.AuthInfo, req *rsserver.ResourceRequest) (rsserver.StorageBackend, error) {
	// Determine storage identifier
	storageID := "public" // default for unauthenticated
	if authInfo != nil {
		storageID = authInfo.UserID
	}

	// Get or create storage for this user and module
	bucketKey := storageID + ":" + req.Resource.Module

	s.mu.Lock()
	defer s.mu.Unlock()

	storage, exists := s.storages[bucketKey]
	if !exists {
		storage = rsstorage.NewBucketStorage(s.sharedStorage, bucketKey)
		s.storages[bucketKey] = storage
	}

	return storage, nil
}
