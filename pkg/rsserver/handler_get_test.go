package rsserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"anime.bike/remotestorage/pkg/rs"
)

// mockStorageBackend is a minimal mock for testing
type mockStorageBackend struct{}

func (m *mockStorageBackend) Get(ctx context.Context, path string) (*rs.Document, *rs.FolderListing, error) {
	return nil, nil, rs.ErrNotFound
}

func (m *mockStorageBackend) Create(ctx context.Context, path string, body io.Reader, contentType string) (string, error) {
	return "", rs.ErrNotFound
}

func (m *mockStorageBackend) Update(ctx context.Context, path string, body io.Reader, contentType string, etag string) (string, error) {
	return "", rs.ErrNotFound
}

func (m *mockStorageBackend) Delete(ctx context.Context, path string, etag string) error {
	return rs.ErrNotFound
}

func (m *mockStorageBackend) Head(ctx context.Context, path string) (*rs.Metadata, error) {
	return nil, rs.ErrNotFound
}

// mockResourceResolver for testing
type mockResourceResolver struct{}

func (m *mockResourceResolver) ResolveResource(r *http.Request) (*ResourceRef, error) {
	return &ResourceRef{
		RequestedUser: "test",
		Module:        "documents",
		Path:          r.URL.Path,
		IsPublic:      false,
	}, nil
}

// mockAuthenticator for testing
type mockAuthenticator struct{}

func (m *mockAuthenticator) Authenticate(r *http.Request, token string) (*AuthInfo, error) {
	return &AuthInfo{
		UserID:   "test",
		Username: "test",
		Scopes: []rs.Scope{
			{Module: "*", Access: rs.ReadWriteAccess},
		},
	}, nil
}

// mockAuthorizer for testing
type mockAuthorizer struct{}

func (m *mockAuthorizer) Authorize(authInfo *AuthInfo, req *ResourceRequest) error {
	return nil
}

// mockStorageProvider for testing
type mockStorageProvider struct {
	backend StorageBackend
}

func (m *mockStorageProvider) GetStorage(ctx context.Context, authInfo *AuthInfo, req *ResourceRequest) (StorageBackend, error) {
	return m.backend, nil
}

func TestHandleGetRange_RejectsFolders(t *testing.T) {
	// Create handler with mocks
	handler := NewBuilder().
		WithResourceResolver(&mockResourceResolver{}).
		WithAuthenticator(&mockAuthenticator{}).
		WithAuthorizer(&mockAuthorizer{}).
		WithStorageProvider(&mockStorageProvider{backend: &mockStorageBackend{}}).
		MustBuild()

	// Test case: Range request to a folder (path ends with /)
	req := httptest.NewRequest("GET", "/folder/", nil)
	req.Header.Set("Range", "bytes=0-100")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should return 400 Bad Request
	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d for range request on folder, got %d", http.StatusBadRequest, w.Code)
	}

	body := w.Body.String()
	if body == "" {
		t.Error("Expected error message in response body")
	}
}

func TestHandleGetRange_AcceptsDocuments(t *testing.T) {
	// For this test, we need a storage backend that actually returns something
	// Since our mock returns ErrNotFound, we expect 404, but importantly NOT 400
	handler := NewBuilder().
		WithResourceResolver(&mockResourceResolver{}).
		WithAuthenticator(&mockAuthenticator{}).
		WithAuthorizer(&mockAuthorizer{}).
		WithStorageProvider(&mockStorageProvider{backend: &mockStorageBackend{}}).
		MustBuild()

	// Test case: Range request to a document (path does NOT end with /)
	req := httptest.NewRequest("GET", "/document.txt", nil)
	req.Header.Set("Range", "bytes=0-100")
	req.Header.Set("Authorization", "Bearer test-token")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Should NOT return 400 (will be 404 from mock, but that's fine)
	if w.Code == http.StatusBadRequest {
		t.Errorf("Range request on document should not return 400, got body: %s", w.Body.String())
	}
}
