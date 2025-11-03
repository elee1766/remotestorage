package rsstorage

import (
	"context"
	"io"

	"anime.bike/remotestorage/pkg/rs"
	"anime.bike/remotestorage/pkg/rsserver/rsstorage/rsstorage_inmemory"
)

// BucketStorage implements StorageBackend for a single user on shared storage
type BucketStorage struct {
	inner  *rsstorage_inmemory.InMemoryStorage
	userID string
}

// NewBucketStorage creates a new bucket storage instance for a specific user
func NewBucketStorage(sharedStorage *rsstorage_inmemory.InMemoryStorage, userID string) *BucketStorage {
	return &BucketStorage{
		inner:  sharedStorage,
		userID: userID,
	}
}

// Get retrieves a document or folder listing
func (b *BucketStorage) Get(ctx context.Context, path string) (*rs.Document, *rs.FolderListing, error) {
	// Use empty string as user_id since bucketing is handled at provider level
	return b.inner.Get(ctx, "", path)
}

// Create stores a new document (returns error if already exists)
func (b *BucketStorage) Create(ctx context.Context, path string, body io.Reader, contentType string) (etag string, err error) {
	return b.inner.Create(ctx, "", path, body, contentType)
}

// Update modifies an existing document (returns error if doesn't exist or etag mismatch)
func (b *BucketStorage) Update(ctx context.Context, path string, body io.Reader, contentType string, etag string) (newETag string, err error) {
	return b.inner.Update(ctx, "", path, body, contentType, etag)
}

// Delete removes a document
func (b *BucketStorage) Delete(ctx context.Context, path string, etag string) error {
	return b.inner.Delete(ctx, "", path, etag)
}

// Head retrieves document metadata
func (b *BucketStorage) Head(ctx context.Context, path string) (*rs.Metadata, error) {
	return b.inner.Head(ctx, "", path)
}

// GetRange retrieves a document with a specific byte range
func (b *BucketStorage) GetRange(ctx context.Context, path string, start, end int64) (*rs.Document, error) {
	return b.inner.GetRange(ctx, "", path, start, end)
}
