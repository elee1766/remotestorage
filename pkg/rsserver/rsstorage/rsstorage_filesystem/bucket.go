package rsstorage_filesystem

import (
	"context"
	"io"
	"path/filepath"

	"anime.bike/remotestorage/pkg/rs"
	"github.com/spf13/afero"
)

// BucketFilesystemStorage implements StorageBackend for a single bucket using filesystem
type BucketFilesystemStorage struct {
	inner *FilesystemStorage
}

// NewBucketFilesystemStorage creates a new bucket storage instance using filesystem
func NewBucketFilesystemStorage(fs afero.Fs, rootDir string) *BucketFilesystemStorage {
	return &BucketFilesystemStorage{
		inner: NewFilesystemStorage(fs, rootDir),
	}
}

// NewOSBucketFilesystemStorage creates a bucket storage using the OS filesystem
func NewOSBucketFilesystemStorage(rootDir string) *BucketFilesystemStorage {
	return NewBucketFilesystemStorage(afero.NewOsFs(), rootDir)
}

// NewMemoryBucketFilesystemStorage creates a bucket storage using in-memory filesystem
func NewMemoryBucketFilesystemStorage() *BucketFilesystemStorage {
	return NewBucketFilesystemStorage(afero.NewMemMapFs(), "/")
}

// Get retrieves a document or folder listing
func (b *BucketFilesystemStorage) Get(ctx context.Context, path string) (*rs.Document, *rs.FolderListing, error) {
	return b.inner.Get(ctx, path)
}

// Create stores a new document (returns error if already exists)
func (b *BucketFilesystemStorage) Create(ctx context.Context, path string, body io.Reader, contentType string) (etag string, err error) {
	return b.inner.Create(ctx, path, body, contentType)
}

// Update modifies an existing document (returns error if doesn't exist or etag mismatch)
func (b *BucketFilesystemStorage) Update(ctx context.Context, path string, body io.Reader, contentType string, etag string) (newETag string, err error) {
	return b.inner.Update(ctx, path, body, contentType, etag)
}

// Delete removes a document
func (b *BucketFilesystemStorage) Delete(ctx context.Context, path string, etag string) error {
	return b.inner.Delete(ctx, path, etag)
}

// Head retrieves document metadata
func (b *BucketFilesystemStorage) Head(ctx context.Context, path string) (*rs.Metadata, error) {
	return b.inner.Head(ctx, path)
}

// GetRange retrieves a document with a specific byte range
func (b *BucketFilesystemStorage) GetRange(ctx context.Context, path string, start, end int64) (*rs.Document, error) {
	return b.inner.GetRange(ctx, path, start, end)
}

// MultiUserFilesystemStorage implements storage for multiple users using filesystem
type MultiUserFilesystemStorage struct {
	fs   afero.Fs
	root string
}

// NewMultiUserFilesystemStorage creates a new multi-user filesystem storage
func NewMultiUserFilesystemStorage(fs afero.Fs, rootDir string) *MultiUserFilesystemStorage {
	return &MultiUserFilesystemStorage{
		fs:   fs,
		root: rootDir,
	}
}

// NewOSMultiUserFilesystemStorage creates a multi-user storage using the OS filesystem
func NewOSMultiUserFilesystemStorage(rootDir string) *MultiUserFilesystemStorage {
	return NewMultiUserFilesystemStorage(afero.NewOsFs(), rootDir)
}

// GetUserStorage returns a storage instance for a specific user
func (m *MultiUserFilesystemStorage) GetUserStorage(userID string) *FilesystemStorage {
	userDir := filepath.Join(m.root, userID)
	return NewFilesystemStorage(m.fs, userDir)
}

// GetBucketStorage returns a bucket storage instance for a specific bucket
func (m *MultiUserFilesystemStorage) GetBucketStorage(bucketID string) *BucketFilesystemStorage {
	bucketDir := filepath.Join(m.root, bucketID)
	return NewBucketFilesystemStorage(m.fs, bucketDir)
}
