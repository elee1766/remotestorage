package rsstorage_inmemory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"anime.bike/remotestorage/pkg/rs"
)

// InMemoryStorage implements in-memory storage for RemoteStorage
type InMemoryStorage struct {
	mu    sync.RWMutex
	files map[string]*fileData
	dirs  map[string]*dirData
}

type fileData struct {
	content      []byte
	contentType  string
	etag         string
	lastModified time.Time
}

type dirData struct {
	etag         string
	lastModified time.Time
}

// NewInMemoryStorage creates a new in-memory storage backend
func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		files: make(map[string]*fileData),
		dirs:  make(map[string]*dirData),
	}
}

// Get retrieves a document or folder listing
func (s *InMemoryStorage) Get(ctx context.Context, user_id, path string) (*rs.Document, *rs.FolderListing, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fullPath := buildPath(user_id, path)
	
	// Check if it's a file
	if file, ok := s.files[fullPath]; ok {
		return &rs.Document{
			Metadata: rs.Metadata{
				Path:         path,
				Name:         pathName(path),
				ContentType:  file.contentType,
				ETag:         file.etag,
				LastModified: file.lastModified,
				Size:         int64(len(file.content)),
				IsFolder:     false,
			},
			Body: io.NopCloser(bytes.NewReader(file.content)),
		}, nil, nil
	}

	// Check if it's a directory
	if !strings.HasSuffix(fullPath, "/") {
		fullPath += "/"
	}

	// Build folder listing
	items := make(map[string]rs.FolderItem)
	dirFound := false
	
	for filePath, file := range s.files {
		if strings.HasPrefix(filePath, fullPath) {
			relPath := strings.TrimPrefix(filePath, fullPath)
			// Only include direct children
			if !strings.Contains(relPath, "/") {
				items[relPath] = rs.FolderItem{
					ETag:          file.etag,
					ContentType:   file.contentType,
					ContentLength: int64(len(file.content)),
				}
				dirFound = true
			}
		}
	}

	// Check subdirectories
	for dirPath := range s.dirs {
		if strings.HasPrefix(dirPath, fullPath) && dirPath != fullPath {
			relPath := strings.TrimPrefix(dirPath, fullPath)
			// Only include direct children
			if idx := strings.Index(relPath, "/"); idx > 0 && idx == len(relPath)-1 {
				dirName := relPath[:idx]
				if _, exists := items[dirName+"/"]; !exists {
					items[dirName+"/"] = rs.FolderItem{
						ETag: "",
					}
					dirFound = true
				}
			}
		}
	}

	if !dirFound && fullPath != buildPath(user_id, "/") {
		return nil, nil, rs.ErrNotFound
	}

	// Calculate folder ETag
	folderEtag := calculateFolderEtag(items)
	
	listing := &rs.FolderListing{
		LDContext: rs.GetFolderListingContext(),
		Metadata: rs.Metadata{
			Path:     path,
			Name:     pathName(path),
			ETag:     folderEtag,
			IsFolder: true,
		},
		Items: items,
	}

	return nil, listing, nil
}

// Create stores a new document
func (s *InMemoryStorage) Create(ctx context.Context, user_id, path string, body io.Reader, contentType string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullPath := buildPath(user_id, path)
	
	// Check if already exists
	if _, exists := s.files[fullPath]; exists {
		return "", rs.ErrAlreadyExists
	}

	// Read content
	content, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	// Generate ETag
	etag := generateEtag(content)
	
	// Store file
	s.files[fullPath] = &fileData{
		content:      content,
		contentType:  contentType,
		etag:         etag,
		lastModified: time.Now(),
	}

	// Update parent directories
	s.updateParentDirs(user_id, path)

	return etag, nil
}

// Update modifies an existing document
func (s *InMemoryStorage) Update(ctx context.Context, user_id, path string, body io.Reader, contentType string, etag string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullPath := buildPath(user_id, path)
	
	// Check if exists
	file, exists := s.files[fullPath]
	if !exists {
		return "", rs.ErrNotFound
	}

	// Check ETag if provided
	if etag != "" && etag != file.etag {
		return "", rs.ErrPreconditionFailed
	}

	// Read content
	content, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}

	// Generate new ETag
	newEtag := generateEtag(content)
	
	// Update file
	s.files[fullPath] = &fileData{
		content:      content,
		contentType:  contentType,
		etag:         newEtag,
		lastModified: time.Now(),
	}

	// Update parent directories
	s.updateParentDirs(user_id, path)

	return newEtag, nil
}

// Delete removes a document
func (s *InMemoryStorage) Delete(ctx context.Context, user_id, path string, etag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	fullPath := buildPath(user_id, path)
	
	// Check if exists
	file, exists := s.files[fullPath]
	if !exists {
		return rs.ErrNotFound
	}

	// Check ETag if provided
	if etag != "" && etag != file.etag {
		return rs.ErrPreconditionFailed
	}

	// Delete file
	delete(s.files, fullPath)

	// Update parent directories
	s.updateParentDirs(user_id, path)

	return nil
}

// Head retrieves document metadata
func (s *InMemoryStorage) Head(ctx context.Context, user_id, path string) (*rs.Metadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fullPath := buildPath(user_id, path)
	
	// Check if it's a file
	file, ok := s.files[fullPath]
	if !ok {
		return nil, rs.ErrNotFound
	}

	return &rs.Metadata{
		Path:         path,
		Name:         pathName(path),
		ContentType:  file.contentType,
		ETag:         file.etag,
		LastModified: file.lastModified,
		Size:         int64(len(file.content)),
		IsFolder:     false,
	}, nil
}

// GetRange retrieves a document with a specific byte range
func (s *InMemoryStorage) GetRange(ctx context.Context, user_id, path string, start, end int64) (*rs.Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fullPath := buildPath(user_id, path)
	
	// Check if it's a file
	file, ok := s.files[fullPath]
	if !ok {
		return nil, rs.ErrNotFound
	}

	contentLen := int64(len(file.content))
	
	// Handle special cases for start and end
	if start == -1 {
		// Last N bytes case: start = -1, end = number of bytes
		if end > contentLen {
			end = contentLen
		}
		start = contentLen - end
		end = contentLen - 1
	} else if end == -1 {
		// From start to end of file
		end = contentLen - 1
	}
	
	// Validate range
	if start < 0 || start >= contentLen || end < start || end >= contentLen {
		return nil, fmt.Errorf("invalid range: start=%d, end=%d, content_length=%d", start, end, contentLen)
	}
	
	// Extract the range
	rangeContent := file.content[start:end+1]
	
	return &rs.Document{
		Metadata: rs.Metadata{
			Path:         path,
			Name:         pathName(path),
			ContentType:  file.contentType,
			ETag:         file.etag,
			LastModified: file.lastModified,
			Size:         int64(len(rangeContent)),
			IsFolder:     false,
		},
		Body: io.NopCloser(bytes.NewReader(rangeContent)),
	}, nil
}

// Helper functions

func buildPath(user_id, path string) string {
	// Ensure path starts with /
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("/%s%s", user_id, path)
}

func pathName(p string) string {
	name := path.Base(p)
	if name == "/" || name == "." {
		return ""
	}
	return name
}

func generateEtag(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])[:16]
}

func calculateFolderEtag(items map[string]rs.FolderItem) string {
	// Simple implementation: hash of all item names and etags
	h := sha256.New()
	for name, item := range items {
		h.Write([]byte(name))
		h.Write([]byte(item.ETag))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (s *InMemoryStorage) updateParentDirs(user_id, path string) {
	// Update modification times for all parent directories
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := 0; i < len(parts); i++ {
		dirPath := buildPath(user_id, "/"+strings.Join(parts[:i], "/")+"/")
		if i == 0 {
			dirPath = buildPath(user_id, "/")
		}
		s.dirs[dirPath] = &dirData{
			lastModified: time.Now(),
		}
	}
}

